const fs = require('fs');
const path = require('path');
const dns = require('dns');
const net = require('net');
const tls = require('tls');

require('dotenv').config({ path: path.join(__dirname, '.env') });

const uri = process.env.MONGO_URI;
if (!uri) {
  console.log('RESULT=MONGO_URI_MISSING');
  process.exit(1);
}

const isSrv = uri.startsWith('mongodb+srv://');
const scheme = isSrv ? 'mongodb+srv' : uri.startsWith('mongodb://') ? 'mongodb' : 'unknown';
let rest = uri.replace(/^mongodb\+srv:\/\//, '').replace(/^mongodb:\/\//, '');
const at = rest.lastIndexOf('@');
const hasCred = at >= 0;
if (hasCred) rest = rest.slice(at + 1);
const queryIdx = rest.indexOf('?');
const query = queryIdx >= 0 ? rest.slice(queryIdx + 1) : '';
const beforePath = queryIdx >= 0 ? rest.slice(0, queryIdx) : rest;
const slash = beforePath.indexOf('/');
const hostPart = slash >= 0 ? beforePath.slice(0, slash) : beforePath;
const dbPath = slash >= 0 ? beforePath.slice(slash + 1) : '';
const hosts = hostPart.split(',').map((h) => h.split(':')[0]).filter(Boolean);

console.log('SCHEME=' + scheme);
console.log('HAS_CRED=' + (hasCred ? 'yes' : 'no'));
console.log('HOSTS=' + hosts.join(','));
console.log('DB_PATH=' + (dbPath || '(empty)'));
console.log('QUERY_KEYS=' + (query ? query.split('&').map((p) => p.split('=')[0]).join(',') : '(none)'));
console.log('NODE=' + process.version);
console.log('DRIVER=' + require('mongodb/package.json').version);
console.log('DNS_BEFORE=' + dns.getServers().join(','));

// Match server index.js DNS fallback
if (dns.getServers().length === 0 || dns.getServers().every((s) => s === '127.0.0.1' || s === '::1')) {
  dns.setServers(['8.8.8.8', '1.1.1.1', '8.8.4.4']);
  console.log('DNS_FALLBACK=applied');
} else {
  console.log('DNS_FALLBACK=skipped');
}
console.log('DNS_AFTER=' + dns.getServers().join(','));

function finishSrv() {
  resolveHosts();
}

if (isSrv && hosts[0]) {
  const srvName = '_mongodb._tcp.' + hosts[0];
  console.log('SRV_NAME=' + srvName);
  dns.resolveSrv(srvName, (err, addresses) => {
    if (err) {
      console.log('SRV_RESOLVE=FAIL code=' + err.code + ' msg=' + err.message);
      resolveHosts();
      return;
    }
    console.log('SRV_RESOLVE=OK count=' + addresses.length);
    addresses.forEach((a, i) => {
      console.log('SRV_TARGET[' + i + ']=' + a.name + ':' + a.port + ' prio=' + a.priority + ' weight=' + a.weight);
    });
    let pending = addresses.length;
    const targets = addresses.map((a) => ({ host: a.name, port: a.port }));
    if (!pending) {
      tcpThenTls(targets);
      return;
    }
    addresses.forEach((a) => {
      dns.lookup(a.name, { all: true }, (e2, addrs) => {
        if (e2) console.log('A_LOOKUP_FAIL ' + a.name + ' ' + e2.code);
        else console.log('A_LOOKUP_OK ' + a.name + ' -> ' + addrs.map((x) => x.address).join(','));
        if (--pending === 0) tcpThenTls(targets);
      });
    });
  });
  // TXT for replicaSet / loadBalanced
  dns.resolveTxt(hosts[0], (err, txt) => {
    if (err) {
      console.log('TXT_RESOLVE=FAIL code=' + err.code);
      return;
    }
    console.log('TXT_RESOLVE=OK count=' + txt.length);
    const flat = txt.map((r) => r.join(''));
    const svc = flat.find((t) => t.includes('serviceHostname'));
    if (svc) {
      const m = svc.match(/serviceHostname=([^;]+)/);
      if (m) console.log('TXT_serviceHostname=' + m[1]);
    } else {
      console.log('TXT_serviceHostname=(not found)');
    }
    const rs = flat.join(';').match(/replicaSet=([^;]+)/);
    if (rs) console.log('TXT_replicaSet=' + rs[1]);
    const lb = flat.join(';').match(/loadBalanced=([^;]+)/);
    if (lb) console.log('TXT_loadBalanced=' + lb[1]);
  });
} else {
  console.log('SRV_RESOLVE=n/a non-srv or no host');
  finishSrv();
}

function resolveHosts() {
  if (!hosts.length) {
    console.log('A_LOOKUP=no hosts');
    tcpThenTls(hosts.map((h) => ({ host: h, port: 27017 })));
    return;
  }
  let pending = hosts.length;
  const targets = hosts.map((h) => ({ host: h, port: 27017 }));
  hosts.forEach((h) => {
    dns.lookup(h, { all: true }, (e, addrs) => {
      if (e) console.log('A_LOOKUP_FAIL ' + h + ' ' + e.code);
      else console.log('A_LOOKUP_OK ' + h + ' -> ' + addrs.map((x) => x.address).join(','));
      if (--pending === 0) tcpThenTls(targets);
    });
  });
}

function tcpThenTls(targets) {
  if (!targets.length) {
    console.log('TCP=no targets');
    mongoConnect();
    return;
  }
  let left = targets.length;
  const done = () => {
    if (--left === 0) {
      tlsAll(targets, mongoConnect);
    }
  };
  targets.forEach(({ host, port }) => {
    const s = net.connect({ host, port, timeout: 8000 });
    s.on('connect', () => {
      console.log('TCP_OK ' + host + ':' + port);
      s.destroy();
      done();
    });
    s.on('timeout', () => {
      console.log('TCP_TIMEOUT ' + host + ':' + port);
      s.destroy();
      done();
    });
    s.on('error', (e) => {
      console.log('TCP_FAIL ' + host + ':' + port + ' ' + e.code);
      done();
    });
  });
}

function tlsAll(targets, cb) {
  if (!targets.length) {
    console.log('TLS=no targets');
    cb();
    return;
  }
  let left = targets.length;
  const done = () => {
    if (--left === 0) cb();
  };
  targets.forEach(({ host, port }) => {
    const sock = tls.connect({
      host,
      port,
      servername: host,
      rejectUnauthorized: true,
      timeout: 10000,
    }, () => {
      console.log('TLS_OK ' + host + ':' + port + ' authorized=' + sock.authorized + ' proto=' + sock.getProtocol());
      sock.end();
      done();
    });
    sock.on('timeout', () => {
      console.log('TLS_TIMEOUT ' + host + ':' + port);
      sock.destroy();
      done();
    });
    sock.on('error', (e) => {
      console.log('TLS_FAIL ' + host + ':' + port + ' code=' + (e.code || '') + ' msg=' + (e.message || ''));
      done();
    });
  });
}

function mongoConnect() {
  const { MongoClient, ServerApiVersion } = require('mongodb');
  const client = new MongoClient(uri, {
    serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true },
    serverSelectionTimeoutMS: 20000,
    connectTimeoutMS: 20000,
  });
  const t0 = Date.now();
  console.log('MONGO_CONNECT_START=1');
  client
    .connect()
    .then(async () => {
      console.log('MONGO_CONNECT=OK elapsed_ms=' + (Date.now() - t0));
      const db = client.db('asset_db');
      const collections = (await db.listCollections().toArray()).map((c) => c.name);
      console.log('DB=asset_db OK collections=' + collections.join(','));
      const packages = db.collection('packages');
      const users = db.collection('users');
      const pc = await packages.countDocuments();
      const uc = await users.countDocuments();
      console.log('PACKAGES_COUNT=' + pc);
      console.log('USERS_COUNT=' + uc);
      const hrCount = await users.countDocuments({ role: 'hr' });
      const empCount = await users.countDocuments({ role: 'employee' });
      console.log('HR_COUNT=' + hrCount);
      console.log('EMPLOYEE_COUNT=' + empCount);
      // GET /users/:email smoke: fetch first hr/employee without printing email/password
      const sampleHr = await users.findOne({ role: 'hr' }, { projection: { password: 0, email: 1, role: 1 } });
      const sampleEmp = await users.findOne({ role: 'employee' }, { projection: { password: 0, email: 1, role: 1 } });
      console.log('SAMPLE_HR=' + (sampleHr ? 'found role=' + sampleHr.role + ' hasEmail=' + Boolean(sampleHr.email) : 'none'));
      console.log('SAMPLE_EMP=' + (sampleEmp ? 'found role=' + sampleEmp.role + ' hasEmail=' + Boolean(sampleEmp.email) : 'none'));
      await client.close();
      console.log('RESULT=SUCCESS');
    })
    .catch((err) => {
      console.log('MONGO_CONNECT=FAIL elapsed_ms=' + (Date.now() - t0));
      console.log('FAIL_NAME=' + err.name);
      console.log('FAIL_CODE=' + (err.code || ''));
      console.log('FAIL_CODE_NAME=' + (err.codeName || ''));
      console.log('FAIL_MESSAGE=' + err.message);
      if (err.cause) {
        console.log('CAUSE_NAME=' + err.cause.name);
        console.log('CAUSE_CODE=' + (err.cause.code || ''));
        console.log('CAUSE_MESSAGE=' + err.cause.message);
      }
      console.log('RESULT=FAIL');
      process.exitCode = 1;
    });
}
