require('dotenv').config();
const dns = require('dns');
if (dns.getServers().length === 0 || dns.getServers().every((s) => s === '127.0.0.1' || s === '::1')) {
  dns.setServers(['8.8.8.8', '1.1.1.1', '8.8.4.4']);
}
const { MongoClient, ServerApiVersion } = require('mongodb');

const uri = process.env.MONGO_URI;
if (!uri) {
  console.log('STAGE=env RESULT=FAIL reason=MONGO_URI_missing');
  process.exit(1);
}
console.log('STAGE=env RESULT=OK loaded=yes scheme=' + (uri.startsWith('mongodb+srv://') ? 'srv' : uri.startsWith('mongodb://') ? 'standard' : 'unknown'));

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
  serverSelectionTimeoutMS: 15000,
  connectTimeoutMS: 15000,
});

(async () => {
  const t0 = Date.now();
  try {
    console.log('STAGE=dns RESULT=OK fallback=' + dns.getServers().join(','));
    await client.connect();
    console.log('STAGE=connect RESULT=OK elapsed_ms=' + (Date.now() - t0));

    const ping = await client.db('admin').command({ ping: 1 });
    console.log('STAGE=admin_ping RESULT=' + (ping && ping.ok === 1 ? 'OK' : 'UNEXPECTED'));

    const db = client.db('asset_db');
    const collections = (await db.listCollections().toArray()).map((c) => c.name);
    console.log('STAGE=asset_db RESULT=OK collections=' + (collections.length ? collections.join(',') : '(none yet)'));

    const dbPing = await db.command({ ping: 1 });
    console.log('STAGE=asset_db_ping RESULT=' + (dbPing && dbPing.ok === 1 ? 'OK' : 'UNEXPECTED'));

    console.log('RESULT=SUCCESS');
  } catch (err) {
    const msg = String(err && err.message ? err.message : err);
    const alert = msg.match(/alert number (\d+)/);
    let stage = 'unknown';
    if (/ENOTFOUND|EAI_AGAIN|ECONNREFUSED/i.test(msg) && !alert) stage = 'dns_or_tcp';
    else if (/timed out|Server selection timed out/i.test(msg) && !alert) stage = 'tcp_or_timeout';
    else if (alert) stage = 'TLS';
    else if (/auth|Authentication|AuthenticationFailed|bad auth/i.test(msg)) stage = 'Authentication';
    else if (/connect/i.test(msg)) stage = 'connect';
    console.log('RESULT=FAIL stage=' + stage);
    console.log('ERROR_NAME=' + (err && err.name ? err.name : 'unknown'));
    if (alert) console.log('TLS_ALERT=' + alert[1]);
    const code = (err && err.code) || (err && err.cause && err.cause.code);
    if (code) console.log('ERROR_CODE=' + code);
    // print a short sanitized reason without URI/credentials
    const safe = msg
      .replace(/mongodb\+srv:\/\/[^\s"']+/gi, 'mongodb+srv://[redacted]')
      .replace(/mongodb:\/\/[^\s"']+/gi, 'mongodb://[redacted]')
      .slice(0, 300);
    console.log('ERROR_SNIPPET=' + safe);
    process.exitCode = 1;
  } finally {
    try { await client.close(); console.log('STAGE=close RESULT=OK'); } catch (_) {}
  }
})();
