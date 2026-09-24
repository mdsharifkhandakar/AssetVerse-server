require('dotenv').config();
const dns = require('dns');
dns.setServers(['8.8.8.8', '1.1.1.1', '8.8.4.4']);
const { MongoClient, ServerApiVersion } = require('mongodb');

const REQUIRED = [
  'users',
  'employeeAffiliations',
  'assets',
  'requests',
  'assignedAssets',
  'packages',
  'payments',
];

const SEED = [
  {
    name: 'Basic',
    price: 5,
    employeeLimit: 5,
    features: ['Asset Tracking', 'Employee Management', 'Basic Support'],
  },
  {
    name: 'Standard',
    price: 8,
    employeeLimit: 10,
    features: ['All Basic features', 'Advanced Analytics', 'Priority Support'],
  },
  {
    name: 'Premium',
    price: 15,
    employeeLimit: 20,
    features: ['All Standard features', 'Custom Branding', '24/7 Support'],
  },
];

const uri = process.env.MONGO_URI;
if (!uri) {
  console.log('MongoDB connection: FAIL');
  console.log('Remaining issue: MONGO_URI missing');
  process.exit(1);
}

const client = new MongoClient(uri, {
  serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true },
  serverSelectionTimeoutMS: 10000,
  connectTimeoutMS: 10000,
});

(async () => {
  try {
    await client.connect();
    const db = client.db('asset_db');
    await db.admin().command({ ping: 1 });

    const existing = (await db.listCollections().toArray()).map((c) => c.name);
    const created = [];
    for (const name of REQUIRED) {
      if (!existing.includes(name)) {
        await db.createCollection(name);
        created.push(name);
      }
    }

    const packages = db.collection('packages');
    let seeded = 0;
    for (const pkg of SEED) {
      const found = await packages.findOne({ name: pkg.name });
      if (!found) {
        await packages.insertOne(pkg);
        seeded += 1;
      }
    }

    const after = (await db.listCollections().toArray()).map((c) => c.name);
    const missing = REQUIRED.filter((r) => !after.includes(r));
    const pkgDocs = await packages
      .find({ name: { $in: ['Basic', 'Standard', 'Premium'] } }, { projection: { name: 1 } })
      .toArray();
    const pkgNames = pkgDocs.map((d) => d.name).sort();
    const expected = ['Basic', 'Premium', 'Standard'];
    const seedOk = expected.every((n) => pkgNames.includes(n)) && pkgNames.length === 3;

    console.log('Database: asset_db');
    console.log('Collections:');
    for (const r of REQUIRED) {
      console.log('- ' + r + (after.includes(r) ? ' OK' : ' MISSING'));
    }
    console.log('MongoDB connection: PASS');
    console.log('Collections: ' + (missing.length ? 'FAIL' : 'PASS'));
    console.log('Package seed: ' + (seedOk ? 'PASS' : 'FAIL'));
    console.log('Created this run: ' + (created.length ? created.join(', ') : '(none)'));
    console.log('Packages inserted this run: ' + seeded);
    console.log('Package names: ' + pkgNames.join(', '));
    console.log(
      'Remaining issue: ' +
        (missing.length === 0 && seedOk
          ? 'none'
          : 'collections=' + (missing.length ? 'FAIL' : 'PASS') + ' seed=' + (seedOk ? 'PASS' : 'FAIL'))
    );
  } catch (err) {
    const msg = String(err.message || err);
    const alert = (msg.match(/alert number (\d+)/) || [])[1];
    let stage = 'UNKNOWN';
    if (/ENOTFOUND|querySrv|EAI_AGAIN/i.test(msg)) stage = 'DNS';
    else if (alert || /SSL|TLS|tlsv1/i.test(msg)) stage = 'TLS' + (alert ? ' alert ' + alert : '');
    else if (/auth|Authentication failed/i.test(msg)) stage = 'AUTH';
    else if (/timed out|ECONN|Server selection/i.test(msg)) stage = 'TCP';
    console.log('Database: asset_db');
    console.log('MongoDB connection: FAIL stage=' + stage);
    console.log('Collections: FAIL');
    console.log('Package seed: FAIL');
    console.log('Remaining issue: connection failed at ' + stage + ' — no data modified');
  } finally {
    try {
      await client.close();
    } catch (_) {}
    process.exit(0);
  }
})();
