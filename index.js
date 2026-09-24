// server.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { MongoClient, ObjectId, ServerApiVersion } = require('mongodb');
const dns = require('dns');
const activeDnsServers = dns.getServers();
if (activeDnsServers.length === 0 || activeDnsServers.every((s) => s === '127.0.0.1' || s === '::1')) {
    dns.setServers(['8.8.8.8', '1.1.1.1', '8.8.4.4']);
}
const admin = require("firebase-admin");
const fs = require("fs");
const path = require("path");
const stripe = process.env.STRIPE_SECRET ? require('stripe')(process.env.STRIPE_SECRET) : null;

function loadServiceAccount() {
    const raw = process.env.FIREBASE_ADMIN_SDK;
    if (!raw || !raw.trim()) return null;
    const value = raw.trim();
    if (value.startsWith("{")) return JSON.parse(value);
    const candidates = [path.resolve(value), path.resolve(__dirname, value)];
    const file = candidates.find((p) => fs.existsSync(p));
    if (!file) throw new Error("Service-account file not found");
    return JSON.parse(fs.readFileSync(file, "utf8"));
}

// Initialize Firebase Admin only when credentials are provided via env
try {
    const serviceAccount = loadServiceAccount();
    if (serviceAccount) {
        admin.initializeApp({
            credential: admin.credential.cert(serviceAccount)
        });
        console.log(`Firebase Admin initialized for project: ${serviceAccount.project_id}`);
    } else {
        console.warn("FIREBASE_ADMIN_SDK not set — Firebase token verification is disabled");
    }
} catch (err) {
    console.error("Firebase Admin initialization failed:", err.message);
}

const app = express();
const port = process.env.PORT || 3000;

// Middleware
const allowedOrigins = [
  'http://localhost:5173',
  'https://assetverse-client.netlify.app',
];

app.use(cors({
  origin: (origin, callback) => {
    // allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    callback(new Error("Not allowed by CORS"));
  },
  credentials: true
}));


app.use(express.json());

// MongoDB
const uri = process.env.MONGO_URI;
const client = uri ? new MongoClient(uri, {
    serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true },
    serverSelectionTimeoutMS: 5000,
    connectTimeoutMS: 5000
}) : null;

// Global collections
let usersCollection;
let assetsCollection;
let requestsCollection;
let assignedAssetsCollection;
let packagesCollection;
let affiliationsCollection;
let paymentsCollection;

function dbReady(req, res, next) {
    if (!usersCollection) {
        return res.status(503).send({
            message: "Database is unavailable. Please try again later.",
            code: "DB_UNAVAILABLE"
        });
    }
    next();
}

/* ================= AUTH / USER ROUTES (always registered) ================= */

// Register
app.post('/users', dbReady, async (req, res) => {
    try {
        const user = { ...req.body };
        if (user.email) user.email = String(user.email).trim().toLowerCase();
        if (!user.email || !user.name || !user.role) return res.status(400).send({ message: "Missing required fields" });
        if (user.role !== "hr" && user.role !== "employee") {
            return res.status(400).send({ message: "Role must be hr or employee" });
        }

        const exists = await usersCollection.findOne({ email: user.email });
        if (exists) return res.status(400).send({ message: "User already exists" });

        if (user.password) {
            user.password = await bcrypt.hash(user.password, 10);
        }

        if (user.role === "hr") {
            if (user.packageLimit === undefined) user.packageLimit = 5;
            if (user.currentEmployees === undefined) user.currentEmployees = 0;
            if (user.subscription === undefined) user.subscription = "basic";
        }

        user.createdAt = user.createdAt ? new Date(user.createdAt) : new Date();
        user.updatedAt = new Date();

        const result = await usersCollection.insertOne(user);
        res.send({ message: "User registered successfully", userId: result.insertedId });
    } catch (err) {
        console.error("POST /users:", err);
        res.status(500).send({ message: "Failed to register user" });
    }
});

// Get user by email
app.get('/users/:email', dbReady, async (req, res) => {
    try {
        const email = String(req.params.email || '').trim().toLowerCase();
        const user = await usersCollection.findOne(
            { email },
            { projection: { password: 0 } }
        );
        if (!user) return res.status(404).send({ message: "User not found" });
        res.send(user);
    } catch (err) {
        console.error("GET /users/:email:", err);
        res.status(500).send({ message: "Failed to load user" });
    }
});

// Update user info
app.put('/users/:email', dbReady, async (req, res) => {
    try {
        const email = String(req.params.email || '').trim().toLowerCase();
        const { displayName, photoURL } = req.body;
        if (!displayName || !String(displayName).trim()) {
            return res.status(400).send({ message: "Name is required" });
        }

        const updateData = { name: String(displayName).trim(), updatedAt: new Date() };
        if (photoURL) updateData.profileImage = photoURL;

        const result = await usersCollection.updateOne({ email }, { $set: updateData });
        if (result.matchedCount === 0) return res.status(404).send({ message: "User not found" });

        res.send({ message: "User info updated successfully" });
    } catch (err) {
        console.error("PUT /users/:email:", err);
        res.status(500).send({ message: "Failed to update user info" });
    }
});

// Legacy password login (Firebase is primary; kept for compatibility)
app.post('/login', dbReady, async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).send({ message: "Email and password required" });

        const user = await usersCollection.findOne({ email });
        if (!user) return res.status(401).send({ message: "Invalid credentials" });

        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(401).send({ message: "Invalid credentials" });

        if (!process.env.JWT_SECRET) {
            return res.status(500).send({ message: "Auth is not configured" });
        }

        const token = jwt.sign(
            { email: user.email, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '1d' }
        );

        res.send({
            token,
            user: {
                name: user.name,
                email: user.email,
                role: user.role,
                companyName: user.companyName || null,
                companyLogo: user.companyLogo || null,
                photoURL: user.profileImage || null
            }
        });
    } catch (err) {
        console.error(err);
        res.status(500).send({ message: "Login failed" });
    }
});

// Cleanup Firebase user after failed backend signup (self-only via ID token)
app.post('/auth/cleanup-failed-signup', async (req, res) => {
    try {
        if (!admin.apps.length) {
            return res.status(503).send({ message: "Firebase Admin is not configured", code: "ADMIN_UNAVAILABLE" });
        }
        const authHeader = req.headers.authorization;
        if (!authHeader) return res.status(401).send({ message: "Unauthorized" });
        const token = authHeader.split(' ')[1];
        if (!token) return res.status(401).send({ message: "Unauthorized" });

        const decoded = await admin.auth().verifyIdToken(token);

        // Only remove if no backend profile exists (avoid deleting completed accounts)
        if (usersCollection) {
            const existing = await usersCollection.findOne({ email: decoded.email });
            if (existing) {
                return res.status(409).send({ message: "Profile already exists", code: "PROFILE_EXISTS" });
            }
        }

        await admin.auth().deleteUser(decoded.uid);
        res.send({ message: "Temporary account cleaned up" });
    } catch (err) {
        console.error("cleanup-failed-signup:", err.message);
        res.status(500).send({ message: "Failed to clean up temporary account", code: "CLEANUP_FAILED" });
    }
});


// ================= MIDDLEWARE =================

// Firebase Token Verification
const verifyFirebaseToken = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).send({ message: "Unauthorized access" });

    const token = authHeader.split(' ')[1];
    if (!token) return res.status(401).send({ message: "Unauthorized access" });

    try {
        const decoded = await admin.auth().verifyIdToken(token);
        req.token_email = decoded.email;
        next();
    } catch (err) {
        return res.status(401).send({ message: "Unauthorized access" });
    }
};

// HR-only middleware
const verifyHR = async (req, res, next) => {
    try {
        const email = req.token_email;
        if (!email) return res.status(401).send({ message: "Unauthorized" });

        const user = await usersCollection.findOne({ email });
        if (!user) return res.status(401).send({ message: "User not found" });
        if (user.role !== "hr") return res.status(403).send({ message: "HR access only" });

        req.user = user; // attach user info
        next();
    } catch (err) {
        console.error(err);
        res.status(500).send({ message: "Server error" });
    }
};

// Root
app.get('/', (req, res) => res.send("AssetVerse server running"));

// ================= DB-BACKED ROUTES (always registered; guarded by dbReady) =================

// /* ================= ASSETS ================= */
// // Get all assets with pagination
app.get('/assets', dbReady, async (req, res) => {
            try {
                const page = parseInt(req.query.page) || 1;
                const limit = parseInt(req.query.limit) || 10;
                const skip = (page - 1) * limit;

                const assets = await assetsCollection.find().skip(skip).limit(limit).toArray();
                const total = await assetsCollection.countDocuments();
                const totalPages = Math.ceil(total / limit);

                res.send({ total, page, limit, totalPages, assets });
            } catch (err) {
                console.error(err);
                res.status(500).send({ message: "Failed to fetch assets" });
            }
        });

        // HR-only: Add asset
        app.post('/assets', dbReady, verifyFirebaseToken, verifyHR, async (req, res) => {
            try {
                const asset = req.body;
                asset.dateAdded = new Date();
                asset.availableQuantity = asset.productQuantity;
                asset.hrEmail = req.user.email;

                const result = await assetsCollection.insertOne(asset);
                res.send({ message: "Asset added successfully", assetId: result.insertedId });
            } catch (err) {
                console.error(err);
                res.status(500).send({ message: "Failed to add asset" });
            }
        });

        // // HR-only: Update asset
        app.put('/assets/:id', dbReady, verifyFirebaseToken, verifyHR, async (req, res) => {
            try {
                const result = await assetsCollection.updateOne(
                    { _id: new ObjectId(req.params.id) },
                    { $set: req.body }
                );
                res.send({ message: "Asset updated successfully", modifiedCount: result.modifiedCount });
            } catch (err) {
                console.error(err);
                res.status(500).send({ message: "Failed to update asset" });
            }
        });

        // HR-only: Delete asset
        app.delete('/assets/:id', dbReady, verifyFirebaseToken, verifyHR, async (req, res) => {
            try {
                const result = await assetsCollection.deleteOne({ _id: new ObjectId(req.params.id) });
                res.send({ message: "Asset deleted successfully", deletedCount: result.deletedCount });
            } catch (err) {
                console.error(err);
                res.status(500).send({ message: "Failed to delete asset" });
            }
        });

        // /* ================= ASSIGNED ASSETS ================= */
        app.get('/assigned-assets', dbReady, async (req, res) => {
            try {
                const email = req.query.email;
                const result = await assignedAssetsCollection.find({ requesterEmail: email }).toArray();
                res.send(result);
            } catch (err) {
                console.error(err);
                res.status(500).send({ message: "Failed to fetch assigned assets" });
            }
        });

        app.put('/assigned-assets/:id', dbReady, async (req, res) => {
            try {
                const id = req.params.id;
                const asset = await assignedAssetsCollection.findOne({ _id: new ObjectId(id) });
                if (!asset) return res.status(404).send({ message: "Assigned asset not found" });
                if (asset.status === "returned") return res.status(400).send({ message: "Asset already returned" });

                await assignedAssetsCollection.updateOne(
                    { _id: new ObjectId(id) },
                    { $set: { status: "returned", returnDate: new Date() } }
                );

                await assetsCollection.updateOne(
                    { _id: new ObjectId(asset.assetId) },
                    { $inc: { availableQuantity: 1 } }
                );

                res.send({ message: "Asset returned successfully" });
            } catch (err) {
                console.error(err);
                res.status(500).send({ message: "Failed to return asset" });
            }
        });

        // /* ================= EMPLOYEE AFFILIATIONS ================= */
        app.get('/employee-affiliations', dbReady, async (req, res) => {
            try {
                const email = req.query.email;
                const affiliations = await affiliationsCollection
                    .find({ employeeEmail: email, status: "active" })
                    .project({ companyName: 1, companyLogo: 1, hrEmail: 1 })
                    .toArray();
                res.send(affiliations);
            } catch (err) {
                console.error(err);
                res.status(500).send({ message: "Failed to fetch affiliations" });
            }
        });

        app.delete('/employee-affiliation', dbReady, async (req, res) => {
            try {
                const { employeeEmail, companyName, hrEmail } = req.body;
                if (!employeeEmail || !companyName || !hrEmail) return res.status(400).send({ message: "Missing required fields" });

                const result = await affiliationsCollection.deleteOne({ employeeEmail, companyName, hrEmail });
                if (result.deletedCount === 0) return res.status(404).send({ message: "Affiliation not found" });

                await usersCollection.updateOne({ email: hrEmail }, { $inc: { currentEmployees: -1 } });
                res.send({ message: "Employee removed from company successfully" });
            } catch (err) {
                console.error(err);
                res.status(500).send({ message: "Failed to remove employee" });
            }
        });

        app.get('/company-employees', dbReady, async (req, res) => {
            try {
                const companyName = req.query.company;
                const employees = await affiliationsCollection.find({ companyName, status: "active" }).toArray();
                const employeeEmails = employees.map(e => e.employeeEmail);
                const users = await usersCollection.find({ email: { $in: employeeEmails } }).project({
                    name: 1, email: 1, profileImage: 1, position: 1, dateOfBirth: 1, createdAt: 1
                }).toArray();
                res.send(users);
            } catch (err) {
                console.error(err);
                res.status(500).send({ message: "Failed to fetch company employees" });
            }
        });

        // /* ================= REQUESTS ================= */
        app.get('/requests', dbReady, async (req, res) => {
            try {
                const hrEmail = req.query.hrEmail;
                const userEmail = req.query.userEmail;
                const query = {};
                if (hrEmail) query.hrEmail = hrEmail;
                if (userEmail) query.requesterEmail = userEmail;
                const requests = await requestsCollection.find(query).toArray();
                res.send(requests);
            } catch (err) {
                console.error(err);
                res.status(500).send({ message: "Failed to fetch requests" });
            }
        });

        app.post('/requests', dbReady, async (req, res) => {
            try {
                const request = req.body;
                if (!request.assetId || !request.assetName || !request.requesterEmail || !request.hrEmail)
                    return res.status(400).send({ message: "Missing required fields" });

                request.requestDate = new Date();
                request.requestStatus = "pending";

                const existingRequest = await requestsCollection.findOne({
                    assetId: request.assetId,
                    requesterEmail: request.requesterEmail,
                    requestStatus: "pending"
                });

                if (existingRequest) return res.status(400).send({ message: "You already have a pending request for this asset" });

                const result = await requestsCollection.insertOne(request);
                res.send({ success: true, insertedId: result.insertedId });
            } catch (err) {
                console.error(err);
                res.status(500).send({ message: "Failed to create request" });
            }
        });

        app.put('/requests/:id', dbReady, async (req, res) => {
            try {
                const id = req.params.id;
                const { requestStatus, processedBy } = req.body;
                const requestItem = await requestsCollection.findOne({ _id: new ObjectId(id) });
                if (!requestItem) return res.status(404).send({ message: "Request not found" });

                const hr = await usersCollection.findOne({ email: requestItem.hrEmail });
                const alreadyAffiliated = await affiliationsCollection.findOne({
                    employeeEmail: requestItem.requesterEmail,
                    hrEmail: requestItem.hrEmail
                });

                if (!alreadyAffiliated && hr.currentEmployees >= hr.packageLimit) {
                    return res.status(403).send({ message: "Package limit reached" });
                }

                await requestsCollection.updateOne(
                    { _id: new ObjectId(id) },
                    { $set: { requestStatus, processedBy, approvalDate: new Date() } }
                );

                if (requestStatus === "approved") {
                    if (!alreadyAffiliated) {
                        const asset = await assetsCollection.findOne({ _id: new ObjectId(requestItem.assetId) });

                        await affiliationsCollection.insertOne({
                            employeeEmail: requestItem.requesterEmail,
                            employeeName: requestItem.requesterName,
                            hrEmail: requestItem.hrEmail,
                            companyName: requestItem.companyName,
                            companyLogo: asset?.companyLogo || "",
                            affiliationDate: new Date(),
                            status: "active"
                        });

                        await usersCollection.updateOne({ email: requestItem.hrEmail }, { $inc: { currentEmployees: 1 } });
                    }

                    await assignedAssetsCollection.insertOne({
                        ...requestItem,
                        assignmentDate: new Date(),
                        status: "assigned"
                    });

                    await assetsCollection.updateOne(
                        { _id: new ObjectId(requestItem.assetId) },
                        { $inc: { availableQuantity: -1 } }
                    );
                }

                res.send({ success: true });
            } catch (err) {
                console.error(err);
                res.status(500).send({ message: "Failed to update request" });
            }
        });

        // /* ================= PACKAGES ================= */
        app.get('/packages', dbReady, async (req, res) => {
            res.send(await packagesCollection.find().toArray());
        });

// ================= PAYMENT RELATED API'S =================

app.get('/payments', dbReady, async (req, res) => {
    try {
        const email = req.query.email;
        const payments = await paymentsCollection
            .find({ hrEmail: email })
            .sort({ paymentDate: -1 })
            .toArray();
        res.send(payments);
    } catch (err) {
        console.error(err);
        res.status(500).send({ message: "Failed to fetch payments" });
    }
});

app.post('/create-checkout-session', dbReady, async (req, res) => {
    try {
        if (!stripe) return res.status(503).send({ message: "Payments not configured" });

        const paymentInfo = req.body;
        const amount = parseInt(paymentInfo.cost) * 100;

        // Create Stripe checkout session
        const session = await stripe.checkout.sessions.create({
            line_items: [
                {
                    price_data: {
                        currency: 'usd',
                        unit_amount: amount,
                        product_data: {
                            name: paymentInfo.parcelName
                        }
                    },
                    quantity: 1,
                },
            ],
            customer_email: paymentInfo.senderEmail,
            mode: 'payment',
            metadata: {
                parcelId: paymentInfo.parcelId
            },
            success_url: `${process.env.SITE_DOMAIN}/dashboard/upgrade-success`,
            cancel_url: `${process.env.SITE_DOMAIN}/dashboard/upgrade-cancelled`,
        });

        // Store payment info in MongoDB
        await paymentsCollection.insertOne({
            hrEmail: paymentInfo.senderEmail,
            packageName: paymentInfo.parcelName,
            amount: paymentInfo.cost,
            parcelId: paymentInfo.parcelId,
            transactionId: `TXN-${Date.now()}`,
            status: "pending", // will update to "completed" after actual Stripe payment
            createdAt: new Date()
        });

        console.log(session);
        res.send({ url: session.url });
    } catch (err) {
        console.error("Stripe / Payment error:", err);
        res.status(500).send({ message: "Failed to create checkout session" });
    }
});

app.patch('/upgrade-package', dbReady, verifyFirebaseToken, async (req, res) => {
    try {
        const { packageName, employeeLimit, amount } = req.body;
        const hrEmail = req.token_email;

        if (!packageName || !employeeLimit || !amount) {
            return res.status(400).send({ message: "Missing package info" });
        }

        await usersCollection.updateOne(
            { email: hrEmail },
            {
                $set: {
                    subscription: packageName,
                    packageLimit: employeeLimit,
                    updatedAt: new Date()
                }
            }
        );

        await paymentsCollection.insertOne({
            hrEmail,
            packageName,
            employeeLimit,
            amount,
            transactionId: `TXN-${Date.now()}`,
            paymentDate: new Date(),
            status: "completed"
        });

        res.send({ success: true });

    } catch (error) {
        console.error("Upgrade error:", error);
        res.status(500).send({ message: "Failed to upgrade package" });
    }
});



// ================= MONGODB CONNECT (once) + SEED =================
function redactMongoError(err) {
    const msg = err && err.message ? String(err.message) : String(err);
    return msg
        .replace(/mongodb(\+srv)?:\/\/[^\s"']+/gi, 'mongodb://[redacted]')
        .replace(/\/\/[^\s@]*:[^\s@]*@/g, '//[redacted]@')
        .slice(0, 300);
}

async function run() {
    if (!client) {
        console.warn("MongoDB warning: MONGO_URI is not set — continuing without database");
        return false;
    }
    await client.connect();
    const db = client.db('asset_db');
    await db.command({ ping: 1 });

    usersCollection = db.collection('users');
    assetsCollection = db.collection('assets');
    requestsCollection = db.collection('requests');
    assignedAssetsCollection = db.collection('assignedAssets');
    packagesCollection = db.collection('packages');
    affiliationsCollection = db.collection('employeeAffiliations');
    paymentsCollection = db.collection('payments');

    console.log("Connected to MongoDB");

    const packageCount = await packagesCollection.countDocuments();
    if (packageCount === 0) {
        await packagesCollection.insertMany([
            {
                name: "Basic",
                price: 10,
                employeeLimit: 5,
                features: ["Asset tracking", "Request & approval workflow", "Employee dashboard"]
            },
            {
                name: "Standard",
                price: 25,
                employeeLimit: 20,
                features: ["Everything in Basic", "Payment history", "Team management"]
            },
            {
                name: "Premium",
                price: 50,
                employeeLimit: 100,
                features: ["Everything in Standard", "Priority support", "Advanced analytics"]
            }
        ]);
        console.log("Seeded default packages (packages collection was empty)");
    }
    return true;
}

const DB_RETRY_MS = 30000;
let dbRetryTimer = null;

function scheduleDbRetry() {
    if (dbRetryTimer) return;
    dbRetryTimer = setInterval(async () => {
        if (usersCollection) {
            clearInterval(dbRetryTimer);
            dbRetryTimer = null;
            return;
        }
        try {
            await run();
        } catch (err) {
            console.warn("MongoDB retry failed:", redactMongoError(err));
        }
    }, DB_RETRY_MS);
    if (dbRetryTimer.unref) dbRetryTimer.unref();
}

// Always start HTTP server, even if MongoDB is unavailable
async function startServer() {
    if (client) {
        const maxStartupAttempts = 3;
        for (let attempt = 1; attempt <= maxStartupAttempts; attempt++) {
            try {
                if (await run()) break;
            } catch (err) {
                console.warn(
                    `MongoDB warning: connection failed (attempt ${attempt}/${maxStartupAttempts}) —`,
                    redactMongoError(err)
                );
            }
            if (attempt < maxStartupAttempts) {
                await new Promise((resolve) => setTimeout(resolve, 1000 * attempt));
            }
        }
        if (!usersCollection) {
            console.warn("MongoDB still unavailable — will keep retrying in the background");
            scheduleDbRetry();
        }
    }

    app.listen(port, () => {
        console.log(`AssetVerse server running on port ${port}`);
        console.log(`Local API base: http://localhost:${port}`);
    });
}

// Graceful shutdown: close the Mongo client before exiting
function shutdown(signal) {
    console.log(`${signal} received — shutting down`);
    const exit = () => process.exit(0);
    if (client) {
        Promise.race([client.close(), new Promise((r) => setTimeout(r, 3000))])
            .then(exit)
            .catch(exit);
    } else {
        exit();
    }
}
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

startServer();
