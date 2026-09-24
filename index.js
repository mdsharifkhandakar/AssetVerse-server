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

// ================= MIDDLEWARE =================

// JWT + Firebase ID token verification (verifyToken middleware)
const verifyToken = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).send({ message: "Unauthorized access" });

    const token = authHeader.split(' ')[1];
    if (!token) return res.status(401).send({ message: "Unauthorized access" });

    // 1) Firebase ID token (primary — used by the web client)
    if (admin.apps.length) {
        try {
            const decoded = await admin.auth().verifyIdToken(token);
            req.token_email = String(decoded.email || "").trim().toLowerCase();
            return next();
        } catch (_) {
            // fall through to JWT
        }
    }

    // 2) App JWT (issued by POST /login)
    if (process.env.JWT_SECRET) {
        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            req.token_email = String(decoded.email || "").trim().toLowerCase();
            return next();
        } catch (_) {
            // fall through
        }
    }

    if (!admin.apps.length) {
        return res.status(503).send({
            message: "Firebase Admin is not configured on the server. Set FIREBASE_ADMIN_SDK.",
            code: "ADMIN_UNAVAILABLE",
        });
    }
    return res.status(401).send({ message: "Unauthorized access" });
};

// Backward-compatible alias
const verifyFirebaseToken = verifyToken;

// HR-only middleware
const verifyHR = async (req, res, next) => {
    try {
        const email = String(req.token_email || "").trim().toLowerCase();
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

// Update user info (authenticated; email/role read-only)
app.put('/users/:email', dbReady, verifyToken, async (req, res) => {
    try {
        const email = String(req.params.email || '').trim().toLowerCase();
        const caller = String(req.token_email || "").trim().toLowerCase();
        if (!caller || caller !== email) {
            return res.status(403).send({ message: "You can only update your own profile" });
        }

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

        const normalizedEmail = String(email).trim().toLowerCase();
        const user = await usersCollection.findOne({ email: normalizedEmail });
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
            return res.status(503).send({
                message: "Firebase Admin is not configured on the server. Set FIREBASE_ADMIN_SDK.",
                code: "ADMIN_UNAVAILABLE",
            });
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


// Root
app.get('/', (req, res) => res.send("AssetVerse server running"));

// ================= DB-BACKED ROUTES (always registered; guarded by dbReady) =================

// /* ================= ASSETS ================= */
// // Get all assets with pagination
app.get('/assets', dbReady, async (req, res) => {
            try {
                const page = Math.max(1, parseInt(req.query.page) || 1);
                const limit = Math.max(1, parseInt(req.query.limit) || 10);
                const skip = (page - 1) * limit;

                const query = {};
                if (req.query.hrEmail) {
                    query.hrEmail = String(req.query.hrEmail).trim().toLowerCase();
                }
                if (req.query.search) {
                    query.productName = {
                        $regex: String(req.query.search).trim().replace(/[.*+?^${}()|[\]\\]/g, "\\$&"),
                        $options: "i"
                    };
                }

                const assets = await assetsCollection.find(query).skip(skip).limit(limit).toArray();
                const total = await assetsCollection.countDocuments(query);
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

        // HR-only: Update asset (owned company only)
        app.put('/assets/:id', dbReady, verifyFirebaseToken, verifyHR, async (req, res) => {
            try {
                if (!ObjectId.isValid(req.params.id)) {
                    return res.status(400).send({ message: "Invalid asset id" });
                }

                const allowed = {};
                if (req.body.productName !== undefined) allowed.productName = String(req.body.productName).trim();
                if (req.body.productQuantity !== undefined) allowed.productQuantity = Number(req.body.productQuantity);
                if (req.body.availableQuantity !== undefined) allowed.availableQuantity = Number(req.body.availableQuantity);
                if (req.body.productType !== undefined) allowed.productType = req.body.productType;
                if (req.body.productImage !== undefined) allowed.productImage = req.body.productImage;
                if (req.body.companyName !== undefined) allowed.companyName = req.body.companyName;

                if (allowed.productName !== undefined && !allowed.productName) {
                    return res.status(400).send({ message: "Product name is required" });
                }
                if (allowed.productQuantity !== undefined && (!Number.isFinite(allowed.productQuantity) || allowed.productQuantity < 1)) {
                    return res.status(400).send({ message: "Invalid quantity" });
                }
                if (allowed.availableQuantity !== undefined && (!Number.isFinite(allowed.availableQuantity) || allowed.availableQuantity < 0)) {
                    return res.status(400).send({ message: "Invalid available quantity" });
                }
                if (
                    allowed.productQuantity !== undefined &&
                    allowed.availableQuantity !== undefined &&
                    allowed.availableQuantity > allowed.productQuantity
                ) {
                    return res.status(400).send({ message: "Available quantity cannot exceed total quantity" });
                }
                if (Object.keys(allowed).length === 0) {
                    return res.status(400).send({ message: "No valid fields to update" });
                }

                const result = await assetsCollection.updateOne(
                    { _id: new ObjectId(req.params.id), hrEmail: req.user.email },
                    { $set: allowed }
                );
                if (result.matchedCount === 0) {
                    return res.status(404).send({ message: "Asset not found or access denied" });
                }
                res.send({ message: "Asset updated successfully", modifiedCount: result.modifiedCount });
            } catch (err) {
                console.error(err);
                res.status(500).send({ message: "Failed to update asset" });
            }
        });

        // HR-only: Delete asset (owned company only)
        app.delete('/assets/:id', dbReady, verifyFirebaseToken, verifyHR, async (req, res) => {
            try {
                if (!ObjectId.isValid(req.params.id)) {
                    return res.status(400).send({ message: "Invalid asset id" });
                }
                const result = await assetsCollection.deleteOne({
                    _id: new ObjectId(req.params.id),
                    hrEmail: req.user.email
                });
                if (result.deletedCount === 0) {
                    return res.status(404).send({ message: "Asset not found or access denied" });
                }
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

        // HR direct assignment — only for already-affiliated employees
        app.post('/assigned-assets', dbReady, verifyToken, verifyHR, async (req, res) => {
            try {
                const { employeeEmail, assetId, note } = req.body || {};
                const employee = String(employeeEmail || "").trim().toLowerCase();
                if (!employee || !assetId) {
                    return res.status(400).send({ message: "employeeEmail and assetId are required" });
                }
                if (!ObjectId.isValid(assetId)) {
                    return res.status(400).send({ message: "Invalid asset id" });
                }

                const affiliation = await affiliationsCollection.findOne({
                    employeeEmail: employee,
                    hrEmail: req.user.email,
                    status: "active"
                });
                if (!affiliation) {
                    return res.status(403).send({
                        message: "Direct assignment is only allowed for already affiliated employees",
                        code: "NOT_AFFILIATED"
                    });
                }

                const asset = await assetsCollection.findOne({
                    _id: new ObjectId(assetId),
                    hrEmail: req.user.email
                });
                if (!asset) {
                    return res.status(404).send({ message: "Asset not found or access denied" });
                }
                if (!(asset.availableQuantity > 0)) {
                    return res.status(400).send({ message: "No available quantity for this asset" });
                }

                const employeeUser = await usersCollection.findOne({ email: employee }, { projection: { password: 0 } });

                const assignment = {
                    assetId: asset._id,
                    assetName: asset.productName,
                    assetType: asset.productType,
                    productImage: asset.productImage || "",
                    requesterName: employeeUser?.name || affiliation.employeeName || employee,
                    requesterEmail: employee,
                    hrEmail: req.user.email,
                    companyName: affiliation.companyName || asset.companyName,
                    note: note || "",
                    requestStatus: "approved",
                    requestDate: new Date(),
                    approvalDate: new Date(),
                    assignmentDate: new Date(),
                    processedBy: req.user.email,
                    status: "assigned",
                    assignedDirectly: true
                };

                const result = await assignedAssetsCollection.insertOne(assignment);
                await assetsCollection.updateOne(
                    { _id: asset._id },
                    { $inc: { availableQuantity: -1 } }
                );

                res.send({
                    message: "Asset assigned successfully",
                    insertedId: result.insertedId,
                    assignment
                });
            } catch (err) {
                console.error(err);
                res.status(500).send({ message: "Failed to assign asset" });
            }
        });

        app.put('/assigned-assets/:id', dbReady, verifyToken, async (req, res) => {
            try {
                const id = req.params.id;
                const asset = await assignedAssetsCollection.findOne({ _id: new ObjectId(id) });
                if (!asset) return res.status(404).send({ message: "Assigned asset not found" });
                if (asset.status === "returned") return res.status(400).send({ message: "Asset already returned" });

                const caller = String(req.token_email || "").trim().toLowerCase();
                const owner = String(asset.requesterEmail || "").trim().toLowerCase();
                if (caller && caller !== owner) {
                    return res.status(403).send({ message: "You can only return your own assets" });
                }

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

        app.delete('/employee-affiliation', dbReady, verifyToken, verifyHR, async (req, res) => {
            try {
                const { employeeEmail, companyName, hrEmail } = req.body;
                if (!employeeEmail || !companyName || !hrEmail) return res.status(400).send({ message: "Missing required fields" });

                const caller = String(req.token_email || "").trim().toLowerCase();
                if (caller !== String(hrEmail || "").trim().toLowerCase()) {
                    return res.status(403).send({ message: "HR access only" });
                }

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
                const page = Math.max(1, parseInt(req.query.page) || 1);
                const limit = Math.max(1, parseInt(req.query.limit) || 10);
                const skip = (page - 1) * limit;

                const affiliations = await affiliationsCollection
                    .find({ companyName, status: "active" })
                    .skip(skip)
                    .limit(limit)
                    .toArray();
                const total = await affiliationsCollection.countDocuments({ companyName, status: "active" });
                const employeeEmails = affiliations.map(e => e.employeeEmail);
                const users = await usersCollection.find({ email: { $in: employeeEmails } }).project({
                    name: 1, email: 1, profileImage: 1, position: 1, dateOfBirth: 1, createdAt: 1
                }).toArray();
                res.send({
                    total,
                    page,
                    limit,
                    totalPages: Math.ceil(total / limit),
                    employees: users
                });
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

        app.post('/requests', dbReady, verifyToken, async (req, res) => {
            try {
                const request = req.body;
                if (!request.assetId || !request.assetName || !request.requesterEmail || !request.hrEmail)
                    return res.status(400).send({ message: "Missing required fields" });

                const caller = String(req.token_email || "").trim().toLowerCase();
                if (caller && caller !== String(request.requesterEmail || "").trim().toLowerCase()) {
                    return res.status(403).send({ message: "Cannot request assets for another user" });
                }

                if (!ObjectId.isValid(String(request.assetId))) {
                    return res.status(400).send({ message: "Invalid asset id" });
                }

                const asset = await assetsCollection.findOne({ _id: new ObjectId(request.assetId) });
                if (!asset) return res.status(404).send({ message: "Asset not found" });
                if (!(asset.availableQuantity > 0)) {
                    return res.status(400).send({ message: "Asset is not available" });
                }

                const requestedQty = Number(request.quantity ?? 1);
                if (!Number.isFinite(requestedQty) || requestedQty < 1) {
                    return res.status(400).send({ message: "Invalid quantity" });
                }
                if (requestedQty > asset.availableQuantity) {
                    return res.status(400).send({ message: "Requested quantity exceeds available quantity" });
                }

                request.requestDate = new Date();
                request.requestStatus = "pending";
                request.quantity = requestedQty;

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

        app.put('/requests/:id', dbReady, verifyToken, verifyHR, async (req, res) => {
            try {
                const id = req.params.id;
                const { requestStatus, processedBy } = req.body;

                if (requestStatus !== "approved" && requestStatus !== "rejected") {
                    return res.status(400).send({ message: "Invalid request status" });
                }

                const requestItem = await requestsCollection.findOne({ _id: new ObjectId(id) });
                if (!requestItem) return res.status(404).send({ message: "Request not found" });

                const caller = String(req.token_email || "").trim().toLowerCase();
                if (caller !== String(requestItem.hrEmail || "").trim().toLowerCase()) {
                    return res.status(403).send({ message: "HR access only" });
                }

                if (requestItem.requestStatus !== "pending") {
                    return res.status(400).send({ message: "Request already processed" });
                }

                const hr = await usersCollection.findOne({ email: requestItem.hrEmail });
                const alreadyAffiliated = await affiliationsCollection.findOne({
                    employeeEmail: requestItem.requesterEmail,
                    hrEmail: requestItem.hrEmail
                });

                // Package limit is enforced only when approving a new employee
                if (
                    requestStatus === "approved" &&
                    !alreadyAffiliated &&
                    hr &&
                    hr.currentEmployees >= hr.packageLimit
                ) {
                    return res.status(403).send({ message: "Package limit reached" });
                }

                await requestsCollection.updateOne(
                    { _id: new ObjectId(id) },
                    { $set: { requestStatus, processedBy, approvalDate: new Date() } }
                );

                if (requestStatus === "approved") {
                    const approvedAsset = await assetsCollection.findOne({ _id: new ObjectId(requestItem.assetId) });
                    if (!approvedAsset) {
                        return res.status(404).send({ message: "Asset not found" });
                    }
                    const deductQty = Number(requestItem.quantity ?? 1) || 1;
                    if (!(approvedAsset.availableQuantity >= deductQty)) {
                        return res.status(400).send({ message: "Insufficient available quantity" });
                    }

                    if (!alreadyAffiliated) {
                        await affiliationsCollection.insertOne({
                            employeeEmail: requestItem.requesterEmail,
                            employeeName: requestItem.requesterName,
                            hrEmail: requestItem.hrEmail,
                            companyName: requestItem.companyName,
                            companyLogo: approvedAsset?.companyLogo || "",
                            affiliationDate: new Date(),
                            status: "active"
                        });

                        await usersCollection.updateOne({ email: requestItem.hrEmail }, { $inc: { currentEmployees: 1 } });
                    }

                    await assignedAssetsCollection.insertOne({
                        ...requestItem,
                        requestStatus: "approved",
                        assignmentDate: new Date(),
                        status: "assigned"
                    });

                    await assetsCollection.updateOne(
                        { _id: new ObjectId(requestItem.assetId) },
                        { $inc: { availableQuantity: -deductQty } }
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

app.post('/create-checkout-session', dbReady, verifyToken, async (req, res) => {
    try {
        if (!stripe) return res.status(503).send({ message: "Payments not configured" });
        if (!process.env.SITE_DOMAIN) {
            return res.status(503).send({ message: "SITE_DOMAIN is not configured" });
        }

        const paymentInfo = req.body;
        const amount = parseInt(paymentInfo.cost) * 100;
        if (!Number.isFinite(amount) || amount <= 0) {
            return res.status(400).send({ message: "Invalid package cost" });
        }

        let packageDoc = null;
        if (paymentInfo.parcelId) {
            if (ObjectId.isValid(String(paymentInfo.parcelId))) {
                packageDoc = await packagesCollection.findOne({ _id: new ObjectId(paymentInfo.parcelId) });
            }
            if (!packageDoc) {
                packageDoc = await packagesCollection.findOne({ name: paymentInfo.parcelName });
            }
        }
        if (!packageDoc) {
            return res.status(400).send({ message: "Invalid package" });
        }
        if (String(packageDoc.price) !== String(paymentInfo.cost)) {
            return res.status(400).send({ message: "Package cost mismatch" });
        }

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

        // Do not log full Stripe session (may contain sensitive URLs/ids)
        res.send({ url: session.url });
    } catch (err) {
        console.error("Stripe / Payment error:", err);
        res.status(500).send({ message: "Failed to create checkout session" });
    }
});

app.patch('/upgrade-package', dbReady, verifyToken, verifyHR, async (req, res) => {
    try {
        const { packageName, amount } = req.body;
        const hrEmail = String(req.token_email || "").trim().toLowerCase();

        if (!packageName || amount === undefined || amount === null) {
            return res.status(400).send({ message: "Missing package info" });
        }

        const packageDoc = await packagesCollection.findOne({ name: packageName });
        if (!packageDoc) {
            return res.status(400).send({ message: "Unknown package" });
        }
        if (Number(packageDoc.price) !== Number(amount)) {
            return res.status(400).send({ message: "Package amount mismatch" });
        }

        const employeeLimit = packageDoc.employeeLimit;

        const updateResult = await usersCollection.updateOne(
            { email: hrEmail, role: "hr" },
            {
                $set: {
                    subscription: packageDoc.name,
                    packageLimit: employeeLimit,
                    updatedAt: new Date()
                }
            }
        );
        if (updateResult.matchedCount === 0) {
            return res.status(404).send({ message: "HR user not found" });
        }

        await paymentsCollection.insertOne({
            hrEmail,
            packageName: packageDoc.name,
            employeeLimit,
            amount: packageDoc.price,
            transactionId: `TXN-${Date.now()}`,
            paymentDate: new Date(),
            status: "completed"
        });

        res.send({ success: true, packageLimit: employeeLimit, subscription: packageDoc.name });

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
