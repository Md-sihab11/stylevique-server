import express from "express";
import cors from "cors";
import "dotenv/config";
import helmet from "helmet";
import multer from "multer";
import { rateLimit } from "express-rate-limit";
import { MongoClient, ObjectId } from "mongodb";
import { createRemoteJWKSet, jwtVerify } from "jose";
import Stripe from "stripe";

// ========================================
// Environment Configuration
// ========================================

const NODE_ENV = process.env.NODE_ENV || "development";
const PORT = Number(process.env.PORT) || 5000;

const MONGODB_URI = (process.env.MONGODB_URI || "").trim();
const DB_NAME = (process.env.DB_NAME || "stylevique").trim();
const AUTH_USER_COLLECTION = (process.env.AUTH_USER_COLLECTION || "user").trim();

const CLIENT_URLS = [
    ...new Set(
        (process.env.CLIENT_URL || "http://localhost:3000")
            .split(",")
            .map((url) => url.trim().replace(/\/+$/, ""))
            .filter(Boolean),
    ),
];
const CLIENT_URL = CLIENT_URLS[0] || "http://localhost:3000";

const BETTER_AUTH_JWKS_URL = (
    process.env.BETTER_AUTH_JWKS_URL || `${CLIENT_URL}/api/auth/jwks`
).trim();
const BETTER_AUTH_ISSUER = (process.env.BETTER_AUTH_ISSUER || CLIENT_URL)
    .trim()
    .replace(/\/+$/, "");
const BETTER_AUTH_AUDIENCE = (process.env.BETTER_AUTH_AUDIENCE || CLIENT_URL)
    .trim()
    .replace(/\/+$/, "");

const STRIPE_SECRET_KEY = (process.env.STRIPE_SECRET_KEY || "").trim();
const STRIPE_WEBHOOK_SECRET = (process.env.STRIPE_WEBHOOK_SECRET || "").trim();
const STRIPE_CURRENCY = (process.env.STRIPE_CURRENCY || "usd").trim().toLowerCase();

const IMGBB_API_KEY = (process.env.IMGBB_API_KEY || "").trim();
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "").trim().toLowerCase();

const MAX_UPLOAD_SIZE_MB =
    Number(process.env.MAX_UPLOAD_SIZE_MB) > 0
        ? Math.min(Number(process.env.MAX_UPLOAD_SIZE_MB), 25)
        : 5;
const MAX_UPLOAD_SIZE_BYTES = MAX_UPLOAD_SIZE_MB * 1024 * 1024;

const IS_ADMIN_PROMOTION_COMMAND = process.argv[2] === "promote-admin";

// ========================================
// Stripe Configuration
// ========================================

const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY) : null;

// ========================================
// Express App Initialization
// ========================================

const app = express();
app.disable("x-powered-by");

if (NODE_ENV === "production") {
    app.set("trust proxy", 1);
}

// ========================================
// Middleware
// ========================================

app.use(
    helmet({
        crossOriginResourcePolicy: { policy: "cross-origin" },
    }),
);

const corsOptions = {
    origin(origin, callback) {
        if (!origin || CLIENT_URLS.includes(origin)) {
            return callback(null, true);
        }
        return callback(
            new Error("This origin is not allowed to access the API."),
        );
    },
    methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: false,
    maxAge: 86400,
    optionsSuccessStatus: 204,
};

app.use(cors(corsOptions));

app.use((req, res, next) => {
    const startedAt = Date.now();
    res.on("finish", () => {
        const pathWithoutQuery = req.originalUrl.split("?")[0];
        const duration = Date.now() - startedAt;
        console.log(`${req.method} ${pathWithoutQuery} ${res.statusCode} ${duration}ms`);
    });
    next();
});

// Stripe webhook MUST use raw body before express.json()
app.post(
    "/api/payments/webhook",
    express.raw({ type: "application/json", limit: "1mb" }),
    (req, res, next) => {
        // stripeWebhookHandler is defined later; hoisting works for function declarations
        stripeWebhookHandler(req, res, next);
    },
);

const generalApiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 300,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    handler(req, res) {
        return res.status(429).json({
            success: false,
            message: "Too many requests. Please try again later.",
        });
    },
});

const bookingLimiter = rateLimit({
    windowMs: 10 * 60 * 1000,
    limit: 30,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    handler(req, res) {
        return res.status(429).json({
            success: false,
            message: "Too many booking attempts. Please wait a few minutes and try again.",
        });
    },
});

const checkoutLimiter = rateLimit({
    windowMs: 10 * 60 * 1000,
    limit: 30,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    handler(req, res) {
        return res.status(429).json({
            success: false,
            message: "Too many payment attempts. Please wait a few minutes and try again.",
        });
    },
});

const uploadLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 40,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    handler(req, res) {
        return res.status(429).json({
            success: false,
            message: "Too many uploads. Please wait a few minutes and try again.",
        });
    },
});

app.use("/api", generalApiLimiter);
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: false, limit: "1mb" }));

app.use("/api", (req, res, next) => {
    res.setHeader("Cache-Control", "no-store");
    next();
});

// ========================================
// MongoDB Connection
// ========================================

let mongoClient = null;
let database = null;
let usersCollection = null;
let servicesCollection = null;
let appointmentsCollection = null;
let transactionsCollection = null;
let reviewsCollection = null;
let supportsTransactions = false;

async function connectToMongoDB() {
    if (mongoClient) {
        return database;
    }

    if (!MONGODB_URI) {
        throw new Error(
            "MONGODB_URI is missing. Copy .env.example to .env and add your MongoDB connection string.",
        );
    }

    const client = new MongoClient(MONGODB_URI, {
        serverSelectionTimeoutMS: 10000,
        connectTimeoutMS: 10000,
    });

    try {
        await client.connect();
        const connectedDatabase = client.db(DB_NAME);
        await connectedDatabase.command({ ping: 1 });

        mongoClient = client;
        database = connectedDatabase;

        usersCollection = database.collection(AUTH_USER_COLLECTION);
        servicesCollection = database.collection("services");
        appointmentsCollection = database.collection("appointments");
        transactionsCollection = database.collection("transactions");
        reviewsCollection = database.collection("reviews");

        const serverInfo = await database.command({ hello: 1 });
        supportsTransactions =
            Boolean(serverInfo.setName) || serverInfo.msg === "isdbgrid";

        return database;
    } catch (error) {
        await client.close().catch(() => { });
        mongoClient = null;
        database = null;

        console.error("MongoDB connection failed:", error.message);
        throw new Error(
            "Could not connect to MongoDB. Check MONGODB_URI, your Atlas IP allowlist and network access.",
        );
    }
}

// ========================================
// Database Indexes
// ========================================

async function ensureDatabaseIndexes() {
    await usersCollection.createIndex(
        { role: 1, createdAt: -1 },
        { name: "users_role_created" },
    );
    await servicesCollection.createIndex(
        { status: 1, category: 1 },
        { name: "services_status_category" },
    );
    await servicesCollection.createIndex({ price: 1 }, { name: "services_price" });
    await servicesCollection.createIndex(
        { createdAt: -1 },
        { name: "services_created" },
    );
    await appointmentsCollection.createIndex(
        { customerId: 1, createdAt: -1 },
        { name: "appointments_customer_created" },
    );
    await appointmentsCollection.createIndex(
        { status: 1, createdAt: -1 },
        { name: "appointments_status_created" },
    );
    await appointmentsCollection.createIndex(
        { appointmentDate: 1, timeSlot: 1 },
        { name: "appointments_date_slot" },
    );
    await appointmentsCollection.createIndex(
        { serviceId: 1 },
        { name: "appointments_service" },
    );
    await appointmentsCollection.createIndex(
        { activeSlotKey: 1 },
        {
            name: "appointments_unique_active_slot",
            unique: true,
            partialFilterExpression: { activeSlotKey: { $type: "string" } },
        },
    );
    await transactionsCollection.createIndex(
        { customerId: 1, createdAt: -1 },
        { name: "transactions_customer_created" },
    );
    await transactionsCollection.createIndex(
        { appointmentId: 1 },
        { name: "transactions_appointment" },
    );
    await transactionsCollection.createIndex(
        { status: 1, createdAt: -1 },
        { name: "transactions_status_created" },
    );
    await transactionsCollection.createIndex(
        { stripeSessionId: 1 },
        {
            name: "transactions_unique_stripe_session",
            unique: true,
            partialFilterExpression: { stripeSessionId: { $type: "string" } },
        },
    );
    await transactionsCollection.createIndex(
        { stripeEventId: 1 },
        {
            name: "transactions_unique_stripe_event",
            unique: true,
            partialFilterExpression: { stripeEventId: { $type: "string" } },
        },
    );
    await reviewsCollection.createIndex(
        { appointmentId: 1 },
        {
            name: "reviews_unique_appointment",
            unique: true,
            partialFilterExpression: { appointmentId: { $type: "string" } },
        },
    );
    await reviewsCollection.createIndex(
        { status: 1, createdAt: -1 },
        { name: "reviews_status_created" },
    );
    await reviewsCollection.createIndex(
        { serviceId: 1, status: 1 },
        { name: "reviews_service_status" },
    );

    return 17;
}

// ========================================
// Common Helper Functions
// ========================================

function httpError(statusCode, message, details) {
    const error = new Error(message);
    error.statusCode = statusCode;
    error.details = details;
    return error;
}

function sendSuccess(res, message, data = {}, statusCode = 200) {
    return res.status(statusCode).json({
        success: true,
        message,
        data,
    });
}

function sendError(res, statusCode, message, details) {
    const response = {
        success: false,
        message,
    };

    if (details !== undefined) {
        response.errors = details;
    }

    return res.status(statusCode).json(response);
}

function escapeRegex(value) {
    return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function isValidUrl(value) {
    try {
        new URL(value);
        return true;
    } catch {
        return false;
    }
}

function parseObjectId(value) {
    if (typeof value !== "string" || !/^[a-fA-F0-9]{24}$/.test(value)) {
        return null;
    }

    try {
        return new ObjectId(value);
    } catch {
        return null;
    }
}

function buildUserIdentityFilter(userId) {
    const stringId = String(userId);

    const filters = [{ _id: stringId }, { id: stringId }];
    const objectId = parseObjectId(stringId);

    if (objectId) {
        filters.push({ _id: objectId });
    }

    return filters.length === 1 ? filters[0] : { $or: filters };
}

async function findUserById(userId) {
    if (!userId) {
        return null;
    }

    return usersCollection.findOne(buildUserIdentityFilter(userId));
}

async function findUsersByIds(userIds) {
    const uniqueIds = [...new Set(userIds.filter(Boolean).map(String))];

    if (uniqueIds.length === 0) {
        return [];
    }

    const objectIds = uniqueIds
        .map((id) => parseObjectId(id))
        .filter((id) => id !== null);

    const filters = [
        { _id: { $in: uniqueIds } },
        { id: { $in: uniqueIds } },
    ];

    if (objectIds.length > 0) {
        filters.push({ _id: { $in: objectIds } });
    }

    return usersCollection.find({ $or: filters }).toArray();
}

function normalizeUser(user) {
    if (!user) {
        return null;
    }

    return {
        id: String(user._id ?? user.id),
        name: user.name ?? "",
        email: user.email ?? "",
        image: user.image ?? null,
        phone: user.phone ?? "",
        role: user.role === "admin" ? "admin" : "customer",
        isBlocked: user.isBlocked === true,
        emailVerified: user.emailVerified === true,
        createdAt: user.createdAt ?? null,
        updatedAt: user.updatedAt ?? null,
    };
}

function normalizeService(service) {
    if (!service) {
        return null;
    }

    return {
        id: String(service._id),
        serviceName: service.serviceName,
        category: service.category,
        description: service.description,
        price: service.price,
        duration: service.duration,
        image: service.image,
        status: service.status,
        createdAt: service.createdAt,
        updatedAt: service.updatedAt,
    };
}

function normalizeAppointment(appointment) {
    if (!appointment) {
        return null;
    }

    return {
        id: String(appointment._id),
        serviceId: String(appointment.serviceId),
        customerId: appointment.customerId,
        appointmentDate: appointment.appointmentDate,
        timeSlot: appointment.timeSlot,
        message: appointment.message ?? "",
        servicePrice: appointment.servicePrice,
        status: appointment.status,
        paymentStatus: appointment.paymentStatus,
        serviceSnapshot: appointment.serviceSnapshot ?? null,
        checkoutSessionId: appointment.checkoutSessionId ?? null,
        confirmedAt: appointment.confirmedAt ?? null,
        cancelledAt: appointment.cancelledAt ?? null,
        paidAt: appointment.paidAt ?? null,
        createdAt: appointment.createdAt,
        updatedAt: appointment.updatedAt,
    };
}

function normalizeTransaction(transaction) {
    if (!transaction) {
        return null;
    }

    return {
        id: String(transaction._id),
        appointmentId: String(transaction.appointmentId),
        customerId: transaction.customerId,
        amount: transaction.amount,
        currency: transaction.currency,
        stripeSessionId: transaction.stripeSessionId,
        stripeEventId: transaction.stripeEventId,
        paymentIntentId: transaction.paymentIntentId ?? null,
        status: transaction.status,
        createdAt: transaction.createdAt,
    };
}

function normalizeReview(review) {
    if (!review) {
        return null;
    }

    return {
        id: String(review._id),
        appointmentId: String(review.appointmentId),
        customerId: review.customerId,
        customerName: review.customerName ?? "",
        serviceId: review.serviceId ?? null,
        serviceName: review.serviceName ?? "",
        serviceImage: review.serviceImage ?? null,
        rating: review.rating,
        highlights: Array.isArray(review.highlights) ? review.highlights : [],
        note: review.note ?? "",
        status: review.status,
        createdAt: review.createdAt,
        updatedAt: review.updatedAt,
    };
}

function buildPagination(page, limit, totalItems) {
    const totalPages = Math.ceil(totalItems / limit);

    return {
        page,
        limit,
        totalItems,
        totalPages,
        hasNextPage: page < totalPages,
        hasPreviousPage: page > 1,
    };
}

function buildServiceSnapshot(service) {
    return {
        serviceName: service.serviceName,
        category: service.category,
        image: service.image,
        duration: service.duration,
    };
}

function parseAppointmentDateTime(dateString, timeSlot) {
    const dateMatch = /^(\d{4})-(\d{2})-(\d{2})$/.exec(dateString);
    const timeMatch = /^(\d{2}):(\d{2})$/.exec(timeSlot);

    if (!dateMatch || !timeMatch) {
        return null;
    }

    const year = Number(dateMatch[1]);
    const month = Number(dateMatch[2]);
    const day = Number(dateMatch[3]);
    const hour = Number(timeMatch[1]);
    const minute = Number(timeMatch[2]);

    const parsedDate = new Date(year, month - 1, day, hour, minute, 0, 0);

    const isRealDate =
        parsedDate.getFullYear() === year &&
        parsedDate.getMonth() === month - 1 &&
        parsedDate.getDate() === day &&
        parsedDate.getHours() === hour &&
        parsedDate.getMinutes() === minute;

    return isRealDate ? parsedDate : null;
}

function isAppointmentSlotInFuture(dateString, timeSlot) {
    const appointmentDateTime = parseAppointmentDateTime(dateString, timeSlot);

    if (!appointmentDateTime) {
        return false;
    }

    return appointmentDateTime.getTime() > Date.now();
}

function buildActiveSlotKey(dateString, timeSlot) {
    return `${dateString}_${timeSlot}`;
}

function roundMoney(value) {
    return Math.round((Number(value) + Number.EPSILON) * 100) / 100;
}

const CURRENCY_DECIMALS = {
    bif: 0,
    clp: 0,
    djf: 0,
    gnf: 0,
    jpy: 0,
    kmf: 0,
    krw: 0,
    mga: 0,
    pyg: 0,
    rwf: 0,
    ugx: 0,
    vnd: 0,
    vuv: 0,
    xaf: 0,
    xof: 0,
    xpf: 0,
    bhd: 3,
    jod: 3,
    kwd: 3,
    omr: 3,
    tnd: 3,
};

function getCurrencyDecimals(currency) {
    return CURRENCY_DECIMALS[String(currency).toLowerCase()] ?? 2;
}

function toMinorCurrencyUnits(amount, currency) {
    const numericAmount = Number(amount);

    if (!Number.isFinite(numericAmount) || numericAmount <= 0) {
        throw httpError(400, "The appointment amount is invalid.");
    }

    return Math.round(numericAmount * 10 ** getCurrencyDecimals(currency));
}

function fromMinorCurrencyUnits(amount, currency) {
    return roundMoney(
        Number(amount) / 10 ** getCurrencyDecimals(currency),
    );
}

async function withTimeout(promise, timeoutMs, timeoutMessage) {
    let timer;

    const timeoutPromise = new Promise((resolve, reject) => {
        timer = setTimeout(() => reject(new Error(timeoutMessage)), timeoutMs);
    });

    try {
        return await Promise.race([promise, timeoutPromise]);
    } finally {
        clearTimeout(timer);
    }
}

function buildCustomerMap(users) {
    const map = new Map();

    for (const user of users) {
        const normalized = normalizeUser(user);
        map.set(normalized.id, normalized);
    }

    return map;
}

// ========================================
// Authentication Middleware
// ========================================

let remoteJwks = null;
let authenticationConfigurationError = null;

try {
    remoteJwks = createRemoteJWKSet(new URL(BETTER_AUTH_JWKS_URL), {
        cacheMaxAge: 10 * 60 * 1000,
        timeoutDuration: 5000,
    });
} catch {
    authenticationConfigurationError =
        "BETTER_AUTH_JWKS_URL is not a valid URL. Protected routes are unavailable.";
}

async function verifyToken(req, res, next) {
    if (authenticationConfigurationError || !remoteJwks) {
        return sendError(
            res,
            503,
            authenticationConfigurationError ||
            "Authentication is not configured on this server.",
        );
    }

    if (!database) {
        return sendError(res, 503, "The database is currently unavailable.");
    }

    const authorizationHeader = req.headers.authorization;

    if (
        typeof authorizationHeader !== "string" ||
        !authorizationHeader.startsWith("Bearer ")
    ) {
        return sendError(
            res,
            401,
            "Authentication required. Send a valid Bearer token.",
        );
    }

    const token = authorizationHeader.slice("Bearer ".length).trim();

    if (!token) {
        return sendError(
            res,
            401,
            "Authentication required. Send a valid Bearer token.",
        );
    }

    try {
        const { payload } = await jwtVerify(token, remoteJwks, {
            issuer: BETTER_AUTH_ISSUER,
            audience: BETTER_AUTH_AUDIENCE,
            clockTolerance: "5s",
        });

        if (!payload.sub || typeof payload.sub !== "string") {
            return sendError(res, 401, "The authentication token has no valid subject.");
        }

        const userDocument = await findUserById(payload.sub);

        if (!userDocument) {
            return sendError(
                res,
                401,
                "Your account could not be found. Please sign in again.",
            );
        }

        if (userDocument.isBlocked === true) {
            return sendError(
                res,
                403,
                "Your account has been blocked. Please contact the salon administrator.",
            );
        }

        req.user = normalizeUser(userDocument);
        next();
    } catch (error) {
        if (error?.code === "ERR_JWT_EXPIRED") {
            return sendError(
                res,
                401,
                "Your authentication token has expired. Please sign in again.",
            );
        }

        if (String(error?.code || "").startsWith("ERR_JWKS")) {
            console.error("JWKS verification service unavailable:", error.code);
            return sendError(
                res,
                503,
                "The authentication verification service is temporarily unavailable.",
            );
        }

        console.warn(
            "JWT verification failed:",
            error?.code || error?.name || "UnknownError",
        );
        return sendError(res, 401, "Invalid authentication token.");
    }
}

// ========================================
// Role Verification Middleware
// ========================================

function verifyCustomer(req, res, next) {
    if (!req.user) {
        return sendError(res, 401, "Authentication required.");
    }

    if (req.user.isBlocked) {
        return sendError(res, 403, "Your account has been blocked.");
    }

    if (req.user.role !== "customer") {
        return sendError(
            res,
            403,
            "Only customer accounts can perform this action. Administrators cannot book appointments.",
        );
    }

    next();
}

function verifyAdmin(req, res, next) {
    if (!req.user) {
        return sendError(res, 401, "Authentication required.");
    }

    if (req.user.isBlocked) {
        return sendError(res, 403, "Your account has been blocked.");
    }

    if (req.user.role !== "admin") {
        return sendError(res, 403, "Administrator access is required.");
    }

    next();
}

// ========================================
// Image Upload Configuration
// ========================================

const ALLOWED_IMAGE_MIME_TYPES = new Set([
    "image/jpeg",
    "image/png",
    "image/webp",
    "image/gif",
]);

const imageUpload = multer({
    storage: multer.memoryStorage(),
    limits: {
        fileSize: MAX_UPLOAD_SIZE_BYTES,
        files: 1,
        fields: 3,
    },
    fileFilter(req, file, callback) {
        if (!ALLOWED_IMAGE_MIME_TYPES.has(file.mimetype)) {
            return callback(
                httpError(
                    422,
                    "Unsupported image type. Please upload a JPEG, PNG, WebP or GIF image.",
                ),
            );
        }

        callback(null, true);
    },
});

function hasValidImageSignature(buffer, mimeType) {
    if (!Buffer.isBuffer(buffer) || buffer.length < 12) {
        return false;
    }

    switch (mimeType) {
        case "image/jpeg":
            return buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff;

        case "image/png":
            return buffer
                .subarray(0, 8)
                .equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]));

        case "image/gif":
            return buffer.subarray(0, 6).toString("ascii").startsWith("GIF8");

        case "image/webp":
            return (
                buffer.subarray(0, 4).toString("ascii") === "RIFF" &&
                buffer.subarray(8, 12).toString("ascii") === "WEBP"
            );

        default:
            return false;
    }
}

async function uploadImageToImgBB(file) {
    const formData = new FormData();
    formData.append("image", file.buffer.toString("base64"));
    formData.append("name", `stylevique-${Date.now()}`);

    let response;

    try {
        response = await fetch(`https://api.imgbb.com/1/upload?key=${encodeURIComponent(IMGBB_API_KEY)}`,
            {
                method: "POST",
                body: formData,
                signal: AbortSignal.timeout(30000),
            },
        );
    } catch (error) {
        console.error("ImgBB request failed:", error.name || "NetworkError");
        throw httpError(
            502,
            "The image hosting service could not be reached. Please try again.",
        );
    }

    let payload = null;

    try {
        payload = await response.json();
    } catch {
        payload = null;
    }

    if (!response.ok || !payload?.success || !payload?.data?.url) {
        console.error(
            "ImgBB rejected the upload. HTTP status:",
            response.status,
            "provider code:",
            payload?.error?.code ?? payload?.status_code ?? "unknown",
        );
        throw httpError(
            502,
            "The image could not be uploaded. Check the ImgBB API key or try a different image.",
        );
    }

    return payload.data.display_url || payload.data.url;
}

// ========================================
// Image Upload API
// ========================================

/**
 * POST /api/uploads/image
 * Stores one image on ImgBB and returns its public URL.
 * Used by the profile form and the admin service form.
 */
app.post(
    "/api/uploads/image",
    uploadLimiter,
    verifyToken,
    imageUpload.single("image"),
    async (req, res) => {
        if (!IMGBB_API_KEY) {
            return sendError(
                res,
                503,
                "Image uploads are not configured yet. Add IMGBB_API_KEY on the server.",
            );
        }

        if (!req.file || !req.file.buffer?.length) {
            return sendError(res, 422, "Choose an image to upload.", [
                {
                    field: "image",
                    message: "A JPEG, PNG, WebP or GIF image is required.",
                },
            ]);
        }

        if (!hasValidImageSignature(req.file.buffer, req.file.mimetype)) {
            return sendError(
                res,
                422,
                "The file contents do not match a supported image type.",
            );
        }

        const url = await uploadImageToImgBB(req.file);

        return sendSuccess(res, "Image uploaded successfully.", { url }, 201);
    },
);

// ========================================
// Services Related APIs
// ========================================

app.get("/api/services", async (req, res) => {
    const page = Number(req.query.page || 1);
    const limit = Number(req.query.limit || 12);
    const search = String(req.query.search || "").trim();
    const category = String(req.query.category || "").trim();
    const sortName = String(req.query.sort || "newest");

    if (!Number.isInteger(page) || page < 1) {
        return sendError(res, 422, "Invalid query parameters.", [
            { field: "page", message: "Page must be a positive whole number." },
        ]);
    }

    if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
        return sendError(res, 422, "Invalid query parameters.", [
            { field: "limit", message: "Limit must be between 1 and 100." },
        ]);
    }

    if (search.length > 100) {
        return sendError(res, 422, "Invalid query parameters.", [
            { field: "search", message: "Search must be 100 characters or fewer." },
        ]);
    }

    if (category.length > 80) {
        return sendError(res, 422, "Invalid query parameters.", [
            { field: "category", message: "Category must be 80 characters or fewer." },
        ]);
    }

    const sortOptions = {
        newest: { createdAt: -1 },
        oldest: { createdAt: 1 },
        price_asc: { price: 1, createdAt: -1 },
        price_desc: { price: -1, createdAt: -1 },
    };

    if (!sortOptions[sortName]) {
        return sendError(res, 422, "Invalid query parameters.", [
            {
                field: "sort",
                message: "Sort must be newest, oldest, price_asc or price_desc.",
            },
        ]);
    }

    const filter = { status: "active" };

    if (search) {
        filter.serviceName = { $regex: escapeRegex(search), $options: "i" };
    }

    if (category) {
        filter.category = { $regex: `^${escapeRegex(category)}$`, $options: "i" };
    }

    const skip = (page - 1) * limit;
    const [services, totalItems] = await Promise.all([
        servicesCollection
            .find(filter)
            .sort(sortOptions[sortName])
            .skip(skip)
            .limit(limit)
            .toArray(),
        servicesCollection.countDocuments(filter),
    ]);

    return sendSuccess(res, "Services retrieved successfully.", {
        services: services.map(normalizeService),
        pagination: buildPagination(page, limit, totalItems),
    });
});

app.get("/api/services/categories", async (req, res) => {
    const categories = await servicesCollection.distinct("category", {
        status: "active",
    });

    return sendSuccess(res, "Service categories retrieved successfully.", {
        categories: categories.filter(Boolean).sort((a, b) => a.localeCompare(b)),
    });
});

app.get("/api/admin/services", verifyToken, verifyAdmin, async (req, res) => {
    const page = Number(req.query.page || 1);
    const limit = Number(req.query.limit || 12);
    const search = String(req.query.search || "").trim();
    const category = String(req.query.category || "").trim();
    const status = String(req.query.status || "");
    const sortName = String(req.query.sort || "newest");

    if (!Number.isInteger(page) || page < 1) {
        return sendError(res, 422, "Invalid query parameters.", [
            { field: "page", message: "Page must be a positive whole number." },
        ]);
    }

    if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
        return sendError(res, 422, "Invalid query parameters.", [
            { field: "limit", message: "Limit must be between 1 and 100." },
        ]);
    }

    if (search.length > 100) {
        return sendError(res, 422, "Invalid query parameters.", [
            { field: "search", message: "Search must be 100 characters or fewer." },
        ]);
    }

    if (category.length > 80) {
        return sendError(res, 422, "Invalid query parameters.", [
            { field: "category", message: "Category must be 80 characters or fewer." },
        ]);
    }

    if (status && !["active", "inactive"].includes(status)) {
        return sendError(res, 422, "Invalid query parameters.", [
            { field: "status", message: "Status must be active or inactive." },
        ]);
    }

    const sortOptions = {
        newest: { createdAt: -1 },
        oldest: { createdAt: 1 },
        price_asc: { price: 1, createdAt: -1 },
        price_desc: { price: -1, createdAt: -1 },
    };

    if (!sortOptions[sortName]) {
        return sendError(res, 422, "Invalid query parameters.", [
            {
                field: "sort",
                message: "Sort must be newest, oldest, price_asc or price_desc.",
            },
        ]);
    }

    const filter = {};

    if (status) {
        filter.status = status;
    }

    if (search) {
        filter.serviceName = { $regex: escapeRegex(search), $options: "i" };
    }

    if (category) {
        filter.category = { $regex: `^${escapeRegex(category)}$`, $options: "i" };
    }

    const skip = (page - 1) * limit;
    const [services, totalItems] = await Promise.all([
        servicesCollection
            .find(filter)
            .sort(sortOptions[sortName])
            .skip(skip)
            .limit(limit)
            .toArray(),
        servicesCollection.countDocuments(filter),
    ]);

    return sendSuccess(res, "Services retrieved successfully.", {
        services: services.map(normalizeService),
        pagination: buildPagination(page, limit, totalItems),
    });
});

/**
 * GET /api/admin/services/:id
 * Returns one service regardless of its status so the admin edit form can
 * load inactive services too.
 */
app.get("/api/admin/services/:id", verifyToken, verifyAdmin, async (req, res) => {
    if (!ObjectId.isValid(req.params.id)) {
        return sendError(res, 404, "Service not found.");
    }

    const service = await servicesCollection.findOne({
        _id: new ObjectId(req.params.id),
    });

    if (!service) {
        return sendError(res, 404, "Service not found.");
    }

    return sendSuccess(res, "Service retrieved successfully.", {
        service: normalizeService(service),
    });
});

app.get("/api/services/:id", async (req, res) => {
    if (!ObjectId.isValid(req.params.id)) {
        return sendError(res, 404, "Service not found.");
    }

    const service = await servicesCollection.findOne({
        _id: new ObjectId(req.params.id),
        status: "active",
    });

    if (!service) {
        return sendError(res, 404, "Service not found.");
    }

    return sendSuccess(res, "Service retrieved successfully.", {
        service: normalizeService(service),
    });
});

app.post("/api/services", verifyToken, verifyAdmin, async (req, res) => {
    const body = req.body || {};
    const errors = [];
    const allowedFields = [
        "serviceName",
        "category",
        "description",
        "price",
        "duration",
        "image",
        "status",
    ];

    for (const field of Object.keys(body)) {
        if (!allowedFields.includes(field)) {
            errors.push({ field, message: "This field is not allowed." });
        }
    }

    const serviceName = typeof body.serviceName === "string" ? body.serviceName.trim() : "";
    const category = typeof body.category === "string" ? body.category.trim() : "";
    const description =
        typeof body.description === "string" ? body.description.trim() : "";
    const image = typeof body.image === "string" ? body.image.trim() : "";
    const price = Number(body.price);
    const duration = Number(body.duration);
    const status = body.status === undefined ? "active" : body.status;

    if (serviceName.length < 2 || serviceName.length > 120) {
        errors.push({
            field: "serviceName",
            message: "Service name must be between 2 and 120 characters.",
        });
    }

    if (category.length < 2 || category.length > 80) {
        errors.push({
            field: "category",
            message: "Category must be between 2 and 80 characters.",
        });
    }

    if (description.length < 10 || description.length > 2000) {
        errors.push({
            field: "description",
            message: "Description must be between 10 and 2000 characters.",
        });
    }

    if (!Number.isFinite(price) || price <= 0 || price > 1000000) {
        errors.push({
            field: "price",
            message: "Price must be greater than 0 and at most 1000000.",
        });
    }

    if (!Number.isInteger(duration) || duration <= 0 || duration > 1440) {
        errors.push({
            field: "duration",
            message: "Duration must be a whole number between 1 and 1440 minutes.",
        });
    }

    if (!isValidUrl(image) || image.length > 2048) {
        errors.push({ field: "image", message: "Image must be a valid URL." });
    }

    if (!["active", "inactive"].includes(status)) {
        errors.push({
            field: "status",
            message: "Status must be active or inactive.",
        });
    }

    if (errors.length > 0) {
        return sendError(
            res,
            422,
            "Validation failed. Please check the submitted fields.",
            errors,
        );
    }

    const now = new Date();
    const serviceDocument = {
        serviceName,
        category,
        description,
        price: roundMoney(price),
        duration,
        image,
        status,
        createdAt: now,
        updatedAt: now,
    };

    const result = await servicesCollection.insertOne(serviceDocument);

    return sendSuccess(
        res,
        "Service created successfully.",
        {
            service: normalizeService({
                ...serviceDocument,
                _id: result.insertedId,
            }),
        },
        201,
    );
});

app.patch("/api/services/:id", verifyToken, verifyAdmin, async (req, res) => {
    if (!ObjectId.isValid(req.params.id)) {
        return sendError(res, 400, "Invalid service ID.");
    }

    const body = req.body || {};
    const errors = [];
    const allowedFields = [
        "serviceName",
        "category",
        "description",
        "price",
        "duration",
        "image",
    ];
    const updateFields = {};

    for (const field of Object.keys(body)) {
        if (!allowedFields.includes(field)) {
            errors.push({
                field,
                message:
                    field === "status"
                        ? "Use PATCH /api/services/:id/status to change status."
                        : "This field is not allowed.",
            });
        }
    }

    if (body.serviceName !== undefined) {
        const serviceName =
            typeof body.serviceName === "string" ? body.serviceName.trim() : "";

        if (serviceName.length < 2 || serviceName.length > 120) {
            errors.push({
                field: "serviceName",
                message: "Service name must be between 2 and 120 characters.",
            });
        } else {
            updateFields.serviceName = serviceName;
        }
    }

    if (body.category !== undefined) {
        const category =
            typeof body.category === "string" ? body.category.trim() : "";

        if (category.length < 2 || category.length > 80) {
            errors.push({
                field: "category",
                message: "Category must be between 2 and 80 characters.",
            });
        } else {
            updateFields.category = category;
        }
    }

    if (body.description !== undefined) {
        const description =
            typeof body.description === "string" ? body.description.trim() : "";

        if (description.length < 10 || description.length > 2000) {
            errors.push({
                field: "description",
                message: "Description must be between 10 and 2000 characters.",
            });
        } else {
            updateFields.description = description;
        }
    }

    if (body.price !== undefined) {
        const price = Number(body.price);

        if (!Number.isFinite(price) || price <= 0 || price > 1000000) {
            errors.push({
                field: "price",
                message: "Price must be greater than 0 and at most 1000000.",
            });
        } else {
            updateFields.price = roundMoney(price);
        }
    }

    if (body.duration !== undefined) {
        const duration = Number(body.duration);

        if (!Number.isInteger(duration) || duration <= 0 || duration > 1440) {
            errors.push({
                field: "duration",
                message: "Duration must be a whole number between 1 and 1440 minutes.",
            });
        } else {
            updateFields.duration = duration;
        }
    }

    if (body.image !== undefined) {
        const image = typeof body.image === "string" ? body.image.trim() : "";

        if (!isValidUrl(image) || image.length > 2048) {
            errors.push({ field: "image", message: "Image must be a valid URL." });
        } else {
            updateFields.image = image;
        }
    }

    if (Object.keys(body).length === 0) {
        errors.push({
            field: "request",
            message: "Provide at least one field to update.",
        });
    }

    if (errors.length > 0) {
        return sendError(
            res,
            422,
            "Validation failed. Please check the submitted fields.",
            errors,
        );
    }

    const updatedService = await servicesCollection.findOneAndUpdate(
        { _id: new ObjectId(req.params.id) },
        {
            $set: {
                ...updateFields,
                updatedAt: new Date(),
            },
        },
        { returnDocument: "after" },
    );

    if (!updatedService) {
        return sendError(res, 404, "Service not found.");
    }

    return sendSuccess(res, "Service updated successfully.", {
        service: normalizeService(updatedService),
    });
});

app.patch("/api/services/:id/status", verifyToken, verifyAdmin, async (req, res) => {
    if (!ObjectId.isValid(req.params.id)) {
        return sendError(res, 400, "Invalid service ID.");
    }

    const body = req.body || {};
    const status = body.status;

    if (
        Object.keys(body).length !== 1 ||
        !["active", "inactive"].includes(status)
    ) {
        return sendError(
            res,
            422,
            "Validation failed. Please check the submitted fields.",
            [
                {
                    field: "status",
                    message: "Send exactly one status field set to active or inactive.",
                },
            ],
        );
    }

    const updatedService = await servicesCollection.findOneAndUpdate(
        { _id: new ObjectId(req.params.id) },
        {
            $set: {
                status,
                updatedAt: new Date(),
            },
        },
        { returnDocument: "after" },
    );

    if (!updatedService) {
        return sendError(res, 404, "Service not found.");
    }

    return sendSuccess(
        res,
        `Service ${status === "active" ? "activated" : "deactivated"} successfully.`,
        { service: normalizeService(updatedService) },
    );
});

app.delete("/api/services/:id", verifyToken, verifyAdmin, async (req, res) => {
    if (!ObjectId.isValid(req.params.id)) {
        return sendError(res, 400, "Invalid service ID.");
    }

    const deletedService = await servicesCollection.findOneAndDelete({
        _id: new ObjectId(req.params.id),
    });

    if (!deletedService) {
        return sendError(res, 404, "Service not found.");
    }

    return sendSuccess(res, "Service deleted successfully.", {
        deletedServiceId: String(deletedService._id),
    });
});

// ========================================
// Appointments Related APIs
// ========================================

const TIME_SLOTS = Object.freeze([
    "09:00",
    "09:30",
    "10:00",
    "10:30",
    "11:00",
    "11:30",
    "12:00",
    "12:30",
    "13:00",
    "13:30",
    "14:00",
    "14:30",
    "15:00",
    "15:30",
    "16:00",
    "16:30",
    "17:00",
    "17:30",
    "18:00",
    "18:30",
]);

const APPOINTMENT_STATUSES = Object.freeze([
    "pending",
    "confirmed",
    "cancelled",
]);

// ========================================
// Reviews Related APIs
// ========================================

const REVIEW_RATING_MIN = 1;
const REVIEW_RATING_MAX = 5;
const REVIEW_STATUSES = Object.freeze(["pending", "approved", "rejected"]);
const REVIEW_HIGHLIGHTS = Object.freeze([
    "Calm & Unhurried",
    "Clear Pricing",
    "Attentive Specialist",
    "Clean & Peaceful",
    "Great Results",
    "On Time",
]);
const REVIEW_NOTE_MAX_LENGTH = 500;

async function attachCustomerInformation(appointments) {
    const customerIds = appointments.map((appointment) => appointment.customerId);
    const customerDocuments = await findUsersByIds(customerIds);
    const customerMap = buildCustomerMap(customerDocuments);

    return appointments.map((appointment) => ({
        ...normalizeAppointment(appointment),
        customer: customerMap.get(String(appointment.customerId)) ?? null,
    }));
}

app.post(
    "/api/appointments",
    bookingLimiter,
    verifyToken,
    verifyCustomer,
    async (req, res) => {
        const body = req.body || {};
        const errors = [];
        const allowedFields = [
            "serviceId",
            "appointmentDate",
            "timeSlot",
            "message",
        ];

        for (const field of Object.keys(body)) {
            if (!allowedFields.includes(field)) {
                errors.push({
                    field,
                    message:
                        "Only serviceId, appointmentDate, timeSlot and message are allowed.",
                });
            }
        }

        const serviceId =
            typeof body.serviceId === "string" ? body.serviceId.trim() : "";
        const appointmentDate =
            typeof body.appointmentDate === "string"
                ? body.appointmentDate.trim()
                : "";
        const timeSlot =
            typeof body.timeSlot === "string" ? body.timeSlot.trim() : "";
        const message =
            body.message === undefined
                ? ""
                : typeof body.message === "string"
                    ? body.message.trim()
                    : null;

        if (!ObjectId.isValid(serviceId)) {
            errors.push({
                field: "serviceId",
                message: "Service ID must be a valid MongoDB ObjectId.",
            });
        }

        if (
            !/^\d{4}-\d{2}-\d{2}$/.test(appointmentDate) ||
            !parseAppointmentDateTime(appointmentDate, "12:00")
        ) {
            errors.push({
                field: "appointmentDate",
                message: "Use a real date in the YYYY-MM-DD format.",
            });
        }

        if (!TIME_SLOTS.includes(timeSlot)) {
            errors.push({
                field: "timeSlot",
                message: "Choose one of the available salon time slots.",
            });
        }

        if (message === null || message.length > 1000) {
            errors.push({
                field: "message",
                message: "Message must be text with 1000 characters or fewer.",
            });
        }

        if (errors.length > 0) {
            return sendError(
                res,
                422,
                "Validation failed. Please check the submitted fields.",
                errors,
            );
        }

        const service = await servicesCollection.findOne({
            _id: new ObjectId(serviceId),
            status: "active",
        });

        if (!service) {
            return sendError(res, 404, "Service not found or is not available.");
        }

        if (!isAppointmentSlotInFuture(appointmentDate, timeSlot)) {
            return sendError(
                res,
                400,
                "The appointment date and time must be in the future.",
            );
        }

        const activeSlotKey = buildActiveSlotKey(appointmentDate, timeSlot);

        const slotAlreadyBooked = await appointmentsCollection.findOne({
            activeSlotKey,
        });

        if (slotAlreadyBooked) {
            return sendError(
                res,
                409,
                "This date and time slot is already booked. Please choose another slot.",
            );
        }

        const now = new Date();
        const appointmentDocument = {
            serviceId: service._id,
            customerId: req.user.id,
            appointmentDate,
            timeSlot,
            message,
            servicePrice: service.price,
            status: "pending",
            paymentStatus: "unpaid",
            serviceSnapshot: buildServiceSnapshot(service),
            activeSlotKey,
            createdAt: now,
            updatedAt: now,
        };

        try {
            const result = await appointmentsCollection.insertOne(
                appointmentDocument,
            );

            return sendSuccess(
                res,
                "Appointment request submitted successfully.",
                {
                    appointment: normalizeAppointment({
                        ...appointmentDocument,
                        _id: result.insertedId,
                    }),
                },
                201,
            );
        } catch (error) {
            if (error?.code === 11000) {
                return sendError(
                    res,
                    409,
                    "This date and time slot was just booked by someone else. Please choose another slot.",
                );
            }

            throw error;
        }
    },
);

app.get("/api/appointments/my", verifyToken, verifyCustomer, async (req, res) => {
    const page = Number(req.query.page || 1);
    const limit = Number(req.query.limit || 20);
    const status = String(req.query.status || "");

    if (!Number.isInteger(page) || page < 1) {
        return sendError(res, 422, "Invalid query parameters.", [
            { field: "page", message: "Page must be a positive whole number." },
        ]);
    }

    if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
        return sendError(res, 422, "Invalid query parameters.", [
            { field: "limit", message: "Limit must be between 1 and 100." },
        ]);
    }

    if (status && !APPOINTMENT_STATUSES.includes(status)) {
        return sendError(res, 422, "Invalid query parameters.", [
            {
                field: "status",
                message: "Status must be pending, confirmed or cancelled.",
            },
        ]);
    }

    const filter = { customerId: req.user.id };

    if (status) {
        filter.status = status;
    }

    const skip = (page - 1) * limit;
    const [appointments, totalItems] = await Promise.all([
        appointmentsCollection
            .find(filter)
            .sort({ appointmentDate: -1, timeSlot: -1 })
            .skip(skip)
            .limit(limit)
            .toArray(),
        appointmentsCollection.countDocuments(filter),
    ]);

    return sendSuccess(res, "Your appointments were retrieved successfully.", {
        appointments: appointments.map(normalizeAppointment),
        pagination: buildPagination(page, limit, totalItems),
    });
});

app.get("/api/appointments/:id", verifyToken, async (req, res) => {
    if (!ObjectId.isValid(req.params.id)) {
        return sendError(res, 400, "Invalid appointment ID.");
    }

    const appointment = await appointmentsCollection.findOne({
        _id: new ObjectId(req.params.id),
    });

    if (!appointment) {
        return sendError(res, 404, "Appointment not found.");
    }

    if (req.user.role !== "admin" && appointment.customerId !== req.user.id) {
        return sendError(res, 403, "You cannot view another customer's appointment.");
    }

    return sendSuccess(res, "Appointment retrieved successfully.", {
        appointment: normalizeAppointment(appointment),
    });
});

app.patch(
    "/api/appointments/:id/cancel",
    verifyToken,
    verifyCustomer,
    async (req, res) => {
        if (!ObjectId.isValid(req.params.id)) {
            return sendError(res, 400, "Invalid appointment ID.");
        }

        const appointmentId = new ObjectId(req.params.id);
        const appointment = await appointmentsCollection.findOne({
            _id: appointmentId,
        });

        if (!appointment) {
            return sendError(res, 404, "Appointment not found.");
        }

        if (appointment.customerId !== req.user.id) {
            return sendError(
                res,
                403,
                "You cannot cancel another customer's appointment.",
            );
        }

        if (appointment.status === "cancelled") {
            return sendError(res, 409, "This appointment is already cancelled.");
        }

        if (appointment.status !== "pending") {
            return sendError(
                res,
                409,
                "Only pending appointments can be cancelled by customers. Please contact the salon to cancel a confirmed appointment.",
            );
        }

        const now = new Date();
        const cancelledAppointment = await appointmentsCollection.findOneAndUpdate(
            {
                _id: appointmentId,
                customerId: req.user.id,
                status: "pending",
            },
            {
                $set: {
                    status: "cancelled",
                    cancelledAt: now,
                    cancelledBy: req.user.id,
                    updatedAt: now,
                },
                $unset: { activeSlotKey: "" },
            },
            { returnDocument: "after" },
        );

        if (!cancelledAppointment) {
            return sendError(
                res,
                409,
                "The appointment could not be cancelled because its status changed.",
            );
        }

        return sendSuccess(
            res,
            "Appointment cancelled successfully. The time slot is now available again.",
            { appointment: normalizeAppointment(cancelledAppointment) },
        );
    },
);

app.get("/api/admin/appointments", verifyToken, verifyAdmin, async (req, res) => {
    const page = Number(req.query.page || 1);
    const limit = Number(req.query.limit || 20);
    const status = String(req.query.status || "");
    const date = String(req.query.date || "");

    if (!Number.isInteger(page) || page < 1) {
        return sendError(res, 422, "Invalid query parameters.", [
            { field: "page", message: "Page must be a positive whole number." },
        ]);
    }

    if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
        return sendError(res, 422, "Invalid query parameters.", [
            { field: "limit", message: "Limit must be between 1 and 100." },
        ]);
    }

    if (status && !APPOINTMENT_STATUSES.includes(status)) {
        return sendError(res, 422, "Invalid query parameters.", [
            {
                field: "status",
                message: "Status must be pending, confirmed or cancelled.",
            },
        ]);
    }

    if (date && !/^\d{4}-\d{2}-\d{2}$/.test(date)) {
        return sendError(res, 422, "Invalid query parameters.", [
            { field: "date", message: "Date must use the YYYY-MM-DD format." },
        ]);
    }

    const filter = {};

    if (status) {
        filter.status = status;
    }

    if (date) {
        filter.appointmentDate = date;
    }

    const skip = (page - 1) * limit;
    const [appointments, totalItems] = await Promise.all([
        appointmentsCollection
            .find(filter)
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit)
            .toArray(),
        appointmentsCollection.countDocuments(filter),
    ]);

    const enrichedAppointments = await attachCustomerInformation(appointments);

    return sendSuccess(res, "Appointments retrieved successfully.", {
        appointments: enrichedAppointments,
        pagination: buildPagination(page, limit, totalItems),
    });
});

app.patch(
    "/api/admin/appointments/:id/status",
    verifyToken,
    verifyAdmin,
    async (req, res) => {
        if (!ObjectId.isValid(req.params.id)) {
            return sendError(res, 400, "Invalid appointment ID.");
        }

        const body = req.body || {};
        const newStatus = body.status;

        if (
            Object.keys(body).length !== 1 ||
            !["confirmed", "cancelled"].includes(newStatus)
        ) {
            return sendError(
                res,
                422,
                "Validation failed. Please check the submitted fields.",
                [
                    {
                        field: "status",
                        message: "Send exactly one status set to confirmed or cancelled.",
                    },
                ],
            );
        }

        const appointmentId = new ObjectId(req.params.id);
        const appointment = await appointmentsCollection.findOne({
            _id: appointmentId,
        });

        if (!appointment) {
            return sendError(res, 404, "Appointment not found.");
        }

        const allowedTransitions = {
            pending: ["confirmed", "cancelled"],
            confirmed: ["cancelled"],
            cancelled: [],
        };
        const allowedNextStatuses = allowedTransitions[appointment.status] ?? [];

        if (!allowedNextStatuses.includes(newStatus)) {
            return sendError(
                res,
                409,
                `An appointment with status "${appointment.status}" cannot be changed to "${newStatus}".`,
            );
        }

        const now = new Date();
        const updateDocument = {
            $set: {
                status: newStatus,
                updatedAt: now,
            },
        };

        if (newStatus === "confirmed") {
            updateDocument.$set.confirmedAt = now;
        }

        if (newStatus === "cancelled") {
            updateDocument.$set.cancelledAt = now;
            updateDocument.$set.cancelledBy = req.user.id;
            updateDocument.$unset = { activeSlotKey: "" };
        }

        const updatedAppointment = await appointmentsCollection.findOneAndUpdate(
            {
                _id: appointmentId,
                status: appointment.status,
            },
            updateDocument,
            { returnDocument: "after" },
        );

        if (!updatedAppointment) {
            return sendError(
                res,
                409,
                "The appointment status changed while you were updating it. Please refresh and try again.",
            );
        }

        const paidCancellationMessage =
            newStatus === "cancelled" && appointment.paymentStatus === "paid"
                ? " The existing payment and transaction history were preserved. No refund was issued by this endpoint."
                : "";

        return sendSuccess(
            res,
            `Appointment ${newStatus === "confirmed" ? "confirmed" : "cancelled"} successfully.${paidCancellationMessage}`,
            { appointment: normalizeAppointment(updatedAppointment) },
        );
    },
);

// ========================================
// Users Related APIs
// ========================================

app.get("/api/users/me", verifyToken, async (req, res) => {
    return sendSuccess(res, "Profile retrieved successfully.", {
        user: req.user,
    });
});

app.patch("/api/users/me", verifyToken, async (req, res) => {
    const body = req.body || {};
    const errors = [];
    const allowedFields = ["name", "image", "phone"];
    const updateFields = {};

    for (const field of Object.keys(body)) {
        if (!allowedFields.includes(field)) {
            errors.push({
                field,
                message:
                    "Only name, image and phone can be updated. Role and blocked status are managed by the server.",
            });
        }
    }

    if (body.name !== undefined) {
        const name = typeof body.name === "string" ? body.name.trim() : "";

        if (name.length < 1 || name.length > 100) {
            errors.push({
                field: "name",
                message: "Name must be between 1 and 100 characters.",
            });
        } else {
            updateFields.name = name;
        }
    }

    if (body.image !== undefined) {
        const image = typeof body.image === "string" ? body.image.trim() : null;

        if (image === null || (image !== "" && (!isValidUrl(image) || image.length > 2048))) {
            errors.push({
                field: "image",
                message: "Image must be a valid URL or an empty string.",
            });
        } else {
            updateFields.image = image;
        }
    }

    if (body.phone !== undefined) {
        const phone = typeof body.phone === "string" ? body.phone.trim() : null;

        if (
            phone === null ||
            phone.length > 30 ||
            !/^[0-9+\-()\s]*$/.test(phone)
        ) {
            errors.push({
                field: "phone",
                message:
                    "Phone may only contain digits, spaces and + - ( ) characters.",
            });
        } else {
            updateFields.phone = phone;
        }
    }

    if (Object.keys(body).length === 0) {
        errors.push({
            field: "request",
            message: "Provide at least one profile field to update.",
        });
    }

    if (errors.length > 0) {
        return sendError(
            res,
            422,
            "Validation failed. Please check the submitted fields.",
            errors,
        );
    }

    const updatedUser = await usersCollection.findOneAndUpdate(
        buildUserIdentityFilter(req.user.id),
        {
            $set: {
                ...updateFields,
                updatedAt: new Date(),
            },
        },
        { returnDocument: "after" },
    );

    if (!updatedUser) {
        return sendError(res, 404, "Your user account could not be found.");
    }

    return sendSuccess(res, "Profile updated successfully.", {
        user: normalizeUser(updatedUser),
    });
});

app.get("/api/admin/users", verifyToken, verifyAdmin, async (req, res) => {
    const page = Number(req.query.page || 1);
    const limit = Number(req.query.limit || 20);
    const search = String(req.query.search || "").trim();

    if (!Number.isInteger(page) || page < 1) {
        return sendError(res, 422, "Invalid query parameters.", [
            { field: "page", message: "Page must be a positive whole number." },
        ]);
    }

    if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
        return sendError(res, 422, "Invalid query parameters.", [
            { field: "limit", message: "Limit must be between 1 and 100." },
        ]);
    }

    if (search.length > 100) {
        return sendError(res, 422, "Invalid query parameters.", [
            { field: "search", message: "Search must be 100 characters or fewer." },
        ]);
    }

    const filter = { role: { $ne: "admin" } };

    if (search) {
        const searchPattern = {
            $regex: escapeRegex(search),
            $options: "i",
        };
        filter.$or = [{ name: searchPattern }, { email: searchPattern }];
    }

    const skip = (page - 1) * limit;
    const [users, totalItems] = await Promise.all([
        usersCollection
            .find(filter)
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit)
            .toArray(),
        usersCollection.countDocuments(filter),
    ]);

    return sendSuccess(res, "Customers retrieved successfully.", {
        users: users.map(normalizeUser),
        pagination: buildPagination(page, limit, totalItems),
    });
});

app.get("/api/admin/users/:id", verifyToken, verifyAdmin, async (req, res) => {
    const userDocument = await findUserById(req.params.id);

    if (!userDocument) {
        return sendError(res, 404, "Customer not found.");
    }

    if (normalizeUser(userDocument).role === "admin") {
        return sendError(
            res,
            403,
            "Administrator accounts cannot be managed through the customer API.",
        );
    }

    return sendSuccess(res, "Customer retrieved successfully.", {
        user: normalizeUser(userDocument),
    });
});

async function updateCustomerBlockedStatus(req, res, shouldBlock) {
    const userDocument = await findUserById(req.params.id);

    if (!userDocument) {
        return sendError(res, 404, "Customer not found.");
    }

    const user = normalizeUser(userDocument);

    if (user.role === "admin") {
        return sendError(
            res,
            403,
            "Administrator accounts cannot be blocked through the customer API.",
        );
    }

    const updatedUser = await usersCollection.findOneAndUpdate(
        { _id: userDocument._id },
        {
            $set: {
                isBlocked: shouldBlock,
                updatedAt: new Date(),
            },
        },
        { returnDocument: "after" },
    );

    if (!updatedUser) {
        return sendError(res, 404, "Customer not found.");
    }

    return sendSuccess(
        res,
        shouldBlock
            ? "Customer blocked successfully. They can no longer use protected APIs."
            : "Customer unblocked successfully.",
        { user: normalizeUser(updatedUser) },
    );
}

app.patch(
    "/api/admin/users/:id/block",
    verifyToken,
    verifyAdmin,
    async (req, res) => {
        return updateCustomerBlockedStatus(req, res, true);
    },
);

app.patch(
    "/api/admin/users/:id/unblock",
    verifyToken,
    verifyAdmin,
    async (req, res) => {
        return updateCustomerBlockedStatus(req, res, false);
    },
);

// ========================================
// Dashboard Related APIs
// ========================================

app.get("/api/dashboard/customer", verifyToken, verifyCustomer, async (req, res) => {
    const customerId = req.user.id;

    const [pendingAppointments, confirmedAppointments, cancelledAppointments] =
        await Promise.all([
            appointmentsCollection.countDocuments({
                customerId,
                status: "pending",
            }),
            appointmentsCollection.countDocuments({
                customerId,
                status: "confirmed",
            }),
            appointmentsCollection.countDocuments({
                customerId,
                status: "cancelled",
            }),
        ]);

    return sendSuccess(res, "Customer dashboard retrieved successfully.", {
        totalAppointments:
            pendingAppointments + confirmedAppointments + cancelledAppointments,
        pendingAppointments,
        confirmedAppointments,
        cancelledAppointments,
    });
});

app.get("/api/dashboard/admin", verifyToken, verifyAdmin, async (req, res) => {
    const [
        totalRegisteredCustomers,
        totalActiveServices,
        pendingAppointments,
        confirmedAppointments,
        cancelledAppointments,
        paymentRows,
    ] = await Promise.all([
        usersCollection.countDocuments({ role: { $ne: "admin" } }),
        servicesCollection.countDocuments({ status: "active" }),
        appointmentsCollection.countDocuments({ status: "pending" }),
        appointmentsCollection.countDocuments({ status: "confirmed" }),
        appointmentsCollection.countDocuments({ status: "cancelled" }),
        transactionsCollection
            .aggregate([
                { $match: { status: "paid" } },
                {
                    $group: {
                        _id: null,
                        count: { $sum: 1 },
                        totalAmount: { $sum: "$amount" },
                    },
                },
            ])
            .toArray(),
    ]);

    const paymentSummary = paymentRows[0] ?? { count: 0, totalAmount: 0 };

    return sendSuccess(res, "Admin dashboard retrieved successfully.", {
        totalRegisteredCustomers,
        totalActiveServices,
        totalAppointments:
            pendingAppointments + confirmedAppointments + cancelledAppointments,
        pendingAppointments,
        confirmedAppointments,
        cancelledAppointments,
        totalSuccessfulPayments: paymentSummary.count,
        totalRevenue: roundMoney(paymentSummary.totalAmount || 0),
        currency: STRIPE_CURRENCY,
    });
});

// ========================================
// Payments Related APIs
// ========================================

function getPaymentIntentId(checkoutSession) {
    if (typeof checkoutSession.payment_intent === "string") {
        return checkoutSession.payment_intent;
    }

    return checkoutSession.payment_intent?.id ?? null;
}

async function getReusableCheckoutSession(appointment, amount, currency) {
    if (!appointment.checkoutSessionId) {
        return null;
    }

    try {
        const existingSession = await stripe.checkout.sessions.retrieve(
            appointment.checkoutSessionId,
        );

        if (
            existingSession.status === "open" &&
            existingSession.payment_status === "unpaid" &&
            existingSession.mode === "payment" &&
            existingSession.amount_total === amount &&
            existingSession.currency === currency &&
            existingSession.url
        ) {
            return existingSession;
        }

        if (existingSession.status === "complete") {
            if (existingSession.payment_status === "paid") {
                throw httpError(
                    409,
                    "A payment session for this appointment is already complete and paid. Please wait for the payment to be verified.",
                );
            }

            const failedTransaction = await transactionsCollection.findOne({
                stripeSessionId: existingSession.id,
                status: "failed",
            });

            if (!failedTransaction) {
                throw httpError(
                    409,
                    "A payment session for this appointment is still being processed. Please wait and check the payment status.",
                );
            }

            return null;
        }

        return null;
    } catch (error) {
        if (error?.statusCode) {
            throw error;
        }

        if (error?.code !== "resource_missing") {
            console.warn(
                "Could not retrieve the existing Stripe Checkout Session:",
                error?.type || error?.name || "UnknownError",
            );
        }

        return null;
    }
}

app.post(
    "/api/payments/checkout",
    checkoutLimiter,
    verifyToken,
    verifyCustomer,
    async (req, res) => {
        if (!stripe) {
            return sendError(
                res,
                503,
                "Stripe payments are not configured yet. Add STRIPE_SECRET_KEY on the server.",
            );
        }

        const body = req.body || {};

        if (
            Object.keys(body).length !== 1 ||
            typeof body.appointmentId !== "string" ||
            !ObjectId.isValid(body.appointmentId)
        ) {
            return sendError(
                res,
                422,
                "Validation failed. Please check the submitted fields.",
                [
                    {
                        field: "appointmentId",
                        message: "A valid appointmentId is required.",
                    },
                ],
            );
        }

        const appointment = await appointmentsCollection.findOne({
            _id: new ObjectId(body.appointmentId),
            customerId: req.user.id,
        });

        if (!appointment) {
            return sendError(
                res,
                404,
                "Appointment not found or does not belong to your account.",
            );
        }

        if (appointment.paymentStatus === "paid") {
            return sendError(res, 409, "This appointment has already been paid.");
        }

        if (appointment.status !== "confirmed") {
            return sendError(
                res,
                409,
                "Only confirmed appointments can be paid. Please wait for the salon to confirm your appointment.",
            );
        }

        const amount = toMinorCurrencyUnits(
            appointment.servicePrice,
            STRIPE_CURRENCY,
        );

        const reusableSession = await getReusableCheckoutSession(
            appointment,
            amount,
            STRIPE_CURRENCY,
        );

        if (reusableSession) {
            return sendSuccess(res, "An open payment session already exists.", {
                checkoutUrl: reusableSession.url,
                sessionId: reusableSession.id,
                appointmentId: String(appointment._id),
                amount: fromMinorCurrencyUnits(amount, STRIPE_CURRENCY),
                currency: STRIPE_CURRENCY,
            });
        }

        const metadata = {
            appointmentId: String(appointment._id),
            customerId: req.user.id,
            serviceId: String(appointment.serviceId),
        };

        let checkoutSession;

        try {
            checkoutSession = await stripe.checkout.sessions.create({
                mode: "payment",
                line_items: [
                    {
                        quantity: 1,
                        price_data: {
                            currency: STRIPE_CURRENCY,
                            unit_amount: amount,
                            product_data: {
                                name:
                                    appointment.serviceSnapshot?.serviceName ||
                                    "Salon service",
                                description: `${appointment.appointmentDate} at ${appointment.timeSlot}`,
                            },
                        },
                    },
                ],
                ...(req.user.email ? { customer_email: req.user.email } : {}),
                client_reference_id: String(appointment._id),
                metadata,
                payment_intent_data: { metadata },
                success_url: `${CLIENT_URL}/payment/success?session_id={CHECKOUT_SESSION_ID}`,
                cancel_url: `${CLIENT_URL}/payment/cancel`,
            });
        } catch (error) {
            console.error(
                "Stripe Checkout Session creation failed:",
                error?.type || error?.name || "UnknownError",
            );
            throw httpError(
                502,
                "The payment session could not be created. Please try again.",
            );
        }

        if (!checkoutSession.url) {
            throw httpError(
                502,
                "Stripe did not return a checkout URL. Please try again.",
            );
        }

        try {
            await appointmentsCollection.updateOne(
                { _id: appointment._id },
                {
                    $set: {
                        checkoutSessionId: checkoutSession.id,
                        checkoutSessionUrl: checkoutSession.url,
                        checkoutSessionExpiresAt: checkoutSession.expires_at
                            ? new Date(checkoutSession.expires_at * 1000)
                            : null,
                        lastCheckoutStatus: "open",
                        updatedAt: new Date(),
                    },
                },
            );
        } catch (error) {
            console.error(
                "Could not save the Stripe Checkout Session reference:",
                error?.name || "DatabaseError",
            );
        }

        return sendSuccess(
            res,
            "Checkout session created successfully.",
            {
                checkoutUrl: checkoutSession.url,
                sessionId: checkoutSession.id,
                appointmentId: String(appointment._id),
                amount: fromMinorCurrencyUnits(amount, STRIPE_CURRENCY),
                currency: STRIPE_CURRENCY,
            },
            201,
        );
    },
);

app.get("/api/payments/verify", verifyToken, verifyCustomer, async (req, res) => {
    const sessionId =
        typeof req.query.session_id === "string"
            ? req.query.session_id.trim()
            : "";

    if (sessionId.length < 5 || sessionId.length > 255) {
        return sendError(res, 422, "Invalid query parameters.", [
            {
                field: "session_id",
                message: "A valid session_id is required.",
            },
        ]);
    }

    let appointment = await appointmentsCollection.findOne({
        checkoutSessionId: sessionId,
        customerId: req.user.id,
    });

    let transaction = await transactionsCollection.findOne({
        stripeSessionId: sessionId,
        customerId: req.user.id,
    });

    if (!appointment && transaction) {
        appointment = await appointmentsCollection.findOne({
            _id: transaction.appointmentId,
            customerId: req.user.id,
        });
    }

    if (!appointment) {
        return sendError(
            res,
            404,
            "No checkout session was found for your account.",
        );
    }

    if (!transaction) {
        transaction = await transactionsCollection.findOne({
            stripeSessionId: sessionId,
            customerId: req.user.id,
        });
    }

    let paymentState = "pending";

    if (transaction?.status === "paid") {
        paymentState = "paid";
    } else if (transaction?.status === "failed") {
        paymentState = "failed";
    } else if (
        appointment.paymentStatus === "paid" &&
        appointment.checkoutSessionId === sessionId
    ) {
        paymentState = "paid";
    }

    const message =
        paymentState === "paid"
            ? "Payment verified successfully by the Stripe webhook."
            : paymentState === "failed"
                ? "Stripe reported that this payment failed. No successful transaction was recorded."
                : "Payment is still being verified. If you just completed checkout, please wait a few seconds and refresh.";

    return sendSuccess(res, message, {
        status: paymentState,
        appointmentId: String(appointment._id),
        paymentStatus: appointment.paymentStatus,
        amount: appointment.servicePrice,
        currency: STRIPE_CURRENCY,
        verifiedByWebhook: paymentState === "paid",
        transaction: normalizeTransaction(transaction),
    });
});

// ========================================
// Stripe Webhook
// ========================================

function isTransactionUnsupportedError(error) {
    const message = String(error?.message || "");

    return (
        error?.code === 20 ||
        error?.code === 263 ||
        /transaction numbers are only allowed|does not support transactions|transaction support is not available/i.test(
            message,
        )
    );
}

async function getVerifiedCheckoutContext(checkoutSession) {
    const appointmentId = checkoutSession.metadata?.appointmentId;
    const customerId = checkoutSession.metadata?.customerId;
    const serviceId = checkoutSession.metadata?.serviceId;

    if (!appointmentId || !customerId) {
        return null;
    }

    const appointmentObjectId = parseObjectId(appointmentId);

    if (!appointmentObjectId) {
        throw httpError(400, "Stripe metadata contains an invalid appointment ID.");
    }

    const appointment = await appointmentsCollection.findOne({
        _id: appointmentObjectId,
    });

    if (!appointment) {
        console.warn("Stripe webhook referenced an appointment that no longer exists.");
        return null;
    }

    if (appointment.customerId !== customerId) {
        throw httpError(
            400,
            "Stripe metadata customer does not match the appointment owner.",
        );
    }

    if (serviceId && String(appointment.serviceId) !== String(serviceId)) {
        throw httpError(
            400,
            "Stripe metadata service does not match the appointment service.",
        );
    }

    const sessionCurrency = String(checkoutSession.currency || "").toLowerCase();

    if (sessionCurrency !== STRIPE_CURRENCY) {
        throw httpError(
            400,
            "Stripe payment currency does not match the configured currency.",
        );
    }

    const expectedAmount = toMinorCurrencyUnits(
        appointment.servicePrice,
        STRIPE_CURRENCY,
    );

    if (checkoutSession.amount_total !== expectedAmount) {
        throw httpError(
            400,
            "Stripe payment amount does not match the appointment price.",
        );
    }

    return appointment;
}

async function recordSuccessfulPayment(appointment, checkoutSession, event) {
    const existingPaidTransaction = await transactionsCollection.findOne({
        stripeSessionId: checkoutSession.id,
        status: "paid",
    });

    if (existingPaidTransaction) {
        return { alreadyProcessed: true };
    }

    const now = new Date();
    const paymentIntentId = getPaymentIntentId(checkoutSession);

    const applyWrites = async (mongoSessionForWrites) => {
        const options = mongoSessionForWrites
            ? { session: mongoSessionForWrites }
            : {};

        await appointmentsCollection.updateOne(
            { _id: appointment._id },
            {
                $set: {
                    paymentStatus: "paid",
                    paidAt: now,
                    updatedAt: now,
                    stripePaymentIntentId: paymentIntentId,
                    checkoutSessionId: checkoutSession.id,
                    checkoutSessionUrl:
                        checkoutSession.url || appointment.checkoutSessionUrl || null,
                    lastCheckoutStatus: "paid",
                },
            },
            options,
        );

        await transactionsCollection.updateOne(
            { stripeSessionId: checkoutSession.id },
            {
                $set: {
                    appointmentId: appointment._id,
                    customerId: appointment.customerId,
                    amount: appointment.servicePrice,
                    currency: STRIPE_CURRENCY,
                    stripeSessionId: checkoutSession.id,
                    stripeEventId: event.id,
                    paymentIntentId,
                    status: "paid",
                    eventType: event.type,
                    updatedAt: now,
                },
                $setOnInsert: { createdAt: now },
            },
            { ...options, upsert: true },
        );
    };

    if (!supportsTransactions) {
        await applyWrites(null);
        return { alreadyProcessed: false };
    }

    const mongoSession = mongoClient.startSession();

    try {
        await mongoSession.withTransaction(async () => {
            await applyWrites(mongoSession);
        });

        return { alreadyProcessed: false };
    } catch (error) {
        if (isTransactionUnsupportedError(error)) {
            supportsTransactions = false;
            console.warn(
                "MongoDB transactions are not supported by this deployment. Falling back to sequential writes.",
            );
            await applyWrites(null);
            return { alreadyProcessed: false };
        }

        if (error?.code === 11000) {
            const paidTransaction = await transactionsCollection.findOne({
                stripeSessionId: checkoutSession.id,
                status: "paid",
            });

            if (paidTransaction) {
                return { alreadyProcessed: true };
            }
        }

        throw error;
    } finally {
        await mongoSession.endSession().catch(() => { });
    }
}

async function handleSuccessfulCheckoutEvent(event) {
    const checkoutSession = event.data.object;

    if (checkoutSession.mode !== "payment") {
        return { ignored: true };
    }

    if (checkoutSession.payment_status !== "paid") {
        await appointmentsCollection.updateOne(
            {
                checkoutSessionId: checkoutSession.id,
                paymentStatus: { $ne: "paid" },
            },
            {
                $set: {
                    lastCheckoutStatus: "complete_pending_payment",
                    updatedAt: new Date(),
                },
            },
        );
        return { ignored: true };
    }

    if (checkoutSession.status && checkoutSession.status !== "complete") {
        return { ignored: true };
    }

    const appointment = await getVerifiedCheckoutContext(checkoutSession);

    if (!appointment) {
        return { ignored: true };
    }

    return recordSuccessfulPayment(appointment, checkoutSession, event);
}

async function handleFailedCheckoutEvent(event) {
    const checkoutSession = event.data.object;

    if (checkoutSession.payment_status === "paid") {
        return { ignored: true };
    }

    const appointment = await getVerifiedCheckoutContext(checkoutSession);

    if (!appointment) {
        return { ignored: true };
    }

    const alreadyPaid = await transactionsCollection.findOne({
        stripeSessionId: checkoutSession.id,
        status: "paid",
    });

    if (alreadyPaid) {
        return { ignored: true };
    }

    const now = new Date();

    try {
        await transactionsCollection.updateOne(
            { stripeSessionId: checkoutSession.id },
            {
                $set: {
                    stripeEventId: event.id,
                    status: "failed",
                    failureReason:
                        "Stripe reported that the asynchronous payment failed.",
                    updatedAt: now,
                },
                $setOnInsert: {
                    appointmentId: appointment._id,
                    customerId: appointment.customerId,
                    amount: appointment.servicePrice,
                    currency: STRIPE_CURRENCY,
                    stripeSessionId: checkoutSession.id,
                    paymentIntentId: getPaymentIntentId(checkoutSession),
                    createdAt: now,
                },
            },
            { upsert: true },
        );
    } catch (error) {
        if (error?.code !== 11000) {
            throw error;
        }
    }

    await appointmentsCollection.updateOne(
        {
            _id: appointment._id,
            paymentStatus: { $ne: "paid" },
        },
        {
            $set: {
                lastPaymentFailureAt: now,
                lastCheckoutStatus: "failed",
                updatedAt: now,
            },
        },
    );

    return { failed: true };
}

async function handleExpiredCheckoutEvent(event) {
    const checkoutSession = event.data.object;
    const appointment = await getVerifiedCheckoutContext(checkoutSession);

    if (!appointment) {
        return { ignored: true };
    }

    await appointmentsCollection.updateOne(
        {
            _id: appointment._id,
            paymentStatus: { $ne: "paid" },
        },
        {
            $set: {
                lastCheckoutStatus: "expired",
                updatedAt: new Date(),
            },
        },
    );

    return { expired: true };
}

async function processStripeEvent(event) {
    switch (event.type) {
        case "checkout.session.completed":
        case "checkout.session.async_payment_succeeded":
            return handleSuccessfulCheckoutEvent(event);

        case "checkout.session.async_payment_failed":
            return handleFailedCheckoutEvent(event);

        case "checkout.session.expired":
            return handleExpiredCheckoutEvent(event);

        default:
            return { ignored: true };
    }
}

async function stripeWebhookHandler(req, res, next) {
    if (!stripe || !STRIPE_WEBHOOK_SECRET) {
        return sendError(
            res,
            503,
            "Stripe webhooks are not configured on this server.",
        );
    }

    const signature = req.headers["stripe-signature"];

    if (!signature || typeof signature !== "string") {
        return sendError(res, 400, "Missing Stripe webhook signature.");
    }

    if (!Buffer.isBuffer(req.body)) {
        return sendError(
            res,
            400,
            "Stripe webhook body was not received as raw JSON. Check middleware order.",
        );
    }

    let event;

    try {
        event = stripe.webhooks.constructEvent(
            req.body,
            signature,
            STRIPE_WEBHOOK_SECRET,
        );
    } catch {
        console.warn("Stripe webhook signature verification failed.");
        return sendError(res, 400, "Invalid Stripe webhook signature.");
    }

    try {
        const result = await processStripeEvent(event);

        return res.status(200).json({
            success: true,
            message: result?.alreadyProcessed
                ? "Duplicate Stripe event already processed."
                : "Stripe webhook processed successfully.",
            data: {
                eventId: event.id,
                eventType: event.type,
            },
        });
    } catch (error) {
        if (error?.statusCode) {
            console.error(
                `Stripe webhook "${event.type}" rejected:`,
                error.message,
            );
            return sendError(res, error.statusCode, error.message);
        }

        console.error(
            "Stripe webhook processing failed:",
            error?.code || error?.name || "UnknownError",
        );

        return sendError(res, 500, "Stripe webhook processing failed.");
    }
}

// ========================================
// Transactions Related APIs
// ========================================

async function attachTransactionDetails(transactions, includeCustomer) {
    if (transactions.length === 0) {
        return [];
    }

    const appointmentIds = [
        ...new Set(transactions.map((transaction) => transaction.appointmentId)),
    ];

    const appointments = await appointmentsCollection
        .find({ _id: { $in: appointmentIds } })
        .toArray();

    const appointmentMap = new Map(
        appointments.map((appointment) => [String(appointment._id), appointment]),
    );

    let customerMap = new Map();

    if (includeCustomer) {
        const customerDocuments = await findUsersByIds(
            transactions.map((transaction) => transaction.customerId),
        );
        customerMap = buildCustomerMap(customerDocuments);
    }

    return transactions.map((transaction) => {
        const appointment = appointmentMap.get(String(transaction.appointmentId));

        return {
            ...normalizeTransaction(transaction),
            appointment: appointment
                ? {
                    id: String(appointment._id),
                    appointmentDate: appointment.appointmentDate,
                    timeSlot: appointment.timeSlot,
                    status: appointment.status,
                    paymentStatus: appointment.paymentStatus,
                    servicePrice: appointment.servicePrice,
                    serviceSnapshot: appointment.serviceSnapshot,
                }
                : null,
            customer: includeCustomer
                ? (customerMap.get(String(transaction.customerId)) ?? null)
                : undefined,
        };
    });
}

async function respondWithTransactions(req, res, includeCustomer) {
    const page = Number(req.query.page || 1);
    const limit = Number(req.query.limit || 20);
    const status = String(req.query.status || "");

    if (!Number.isInteger(page) || page < 1) {
        return sendError(res, 422, "Invalid query parameters.", [
            { field: "page", message: "Page must be a positive whole number." },
        ]);
    }

    if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
        return sendError(res, 422, "Invalid query parameters.", [
            { field: "limit", message: "Limit must be between 1 and 100." },
        ]);
    }

    if (status && !["paid", "failed"].includes(status)) {
        return sendError(res, 422, "Invalid query parameters.", [
            { field: "status", message: "Status must be paid or failed." },
        ]);
    }

    const filter = includeCustomer
        ? {}
        : { customerId: req.user.id };

    if (status) {
        filter.status = status;
    }

    const skip = (page - 1) * limit;

    const [transactions, totalItems] = await Promise.all([
        transactionsCollection
            .find(filter)
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit)
            .toArray(),
        transactionsCollection.countDocuments(filter),
    ]);

    const enrichedTransactions = await attachTransactionDetails(
        transactions,
        includeCustomer,
    );

    return sendSuccess(res, "Transactions retrieved successfully.", {
        transactions: enrichedTransactions,
        pagination: buildPagination(page, limit, totalItems),
    });
}

app.get("/api/transactions/my", verifyToken, verifyCustomer, async (req, res) => {
    return respondWithTransactions(req, res, false);
});

app.get("/api/admin/transactions", verifyToken, verifyAdmin, async (req, res) => {
    return respondWithTransactions(req, res, true);
});

// ========================================
// Review Routes
// ========================================

function validateReviewFields(body) {
    const errors = [];
    const allowedFields = ["appointmentId", "rating", "highlights", "note"];

    for (const field of Object.keys(body)) {
        if (!allowedFields.includes(field)) {
            errors.push({
                field,
                message: "Only appointmentId, rating, highlights and note are allowed.",
            });
        }
    }

    const rating = body.rating;
    if (
        !Number.isInteger(rating) ||
        rating < REVIEW_RATING_MIN ||
        rating > REVIEW_RATING_MAX
    ) {
        errors.push({
            field: "rating",
            message: "Choose a rating between 1 and 5.",
        });
    }

    const rawHighlights = body.highlights;
    let highlights = [];

    if (rawHighlights !== undefined && !Array.isArray(rawHighlights)) {
        errors.push({
            field: "highlights",
            message: "Highlights must be a list of the offered labels.",
        });
    } else if (Array.isArray(rawHighlights)) {
        if (rawHighlights.length > 4) {
            errors.push({
                field: "highlights",
                message: "Choose at most four highlights.",
            });
        }
        highlights = [...new Set(rawHighlights.filter((item) => typeof item === "string"))];
        for (const highlight of highlights) {
            if (!REVIEW_HIGHLIGHTS.includes(highlight)) {
                errors.push({
                    field: "highlights",
                    message: "One or more highlights are not offered by the salon.",
                });
                break;
            }
        }
    }

    const note =
        body.note === undefined
            ? ""
            : typeof body.note === "string"
                ? body.note.trim()
                : null;

    if (note === null || note.length > REVIEW_NOTE_MAX_LENGTH) {
        errors.push({
            field: "note",
            message: `Note must be text with ${REVIEW_NOTE_MAX_LENGTH} characters or fewer.`,
        });
    }

    return { errors, rating, highlights, note };
}

app.post("/api/reviews", verifyToken, verifyCustomer, async (req, res) => {
    const body = req.body || {};
    const parsed = validateReviewFields(body);

    const appointmentId =
        typeof body.appointmentId === "string" ? body.appointmentId.trim() : "";

    if (!ObjectId.isValid(appointmentId)) {
        parsed.errors.push({
            field: "appointmentId",
            message: "Appointment ID must be a valid MongoDB ObjectId.",
        });
    }

    if (parsed.errors.length > 0) {
        return sendError(
            res,
            422,
            "Validation failed. Please check the submitted fields.",
            parsed.errors,
        );
    }

    const appointment = await appointmentsCollection.findOne({
        _id: new ObjectId(appointmentId),
    });

    if (!appointment) {
        return sendError(res, 404, "Appointment not found.");
    }

    if (appointment.customerId !== req.user.id) {
        return sendError(res, 403, "You can only review your own appointments.");
    }

    if (appointment.status !== "confirmed") {
        return sendError(
            res,
            409,
            "Only completed visits can be reviewed.",
        );
    }

    const visitDateTime = parseAppointmentDateTime(
        appointment.appointmentDate,
        appointment.timeSlot,
    );

    if (!visitDateTime || visitDateTime.getTime() > Date.now()) {
        return sendError(
            res,
            409,
            "You can review this visit after its appointment time has passed.",
        );
    }

    const alreadyReviewed = await reviewsCollection.findOne({ appointmentId });
    if (alreadyReviewed) {
        return sendError(
            res,
            409,
            "You have already reviewed this appointment.",
        );
    }

    const now = new Date();
    const reviewDocument = {
        appointmentId,
        customerId: req.user.id,
        customerName: req.user.name || "Stylevique customer",
        serviceId: appointment.serviceId ? String(appointment.serviceId) : null,
        serviceName: appointment.serviceSnapshot?.serviceName ?? "Salon service",
        serviceImage: appointment.serviceSnapshot?.image ?? null,
        rating: parsed.rating,
        highlights: parsed.highlights,
        note: parsed.note,
        status: "pending",
        createdAt: now,
        updatedAt: now,
    };

    try {
        const result = await reviewsCollection.insertOne(reviewDocument);

        return sendSuccess(
            res,
            "Thank you. Your review was submitted for approval.",
            { review: normalizeReview({ ...reviewDocument, _id: result.insertedId }) },
            201,
        );
    } catch (error) {
        if (error?.code === 11000) {
            return sendError(
                res,
                409,
                "You have already reviewed this appointment.",
            );
        }
        throw error;
    }
});

app.get("/api/reviews/summary", async (req, res) => {
    const serviceId = String(req.query.serviceId || "").trim();
    const filter = { status: "approved" };

    if (serviceId) {
        if (!ObjectId.isValid(serviceId)) {
            return sendError(res, 422, "Invalid query parameters.", [
                { field: "serviceId", message: "Service ID must be a valid MongoDB ObjectId." },
            ]);
        }
        filter.serviceId = serviceId;
    }

    const [summary] = await reviewsCollection
        .aggregate([
            { $match: filter },
            {
                $group: {
                    _id: null,
                    totalReviews: { $sum: 1 },
                    averageRating: { $avg: "$rating" },
                },
            },
        ])
        .toArray();

    return sendSuccess(res, "Review summary retrieved successfully.", {
        totalReviews: summary?.totalReviews ?? 0,
        averageRating: summary ? Math.round(summary.averageRating * 10) / 10 : 0,
    });
});

app.get("/api/reviews/my", verifyToken, verifyCustomer, async (req, res) => {
    const page = Number(req.query.page || 1);
    const limit = Number(req.query.limit || 20);

    if (!Number.isInteger(page) || page < 1) {
        return sendError(res, 422, "Invalid query parameters.", [
            { field: "page", message: "Page must be a positive whole number." },
        ]);
    }

    if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
        return sendError(res, 422, "Invalid query parameters.", [
            { field: "limit", message: "Limit must be between 1 and 100." },
        ]);
    }

    const filter = { customerId: req.user.id };
    const skip = (page - 1) * limit;
    const [reviews, totalItems] = await Promise.all([
        reviewsCollection
            .find(filter)
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit)
            .toArray(),
        reviewsCollection.countDocuments(filter),
    ]);

    return sendSuccess(res, "Your reviews were retrieved successfully.", {
        reviews: reviews.map(normalizeReview),
        pagination: buildPagination(page, limit, totalItems),
    });
});

app.patch("/api/reviews/:id", verifyToken, verifyCustomer, async (req, res) => {
    if (!ObjectId.isValid(req.params.id)) {
        return sendError(res, 400, "Invalid review ID.");
    }

    const body = req.body || {};
    // Editing an existing review replaces these fields; appointmentId and
    // customer ownership stay fixed by the server.
    const parsed = validateReviewFields({
        rating: body.rating,
        highlights: body.highlights,
        note: body.note,
    });

    if (parsed.errors.length > 0) {
        return sendError(
            res,
            422,
            "Validation failed. Please check the submitted fields.",
            parsed.errors,
        );
    }

    const review = await reviewsCollection.findOne({
        _id: new ObjectId(req.params.id),
    });

    if (!review) {
        return sendError(res, 404, "Review not found.");
    }

    if (review.customerId !== req.user.id) {
        return sendError(res, 403, "You can only edit your own reviews.");
    }

    if (review.status !== "rejected") {
        return sendError(
            res,
            409,
            "Only rejected reviews can be edited and resubmitted.",
        );
    }

    const updatedAt = new Date();
    await reviewsCollection.updateOne(
        { _id: review._id },
        {
            $set: {
                rating: parsed.rating,
                highlights: parsed.highlights,
                note: parsed.note,
                status: "pending",
                updatedAt,
            },
            $unset: { rejectionReason: "" },
        },
    );

    return sendSuccess(res, "Your review was resubmitted for approval.", {
        review: normalizeReview({
            ...review,
            rating: parsed.rating,
            highlights: parsed.highlights,
            note: parsed.note,
            status: "pending",
            updatedAt,
        }),
    });
});

app.get("/api/reviews", async (req, res) => {
    const page = Number(req.query.page || 1);
    const limit = Number(req.query.limit || 12);
    const serviceId = String(req.query.serviceId || "").trim();

    if (!Number.isInteger(page) || page < 1) {
        return sendError(res, 422, "Invalid query parameters.", [
            { field: "page", message: "Page must be a positive whole number." },
        ]);
    }

    if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
        return sendError(res, 422, "Invalid query parameters.", [
            { field: "limit", message: "Limit must be between 1 and 100." },
        ]);
    }

    const filter = { status: "approved" };

    if (serviceId) {
        if (!ObjectId.isValid(serviceId)) {
            return sendError(res, 422, "Invalid query parameters.", [
                {
                    field: "serviceId",
                    message: "Service ID must be a valid MongoDB ObjectId.",
                },
            ]);
        }
        filter.serviceId = serviceId;
    }

    const skip = (page - 1) * limit;
    const [reviews, totalItems] = await Promise.all([
        reviewsCollection
            .find(filter)
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit)
            .toArray(),
        reviewsCollection.countDocuments(filter),
    ]);

    return sendSuccess(res, "Reviews retrieved successfully.", {
        reviews: reviews.map(normalizeReview),
        pagination: buildPagination(page, limit, totalItems),
    });
});

app.get("/api/admin/reviews", verifyToken, verifyAdmin, async (req, res) => {
    const page = Number(req.query.page || 1);
    const limit = Number(req.query.limit || 20);
    const status = String(req.query.status || "");

    if (!Number.isInteger(page) || page < 1) {
        return sendError(res, 422, "Invalid query parameters.", [
            { field: "page", message: "Page must be a positive whole number." },
        ]);
    }

    if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
        return sendError(res, 422, "Invalid query parameters.", [
            { field: "limit", message: "Limit must be between 1 and 100." },
        ]);
    }

    if (status && !REVIEW_STATUSES.includes(status)) {
        return sendError(res, 422, "Invalid query parameters.", [
            {
                field: "status",
                message: "Status must be pending, approved or rejected.",
            },
        ]);
    }

    const filter = status ? { status } : {};
    const skip = (page - 1) * limit;
    const [reviews, totalItems] = await Promise.all([
        reviewsCollection
            .find(filter)
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit)
            .toArray(),
        reviewsCollection.countDocuments(filter),
    ]);

    return sendSuccess(res, "Reviews retrieved successfully.", {
        reviews: reviews.map(normalizeReview),
        pagination: buildPagination(page, limit, totalItems),
    });
});

app.patch(
    "/api/admin/reviews/:id/status",
    verifyToken,
    verifyAdmin,
    async (req, res) => {
        if (!ObjectId.isValid(req.params.id)) {
            return sendError(res, 400, "Invalid review ID.");
        }

        const status = req.body?.status;
        if (!["approved", "rejected"].includes(status)) {
            return sendError(res, 422, "Invalid status.", [
                {
                    field: "status",
                    message: "Status must be approved or rejected.",
                },
            ]);
        }

        const review = await reviewsCollection.findOne({
            _id: new ObjectId(req.params.id),
        });

        if (!review) {
            return sendError(res, 404, "Review not found.");
        }

        const now = new Date();
        await reviewsCollection.updateOne(
            { _id: review._id },
            {
                $set: {
                    status,
                    reviewedAt: now,
                    reviewedBy: req.user.id,
                    updatedAt: now,
                },
            },
        );

        return sendSuccess(res, `Review ${status} successfully.`, {
            review: normalizeReview({
                ...review,
                status,
                reviewedAt: now,
                reviewedBy: req.user.id,
                updatedAt: now,
            }),
        });
    },
);

// ========================================
// Error Handling
// ========================================

function notFoundHandler(req, res) {
    const pathWithoutQuery = req.originalUrl.split("?")[0];
    return sendError(
        res,
        404,
        `Route ${req.method} ${pathWithoutQuery} was not found.`,
    );
}

function errorHandler(error, req, res, next) {
    if (res.headersSent) {
        return next(error);
    }

    let statusCode = 500;
    let message = "An unexpected internal server error occurred.";
    let details;

    if (error?.statusCode) {
        statusCode = error.statusCode;
        message = error.message;
        details = error.details;
    } else if (error instanceof multer.MulterError) {
        if (error.code === "LIMIT_FILE_SIZE") {
            statusCode = 413;
            message = `The image is too large. The maximum size is ${MAX_UPLOAD_SIZE_MB} MB.`;
        } else if (error.code === "LIMIT_UNEXPECTED_FILE") {
            statusCode = 422;
            message = "Unexpected file field. Use the field name \"image\" for one image.";
        } else {
            statusCode = 400;
            message = "The image upload could not be processed.";
        }
    } else if (error?.type === "entity.parse.failed") {
        statusCode = 400;
        message = "The request body contains invalid JSON.";
    } else if (error?.type === "entity.too.large") {
        statusCode = 413;
        message = "The request body is too large.";
    } else if (error?.code === 11000) {
        statusCode = 409;

        if (error?.keyPattern?.activeSlotKey) {
            message =
                "This date and time slot is already booked. Please choose another slot.";
        } else if (
            error?.keyPattern?.stripeEventId ||
            error?.keyPattern?.stripeSessionId
        ) {
            message = "This payment event has already been processed.";
        } else {
            message = "A record with the same unique value already exists.";
        }
    } else if (
        error?.name === "BSONError" ||
        error?.name === "BSONTypeError" ||
        error?.name === "BSONInvalidParameterError"
    ) {
        statusCode = 400;
        message = "The request contains an invalid identifier.";
    } else if (String(error?.type || "").startsWith("Stripe")) {
        statusCode = 502;
        message = "The payment provider could not process this request.";
    } else if (error?.status === 400 && error instanceof SyntaxError) {
        statusCode = 400;
        message = "The request body could not be parsed.";
    }

    const pathWithoutQuery = req.originalUrl.split("?")[0];

    if (statusCode >= 500) {
        console.error(
            `[${req.method} ${pathWithoutQuery}]`,
            error?.stack || error?.message || "Unknown error",
        );
    } else {
        console.warn(
            `[${req.method} ${pathWithoutQuery}] ${statusCode}: ${message}`,
        );
    }

    const response = {
        success: false,
        message,
    };

    if (details !== undefined) {
        response.errors = details;
    }

    return res.status(statusCode).json(response);
}

// ========================================
// Server Initialization
// ========================================

app.get("/", (req, res) => {
    return sendSuccess(res, "Welcome to the Stylevique salon booking API.", {
        name: "Stylevique API",
        version: "1.0.0",
        health: "/api/health",
    });
});

app.get("/api/health", async (req, res) => {
    let databaseStatus = "disconnected";

    if (database) {
        try {
            await withTimeout(
                database.command({ ping: 1 }),
                3000,
                "Database health check timed out.",
            );
            databaseStatus = "connected";
        } catch {
            databaseStatus = "unavailable";
        }
    }

    const isHealthy = databaseStatus === "connected";

    return res.status(isHealthy ? 200 : 503).json({
        success: isHealthy,
        message: isHealthy
            ? "Stylevique API is healthy."
            : "Stylevique API is running, but the database is unavailable.",
        data: {
            status: isHealthy ? "ok" : "degraded",
            database: databaseStatus,
            uptimeSeconds: Math.round(process.uptime()),
            timestamp: new Date().toISOString(),
            integrations: {
                betterAuthJwt: Boolean(remoteJwks && !authenticationConfigurationError),
                stripeCheckout: Boolean(stripe),
                stripeWebhook: Boolean(stripe && STRIPE_WEBHOOK_SECRET),
                imgbbUploads: Boolean(IMGBB_API_KEY),
            },
        },
    });
});

function logConfigurationWarnings() {
    console.log("Stylevique server configuration:");
    console.log(`- Environment: ${NODE_ENV}`);
    console.log(`- Port: ${PORT}`);
    console.log(`- Allowed CORS origins: ${CLIENT_URLS.join(", ")}`);
    console.log(`- Better Auth user collection: ${AUTH_USER_COLLECTION}`);
    console.log(`- Better Auth issuer: ${BETTER_AUTH_ISSUER}`);
    console.log(`- Better Auth JWKS: ${BETTER_AUTH_JWKS_URL}`);
    console.log(`- Stripe currency: ${STRIPE_CURRENCY}`);

    if (!MONGODB_URI) {
        console.warn("- WARNING: MONGODB_URI is missing.");
    }

    if (authenticationConfigurationError) {
        console.warn(`- WARNING: ${authenticationConfigurationError}`);
    }

    if (!stripe) {
        console.warn(
            "- Stripe checkout is disabled: STRIPE_SECRET_KEY is not configured.",
        );
    } else if (!STRIPE_WEBHOOK_SECRET) {
        console.warn(
            "- Stripe checkout is enabled, but webhooks are disabled: STRIPE_WEBHOOK_SECRET is not configured.",
        );
    }

    if (!IMGBB_API_KEY) {
        console.warn("- Image uploads are disabled: IMGBB_API_KEY is not configured.");
    }

    if (!ADMIN_EMAIL) {
        console.warn(
            "- Admin promotion is unavailable until ADMIN_EMAIL is configured.",
        );
    }
}

async function startServer() {
    logConfigurationWarnings();

    await connectToMongoDB();
    const createdIndexes = await ensureDatabaseIndexes();

    console.log(
        `MongoDB connected to database "${DB_NAME}". ${createdIndexes} indexes are ready.`,
    );
    console.log(
        `Multi-document transactions: ${supportsTransactions ? "supported" : "not supported (sequential fallback active)"}`,
    );

    const server = await new Promise((resolve, reject) => {
        const httpServer = app.listen(PORT, () => resolve(httpServer));
        httpServer.once("error", reject);
    });

    console.log(`Stylevique API is listening on http://localhost:${PORT}`);

    let isShuttingDown = false;

    async function shutdown(signal) {
        if (isShuttingDown) {
            return;
        }

        isShuttingDown = true;
        console.log(`Received ${signal}. Shutting down gracefully...`);

        const forceExitTimer = setTimeout(() => {
            console.error("Graceful shutdown timed out. Forcing exit.");
            process.exit(1);
        }, 10000);
        forceExitTimer.unref();

        const closeServerPromise = new Promise((resolve) => {
            server.close(() => resolve());
        });

        setTimeout(() => {
            server.closeAllConnections?.();
        }, 5000).unref();

        await closeServerPromise;

        if (mongoClient) {
            await mongoClient.close().catch((error) => {
                console.error("MongoDB close failed:", error.name || "UnknownError");
            });
            mongoClient = null;
            database = null;
        }

        clearTimeout(forceExitTimer);
        console.log("Shutdown complete.");
        process.exit(0);
    }

    process.on("SIGINT", () => {
        shutdown("SIGINT");
    });

    process.on("SIGTERM", () => {
        shutdown("SIGTERM");
    });

    process.on("unhandledRejection", (reason) => {
        console.error(
            "Unhandled promise rejection:",
            reason instanceof Error ? reason.message : "Unknown reason",
        );
    });

    process.on("uncaughtException", (error) => {
        console.error("Uncaught exception:", error.message);
        shutdown("uncaughtException");
    });
}

async function promoteAdminFromCli() {
    const requestedEmail = (process.argv[3] || "").trim().toLowerCase();

    if (!ADMIN_EMAIL) {
        throw new Error(
            "ADMIN_EMAIL is not configured. Set it in .env before promoting an administrator.",
        );
    }

    if (!requestedEmail) {
        throw new Error(
            "Usage: node index.js promote-admin admin@example.com",
        );
    }

    if (requestedEmail !== ADMIN_EMAIL) {
        throw new Error(
            "The supplied email does not match the configured ADMIN_EMAIL. Promotion refused.",
        );
    }

    await connectToMongoDB();

    try {
        const matchingUsers = await usersCollection
            .find({
                email: {
                    $regex: `^${escapeRegex(requestedEmail)}$`,
                    $options: "i",
                },
            })
            .limit(2)
            .toArray();

        if (matchingUsers.length === 0) {
            throw new Error(
                "No Better Auth user exists with that email. Register the account first, then run this command again.",
            );
        }

        if (matchingUsers.length > 1) {
            throw new Error(
                "Multiple user records use that email. Promotion aborted to avoid promoting the wrong account.",
            );
        }

        const userDocument = matchingUsers[0];

        if (normalizeUser(userDocument).role === "admin") {
            console.log(`The account ${requestedEmail} is already an administrator.`);
            return;
        }

        const updateResult = await usersCollection.updateOne(
            { _id: userDocument._id },
            {
                $set: {
                    role: "admin",
                    updatedAt: new Date(),
                },
            },
        );

        if (updateResult.matchedCount !== 1) {
            throw new Error("The user could not be updated. Promotion aborted.");
        }

        console.log(
            `Successfully promoted ${requestedEmail} to administrator. No password or account credential was changed.`,
        );
    } finally {
        if (mongoClient) {
            await mongoClient.close().catch(() => { });
            mongoClient = null;
            database = null;
        }
    }
}

// 404 and error middleware must be registered after every route.
app.use(notFoundHandler);
app.use(errorHandler);

if (IS_ADMIN_PROMOTION_COMMAND) {
    promoteAdminFromCli()
        .then(() => process.exit(0))
        .catch((error) => {
            console.error("Admin promotion failed:", error.message);
            process.exit(1);
        });
} else {
    startServer().catch((error) => {
        console.error("Stylevique server failed to start:", error.message);
        process.exit(1);
    });
}
