# Stylevique Server

Stylevique Server is the REST API for **Stylevique**, a full-stack salon appointment booking platform. It is a traditional Express.js application with all backend logic kept inside **one main file, `index.js`**, as requested. It uses the native MongoDB driver (not Mongoose), Better Auth JWT verification, Stripe Checkout and verified Stripe webhooks, and ImgBB for image hosting.

> **Important:** the backend does not implement its own login or registration system. Better Auth runs in the Next.js frontend and owns authentication. Express verifies the JWT that Better Auth issues.

---

## Features

- Single-file Express.js backend (`index.js`)
- Better Auth JWT verification through a remote JWKS endpoint (`jose`)
- Database-backed role and blocked-status checks on every protected request
- Customer and admin authorization enforced on the server
- Service management with public/active filtering and admin CRUD
- Appointment booking with server-side price lookup and service snapshots
- Database-level duplicate appointment protection using a unique partial index
- Customer appointment cancellation that releases the reserved time slot
- Admin appointment status transitions (pending → confirmed/cancelled, confirmed → cancelled)
- Customer profiles with protected fields (`role`, `isBlocked`, `email`, `password` cannot be changed)
- Admin customer search, detail, block and unblock APIs
- Customer and admin dashboard statistics calculated by MongoDB aggregations
- ImgBB image uploads through Multer memory storage
- Stripe Checkout using the trusted database price
- Stripe webhook verification with raw-body middleware, amount/currency checks and idempotency
- MongoDB transaction support for payment recording, with a safe fallback for standalone MongoDB
- Read-only transaction APIs for customers and admins
- Helmet, CORS allow-list, rate limiting, request-size limits and inline request validation
- Secure CLI-only admin promotion
- Graceful shutdown that closes the HTTP and MongoDB connections

---

## Technology Stack

| Layer | Technology |
| --- | --- |
| Runtime | Node.js (ES Modules) |
| Server | Express.js 5 |
| Database | MongoDB Atlas + native `mongodb` driver |
| Authentication | Better Auth JWT plugin, verified with `jose` |
| Validation | inline request checks |
| Payments | Stripe Checkout + Stripe webhooks |
| Image hosting | ImgBB |
| Upload handling | Multer (memory storage) |
| Security | Helmet, CORS, express-rate-limit |
| Configuration | dotenv |

---

## Folder Structure

```text
stylevique-server/
├── index.js          # Entire backend implementation
├── package.json
├── package-lock.json
├── .env              # Local secrets (never committed)
├── .env.example      # Safe template (no real credentials)
├── .gitignore
└── README.md
```

No `controllers/`, `routes/`, `services/`, `models/`, `middleware/`, `config/` or `utils/` folders are used. Small reusable helper functions live inside `index.js`.

---

## Installation

Requirements:

- Node.js 20 or newer (Node 24 is recommended)
- A MongoDB Atlas account or a local MongoDB replica set
- A running Stylevique Next.js frontend for Better Auth
- Stripe test-mode account (for payments)
- ImgBB account (for image uploads)

```bash
cd stylevique-server

# Install dependencies (do not re-run npm init)
npm install

# Create your local environment file
# Windows PowerShell:
Copy-Item .env.example .env
# macOS/Linux:
# cp .env.example .env

# Fill in the values in .env, then start the API
npm run dev
```

Production start:

```bash
npm start
```

---

## How to Run Locally

1. Start the Next.js frontend on `http://localhost:3000`.
2. Make sure Better Auth is configured with the JWT plugin (see below).
3. Fill in `.env` in this server project.
4. Start the backend:

```bash
npm run dev
```

5. Check the health endpoint:

```text
http://localhost:5000/api/health
```

The API will not start its HTTP listener until MongoDB connects successfully. This is intentional: the application cannot serve useful requests without its database.

---

## Environment Variables

| Name | Required | Purpose |
| --- | --- | --- |
| `PORT` | Optional | Express port (default `5000`) |
| `NODE_ENV` | Optional | `development` or `production` |
| `MONGODB_URI` | **Yes** | MongoDB Atlas connection string |
| `DB_NAME` | **Yes** | Database name (must match Better Auth, normally `stylevique`) |
| `CLIENT_URL` | **Yes** | Frontend origin(s); comma-separated list is supported |
| `AUTH_USER_COLLECTION` | **Yes** | Better Auth user collection (default `user`) |
| `BETTER_AUTH_JWKS_URL` | **Yes** | Example: `http://localhost:3000/api/auth/jwks` |
| `BETTER_AUTH_ISSUER` | **Yes** | JWT `iss` value (Better Auth base URL by default) |
| `BETTER_AUTH_AUDIENCE` | **Yes** | JWT `aud` value (Better Auth base URL by default) |
| `STRIPE_SECRET_KEY` | Payments | Stripe test/live secret key |
| `STRIPE_WEBHOOK_SECRET` | Payments | Stripe webhook signing secret |
| `STRIPE_CURRENCY` | Optional | Lowercase currency code, default `usd` |
| `IMGBB_API_KEY` | Uploads | ImgBB API key |
| `ADMIN_EMAIL` | Admin promotion | The only email allowed to be promoted to admin |
| `MAX_UPLOAD_SIZE_MB` | Optional | Upload limit, default `5`, capped at `25` |

`CLIENT_URL`, JWT verification, Stripe and ImgBB are required for the features that use them. The server still starts when Stripe, ImgBB or `ADMIN_EMAIL` are missing, but the related endpoints return a clear `503 Service Unavailable` response.

**Never commit `.env`.** It is already listed in `.gitignore`. `.env.example` must contain names/placeholders only.

---

## MongoDB Setup

1. Create a free MongoDB Atlas cluster.
2. Create a database user with read/write access.
3. Add your current IP address to the Atlas IP allow-list.
4. Copy the connection string into `MONGODB_URI`.
5. Set `DB_NAME=stylevique`.

The backend connects with `MongoClient` and uses these collections:

| Collection | Owner | Purpose |
| --- | --- | --- |
| `user` | Better Auth | Authentication user records and app fields (`role`, `isBlocked`, `phone`) |
| `services` | Express API | Salon services |
| `appointments` | Express API | Appointment requests and service snapshots |
| `transactions` | Express API | Verified successful/failed Stripe payment records |

Better Auth's MongoDB adapter normally stores the primary key in `_id` (an ObjectId) while exposing it to the frontend as the string `user.id`. The backend supports both `_id`-as-ObjectId and `_id`-as-string mappings, plus a legacy `id` field. It also supports changing the collection name with `AUTH_USER_COLLECTION`.

### Indexes created at startup

- Services: `{ status, category }`, `{ price }`, `{ createdAt }`
- Appointments: `{ customerId, createdAt }`, `{ status, createdAt }`, `{ appointmentDate, timeSlot }`, `{ serviceId }`
- Appointments: **unique partial** index on `activeSlotKey`
- Transactions: `{ customerId, createdAt }`, `{ appointmentId }`, `{ status, createdAt }`
- Transactions: **unique partial** index on `stripeSessionId`
- Transactions: **unique partial** index on `stripeEventId`
- Users: `{ role, createdAt }`

The unique partial index is what prevents two concurrent requests from booking the same date and time slot. A pre-check also exists for a friendly error, but the database index is the real guarantee.

### Weird duplicate-key startup error?

If the unique `activeSlotKey` index cannot be created, the database already contains duplicate active slot values. Inspect and resolve those existing appointments before restarting. Do not remove the index; it protects the booking system.

---

## Better Auth JWT Integration

### 1. What the backend verifies

The Express API:

1. Reads `Authorization: Bearer <jwt>`.
2. Fetches Better Auth's public keys from `BETTER_AUTH_JWKS_URL`.
3. Verifies the signature, expiration time, issuer and audience with `jose`.
4. Uses the JWT subject (`sub`) to load the current user from MongoDB.
5. Re-checks the **current** `role` and `isBlocked` values in the database.
6. Rejects missing users with `401` and blocked users with `403`.

The backend never trusts a role supplied by the browser and never trusts old role claims alone.

### 2. Frontend auth server configuration (required)

The existing frontend auth config in `src/lib/auth.ts` already references `jwt(...)`, but **it does not import it** in the current version. Add the import and the user fields:

```ts
// src/lib/auth.ts
import { betterAuth } from "better-auth";
import { MongoClient } from "mongodb";
import { mongodbAdapter } from "@better-auth/mongo-adapter";
import { jwt } from "better-auth/plugins"; // REQUIRED

const client = new MongoClient(process.env.MONGODB_URI!);
const db = client.db("stylevique"); // must match backend DB_NAME

export const auth = betterAuth({
  emailAndPassword: {
    enabled: true,
    minPasswordLength: 6,
  },
  baseURL: process.env.BETTER_AUTH_URL!,
  socialProviders: {
    google: {
      clientId: process.env.GOOGLE_CLIENT_ID as string,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET as string,
    },
  },
  database: mongodbAdapter(db, { client }),

  // Application fields stored in Better Auth's user collection.
  // input: false prevents public sign-up/profile APIs from writing them.
  user: {
    additionalFields: {
      role: {
        type: "string",
        required: false,
        defaultValue: "customer",
        input: false,
      },
      isBlocked: {
        type: "boolean",
        required: false,
        defaultValue: false,
        input: false,
      },
      phone: {
        type: "string",
        required: false,
        input: true,
      },
    },
  },

  plugins: [
    jwt({ sessionCookieCache: true }),
  ],
  session: {
    cookieCache: {
      enabled: true,
      strategy: "jwt",
      maxAge: 7 * 24 * 60 * 60,
    },
  },
});
```

Better Auth's JWT plugin defaults:

- JWKS endpoint: `/api/auth/jwks`
- Issuer: Better Auth `baseURL`
- Audience: Better Auth `baseURL`
- Subject: the authenticated user's ID

If you set custom `jwt.issuer`, `jwt.audience` or a custom JWKS path in Better Auth, update the three `BETTER_AUTH_*` variables in this backend to match.

### 3. Frontend auth client configuration (required)

The current `src/lib/auth-client.ts` creates a configured client and then exports actions from a second unconfigured client. Use one client and add the JWT client plugin:

```ts
// src/lib/auth-client.ts
import { createAuthClient } from "better-auth/react";
import { jwtClient } from "better-auth/client/plugins";

export const authClient = createAuthClient({
  baseURL: process.env.NEXT_PUBLIC_APP_URL ?? "http://localhost:3000",
  plugins: [jwtClient()],
});

export const { signIn, signUp, signOut, useSession } = authClient;
```

### 4. Retrieving and sending the JWT

```ts
const { data, error } = await authClient.token();

if (error || !data?.token) {
  throw new Error("Please sign in again.");
}

const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/users/me`, {
  headers: {
    Authorization: `Bearer ${data.token}`,
  },
});
```

The JWT is short-lived (15 minutes by default). Request a fresh token before API calls, or refresh it when the API returns `401`.

---

## ImgBB Configuration

1. Create an ImgBB account.
2. Open the ImgBB API page and generate an API key.
3. Add it to `.env` as `IMGBB_API_KEY`.
4. Never expose this key in the frontend.

Uploads use:

```text
POST /api/uploads/image
Content-Type: multipart/form-data
Authorization: Bearer <jwt>
Field name: image
```

Allowed types: JPEG, PNG, WebP and GIF. The backend checks the MIME type, the file size and basic image magic bytes before sending the file to ImgBB. The frontend receives only the hosted image URL and should save that URL in the service or profile record.

---

## Stripe Test-Mode Configuration

1. Create a Stripe account and switch to **Test mode**.
2. Copy the test secret key (`sk_test_...`) into `STRIPE_SECRET_KEY`.
3. Set `STRIPE_CURRENCY=usd` (or another supported currency).
4. Enable the payment methods you want in **Stripe Dashboard → Settings → Payments**. The backend intentionally does not send the legacy `payment_method_types` parameter, because newer Stripe accounts reject it. Stripe applies the Dashboard settings to Checkout automatically.
5. Install the Stripe CLI.
6. Start the backend.
7. Forward webhooks to the local API:

```bash
stripe listen --forward-to localhost:5000/api/payments/webhook
```

8. Copy the printed `whsec_...` value into `STRIPE_WEBHOOK_SECRET`.
9. Restart the backend after changing environment variables.
10. Test a payment with card `4242 4242 4242 4242`, any future expiry date and any CVC.

### Checkout flow

```text
Customer booking → admin confirms → customer requests checkout
→ Stripe Checkout → success redirect → Stripe webhook → backend verifies
→ appointment.paymentStatus = "paid" + transaction inserted
```

The success redirect is **not** proof of payment. The frontend should poll `GET /api/payments/verify?session_id=...` until the backend reports `paid` or `failed`.

The backend only allows checkout when:

- `appointment.status === "confirmed"`
- `appointment.paymentStatus === "unpaid"`
- the appointment belongs to the authenticated customer
- the customer is not blocked

The amount comes from `appointment.servicePrice` stored in MongoDB. A client-supplied amount or currency is ignored.

### Webhook setup checklist

- The webhook route is registered **before** `express.json()` and uses `express.raw()`.
- `STRIPE_WEBHOOK_SECRET` must belong to the same Stripe mode and endpoint.
- Supported events:
  - `checkout.session.completed`
  - `checkout.session.async_payment_succeeded`
  - `checkout.session.async_payment_failed`
  - `checkout.session.expired`
- Signatures are verified with `stripe.webhooks.constructEvent`.
- Amount and currency are compared with the trusted appointment price.
- Repeated deliveries are idempotent through unique indexes.
- A paid appointment that is cancelled keeps `paymentStatus: "paid"` and its transaction history. No refund is claimed or issued by this backend.

For production, create a real Stripe webhook endpoint pointing to:

```text
https://your-api-domain.com/api/payments/webhook
```

Select the four events above and copy that endpoint's signing secret into the production environment.

---

## Admin Promotion Command

Public registration must never create an administrator. The only supported promotion path is a CLI command:

```bash
# 1. Register the account normally through the frontend first.
# 2. Put the same email in ADMIN_EMAIL in .env.
# 3. Run:

node index.js promote-admin admin@example.com
# or:
npm run promote-admin -- admin@example.com
```

Safety rules:

- The account must already exist in Better Auth's user collection.
- The supplied email must exactly match `ADMIN_EMAIL`.
- Multiple matching user records abort the command.
- Only the matched user's `role` becomes `admin`.
- Passwords and authentication credentials are never changed.
- There is no HTTP endpoint for admin promotion.

---

## Common Response Format

Success:

```json
{
  "success": true,
  "message": "Operation successful",
  "data": {}
}
```

Failure:

```json
{
  "success": false,
  "message": "Something went wrong"
}
```

Validation failures include an `errors` array:

```json
{
  "success": false,
  "message": "Validation failed. Please check the submitted fields.",
  "errors": [
    { "field": "price", "message": "Too small: expected number to be >0" }
  ]
}
```

HTTP status codes used: `200`, `201`, `400`, `401`, `403`, `404`, `409`, `413`, `422`, `429`, `500`, `502`, `503`.

---

## API Documentation

Base URL:

```text
http://localhost:5000
```

Protected routes require:

```http
Authorization: Bearer <better-auth-jwt>
```

### System

| Method | Endpoint | Access | Description |
| --- | --- | --- | --- |
| `GET` | `/` | Public | API welcome message |
| `GET` | `/api/health` | Public | API/database health |

### Services

| Method | Endpoint | Access | Description |
| --- | --- | --- | --- |
| `GET` | `/api/services` | Public | Active services with search, category, sort and pagination |
| `GET` | `/api/services/categories` | Public | Categories from active services |
| `GET` | `/api/services/:id` | Public | Active service details |
| `GET` | `/api/admin/services` | Admin | All services, including inactive |
| `POST` | `/api/services` | Admin | Create service |
| `PATCH` | `/api/services/:id` | Admin | Update service fields |
| `PATCH` | `/api/services/:id/status` | Admin | Activate/deactivate |
| `DELETE` | `/api/services/:id` | Admin | Delete service |

Public query parameters:

```text
search=hair
category=Haircut %26 Styling
sort=price_asc | price_desc | newest | oldest
page=1
limit=12
```

Admin service list also supports `status=active|inactive`. Filters can be combined.

Service creation body:

```json
{
  "serviceName": "Signature Haircut",
  "category": "Haircut & Styling",
  "description": "A consultation, shampoo, precision cut and finish.",
  "price": 45,
  "duration": 60,
  "image": "https://i.ibb.co/.../service.jpg",
  "status": "active"
}
```

Price and duration must be positive. `status` defaults to `active`.

### Image Uploads

| Method | Endpoint | Access | Description |
| --- | --- | --- | --- |
| `POST` | `/api/uploads/image` | Authenticated | Upload one image to ImgBB |

Multipart field: `image`.

### Appointments

| Method | Endpoint | Access | Description |
| --- | --- | --- | --- |
| `POST` | `/api/appointments` | Customer | Book an appointment |
| `GET` | `/api/appointments/my` | Customer | Own appointments |
| `GET` | `/api/appointments/:id` | Customer/Admin | Own appointment, or any appointment for admins |
| `PATCH` | `/api/appointments/:id/cancel` | Customer | Cancel own pending appointment |
| `GET` | `/api/admin/appointments` | Admin | All appointments |
| `PATCH` | `/api/admin/appointments/:id/status` | Admin | Confirm or cancel |

Booking body:

```json
{
  "serviceId": "66f1c0d3a1b2c3d4e5f60789",
  "appointmentDate": "2026-12-10",
  "timeSlot": "10:00",
  "message": "Please use fragrance-free products."
}
```

Rules:

- `serviceId` must reference an active service.
- The customer ID is taken from the verified JWT, never from the request body.
- The price is read from MongoDB, never from the request body.
- The date and time must be in the future.
- Only the predefined time slots are accepted.
- A unique database index prevents double booking.
- New appointments start as `pending` and `unpaid`.
- A service snapshot is saved with the appointment.

Current time slots:

```text
09:00 09:30 10:00 10:30 11:00 11:30 12:00 12:30
13:00 13:30 14:00 14:30 15:00 15:30 16:00 16:30
17:00 17:30 18:00 18:30
```

Keep `TIME_SLOTS` in `index.js` and the frontend booking form in sync.

Admin status transitions:

| Current | Allowed next |
| --- | --- |
| `pending` | `confirmed`, `cancelled` |
| `confirmed` | `cancelled` |
| `cancelled` | none |

Only pending appointments can be confirmed. Cancelling releases the slot. A paid appointment remains paid after cancellation and its transaction history is preserved.

### Users

| Method | Endpoint | Access | Description |
| --- | --- | --- | --- |
| `GET` | `/api/users/me` | Authenticated | Current profile |
| `PATCH` | `/api/users/me` | Authenticated | Update own `name`, `image`, `phone` |
| `GET` | `/api/admin/users` | Admin | Registered customers (search + pagination) |
| `GET` | `/api/admin/users/:id` | Admin | Customer details |
| `PATCH` | `/api/admin/users/:id/block` | Admin | Block customer |
| `PATCH` | `/api/admin/users/:id/unblock` | Admin | Unblock customer |

Profile updates are strict. Sending `role`, `isBlocked`, `email` or `password` to `PATCH /api/users/me` is rejected with `422`. Role and blocked status are never editable by customers.

Admin users search:

```text
/api/admin/users?search=jane&page=1&limit=20
```

### Dashboard

| Method | Endpoint | Access | Description |
| --- | --- | --- | --- |
| `GET` | `/api/dashboard/customer` | Customer | Own appointment statistics |
| `GET` | `/api/dashboard/admin` | Admin | Salon-wide statistics |

Customer response data:

```json
{
  "totalAppointments": 5,
  "pendingAppointments": 1,
  "confirmedAppointments": 2,
  "cancelledAppointments": 2
}
```

Admin response data:

```json
{
  "totalRegisteredCustomers": 24,
  "totalActiveServices": 9,
  "totalAppointments": 41,
  "pendingAppointments": 5,
  "confirmedAppointments": 17,
  "cancelledAppointments": 19,
  "totalSuccessfulPayments": 12,
  "totalRevenue": 640,
  "currency": "usd"
}
```

### Payments

| Method | Endpoint | Access | Description |
| --- | --- | --- | --- |
| `POST` | `/api/payments/checkout` | Customer | Create/reuse a Stripe Checkout Session |
| `GET` | `/api/payments/verify?session_id=...` | Customer | Read verified payment state |
| `POST` | `/api/payments/webhook` | Stripe | Raw-body signed webhook |

Checkout body:

```json
{ "appointmentId": "66f1c0d3a1b2c3d4e5f60789" }
```

The response includes `checkoutUrl`, `sessionId`, `appointmentId`, `amount` and `currency`. Redirect the browser to `checkoutUrl`.

`GET /api/payments/verify` never updates payment state. It reports:

- `paid` only after a verified webhook transaction exists for that session
- `failed` if Stripe reported an asynchronous payment failure
- `pending` while verification is still in progress

### Transactions

| Method | Endpoint | Access | Description |
| --- | --- | --- | --- |
| `GET` | `/api/transactions/my` | Customer | Own transactions |
| `GET` | `/api/admin/transactions` | Admin | All transactions with customer/service details |

Both support `status=paid|failed`, `page` and `limit`.

Transactions are read-only. There is intentionally no endpoint for creating, editing or deleting transactions or manually marking an appointment as paid.

---

## Frontend Integration Guide

### 1. Environment

In the Next.js project, set:

```env
NEXT_PUBLIC_API_URL=http://localhost:5000
```

The frontend and backend must use the same MongoDB database name and the same Better Auth base URL.

### 2. Reusable API helper

```ts
// src/lib/api.ts
import { authClient } from "@/lib/auth-client";

const API_URL = process.env.NEXT_PUBLIC_API_URL!;

export async function apiRequest<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const { data, error } = await authClient.token();

  if (error || !data?.token) {
    throw new Error("Please sign in again.");
  }

  const headers = new Headers(options.headers);
  headers.set("Authorization", `Bearer ${data.token}`);

  if (options.body && !(options.body instanceof FormData)) {
    headers.set("Content-Type", "application/json");
  }

  const response = await fetch(`${API_URL}${path}`, {
    ...options,
    headers,
  });

  const payload = await response.json();

  if (!response.ok || payload.success === false) {
    throw new Error(payload.message || "Request failed.");
  }

  return payload.data as T;
}
```

### 3. Upload an image

```ts
const formData = new FormData();
formData.append("image", file);

const result = await apiRequest<{ url: string }>("/api/uploads/image", {
  method: "POST",
  body: formData,
});

// Save result.url in the profile or service form.
```

Do **not** set the `Content-Type` header manually for `FormData`; the browser must add the multipart boundary.

### 4. Create an appointment

```ts
await apiRequest("/api/appointments", {
  method: "POST",
  body: JSON.stringify({
    serviceId,
    appointmentDate: "2026-12-10",
    timeSlot: "10:00",
    message: "Please use fragrance-free products.",
  }),
});
```

### 5. Create a Checkout Session

```ts
const checkout = await apiRequest<{ checkoutUrl: string }>(
  "/api/payments/checkout",
  {
    method: "POST",
    body: JSON.stringify({ appointmentId }),
  },
);

window.location.href = checkout.checkoutUrl;
```

### 6. Payment success page

The success page receives `session_id` in the URL. Do not assume the payment is complete just because Stripe redirected the browser. Poll the backend:

```ts
const sessionId = searchParams.get("session_id");

const result = await apiRequest<{ status: "pending" | "paid" | "failed" }>(
  `/api/payments/verify?session_id=${encodeURIComponent(sessionId!)}`,
);

if (result.status === "paid") {
  // Show the confirmed payment and refresh the appointment.
} else if (result.status === "pending") {
  // Show "Verifying payment..." and poll again after a short delay.
} else {
  // Show the failed-payment message.
}
```

### 7. Dashboard data

```ts
const customerStats = await apiRequest("/api/dashboard/customer");
const adminStats = await apiRequest("/api/dashboard/admin");
```

### 8. List data

```ts
const services = await apiRequest("/api/services?search=hair&sort=price_asc&page=1&limit=12");
const myAppointments = await apiRequest("/api/appointments/my?page=1&limit=20");
const myTransactions = await apiRequest("/api/transactions/my?page=1&limit=20");
```

---

## Security Notes

- JWTs are verified against Better Auth's JWKS, including signature, expiry, issuer and audience.
- Roles and blocked status are re-read from MongoDB on every protected request.
- Admin-only routes use `verifyAdmin`; customer bookings use `verifyCustomer`.
- Public sign-up cannot choose an admin role.
- Profile updates reject protected fields.
- Search terms are escaped before being used in MongoDB regexes.
- Request bodies are limited to 1 MB; images are limited by `MAX_UPLOAD_SIZE_MB`.
- ImgBB and Stripe keys remain server-side.
- Webhook raw-body middleware is registered before the JSON parser.
- Webhook signatures, amounts, currencies, appointment metadata and customer metadata are verified.
- Duplicate webhooks are handled by unique indexes and idempotent checks.
- Error responses do not expose stack traces, database errors or secrets.
- Rate limiting is enabled for general API, booking, checkout and upload requests.
- CORS only allows the origins configured in `CLIENT_URL`.
- Helmet adds security headers.
- Blocking a user is enforced by the API even if their existing JWT has not expired.

---

## Available Scripts

| Script | Command | Purpose |
| --- | --- | --- |
| `npm start` | `node index.js` | Start production server |
| `npm run dev` | `nodemon index.js` | Start with automatic restarts |
| `npm run promote-admin -- email` | CLI promotion | Promote an existing user |
| `npm run check` | `node --check index.js` | Syntax-check the backend |

---

## Client Repository

```text
Client repository: https://github.com/Md-sihab11/stylevique-clientSide
```

The frontend is a separate Next.js repository. See the integration section above for the required Better Auth JWT plugin and environment changes.

## Live Site

```text
Live site: <add your deployed frontend URL here>
Live API: <add your deployed backend URL here>
```

No deployment links are invented. Add real links after deployment.

---

## Troubleshooting

**`MONGODB_URI is missing`**  
Create `.env` from `.env.example` and add the Atlas connection string.

**MongoDB connection fails on `querySrv ECONNREFUSED`**  
Your network/DNS is blocking MongoDB Atlas SRV lookups. Try another network, disable a VPN or use a standard `mongodb://` connection string with the Atlas host list.

**`401 Unauthorized` on every protected route**  
Check that Better Auth's JWT plugin is imported and enabled, that `authClient.token()` returns a token, and that the issuer/audience/JWKS variables match Better Auth.

**`403 Administrator access is required`**  
Promote the account with the CLI command and sign in again. The backend re-reads the database role, so a new token is not strictly required, but the frontend may cache session data.

**`503 Stripe payments are not configured`**  
Add `STRIPE_SECRET_KEY` and `STRIPE_WEBHOOK_SECRET` and restart.

**Webhook signature errors**  
Use the signing secret printed by `stripe listen`, make sure the raw-body route is unchanged, and confirm the Stripe mode matches the secret key.

**Payment stays `pending`**  
The browser success redirect is not payment verification. Ensure `stripe listen` is running and forwarding to `/api/payments/webhook`, then check the backend logs.

**`409 This date and time slot is already booked`**  
Another pending or confirmed appointment owns that slot. Choose another time or cancel the existing pending appointment.

**Image upload returns `503`**  
Add `IMGBB_API_KEY` to `.env` and restart.

**Image upload returns `502` and the log shows ImgBB code `103`**  
ImgBB rejected the key itself (`You have been forbidden to use this website`), not the image. Generate a new API key at [api.imgbb.com](https://api.imgbb.com/) and update `IMGBB_API_KEY`. The backend deliberately returns a safe `502` instead of exposing the provider response.

**Stripe checkout says `payment_method_types` is no longer supported**  
This backend does not send that legacy parameter. If you see this from an older copy of the code, remove `payment_method_types` and manage payment methods in the Stripe Dashboard. Also make sure your Stripe account has at least one payment method enabled.

---

## License

ISC
