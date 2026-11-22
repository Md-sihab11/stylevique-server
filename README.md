# Stylevique Server

Stylevique Server is the REST API for **Stylevique**, a full-stack salon appointment booking platform. It manages salon services, appointment bookings, customers, reviews, dashboard statistics, image uploads, and Stripe payments.

The backend is built with Express.js and MongoDB Atlas using the native MongoDB driver. Authentication is managed by Better Auth in the Next.js frontend, while the Express API verifies JWTs to protect private endpoints.

---

## Important Features

- Better Auth JWT verification using `jose` and JWKS.
- Role-based authorization for customers and administrators.
- Service management with search, filtering, sorting, and pagination.
- Appointment booking, cancellation, and administrator approval.
- Duplicate appointment prevention using MongoDB indexes.
- Customer profile management and administrator customer management.
- Customer and administrator dashboard statistics.
- Stripe Checkout integration with verified webhooks.
- Payment and transaction history.
- Customer reviews with administrator approval.
- ImgBB image uploads using Multer.
- API security with Helmet, CORS, and rate limiting.
- Secure administrator promotion through a CLI command.

---

## Technology Stack

| Layer | Technology |
| --- | --- |
| Runtime | Node.js |
| Backend Framework | Express.js 5 |
| Language | JavaScript |
| Database | MongoDB Atlas |
| MongoDB Driver | Native MongoDB Driver |
| Authentication | Better Auth JWT |
| JWT Verification | jose |
| Payments | Stripe Checkout and Webhooks |
| Image Hosting | ImgBB |
| File Upload | Multer |
| Security | Helmet, CORS, express-rate-limit |
| Configuration | dotenv |
| Development | Nodemon |

---

## Installation Instructions

**Prerequisites:**
- Node.js 20 or newer
- npm
- MongoDB Atlas account
- Stripe account
- ImgBB account

Clone the repository:

```bash
git clone https://github.com/Md-sihab11/stylevique-server.git
```

Navigate to the project directory:

```bash
cd stylevique-server
```

Install dependencies:

```bash
npm install
```

---

## How to Run the Project Locally

1. Create a `.env` file from `.env.example`.

**Windows PowerShell:**

```powershell
Copy-Item .env.example .env
```

**macOS / Linux:**

```bash
cp .env.example .env
```

2. Configure the required environment variables in `.env`.

3. Start the Stylevique Next.js frontend with Better Auth configured.

4. Start the Express backend:

```bash
npm run dev
```

5. Open the API health endpoint:

```text
http://localhost:5000/api/health
```

For production:

```bash
npm start
```

---

## Required Environment Variables

```env
PORT
NODE_ENV
MONGODB_URI
DB_NAME
CLIENT_URL
AUTH_USER_COLLECTION
BETTER_AUTH_JWKS_URL
BETTER_AUTH_ISSUER
BETTER_AUTH_AUDIENCE
STRIPE_SECRET_KEY
STRIPE_WEBHOOK_SECRET
STRIPE_CURRENCY
IMGBB_API_KEY
ADMIN_EMAIL
MAX_UPLOAD_SIZE_MB
```

---

## Live Website Link

- **Frontend:** https://stylevique.vercel.app
- **Backend API:** https://stylevique-server.onrender.com

---

## Client and Server Repository Links

| Repository | GitHub Link |
| --- | --- |
| Client | https://github.com/Md-sihab11/stylevique-clientSide |
| Server | https://github.com/Md-sihab11/stylevique-server |
