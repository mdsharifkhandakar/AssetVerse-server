# AssetVerse Server

AssetVerse Server is the backend API for the AssetVerse B2B corporate
asset management system. It provides API endpoints for authentication
support, users, companies, assets, employee affiliations, asset
requests, assigned assets, packages, and payments.

## Live API

https://asset-verse-server-jade.vercel.app/

## Purpose

The server handles the application data and backend operations for
AssetVerse, including:

-   User profiles and roles
-   HR company information
-   Company assets
-   Employee affiliations
-   Asset requests
-   Assigned assets
-   Subscription packages
-   Payment records
-   Firebase Admin authentication
-   MongoDB database access
-   HR role verification

## Key Features

### User Management

-   HR and Employee profiles
-   Role-based access
-   Profile retrieval and updates
-   Firebase token verification

### Asset Management

-   Add assets
-   View company assets
-   Update assets
-   Delete assets
-   Returnable and Non-returnable asset types
-   Available quantity tracking

### Request Management

-   Employee asset requests
-   HR approval/rejection
-   Approval date and request status
-   Asset quantity updates
-   Assigned asset creation
-   Employee affiliation flow

### Employee Management

-   Company affiliations
-   Multiple company support
-   Employee list
-   Employee removal workflow

### Package Management

-   Basic, Standard and Premium packages
-   Employee limits
-   Package upgrades
-   Payment records

## Technology

-   Node.js
-   Express.js
-   MongoDB
-   Firebase Admin SDK
-   JSON Web Token (JWT)
-   Stripe
-   CORS
-   dotenv

## Database

The application uses MongoDB with the database:

``` text
asset_db
```

Main collections:

``` text
users
employeeAffiliations
assets
requests
assignedAssets
packages
payments
```

## Environment Variables

Create a `.env` file inside the server project:

``` env
PORT=5000

MONGO_URI=your_mongodb_connection_string

FIREBASE_ADMIN_SDK=your_firebase_admin_service_account_json

JWT_SECRET=your_jwt_secret

STRIPE_SECRET=your_stripe_secret
```

Never commit `.env` or any Firebase service-account private key to
GitHub.

For Vercel, configure the required environment variables in the
project's Environment Variables settings.

## Local Setup

### 1. Clone the repository

``` bash
git clone <your-server-repository-url>
cd AssetVerse-server
```

### 2. Install dependencies

``` bash
npm install
```

### 3. Configure environment variables

Create `.env` and provide the required MongoDB, Firebase Admin, JWT and
Stripe configuration.

### 4. Start the server

``` bash
npm start
```

If the project uses a development script, you can also use:

``` bash
npm run dev
```

The local API normally runs at:

``` text
http://localhost:5000
```

## Production Deployment

The backend is deployed on Vercel.

Production API:

``` text
https://asset-verse-server-jade.vercel.app/
```

The production server allows the deployed frontend origin:

``` text
https://assetverse-client.netlify.app
```

and the local development origin:

``` text
http://localhost:5173
```
## Authentication

Firebase Admin SDK is used on the server to verify Firebase ID tokens.

Protected operations use authentication and HR role verification where
required.

## API Areas

The backend provides API routes for:

``` text
/users
/assets
/requests
/assigned-assets
/employee-affiliation
/packages
/payments
```

The exact endpoint parameters and response structures are maintained in
the server source code.

## Security

-   Secrets are stored in environment variables.
-   Firebase service-account credentials are not hardcoded.
-   MongoDB credentials are not hardcoded.
-   Protected operations use authentication and role checks where
    implemented.
-   CORS is configured for local development and the production
    frontend.

## Assignment

This backend is part of the AssetVerse Corporate Asset Management System
assignment.

The server supports the required HR and Employee asset-management
workflow, including company assets, employee requests, approvals,
affiliations, assigned assets, packages, and payment-related data.

## License

This project is created for educational and portfolio purposes.

