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

