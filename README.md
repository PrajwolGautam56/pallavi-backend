# Pallavi Backend

Express and Node.js API for the Pallabi Savings & Credit Cooperative website.

## Features

- MongoDB content storage
- Secure admin and editor accounts
- JWT authentication with HTTP-only cookies
- Cloudinary image and PDF uploads
- Dynamic website content API

## Local setup

1. Install Node.js 20 or newer.
2. Run `npm install`.
3. Copy `.env.example` to `.env` and fill in private values.
4. Run `npm run dev`.

Set `CLIENT_ORIGIN` to the frontend URLs allowed to call the API. Never commit `.env`.
