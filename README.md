# Orbiti

## Overview

This repository contains the Orbiti application split into two main parts:

- `obriti-backend/` — FastAPI backend that handles authentication, vulnerability management, integrations, and data services.
- `obriti-frontend/` — React + Vite TypeScript frontend that provides the web user interface.

The backend is built with FastAPI, SQLAlchemy, MySQL, and optionally Elasticsearch. The frontend is built with Vite, React, Tailwind CSS, and shadcn-ui.

## Repository Structure

```text
obriti-backend/
  .env.example
  docker-compose.example.yml
  Dockerfile
  requirements.txt
  src/
    main.py
    api/
    config/
    services/
    models/
    utils/
    migrations/
obriti-frontend/
  package.json
  vite.config.ts
  src/
    App.tsx
    main.tsx
    components/
    pages/
    services/
    utils/
```

## Backend Setup (obriti-backend)

### Prerequisites

- Python 3.10+
- MySQL 8.0+
- Docker and Docker Compose (recommended for full stack)
- Node.js / npm only if you want to build the frontend from the backend environment as well

### Local Development

1. Copy the example environment file:

```bash
cd obriti-backend
cp .env.example .env
```

2. Edit `.env` and configure the required values:

- `DATABASE_URL`
- `SECRET_KEY`
- `SMTP_SERVER`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM_EMAIL`
- `API_ACCESS_TOKEN`
- `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`
- `ADMIN_USERNAME`, `ADMIN_PASSWORD`, `ADMIN_EMAIL`
- `ENVIRONMENT`, `DEBUG`, `LOG_LEVEL`

3. Install dependencies:

```bash
cd obriti-backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

4. Run the backend:

```bash
cd obriti-backend
uvicorn src.main:app --host 0.0.0.0 --port 8000 --reload
```

5. The backend API should be available at:

```text
http://localhost:8000
```

### Docker Compose

Use the provided `docker-compose.example.yml` to launch the backend together with MySQL and Elasticsearch:

1. Create `.env.production` from `.env.example` and fill in credentials.

```bash
cd obriti-backend
cp .env.example .env.production
```

2. Start the stack:

```bash
cd obriti-backend
docker-compose -f docker-compose.example.yml --env-file .env.production up -d
```

3. Stop the stack:

```bash
docker-compose -f docker-compose.example.yml down
```

### Backend Notes

- The backend expects `DATABASE_URL` in SQLAlchemy format, such as:

```text
mysql+pymysql://username:password@host:port/database_name
```

- Microsoft SSO configuration is loaded from the database via integration config entries.
- The backend uses a dynamic `FRONTEND_URL` value for safe redirect handling.

## Frontend Setup (obriti-frontend)

### Prerequisites

- Node.js 18+
- npm

### Install Dependencies

```bash
cd obriti-frontend
npm install
```

### Run Local Frontend

```bash
cd obriti-frontend
npm run dev
```

The frontend development server typically runs at:

```text
http://localhost:5173
```

### Build for Production

```bash
cd obriti-frontend
npm run build
```

### Preview Production Build

```bash
cd obriti-frontend
npm run preview
```

## Environment Variables

### Backend

The backend environment variables are defined in `obriti-backend/.env.example` and include:

- `DATABASE_URL`
- `SECRET_KEY`
- `SMTP_SERVER`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM_EMAIL`
- `NESSUS_API_URL`, `NESSUS_ACCESS_KEY`, `NESSUS_SECRET_KEY`
- `API_ACCESS_TOKEN`
- `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`
- `ADMIN_USERNAME`, `ADMIN_PASSWORD`, `ADMIN_EMAIL`
- `DEBUG`, `ENVIRONMENT`, `LOG_LEVEL`
- `ALLOWED_HOSTS`, `CORS_ORIGINS`
- Optional Elasticsearch credentials

### Frontend

The frontend project does not currently include a public `.env` example. Typical Vite environment patterns are:

- `VITE_API_URL`
- `VITE_SOME_OTHER_KEY`

If your frontend requires a runtime API URL, add it to `obriti-frontend/.env` or `obriti-frontend/.env.development`.

## Running the Full Stack

To run both backend and frontend locally:

1. Start backend (via Docker or direct run).
2. Start frontend with `npm run dev`.
3. Open the frontend URL in your browser.

## Helpful Commands

### Backend

```bash
cd obriti-backend
python3 -m py_compile src/main.py
uvicorn src.main:app --reload
```

### Frontend

```bash
cd obriti-frontend
npm run dev
npm run build
npm run lint
```

## Key Features

- Microsoft Azure SSO login
- Vulnerability and host management APIs
- Exception handling for vulnerability coverage
- Elasticsearch support for search/analytics
- React dashboard UI with charts, filters, and reports

## Notes

- Do not commit secret credentials to git.
- Use separate `.env` files for development and production.
- If using Docker, keep credentials in an `.env.production` file referenced by compose.

## Troubleshooting

- If the backend cannot connect to MySQL, verify `DATABASE_URL` and MySQL credentials.
- If the frontend cannot reach the backend, confirm the API base URL and CORS settings.
- For SSO issues, verify Azure app configuration and redirect URI settings.

---

## License

Add your project license information here.
