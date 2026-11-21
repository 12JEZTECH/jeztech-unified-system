# JEZTECH Learning v2

CBC + 8-4-4 virtual learning platform starter.

- Learner pathways: CBC PP1, PP2, Grade 1–12; 8-4-4 Standard 1–8 and Form 1–4.
- No registration fee. Learners request registration and an administrator activates the account.
- Learner sign-in uses admission number; staff use email/username.
- Teacher workspace creates class/subject courses, lessons, notes, activities and optional video links.
- Admin manages teacher accounts, tuition amount, access duration, learner expiry/suspension and M-Pesa payment records.
- Safaricom Daraja STK Push with callback-driven access extension after successful payment.
- FastAPI + SQLAlchemy; PostgreSQL supported, SQLite local default.

## Run API

```bash
cd backend
python -m venv .venv
pip install -r requirements.txt
cp .env.example .env
# Configure DATABASE_URL and JWT_SECRET_KEY
uvicorn app.main:app --reload
```

Create the first administrator once, from a trusted terminal:

```bash
python create_first_admin.py
```

API docs: http://127.0.0.1:8000/docs

## M-Pesa (Daraja)

Configure server-only environment variables: MPESA_ENV, MPESA_CONSUMER_KEY, MPESA_CONSUMER_SECRET, MPESA_SHORTCODE, MPESA_PASSKEY, MPESA_CALLBACK_URL, DEFAULT_TUITION_AMOUNT, DEFAULT_ACCESS_DAYS. Use sandbox first. The callback URL must be publicly reachable over HTTPS. Never commit live credentials. Access is extended only after a successful callback whose amount and receipt are present.

## Deploy

Deploy the API directory to Render or another Python host. Use managed PostgreSQL. Configure CORS for the actual frontend origin. The frontend must use the deployed API URL. No credentials are stored in the browser.

## Production hardening still required

Before real learner use: add migrations, rate limiting and password reset, reconcile callbacks against Daraja transaction status, harden callback validation, monitoring/backups, secure media storage and signed URLs, privacy/consent review, and payment failure/duplicate callback tests. This is a functional starter, not a claim of KICD approval or a live deployment.
