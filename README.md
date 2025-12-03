# AutoPilot Backend — Production-ready Quickstart

This version adds:
- Stripe invoice creation + webhook handling
- WhatsApp webhook HMAC validation per-client using webhookSecret and whatsappPhoneId
- Endpoints to rotate webhook secret and set whatsappPhoneId
- Rate limiting, worker concurrency, retries

## Setup (local)
1. Install dependencies:
   ```bash
   npm install
   npx prisma generate
   npx prisma migrate dev --name init
   ```

2. Start with Docker (recommended for local):
   ```bash
   docker-compose up -d
   npm run dev
   ```

## Required ENV
- DATABASE_URL
- REDIS_URL
- OPENAI_KEY
- WHATSAPP_TOKEN
- WHATSAPP_PHONE_ID (optional global fallback)
- STRIPE_SECRET (for billing)
- STRIPE_WEBHOOK_SECRET (for verifying webhooks)
- JWT_SECRET (if you add JWT auth)

## Deploy to Railway
1. Push repo to GitHub and connect to Railway.
2. Add Postgres and Redis plugins.
3. Set environment variables in Railway (see list above).
4. Create two services on Railway:
   - Web: `npm start`
   - Worker: `npm run worker`
5. Run migrations:
   ```bash
   railway run npx prisma migrate deploy
   ```

## Notes
- Ensure you register your webhook URL with WhatsApp (and set client whatsappPhoneId).
- Keep webhook secrets private; rotate regularly.
- For production, use Sentry/Logflare for error monitoring.
