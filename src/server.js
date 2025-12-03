/*
src/server.js
Express API server for AutoPilot AI Systems - production-ready additions:
- Stripe billing webhook and invoice creation
- WhatsApp webhook signature validation using per-client webhookSecret
- endpoints to manage client's whatsappPhoneId and webhookSecret
- rate limiting and basic validation
*/
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import bodyParser from 'body-parser';
import crypto from 'crypto';
import { PrismaClient } from '@prisma/client';
import IORedis from 'ioredis';
import { Queue } from 'bullmq';
import rateLimit from 'express-rate-limit';
import Stripe from 'stripe';

const prisma = new PrismaClient();
const app = express();

// Read raw body for webhook routes later; default json parser for others.
app.use((req, res, next) => {
  // expose rawBody on req for signature verification when needed
  let data = '';
  req.setEncoding('utf8');
  req.on('data', chunk => { data += chunk; });
  req.on('end', () => {
    req.rawBody = data;
    next();
  });
});

app.use(helmet());
app.use(cors());
app.use(bodyParser.json({ limit: '1mb' }));
app.use(morgan('tiny'));

// rate limiter
const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 120, // limit each IP to 120 requests per windowMs
});
app.use(limiter);

// Redis & queue for enqueuing jobs
const redisUrl = process.env.REDIS_URL || 'redis://localhost:6379';
const redis = new IORedis(redisUrl);
const jobQueue = new Queue('automation-run', { connection: redis });

// Stripe init (for server-side operations)
const stripeSecret = process.env.STRIPE_SECRET;
const stripeWebhookSecret = process.env.STRIPE_WEBHOOK_SECRET; // for verifying webhooks
const stripe = stripeSecret ? new Stripe(stripeSecret, { apiVersion: '2022-11-15' }) : null;

// ---------- helper functions ----------
function timingSafeCompare(a, b) {
  try {
    const buffA = Buffer.from(a);
    const buffB = Buffer.from(b);
    if (buffA.length !== buffB.length) return false;
    return crypto.timingSafeEqual(buffA, buffB);
  } catch (err) {
    return false;
  }
}

// ---------- middleware: api-key auth ----------
async function apiKeyAuth(req, res, next) {
  const key = req.header('x-api-key') || req.query.apiKey;
  if (!key) return res.status(401).json({ error: 'Missing API key' });
  const client = await prisma.client.findUnique({ where: { apiKey: key } });
  if (!client) return res.status(401).json({ error: 'Invalid API key' });
  req.client = client;
  next();
}

// ---------- health ----------
app.get('/health', (req, res) => res.json({ ok: true, time: new Date() }));

// ---------- admin: create client (protected in prod) ----------
app.post('/clients', async (req, res) => {
  const { name, contact_email, plan } = req.body;
  if (!name || !contact_email) return res.status(400).json({ error: 'name & contact_email required' });

  const client = await prisma.client.create({
    data: {
      name,
      contact_email,
      plan: plan || 'starter',
      apiKey: crypto.randomBytes(24).toString('hex'),
      webhookSecret: crypto.randomBytes(32).toString('hex'),
    }
  });
  res.json(client);
});

// endpoint to update client's whatsappPhoneId and webhookSecret rotation
app.patch('/clients/:id', async (req, res) => {
  const { id } = req.params;
  const { whatsappPhoneId, rotateWebhookSecret } = req.body;
  const update = {};
  if (whatsappPhoneId) update.whatsappPhoneId = whatsappPhoneId;
  if (rotateWebhookSecret) update.webhookSecret = crypto.randomBytes(32).toString('hex');
  const client = await prisma.client.update({ where: { id }, data: update });
  res.json(client);
});

// ---------- create automation (admin) ----------
app.post('/clients/:id/automations', async (req, res) => {
  const { id } = req.params;
  const { name, type, config } = req.body;
  if (!name || !type) return res.status(400).json({ error: 'name & type required' });

  const automation = await prisma.automation.create({
    data: { clientId: id, name, type, config: config || {} }
  });
  res.json(automation);
});

// ---------- trigger automation (client) ----------
app.post('/automations/:id/trigger', apiKeyAuth, async (req, res) => {
  const { id } = req.params;
  const automation = await prisma.automation.findUnique({ where: { id }});
  if (!automation) return res.status(404).json({ error: 'Not found' });

  const run = await prisma.automationRun.create({
    data: { automationId: id, status: 'queued' }
  });

  // Enqueue to worker queue (BullMQ)
  await jobQueue.add('run', { runId: run.id, context: req.body.context || {} });

  res.json({ runId: run.id, status: 'queued' });
});

// ---------- lead webhook (public) ----------
app.post('/webhooks/lead', async (req, res) => {
  const { clientApiKey, lead } = req.body;
  if (!clientApiKey || !lead) return res.status(400).json({ error: 'clientApiKey & lead required' });

  const client = await prisma.client.findUnique({ where: { apiKey: clientApiKey }});
  if (!client) return res.status(400).json({ error: 'Invalid client key' });

  const created = await prisma.lead.create({
    data: { clientId: client.id, name: lead.name, phone: lead.phone, source: lead.source, payload: lead }
  });

  // create runs for active automations
  const automations = await prisma.automation.findMany({ where: { clientId: client.id, status: 'active' }});
  for (const a of automations) {
    const run = await prisma.automationRun.create({ data: { automationId: a.id, status: 'queued' }});
    await jobQueue.add('run', { runId: run.id, context: { lead }});
  }

  res.json({ ok: true, lead: created });
});

// ---------- WhatsApp webhook with HMAC validation (X-Hub-Signature-256) ----------
app.post('/webhooks/whatsapp', async (req, res) => {
  // raw body available at req.rawBody
  const signature = req.header('x-hub-signature-256') || req.header('X-Hub-Signature-256');
  if (!signature) {
    console.warn('Missing WhatsApp signature header');
    return res.sendStatus(400);
  }

  // We need to determine which client this webhook is for.
  // WhatsApp sends "metadata" including phone_number_id. We'll parse JSON and extract it.
  let payload;
  try {
    payload = JSON.parse(req.rawBody || '{}');
  } catch (err) {
    console.warn('Invalid JSON in webhook raw body');
    return res.sendStatus(400);
  }

  // Attempt to read phone_number_id from payload structure commonly:
  // payload.entry[0].changes[0].value.metadata.phone_number_id
  const phoneId = payload?.entry?.[0]?.changes?.[0]?.value?.metadata?.phone_number_id;
  if (!phoneId) {
    console.warn('Could not find phone_number_id in webhook payload');
    return res.sendStatus(400);
  }

  // Find client by whatsappPhoneId
  const client = await prisma.client.findFirst({ where: { whatsappPhoneId: phoneId }});
  if (!client) {
    console.warn('No client mapped to phoneId', phoneId);
    return res.sendStatus(404);
  }

  // Validate HMAC: header = "sha256=..." value
  const expectedSig = signature.split('=')[1];
  const hmac = crypto.createHmac('sha256', client.webhookSecret);
  hmac.update(req.rawBody || '');
  const calculated = hmac.digest('hex');

  if (!timingSafeCompare(calculated, expectedSig)) {
    console.warn('WhatsApp webhook signature mismatch for client', client.id);
    return res.sendStatus(401);
  }

  // At this point webhook is validated and from this client's WhatsApp.
  // Process message: create lead or update conversation
  try {
    // Example: extract sender phone and message text
    const messages = payload?.entry?.[0]?.changes?.[0]?.value?.messages || [];
    for (const msg of messages) {
      const from = msg.from; // sender phone number
      const text = msg.text?.body || msg.button?.text || null;
      // create lead record (if not exists)
      await prisma.lead.create({
        data: {
          clientId: client.id,
          name: null,
          phone: from,
          source: 'whatsapp',
          payload: msg
        }
      });
    }
  } catch (err) {
    console.error('Error processing whatsapp webhook', err);
  }

  res.sendStatus(200);
});

// ---------- Stripe webhook endpoint (verify signature and update invoices) ----------
app.post('/webhooks/stripe', bodyParser.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.header('stripe-signature');
  if (!stripe || !stripeWebhookSecret) {
    console.warn('Stripe not configured; ignoring webhook');
    return res.status(501).send('Stripe not configured');
  }
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, stripeWebhookSecret);
  } catch (err) {
    console.error('Stripe webhook signature verification failed.', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  // Handle the event
  switch (event.type) {
    case 'invoice.payment_succeeded':
      {
        const invoice = event.data.object;
        // find by stripeInvoiceId
        const rec = await prisma.invoice.findFirst({ where: { stripeInvoiceId: invoice.id }});
        if (rec) {
          await prisma.invoice.update({ where: { id: rec.id }, data: { status: 'paid' }});
        }
      }
      break;
    case 'invoice.payment_failed':
      {
        const invoice = event.data.object;
        const rec = await prisma.invoice.findFirst({ where: { stripeInvoiceId: invoice.id }});
        if (rec) {
          await prisma.invoice.update({ where: { id: rec.id }, data: { status: 'failed' }});
        }
      }
      break;
    default:
      console.log(`Unhandled Stripe event type ${event.type}`);
  }

  res.json({ received: true });
});

// ---------- create invoice + Stripe invoice (admin) ----------
app.post('/clients/:id/invoices', async (req, res) => {
  const { id } = req.params;
  const { amount, currency, description } = req.body;
  if (!amount) return res.status(400).json({ error: 'amount required' });

  const client = await prisma.client.findUnique({ where: { id }});
  if (!client) return res.status(404).json({ error: 'client not found' });

  // Create invoice record in DB
  const invoice = await prisma.invoice.create({
    data: {
      clientId: client.id,
      amount,
      currency: currency || 'INR',
      status: 'pending',
      metadata: { description }
    }
  });

  // If Stripe configured, create Stripe invoice
  if (stripe) {
    // ensure stripeCustomerId exists
    let customerId = client.stripeCustomerId;
    if (!customerId) {
      const cust = await stripe.customers.create({ email: client.contact_email, name: client.name });
      customerId = cust.id;
      await prisma.client.update({ where: { id: client.id }, data: { stripeCustomerId: customerId }});
    }

    // Create an invoice item and invoice
    const item = await stripe.invoiceItems.create({
      customer: customerId,
      currency: invoice.currency,
      amount: invoice.amount,
      description: description || `Invoice ${invoice.id}`
    });

    const stripeInvoice = await stripe.invoices.create({
      customer: customerId,
      auto_advance: true // attempt to finalize and pay automatically
    });

    // Save stripe invoice id
    await prisma.invoice.update({ where: { id: invoice.id }, data: { stripeInvoiceId: stripeInvoice.id }});
    return res.json({ invoice, stripeInvoiceId: stripeInvoice.id, checkoutUrl: stripeInvoice.hosted_invoice_url || null });
  }

  res.json({ invoice });
});

// ---------- basic metrics endpoint (admin) ----------
app.get('/metrics/mrr', async (req, res) => {
  const clients = await prisma.client.findMany();
  const mrr = clients.reduce((sum, c) => {
    const planMap = { starter: 6000, growth: 12000, scale: 20000 };
    return sum + (planMap[c.plan] || 6000);
  }, 0);
  res.json({ mrr, clients: clients.length });
});

// ---------- start ----------
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`API listening on ${PORT}`));
