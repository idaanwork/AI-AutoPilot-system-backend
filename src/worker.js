/*
src/worker.js
BullMQ worker that processes automation.run jobs
- includes backoff/retries and logging
*/
import { Worker, Queue, QueueScheduler } from 'bullmq';
import IORedis from 'ioredis';
import { PrismaClient } from '@prisma/client';
import axios from 'axios';

const prisma = new PrismaClient();
const redisUrl = process.env.REDIS_URL || 'redis://localhost:6379';
const connection = new IORedis(redisUrl);

const queueName = 'automation-run';
new QueueScheduler(queueName, { connection });

const worker = new Worker(queueName, async job => {
  const { runId, context } = job.data;
  console.log('Processing run', runId);

  const run = await prisma.automationRun.findUnique({ where: { id: runId }, include: { automation: true }});
  if (!run) throw new Error('Run not found: ' + runId);

  try {
    await prisma.automationRun.update({ where: { id: runId }, data: { status: 'running', attempts: { increment: 1 } }});

    const automation = run.automation;
    // Build prompt with template
    const prompt = `Generate a short, helpful WhatsApp message. Template: ${JSON.stringify(automation.config || {})} Context: ${JSON.stringify(context || {})}`;

    const message = await callOpenAI(prompt);

    const phone = context?.lead?.phone || automation.config?.testPhone;
    if (!phone) {
      await prisma.automationRun.update({ where: { id: runId }, data: { status: 'failed', logs: { error: 'no phone in context' } }});
      return;
    }

    const sendRes = await sendWhatsAppMessage(phone, message, automation.clientId);

    await prisma.automationRun.update({ where: { id: runId }, data: { status: 'done', logs: { sendRes } }});
    console.log('Run done', runId);
  } catch (err) {
    console.error('Worker error', err);
    await prisma.automationRun.update({ where: { id: runId }, data: { status: 'failed', logs: { error: err.message } }});
    throw err;
  }
}, {
  connection,
  lockDuration: 300000, // 5 minutes
  concurrency: 5
});

worker.on('completed', job => console.log('Job completed', job.id));
worker.on('failed', (job, err) => console.error('Job failed', job?.id, err?.message));
console.log('Worker started — listening for jobs');

// ---- Helper functions ----
async function callOpenAI(prompt) {
  const apiKey = process.env.OPENAI_KEY;
  if (!apiKey) {
    return `OPENAI_KEY missing; prompt: ${prompt.slice(0,120)}`;
  }

  try {
    const res = await axios.post('https://api.openai.com/v1/chat/completions', {
      model: 'gpt-4o-mini',
      messages: [{ role: 'system', content: 'You are a succinct assistant.' }, { role: 'user', content: prompt }],
      max_tokens: 200
    }, {
      headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' }
    });
    const text = res.data?.choices?.[0]?.message?.content || JSON.stringify(res.data).slice(0,200);
    return text;
  } catch (err) {
    console.error('OpenAI error', err?.response?.data || err.message);
    return `OpenAI error: ${err.message}`;
  }
}

async function sendWhatsAppMessage(phone, text, clientId) {
  const token = process.env.WHATSAPP_TOKEN;
  if (!token) {
    console.log('[WhatsApp] WHATSAPP_TOKEN missing — logging message instead');
    return { logged: true, phone, text: text.slice(0,140) };
  }

  // Retrieve client's whatsappPhoneId for phone-number-id
  const client = await prisma.client.findUnique({ where: { id: clientId }});
  const phoneId = client?.whatsappPhoneId || process.env.WHATSAPP_PHONE_ID;
  if (!phoneId) {
    console.log('[WhatsApp] No whatsapp phone id configured for client', clientId);
    return { logged: true, phone, text: text.slice(0,140) };
  }

  const url = `https://graph.facebook.com/v17.0/${phoneId}/messages`;

  try {
    const res = await axios.post(url, {
      messaging_product: 'whatsapp',
      to: phone,
      text: { body: text }
    }, {
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }
    });
    return { ok: true, data: res.data };
  } catch (err) {
    console.error('WhatsApp send error', err?.response?.data || err.message);
    return { ok: false, error: err?.response?.data || err.message };
  }
}
