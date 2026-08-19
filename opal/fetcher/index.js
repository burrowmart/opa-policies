'use strict';

/**
 * Bridges user-service's `user.attributes-changed` outbox event (RabbitMQ)
 * into a live OPAL server data update. This is step 3 of the attribute flow
 * documented in opa-policies/README.md: outbox -> RabbitMQ -> [this process]
 * -> OPAL server -> OPAL client (sidecar on each OPA DaemonSet pod) -> OPA.
 *
 * Pushes data inline (url: "") rather than handing OPAL clients a URL to
 * fetch — this is OPAL's own documented pattern for a data provider that
 * already has the payload in hand (see the "Trigger Data Updates" tutorial),
 * so it avoids a redundant HTTP round trip back to user-service per event.
 */

const amqp = require('amqplib');

const RABBITMQ_URL = process.env.RABBITMQ_URL || 'amqp://guest:guest@localhost:5672';
const OPAL_SERVER_URL = process.env.OPAL_SERVER_URL || 'http://localhost:7002';
const OPAL_AUTH_MASTER_TOKEN = process.env.OPAL_AUTH_MASTER_TOKEN;

const EXCHANGE = 'domain.events';
const ROUTING_KEY = 'user.attributes-changed';
const QUEUE = 'opal.user-attributes-changed';
const DLX = 'opal.user-attributes-changed.dlx';
const MAX_RETRIES = 5;

if (!OPAL_AUTH_MASTER_TOKEN) {
  console.error('opal-fetcher: OPAL_AUTH_MASTER_TOKEN is required');
  process.exit(1);
}

async function pushToOpal(payload, reason) {
  const res = await fetch(`${OPAL_SERVER_URL}/data/config`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      authorization: `Bearer ${OPAL_AUTH_MASTER_TOKEN}`,
    },
    body: JSON.stringify({
      entries: [
        {
          url: '',
          topics: ['policy_data'],
          dst_path: `/users/${encodeURIComponent(payload.email)}`,
          save_method: 'PUT',
          data: { email: payload.email, roles: payload.roles, attributes: payload.attributes },
        },
      ],
      reason,
    }),
  });
  if (!res.ok) {
    throw new Error(`OPAL server rejected update: ${res.status} ${await res.text()}`);
  }
}

async function handle(ch, msg) {
  const retryCount = Number(msg.properties.headers?.['x-retry-count'] ?? 0);
  let email = '(unparsed)';
  try {
    const envelope = JSON.parse(msg.content.toString());
    const payload = envelope.payload;
    email = payload.email;
    console.log(
      `opal-fetcher: received user.attributes-changed email=${email} messageId=${envelope.messageId} correlationId=${envelope.correlationId} attributes=${JSON.stringify(payload.attributes)}`,
    );
    await pushToOpal(payload, `user-attributes-changed:${email}`);
    console.log(`opal-fetcher: pushed /users/${email} to OPAL server (${OPAL_SERVER_URL}/data/config)`);
    ch.ack(msg);
  } catch (err) {
    console.error(`opal-fetcher: failed to process event for ${email} (retry ${retryCount}):`, err.message);
    if (retryCount >= MAX_RETRIES) {
      console.error(`opal-fetcher: exceeded ${MAX_RETRIES} retries for ${email} — routing to DLQ`);
      ch.nack(msg, false, false);
      return;
    }
    ch.ack(msg);
    ch.publish(EXCHANGE, msg.fields.routingKey, msg.content, {
      ...msg.properties,
      headers: { ...msg.properties.headers, 'x-retry-count': retryCount + 1 },
    });
  }
}

async function main() {
  const conn = await amqp.connect(RABBITMQ_URL);
  // amqplib rethrows unhandled connection-level errors as an uncaught
  // exception that kills the process — log instead so a transient blip
  // doesn't take the fetcher down.
  conn.on('error', (err) => console.error('opal-fetcher: AMQP connection error', err));
  const ch = await conn.createChannel();

  await ch.assertExchange(EXCHANGE, 'topic', { durable: true });
  await ch.assertExchange(DLX, 'direct', { durable: true });
  await ch.assertQueue(QUEUE, { durable: true, arguments: { 'x-dead-letter-exchange': DLX } });
  await ch.bindQueue(QUEUE, EXCHANGE, ROUTING_KEY);
  await ch.assertQueue(`${QUEUE}.dlq`, { durable: true });
  await ch.bindQueue(`${QUEUE}.dlq`, DLX, ROUTING_KEY);

  console.log(`opal-fetcher: bound to ${EXCHANGE}/${ROUTING_KEY}, pushing to ${OPAL_SERVER_URL}/data/config`);

  ch.consume(
    QUEUE,
    (msg) => {
      if (!msg) return;
      void handle(ch, msg);
    },
    { noAck: false },
  );
}

main().catch((err) => {
  console.error('opal-fetcher: fatal startup error', err);
  process.exit(1);
});
