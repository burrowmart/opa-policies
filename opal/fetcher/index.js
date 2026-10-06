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
 *
 * Failure handling: a failed push is parked in a TTL retry queue and comes
 * back RETRY_DELAY_MS later (dead-lettered straight into our own queue via
 * the default exchange), up to MAX_RETRIES times, then lands in the DLQ for
 * manual inspection. A dead broker connection exits the process — the
 * Deployment's restartPolicy (Always) is the reconnect loop; staying alive
 * with a closed connection would just be a zombie consuming nothing.
 */

const amqp = require('amqplib');

const RABBITMQ_URL = process.env.RABBITMQ_URL || 'amqp://guest:guest@localhost:5672';
const OPAL_SERVER_URL = process.env.OPAL_SERVER_URL || 'http://localhost:7002';
const OPAL_AUTH_MASTER_TOKEN = process.env.OPAL_AUTH_MASTER_TOKEN;

const EXCHANGE = 'domain.events';
const ROUTING_KEY = 'user.attributes-changed';
const QUEUE = 'opal.user-attributes-changed';
const RETRY_QUEUE = `${QUEUE}.retry`;
const DLX = 'opal.user-attributes-changed.dlx';
const MAX_RETRIES = 5;
// Queue-level x-message-ttl is immutable after declaration: changing this
// value requires deleting the retry queue first (assertQueue would fail with
// PRECONDITION_FAILED against the old value).
const RETRY_DELAY_MS = Number(process.env.RETRY_DELAY_MS || 15_000);

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
    // Park the message in the TTL retry queue instead of republishing to the
    // shared topic exchange: sendToQueue targets only our own retry queue
    // (republishing to domain.events would re-deliver the event to every
    // other subscriber of this routing key too), and the TTL gives OPAL
    // RETRY_DELAY_MS to recover instead of burning all retries in seconds.
    ch.ack(msg);
    ch.sendToQueue(RETRY_QUEUE, msg.content, {
      ...msg.properties,
      headers: { ...msg.properties.headers, 'x-retry-count': retryCount + 1 },
    });
  }
}

function exitOnClose(what) {
  return () => {
    // No in-process reconnect: a Deployment restart (restartPolicy: Always,
    // with backoff) is simpler and equivalent. Staying alive here would be a
    // zombie — the consumer is gone, but nothing would notice.
    console.error(`opal-fetcher: AMQP ${what} closed — exiting for the Deployment to restart the pod`);
    process.exit(1);
  };
}

async function main() {
  const conn = await amqp.connect(RABBITMQ_URL);
  // amqplib rethrows unhandled connection-level errors as an uncaught
  // exception that kills the process — log here; the paired 'close' event
  // (which always follows) does the exit.
  conn.on('error', (err) => console.error('opal-fetcher: AMQP connection error', err));
  conn.on('close', exitOnClose('connection'));
  const ch = await conn.createChannel();
  ch.on('error', (err) => console.error('opal-fetcher: AMQP channel error', err));
  ch.on('close', exitOnClose('channel'));

  await ch.assertExchange(EXCHANGE, 'topic', { durable: true });
  await ch.assertExchange(DLX, 'direct', { durable: true });
  await ch.assertQueue(QUEUE, { durable: true, arguments: { 'x-dead-letter-exchange': DLX } });
  await ch.bindQueue(QUEUE, EXCHANGE, ROUTING_KEY);
  // Retry parking lot: expired messages dead-letter through the default
  // exchange ('') whose routing key IS the destination queue name, landing
  // back in our main queue after RETRY_DELAY_MS.
  await ch.assertQueue(RETRY_QUEUE, {
    durable: true,
    arguments: {
      'x-message-ttl': RETRY_DELAY_MS,
      'x-dead-letter-exchange': '',
      'x-dead-letter-routing-key': QUEUE,
    },
  });
  await ch.assertQueue(`${QUEUE}.dlq`, { durable: true });
  // Two bindings, because the routing key at nack time depends on how the
  // message last arrived: straight off the topic exchange it still carries
  // ROUTING_KEY, but a retry-queue return rewrote it to QUEUE (that's what
  // x-dead-letter-routing-key does) — and a message that exhausted
  // MAX_RETRIES has always taken the retry path. Without the second binding
  // the final nack would dead-letter with a key the DLX has no binding for,
  // and RabbitMQ would silently drop it.
  await ch.bindQueue(`${QUEUE}.dlq`, DLX, ROUTING_KEY);
  await ch.bindQueue(`${QUEUE}.dlq`, DLX, QUEUE);

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
