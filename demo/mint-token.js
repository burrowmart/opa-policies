#!/usr/bin/env node
'use strict';

/**
 * Mints an RS256 JWT signed by the demo keypair (see gen-keys.js), standing
 * in for what Cloudflare's OAuth worker would have already validated and
 * injected by the time a request reaches the cluster (ARCHITECTURE.md
 * "Auth & Authz"). envoy.rego verifies this signature against bundle/jwks.json
 * and reads `email` + `cognito:groups` from it — nothing else in the claims
 * is trusted; attributes always come from data.users (OPAL), never the token.
 *
 * Usage: node mint-token.js <email> <role1,role2,...> [ttl-seconds]
 *
 * ttl-seconds defaults to 3600. The long-TTL case is the demo deploy script
 * (platform-infra/demo/opa-stack.sh) minting the svc-opal-fetcher token that
 * gets baked into the opal-server-secrets Secret — a 1h token there would
 * silently break OPAL's periodic re-sync an hour after deploy. Demo-only:
 * in production this identity gets a real Cognito client-credentials token.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const KID = 'archtenet-demo-2026';
const ISSUER = 'archtenet-demo';
const AUDIENCE = 'archtenet-demo-clients';
const PRIVATE_KEY_PATH = path.join(__dirname, '.keys', 'private-key.pem');

const [, , email, rolesArg, ttlArg] = process.argv;
if (!email || !rolesArg) {
  console.error('Usage: node mint-token.js <email> <role1,role2,...> [ttl-seconds]');
  process.exit(1);
}
const ttl = ttlArg ? Number(ttlArg) : 3600;
if (!Number.isFinite(ttl) || ttl <= 0) {
  console.error(`ttl-seconds must be a positive number, got: ${ttlArg}`);
  process.exit(1);
}

if (!fs.existsSync(PRIVATE_KEY_PATH)) {
  console.error('No private key found — run `node gen-keys.js` first.');
  process.exit(1);
}

const privateKey = fs.readFileSync(PRIVATE_KEY_PATH, 'utf8');
const roles = rolesArg.split(',').filter(Boolean);

function b64url(value) {
  return Buffer.from(value).toString('base64url');
}

const header = { alg: 'RS256', typ: 'JWT', kid: KID };
const now = Math.floor(Date.now() / 1000);
const payload = {
  email,
  'cognito:groups': roles,
  iss: ISSUER,
  aud: AUDIENCE,
  iat: now,
  exp: now + ttl,
};

const signingInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
const signature = crypto.sign('RSA-SHA256', Buffer.from(signingInput), privateKey);

console.log(`${signingInput}.${signature.toString('base64url')}`);
