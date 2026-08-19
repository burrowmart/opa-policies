#!/usr/bin/env node
'use strict';

/**
 * Generates the demo-only RSA keypair used by the OPA end-to-end demo.
 * The public half becomes bundle/jwks.json (committed — real IdP-verified
 * material never lives here in production, see envoy.rego's header comment).
 * The private half is written outside the bundle and gitignored; mint-token.js
 * reads it to sign demo JWTs standing in for what Cognito would issue.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const KID = 'archtenet-demo-2026';
// Must be bundle/jwks/data.json, not bundle/jwks.json: OPA's directory/bundle
// loader only auto-merges files literally named data.json into the data tree
// at their directory path (bundle/jwks/data.json -> data.jwks). An arbitrary
// filename like jwks.json is silently ignored — found by testing, not docs.
const BUNDLE_DIR = path.join(__dirname, '..', 'bundle', 'jwks');
const KEYS_DIR = path.join(__dirname, '.keys');

const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
});

const jwk = publicKey.export({ format: 'jwk' });
jwk.kid = KID;
jwk.alg = 'RS256';
jwk.use = 'sig';

fs.mkdirSync(KEYS_DIR, { recursive: true });
fs.writeFileSync(
  path.join(KEYS_DIR, 'private-key.pem'),
  privateKey.export({ format: 'pem', type: 'pkcs8' }),
  { mode: 0o600 },
);
fs.mkdirSync(BUNDLE_DIR, { recursive: true });
fs.writeFileSync(
  path.join(BUNDLE_DIR, 'data.json'),
  JSON.stringify({ keys: [jwk] }, null, 2) + '\n',
);

console.log(`Wrote public JWK (kid=${KID}) -> bundle/jwks/data.json`);
console.log('Wrote private key -> demo/.keys/private-key.pem (gitignored, demo-only)');
