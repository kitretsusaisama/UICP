/**
 * Live Firebase OTP test script.
 *
 * Tests the FirebaseOtpAdapter against the real Firebase project using:
 *   - Test phone +917676767676 (registered in Firebase console with OTP 123456)
 *
 * Run with:
 *   node scripts/test-firebase-otp.mjs
 */

import { readFileSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ── Load .env manually (no dotenv dependency needed) ─────────────────────────
const envPath = resolve(__dirname, '../.env');
const envContent = readFileSync(envPath, 'utf8');
for (const line of envContent.split('\n')) {
  const trimmed = line.trim();
  if (!trimmed || trimmed.startsWith('#')) continue;
  const eqIdx = trimmed.indexOf('=');
  if (eqIdx === -1) continue;
  const key = trimmed.slice(0, eqIdx).trim();
  const value = trimmed.slice(eqIdx + 1).trim();
  if (!process.env[key]) process.env[key] = value;
}

const PROJECT_ID   = process.env.FIREBASE_PROJECT_ID;
const CLIENT_EMAIL = process.env.FIREBASE_CLIENT_EMAIL;
const PRIVATE_KEY  = process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n');

// ── Validate config ───────────────────────────────────────────────────────────
if (!PROJECT_ID || !CLIENT_EMAIL || !PRIVATE_KEY) {
  console.error('❌  Missing Firebase env vars. Check .env for FIREBASE_PROJECT_ID, FIREBASE_CLIENT_EMAIL, FIREBASE_PRIVATE_KEY.');
  process.exit(1);
}

console.log(`\n🔥  Firebase project : ${PROJECT_ID}`);
console.log(`📧  Service account  : ${CLIENT_EMAIL}`);
console.log(`🔑  Private key      : ${PRIVATE_KEY.slice(0, 40)}...\n`);

// ── Init Firebase Admin ───────────────────────────────────────────────────────
let admin;
try {
  const mod = await import('firebase-admin');
  admin = mod.default ?? mod;
} catch {
  console.error('❌  firebase-admin not installed. Run: npm install firebase-admin');
  process.exit(1);
}

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert({ projectId: PROJECT_ID, clientEmail: CLIENT_EMAIL, privateKey: PRIVATE_KEY }),
  });
  console.log('✅  Firebase Admin SDK initialised\n');
}

// ── Test 1: FCM topic message to test phone ───────────────────────────────────
const TEST_PHONE = '+917676767676';
const TEST_CODE  = '123456';
const topic      = `otp-${TEST_PHONE.replace(/\+/g, '')}`;

console.log(`📱  Test 1 — FCM topic message`);
console.log(`    Phone  : ${TEST_PHONE}`);
console.log(`    Code   : ${TEST_CODE}`);
console.log(`    Topic  : ${topic}`);

try {
  const messageId = await admin.messaging().send({
    topic,
    data: {
      code: TEST_CODE,
      purpose: 'IDENTITY_VERIFICATION',
      tenantName: 'UICP Test',
      message: `Your UICP Test verification code is: ${TEST_CODE}. Valid for 5 minutes.`,
    },
  });
  console.log(`✅  FCM message sent — message ID: ${messageId}\n`);
} catch (err) {
  console.error(`❌  FCM send failed: ${err.message}`);
  if (err.code) console.error(`    Error code: ${err.code}`);
  console.log('');
}

// ── Test 2: Verify Firebase Auth is reachable (list users — max 1) ────────────
console.log(`👤  Test 2 — Firebase Auth connectivity`);
try {
  const result = await admin.auth().listUsers(1);
  console.log(`✅  Firebase Auth reachable — ${result.users.length} user(s) returned in sample\n`);
} catch (err) {
  console.error(`❌  Firebase Auth check failed: ${err.message}\n`);
}

// ── Test 3: Verify test phone number is registered in Firebase Auth ───────────
console.log(`🔍  Test 3 — Check test phone number in Firebase Auth`);
try {
  const user = await admin.auth().getUserByPhoneNumber(TEST_PHONE);
  console.log(`✅  Test phone ${TEST_PHONE} found in Firebase Auth`);
  console.log(`    UID      : ${user.uid}`);
  console.log(`    Created  : ${new Date(user.metadata.creationTime).toISOString()}\n`);
} catch (err) {
  if (err.code === 'auth/user-not-found') {
    console.log(`ℹ️   Test phone ${TEST_PHONE} not yet registered in Firebase Auth.`);
    console.log(`    This is fine — FCM topic delivery does not require Auth registration.`);
    console.log(`    To test phone sign-in, add it under Authentication → Test phone numbers.\n`);
  } else {
    console.error(`❌  getUserByPhoneNumber failed: ${err.message}\n`);
  }
}

console.log('🏁  Firebase OTP test complete.');
