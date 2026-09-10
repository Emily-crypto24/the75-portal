/**
 * Server-side vendor PIN verification.
 *
 * Vendors have no account -- they authenticate with a link (slotId) + their
 * company name + a 4-digit PIN. This function is the ONLY place the PIN is
 * ever checked. It reads the real PIN from `vendorSlotSecrets/{slotId}` (a
 * collection normal clients can never read -- see firestore.rules), and on a
 * correct match mints a custom auth token scoped to that one slot via a
 * `vendorSlotId` claim. Firestore rules then trust that claim to scope the
 * vendor's subsequent reads/writes to `vendorSlots/{slotId}` only.
 *
 * The company name is NOT a security secret the way the PIN is -- it's an
 * identity-confirmation field, matched case-insensitively (trimmed,
 * lowercased both sides) against vendorSlots.vendorName, the same UX pattern
 * as the guest portal's name field. It's checked server-side (not
 * client-side) purely because the client has no read access to vendorName
 * before the PIN succeeds. A name mismatch does NOT count against the PIN's
 * own attempt counter/lockout below -- that stays PIN-only, unchanged. If
 * vendorName isn't set yet (nobody's claimed this slot's company name),
 * whatever the vendor types on their first successful PIN entry is saved as
 * vendorName, so it matches on every future visit.
 *
 * Brute-force protection, two layers:
 *  1. Per-slot: 5 wrong PIN attempts locks that slot for 15 minutes. The
 *     attempt counter and lock live in vendorSlotSecrets, updated inside a
 *     transaction so concurrent guesses can't race past the limit.
 *  2. Per-IP: a coarse cap on total calls to this function (any slotId,
 *     found or not) from one source IP in a rolling window -- see
 *     checkIpRateLimit. Layer 1 alone doesn't stop someone from trying many
 *     DIFFERENT slotIds (e.g. guessing common couple-name combinations)
 *     without ever tripping any single slot's lockout; layer 2 catches that.
 *     It's a coarse mitigation, not a complete one -- a determined attacker
 *     rotating IPs isn't stopped by this alone (see the security review
 *     notes on what still needs real infrastructure, e.g. Cloud Armor, to
 *     fully close).
 */

const { onCall, HttpsError } = require("firebase-functions/v2/https");
const { setGlobalOptions } = require("firebase-functions/v2");
const logger = require("firebase-functions/logger");
const admin = require("firebase-admin");

admin.initializeApp();
const db = admin.firestore();

setGlobalOptions({ maxInstances: 10 });

const MAX_ATTEMPTS = 5;
const LOCK_MINUTES = 15;
const SLOT_ID_RE = /^[a-zA-Z0-9_-]{1,200}$/;
const PIN_RE = /^\d{4}$/;
const COMPANY_NAME_MAX_LEN = 200;

function normalizeCompanyName(s) {
  return String(s || "").trim().toLowerCase();
}

const IP_RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000; // 15 minutes
const IP_RATE_LIMIT_MAX = 20; // total calls per IP per window, across every slotId

// Coarse per-IP throttle so guessing many different slotIds can't dodge the
// per-slot lockout above (a "not found" slotId never touches vendorSlotSecrets,
// so without this, slotId guessing itself has no rate limit at all). Fails
// OPEN (returns true) if the IP is unavailable or Firestore errors, rather
// than locking out all vendors because of an infrastructure hiccup -- a
// deliberate availability-over-strictness tradeoff for a wedding-day tool.
async function checkIpRateLimit(ip) {
  if (!ip) return true;
  const docId = String(ip).replace(/[^a-zA-Z0-9]/g, "_").slice(0, 200) || "unknown";
  const ref = db.collection("pinAttemptLog").doc(docId);
  const now = Date.now();
  try {
    return await db.runTransaction(async (tx) => {
      const snap = await tx.get(ref);
      const data = snap.exists ? snap.data() : null;
      if (!data || now - data.windowStart > IP_RATE_LIMIT_WINDOW_MS) {
        tx.set(ref, { windowStart: now, count: 1 });
        return true;
      }
      if (data.count >= IP_RATE_LIMIT_MAX) return false;
      tx.update(ref, { count: admin.firestore.FieldValue.increment(1) });
      return true;
    });
  } catch (e) {
    return true;
  }
}

exports.verifyVendorPin = onCall({ enforceAppCheck: true }, async (request) => {
  // slotId is declared outside the try block (not const/let inside) so the
  // catch-all below can still tag its log line with which slot was being
  // verified, even if the failure happens before slotId is assigned.
  let slotId = "(unparsed)";
  try {
    slotId = String((request.data && request.data.slotId) || "").trim();
    const pin = String((request.data && request.data.pin) || "").trim();
    const companyNameRaw = String((request.data && request.data.companyName) || "").trim().slice(0, COMPANY_NAME_MAX_LEN);

    if (!SLOT_ID_RE.test(slotId)) {
      throw new HttpsError("invalid-argument", "Invalid access link.");
    }
    if (!companyNameRaw) {
      throw new HttpsError("invalid-argument", "Enter your company name.");
    }
    if (!PIN_RE.test(pin)) {
      throw new HttpsError("invalid-argument", "PIN must be 4 digits.");
    }

    const ip = request.rawRequest && request.rawRequest.ip;
    const withinIpLimit = await checkIpRateLimit(ip);
    if (!withinIpLimit) {
      throw new HttpsError("resource-exhausted", "Too many attempts from this network. Please try again later.");
    }

    const secretsRef = db.collection("vendorSlotSecrets").doc(slotId);
    const slotRef = db.collection("vendorSlots").doc(slotId);

    // The transaction only ever returns a status -- it never throws -- so that
    // attempt-count writes always commit, even on a wrong guess. The actual
    // HttpsError is thrown afterward, based on that status.
    const outcome = await db.runTransaction(async (tx) => {
      const [secretsSnap, slotSnap] = await Promise.all([tx.get(secretsRef), tx.get(slotRef)]);

      if (!secretsSnap.exists || !slotSnap.exists) {
        return { status: "not_found" };
      }

      const secrets = secretsSnap.data();
      const now = admin.firestore.Timestamp.now();

      if (secrets.lockedUntil && secrets.lockedUntil.toMillis() > now.toMillis()) {
        const minutesLeft = Math.ceil((secrets.lockedUntil.toMillis() - now.toMillis()) / 60000);
        return { status: "locked", minutesLeft };
      }

      if (secrets.accessPin !== pin) {
        const failedAttempts = (secrets.failedAttempts || 0) + 1;
        if (failedAttempts >= MAX_ATTEMPTS) {
          tx.update(secretsRef, {
            failedAttempts: 0,
            lockedUntil: admin.firestore.Timestamp.fromMillis(now.toMillis() + LOCK_MINUTES * 60000),
          });
          return { status: "locked", minutesLeft: LOCK_MINUTES };
        }
        tx.update(secretsRef, { failedAttempts });
        return { status: "wrong" };
      }

      tx.update(secretsRef, { failedAttempts: 0, lockedUntil: admin.firestore.FieldValue.delete() });
      return { status: "ok", slotData: slotSnap.data() };
    });

    logger.info("verifyVendorPin: transaction outcome", { slotId, status: outcome.status });

    // "not_found" and "wrong" throw the IDENTICAL error (same code, same
    // message) -- SECURITY FIX: they previously used different HttpsError
    // codes ("not-found" vs "permission-denied") and different message text,
    // even though the comment already claimed they were the same. That let a
    // caller distinguish "this slotId doesn't exist" from "this slotId exists
    // but the PIN was wrong" by inspecting the error, which is exactly the
    // oracle a slotId-guessing attacker wants (and "not_found" guesses don't
    // count against the per-slot lockout at all, since there's no doc to
    // write a counter to -- so this was a free, unthrottled way to enumerate
    // real couples/events before the IP rate limit above was added).
    if (outcome.status === "not_found" || outcome.status === "wrong") {
      throw new HttpsError("permission-denied", "Incorrect PIN.");
    }
    if (outcome.status === "locked") {
      const unit = outcome.minutesLeft === 1 ? "minute" : "minutes";
      throw new HttpsError(
        "resource-exhausted",
        `Too many incorrect attempts. Try again in ${outcome.minutesLeft} ${unit}.`
      );
    }

    // PIN was correct. Company name is checked here, not folded into the
    // transaction above -- a name mismatch/typo shouldn't burn any of the
    // PIN's 5-attempt budget, since the name was never the actual secret.
    // slotData.vendorName can in principle be any type a client or admin
    // ever wrote (Firestore doesn't enforce a schema) -- coerce with
    // String(...) rather than assuming it's already a string, so a stray
    // non-string value here can't throw and turn into an opaque "internal".
    const storedName = String(outcome.slotData.vendorName || "").trim();
    if (storedName) {
      if (normalizeCompanyName(storedName) !== normalizeCompanyName(companyNameRaw)) {
        throw new HttpsError("permission-denied", "That company name doesn't match our records for this link. Please double check with your couple.");
      }
    } else {
      // Nobody's claimed a company name for this slot yet -- whatever this
      // vendor typed becomes the name of record, so it matches on future visits.
      try {
        await slotRef.update({ vendorName: companyNameRaw });
      } catch (e) {
        // Non-fatal: worst case the name stays unclaimed and every future
        // visit accepts any company name until someone sets it via the
        // Logistics form instead. Don't block access over this.
        logger.warn("verifyVendorPin: non-fatal vendorName claim failed", { slotId, message: e && e.message });
      }
    }

    const uid = `vendor_${slotId}`;
    const token = await admin.auth().createCustomToken(uid, { vendorSlotId: slotId });

    logger.info("verifyVendorPin: success", { slotId });

    return {
      token,
      category: outcome.slotData.category || null,
      otherLabel: outcome.slotData.otherLabel || null,
      coupleSlug: outcome.slotData.coupleSlug || null,
    };
  } catch (err) {
    // HttpsErrors above are expected, user-facing outcomes (wrong PIN,
    // locked out, name mismatch, bad input) -- pass them through unchanged.
    // Anything else is a genuine bug reaching here uncaught, which the
    // client only ever sees as the generic, stack-free "internal" error.
    // Logging it explicitly (with slotId + message + stack, never the PIN
    // itself) means a real failure like this is actually diagnosable from
    // Cloud Functions logs instead of being a dead end.
    if (err instanceof HttpsError) throw err;
    logger.error("verifyVendorPin: uncaught error", { slotId, message: err && err.message, stack: err && err.stack });
    throw new HttpsError("internal", "Something went wrong verifying your PIN. Please try again in a moment.");
  }
});
