/**
 * Server-side vendor PIN verification.
 *
 * Vendors have no account -- they authenticate with a link (slotId) + a 4-digit
 * PIN. This function is the ONLY place the PIN is ever checked. It reads the
 * real PIN from `vendorSlotSecrets/{slotId}` (a collection normal clients can
 * never read -- see firestore.rules), and on a correct match mints a custom
 * auth token scoped to that one slot via a `vendorSlotId` claim. Firestore
 * rules then trust that claim to scope the vendor's subsequent reads/writes
 * to `vendorSlots/{slotId}` only.
 *
 * Brute-force protection: 5 wrong attempts locks the slot for 15 minutes.
 * The attempt counter and lock live in vendorSlotSecrets, updated inside a
 * transaction so concurrent guesses can't race past the limit.
 */

const { onCall, HttpsError } = require("firebase-functions/v2/https");
const { setGlobalOptions } = require("firebase-functions/v2");
const admin = require("firebase-admin");

admin.initializeApp();
const db = admin.firestore();

setGlobalOptions({ maxInstances: 10 });

const MAX_ATTEMPTS = 5;
const LOCK_MINUTES = 15;
const SLOT_ID_RE = /^[a-zA-Z0-9_-]{1,200}$/;
const PIN_RE = /^\d{4}$/;

exports.verifyVendorPin = onCall({ enforceAppCheck: true }, async (request) => {
  const slotId = String((request.data && request.data.slotId) || "").trim();
  const pin = String((request.data && request.data.pin) || "").trim();

  if (!SLOT_ID_RE.test(slotId)) {
    throw new HttpsError("invalid-argument", "Invalid access link.");
  }
  if (!PIN_RE.test(pin)) {
    throw new HttpsError("invalid-argument", "PIN must be 4 digits.");
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

  if (outcome.status === "not_found") {
    // Deliberately the same error shape as a wrong PIN -- don't reveal
    // whether a link itself is valid to someone probing slot ids.
    throw new HttpsError("not-found", "Link or PIN not recognized.");
  }
  if (outcome.status === "locked") {
    const unit = outcome.minutesLeft === 1 ? "minute" : "minutes";
    throw new HttpsError(
      "resource-exhausted",
      `Too many incorrect attempts. Try again in ${outcome.minutesLeft} ${unit}.`
    );
  }
  if (outcome.status === "wrong") {
    throw new HttpsError("permission-denied", "Incorrect PIN.");
  }

  const uid = `vendor_${slotId}`;
  const token = await admin.auth().createCustomToken(uid, { vendorSlotId: slotId });

  return {
    token,
    category: outcome.slotData.category || null,
    otherLabel: outcome.slotData.otherLabel || null,
    coupleSlug: outcome.slotData.coupleSlug || null,
  };
});
