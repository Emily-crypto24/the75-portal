// Firestore security-rules tests. See README.md for how to run.
//
//   RULES_FILE=<path>   rules to test (default: ../firestore.rules)
//   RULES_MODE=new      also run the tests that only make sense for the
//                       session-epoch / on-off / pilot rules
//
// Section A runs the live index.html's own write paths (couple saves, signup,
// RSVP submissions, publicCouples, admin saves, settings, linen orders) and
// must pass on BOTH the old and the new rules -- that is the "did we break the
// live site" check. Section B is the existing vendor-portal behaviour, also
// required to pass on both. Section C only runs against the new rules.
const { test, describe, before, after, beforeEach } = require("node:test");
const fs = require("fs");
const path = require("path");
const { initializeTestEnvironment, assertSucceeds, assertFails } = require("@firebase/rules-unit-testing");
const {
  doc, getDoc, setDoc, updateDoc, deleteDoc, getDocs, collection, query, where, arrayUnion,
} = require("firebase/firestore");

require("firebase/firestore").setLogLevel("silent");
const RULES = process.env.RULES_FILE ? path.resolve(process.env.RULES_FILE) : path.join(__dirname, "..", "firestore.rules");
const NEW = process.env.RULES_MODE === "new";
const newOnly = { skip: NEW ? false : "new-rules-only" };

let env;
before(async () => {
  env = await initializeTestEnvironment({ projectId: "demo-the75-rules", firestore: { rules: fs.readFileSync(RULES, "utf8") } });
});
after(async () => { await env.cleanup(); });

// ── principals ──────────────────────────────────────────────────────────
const couple = (uid) => env.authenticatedContext(uid, { email: `${uid}@example.com`, email_verified: true }).firestore();
const admin = () => env.authenticatedContext("adminUid", { email: "jess@theseventyfivevenue.com", email_verified: true }).firestore();
const adminUnverified = () => env.authenticatedContext("adminUid2", { email: "jess@theseventyfivevenue.com", email_verified: false }).firestore();
const guest = () => env.unauthenticatedContext().firestore();
// A vendor session as verifyVendorPin mints it. epoch === undefined models the
// OLD token (only the vendorSlotId claim), which is what existing sessions hold.
const vendor = (slotId, epoch) => env.authenticatedContext("vendor_" + slotId, epoch === undefined ? { vendorSlotId: slotId } : { vendorSlotId: slotId, sessionEpoch: epoch }).firestore();

const SLOTS = {
  "sam-alex_dj": { coupleUid: "coupleA", coupleSlug: "sam-alex", category: "dj" },
  "sam-alex_caterer": { coupleUid: "coupleA", coupleSlug: "sam-alex", category: "caterer" },
  "sam-alex_photo": { coupleUid: "coupleA", coupleSlug: "sam-alex", category: "photo" },
  "sam-alex_florist": { coupleUid: "coupleA", coupleSlug: "sam-alex", category: "florist" },
  "jo-pat_dj": { coupleUid: "coupleB", coupleSlug: "jo-pat", category: "dj" },
};
const E = (slotId) => "E-" + slotId; // the epoch we seed for each slot

const validRsvp = () => ({ coupleSlug: "sam-alex", guestName: "Guest One", rsvpStatus: "yes", plusOneName: "", mealChoice: "chicken", plusOneMealChoice: "", allergies: "", plusOneAllergies: "", submittedAt: new Date().toISOString(), status: "new" });

async function seed({ portal = { enabled: true }, withEpochs = true } = {}) {
  await env.clearFirestore();
  await env.withSecurityRulesDisabled(async (ctx) => {
    const db = ctx.firestore();
    const put = (p, d) => setDoc(doc(db, p), d);
    await put("couples/coupleA", { uid: "coupleA", slug: "sam-alex", status: "active", notes: [], timelineItems: [], guestList: [] });
    await put("couples/coupleB", { uid: "coupleB", slug: "jo-pat", status: "active", notes: [] });
    await put("publicCouples/sam-alex", { names: "Sam & Alex" });
    await put("settings/signupCode", { code: "LETMEIN" });
    await put("settings/resources", { items: [] });
    if (portal) await put("settings/vendorPortal", portal);
    await put("rsvpSubmissions/r1", { ...validRsvp(), coupleSlug: "sam-alex" });
    await put("rsvpSubmissions/r2", { ...validRsvp(), coupleSlug: "jo-pat" });
    await put("linenOrders/coupleA", { x: 1 });
    for (const [id, s] of Object.entries(SLOTS)) {
      await put("vendorSlots/" + id, { ...s, vendorName: "Co " + id, responses: {}, notes: [], barNotes: [], status: "incomplete" });
      await put("vendorSlotSecrets/" + id, { coupleUid: s.coupleUid, accessPin: "1234", failedAttempts: 0, ...(withEpochs ? { sessionEpoch: E(id) } : {}) });
    }
    for (const d of ["venueInfo", "guestRoster", "socialHandles", "hairMakeupRoster", "privateStuff"]) await put("couples/coupleA/vendorSharedData/" + d, { v: 1 });
    await put("couples/coupleB/vendorSharedData/venueInfo", { v: 1 });
    await put("couples/coupleA/sharedTimeline/t1", { notes: [{ text: "first", author: "x" }] });
  });
}
const patchDoc = (p, d) => env.withSecurityRulesDisabled((ctx) => setDoc(doc(ctx.firestore(), p), d, { merge: true }));
const rawDelete = (p) => env.withSecurityRulesDisabled((ctx) => deleteDoc(doc(ctx.firestore(), p)));
const rawSet = (p, d) => env.withSecurityRulesDisabled((ctx) => setDoc(doc(ctx.firestore(), p), d));

// ═════════════════════════════════════════════════════════════════════════
// A. LIVE index.html WRITE/READ PATHS  (must pass on old AND new rules)
// ═════════════════════════════════════════════════════════════════════════
describe("A. live-site paths", () => {
  beforeEach(() => seed());

  test("signup: create own couples/{uid} with the right signup code (index.html:651)", async () => {
    await assertSucceeds(setDoc(doc(couple("newUser"), "couples/newUser"), { uid: "newUser", email: "n@x.com", status: "active", notes: [], slug: "new-slug", signupCode: "LETMEIN" }));
  });
  test("signup: wrong code, or someone else's uid, is refused", async () => {
    await assertFails(setDoc(doc(couple("newUser"), "couples/newUser"), { uid: "newUser", signupCode: "WRONG" }));
    await assertFails(setDoc(doc(couple("newUser"), "couples/other"), { uid: "other", signupCode: "LETMEIN" }));
    await assertFails(setDoc(doc(guest(), "couples/newUser"), { uid: "newUser", signupCode: "LETMEIN" }));
  });

  // Every field family the couple's tools save (index.html lines 1015-3374)
  for (const [label, patch] of [
    ["vendorMeetings", { vendorMeetings: [{ id: "1" }] }], ["financeEntries", { financeEntries: [{ id: "1" }] }],
    ["guestPortalContent", { guestPortalContent: { a: 1 } }], ["placesToStay", { placesToStay: [] }], ["thingsToDo", { thingsToDo: [] }],
    ["registryLinks", { registryLinks: [] }], ["registryItems", { registryItems: [] }], ["itineraryItems", { itineraryItems: [] }],
    ["weddingParty", { weddingParty: [] }], ["faqs", { faqs: [] }], ["guestList", { guestList: [{ id: "g" }] }],
    ["blockedGuestNames", { blockedGuestNames: ["x"] }], ["guestListSettings", { guestListSettings: { dinnerStyle: "Buffet" } }],
    ["bachParties", { bachParties: [] }], ["rehearsalDinner", { rehearsalDinner: { venueName: "v" } }], ["timelineItems", { timelineItems: [{ id: "t" }] }],
    ["notesTool", { notesTool: [] }], ["ideaItems", { ideaItems: [] }], ["checklistItems", { checklistItems: [] }],
    ["slug", { slug: "sam-alex" }], ["meeting form fields (dotted)", { "meeting1.venue": "Barn" }], ["dayOf dotted", { "dayOf.uniqueNotes": [] }],
  ]) {
    test(`couple saves own doc: ${label}`, async () => { await assertSucceeds(updateDoc(doc(couple("coupleA"), "couples/coupleA"), patch)); });
  }
  test("couple cannot read or write another couple's doc", async () => {
    await assertFails(getDoc(doc(couple("coupleA"), "couples/coupleB")));
    await assertFails(updateDoc(doc(couple("coupleA"), "couples/coupleB"), { notesTool: [] }));
    await assertSucceeds(getDoc(doc(couple("coupleA"), "couples/coupleA")));
  });
  test("signed-out visitor cannot read or write couples", async () => {
    await assertFails(getDoc(doc(guest(), "couples/coupleA")));
    await assertFails(updateDoc(doc(guest(), "couples/coupleA"), { notesTool: [] }));
  });

  test("publicCouples: anyone can get one doc (guest page), nobody can list", async () => {
    await assertSucceeds(getDoc(doc(guest(), "publicCouples/sam-alex")));
    await assertFails(getDocs(collection(guest(), "publicCouples")));
  });
  test("publicCouples: couple writes only their own slug (index.html:664, 3315)", async () => {
    await assertSucceeds(setDoc(doc(couple("coupleA"), "publicCouples/sam-alex"), { names: "Sam & Alex 2" }));
    await assertFails(setDoc(doc(couple("coupleA"), "publicCouples/jo-pat"), { names: "hijack" }));
    await assertFails(setDoc(doc(guest(), "publicCouples/sam-alex"), { names: "x" }));
    await assertSucceeds(setDoc(doc(admin(), "publicCouples/jo-pat"), { names: "admin" }));
  });

  test("RSVP: a signed-out guest can submit a valid RSVP (index.html:603)", async () => {
    await assertSucceeds(setDoc(doc(collection(guest(), "rsvpSubmissions")), validRsvp()));
  });
  test("RSVP: malformed submissions are refused (extra field, wrong type, oversize)", async () => {
    await assertFails(setDoc(doc(collection(guest(), "rsvpSubmissions")), { ...validRsvp(), isAdmin: true }));
    await assertFails(setDoc(doc(collection(guest(), "rsvpSubmissions")), { ...validRsvp(), guestName: 42 }));
    await assertFails(setDoc(doc(collection(guest(), "rsvpSubmissions")), { ...validRsvp(), allergies: "x".repeat(501) }));
  });
  test("RSVP: couple reads (query) and deletes only their own submissions (index.html:2018, 1987)", async () => {
    const mine = query(collection(couple("coupleA"), "rsvpSubmissions"), where("coupleSlug", "==", "sam-alex"));
    await assertSucceeds(getDocs(mine));
    await assertFails(getDocs(query(collection(couple("coupleA"), "rsvpSubmissions"), where("coupleSlug", "==", "jo-pat"))));
    await assertFails(getDocs(collection(couple("coupleA"), "rsvpSubmissions")));
    await assertSucceeds(deleteDoc(doc(couple("coupleA"), "rsvpSubmissions/r1")));
    await assertFails(deleteDoc(doc(couple("coupleA"), "rsvpSubmissions/r2")));
    await assertFails(getDocs(collection(guest(), "rsvpSubmissions")));
  });

  test("settings: signed-in users read; only admin writes (resources, signupCode)", async () => {
    await assertSucceeds(getDoc(doc(couple("coupleA"), "settings/resources")));
    await assertFails(getDoc(doc(guest(), "settings/resources")));
    await assertFails(setDoc(doc(couple("coupleA"), "settings/resources"), { items: [1] }));
    await assertSucceeds(setDoc(doc(admin(), "settings/resources"), { items: [1] }));
    await assertSucceeds(setDoc(doc(admin(), "settings/signupCode"), { code: "NEW", updatedAt: "now" }));
    await assertFails(setDoc(doc(couple("coupleA"), "settings/signupCode"), { code: "NEW" }));
  });

  test("linenOrders: admin only (index.html:3690-3702)", async () => {
    await assertSucceeds(setDoc(doc(admin(), "linenOrders/coupleA"), { y: 2 }));
    await assertSucceeds(deleteDoc(doc(admin(), "linenOrders/coupleA")));
    await assertFails(getDoc(doc(couple("coupleA"), "linenOrders/coupleA")));
  });

  test("admin dashboard: list couples, edit any couple (status, notes, lead coordinator, timeline, dayOf, closeout)", async () => {
    await assertSucceeds(getDocs(collection(admin(), "couples")));
    const a = (id) => doc(admin(), "couples/" + id);
    await assertSucceeds(updateDoc(a("coupleB"), { status: "inactive" }));
    await assertSucceeds(updateDoc(a("coupleB"), { notes: arrayUnion({ text: "hi" }) }));
    await assertSucceeds(updateDoc(a("coupleB"), { leadCoordinator: { name: "K" } }));
    await assertSucceeds(updateDoc(a("coupleB"), { timelineItems: [] }));
    await assertSucceeds(updateDoc(a("coupleB"), { "dayOf.uniqueNotes": [] }));
    await assertSucceeds(updateDoc(a("coupleB"), { "closeoutSheet.x": "y" }));
    await assertFails(getDocs(collection(couple("coupleA"), "couples")));
    await assertFails(getDocs(collection(guest(), "couples")));
  });
  test("an admin email without a verified address gets no admin access", async () => {
    await assertFails(getDocs(collection(adminUnverified(), "couples")));
    await assertFails(updateDoc(doc(adminUnverified(), "couples/coupleB"), { status: "x" }));
  });

  test("a vendor session has no access to any of the live-site data", async () => {
    const v = vendor("sam-alex_dj", E("sam-alex_dj"));
    await assertFails(getDoc(doc(v, "couples/coupleA")));
    await assertFails(updateDoc(doc(v, "couples/coupleA"), { notesTool: [] }));
    await assertFails(setDoc(doc(v, "publicCouples/sam-alex"), { names: "x" }));
    await assertFails(getDocs(query(collection(v, "rsvpSubmissions"), where("coupleSlug", "==", "sam-alex"))));
    await assertFails(setDoc(doc(v, "settings/resources"), { items: [] }));
    await assertFails(getDoc(doc(v, "linenOrders/coupleA")));
  });
});

// ═════════════════════════════════════════════════════════════════════════
// B. EXISTING VENDOR-PORTAL BEHAVIOUR  (must pass on old AND new rules)
// ═════════════════════════════════════════════════════════════════════════
describe("B. vendor portal (existing behaviour)", () => {
  beforeEach(() => seed());
  const dj = () => vendor("sam-alex_dj", E("sam-alex_dj"));

  test("vendor reads own slot and the other slots of the same event, not another event's", async () => {
    await assertSucceeds(getDoc(doc(dj(), "vendorSlots/sam-alex_dj")));
    await assertSucceeds(getDoc(doc(dj(), "vendorSlots/sam-alex_caterer")));
    await assertFails(getDoc(doc(dj(), "vendorSlots/jo-pat_dj")));
  });
  test("vendor writes only its operational fields on its own slot", async () => {
    await assertSucceeds(updateDoc(doc(dj(), "vendorSlots/sam-alex_dj"), { responses: { a: 1 }, lastEditedBy: "Co", lastEditedAt: "now", status: "complete" }));
    await assertFails(updateDoc(doc(dj(), "vendorSlots/sam-alex_dj"), { coupleUid: "coupleB" }));
    await assertFails(updateDoc(doc(dj(), "vendorSlots/sam-alex_dj"), { notes: [{ id: "x" }] }));
    await assertFails(updateDoc(doc(dj(), "vendorSlots/sam-alex_dj"), { barNotes: [{ id: "x" }] }));
    await assertFails(updateDoc(doc(dj(), "vendorSlots/sam-alex_caterer"), { responses: { a: 1 } }));
  });
  test("vendor cannot create or delete slots, or touch the PIN document", async () => {
    await assertFails(deleteDoc(doc(dj(), "vendorSlots/sam-alex_dj")));
    await assertFails(setDoc(doc(dj(), "vendorSlots/sam-alex_new"), { coupleUid: "coupleA", coupleSlug: "sam-alex", category: "dj" }));
    await assertFails(getDoc(doc(dj(), "vendorSlotSecrets/sam-alex_dj")));
    await assertFails(updateDoc(doc(dj(), "vendorSlotSecrets/sam-alex_dj"), { accessPin: "0000" }));
  });
  test("vendorSharedData: event-wide docs readable, guest roster only for caterer/photo, never writable", async () => {
    await assertSucceeds(getDoc(doc(dj(), "couples/coupleA/vendorSharedData/venueInfo")));
    await assertSucceeds(getDoc(doc(dj(), "couples/coupleA/vendorSharedData/socialHandles")));
    await assertSucceeds(getDoc(doc(dj(), "couples/coupleA/vendorSharedData/hairMakeupRoster")));
    await assertFails(getDoc(doc(dj(), "couples/coupleA/vendorSharedData/guestRoster")));
    await assertFails(getDoc(doc(vendor("sam-alex_florist", E("sam-alex_florist")), "couples/coupleA/vendorSharedData/guestRoster")));
    await assertSucceeds(getDoc(doc(vendor("sam-alex_caterer", E("sam-alex_caterer")), "couples/coupleA/vendorSharedData/guestRoster")));
    await assertSucceeds(getDoc(doc(vendor("sam-alex_photo", E("sam-alex_photo")), "couples/coupleA/vendorSharedData/guestRoster")));
    await assertFails(getDoc(doc(dj(), "couples/coupleA/vendorSharedData/privateStuff")));
    await assertFails(getDoc(doc(dj(), "couples/coupleB/vendorSharedData/venueInfo")));
    await assertFails(setDoc(doc(dj(), "couples/coupleA/vendorSharedData/venueInfo"), { v: 2 }));
  });
  test("shared timeline: vendors read, append notes, but cannot rewrite or delete", async () => {
    const t = (v) => doc(v, "couples/coupleA/sharedTimeline/t1");
    await assertSucceeds(getDoc(t(dj())));
    await assertSucceeds(updateDoc(t(dj()), { notes: [{ text: "first", author: "x" }, { text: "mine", author: "dj" }] }));
    await assertFails(updateDoc(t(dj()), { notes: [{ text: "REWRITTEN", author: "x" }, { text: "mine", author: "dj" }] }));
    await assertFails(updateDoc(t(dj()), { notes: [] }));
    await assertFails(deleteDoc(t(dj())));
    await assertSucceeds(setDoc(doc(dj(), "couples/coupleA/sharedTimeline/t2"), { notes: [{ text: "n" }] }));
    await assertFails(setDoc(doc(dj(), "couples/coupleA/sharedTimeline/t3"), { notes: [], extra: 1 }));
    await assertFails(getDoc(doc(dj(), "couples/coupleB/sharedTimeline/t1")));
  });
  test("couple manages its own slots, PINs and shared data; not another couple's", async () => {
    const c = () => couple("coupleA");
    await assertSucceeds(getDoc(doc(c(), "vendorSlots/sam-alex_dj")));
    await assertSucceeds(updateDoc(doc(c(), "vendorSlots/sam-alex_dj"), { vendorName: "Renamed", notes: [{ id: "n" }] }));
    await assertSucceeds(setDoc(doc(c(), "vendorSlots/sam-alex_new"), { coupleUid: "coupleA", coupleSlug: "sam-alex", category: "dj" }));
    await assertFails(setDoc(doc(c(), "vendorSlots/x_new"), { coupleUid: "coupleB", category: "dj" }));
    await assertSucceeds(getDoc(doc(c(), "vendorSlotSecrets/sam-alex_dj")));
    await assertSucceeds(setDoc(doc(c(), "vendorSlotSecrets/sam-alex_new"), { coupleUid: "coupleA", accessPin: "4321", failedAttempts: 0, lockedUntil: null }));
    await assertSucceeds(deleteDoc(doc(c(), "vendorSlotSecrets/sam-alex_new")));
    await assertSucceeds(deleteDoc(doc(c(), "vendorSlots/sam-alex_new")));
    await assertSucceeds(setDoc(doc(c(), "couples/coupleA/vendorSharedData/venueInfo"), { v: 3 }));
    await assertSucceeds(getDoc(doc(c(), "couples/coupleA/vendorSharedData/privateStuff")));
    await assertFails(getDoc(doc(c(), "vendorSlots/jo-pat_dj")));
    await assertFails(getDoc(doc(c(), "vendorSlotSecrets/jo-pat_dj")));
    await assertFails(getDoc(doc(couple("coupleB"), "couples/coupleA/vendorSharedData/venueInfo")));
  });
  test("admin can do everything on vendor data; signed-out users nothing", async () => {
    await assertSucceeds(getDoc(doc(admin(), "vendorSlotSecrets/sam-alex_dj")));
    await assertSucceeds(updateDoc(doc(admin(), "vendorSlots/sam-alex_dj"), { notes: [{ id: "staff" }], coupleUid: "coupleA" }));
    await assertFails(getDoc(doc(guest(), "vendorSlots/sam-alex_dj")));
    await assertFails(getDoc(doc(guest(), "couples/coupleA/vendorSharedData/venueInfo")));
  });
});

// ═════════════════════════════════════════════════════════════════════════
// C. NEW RULES ONLY: session epoch, on/off setting, pilot list
// ═════════════════════════════════════════════════════════════════════════
describe("C. session epoch", () => {
  beforeEach(() => seed());
  const readOwn = (v) => getDoc(doc(v, "vendorSlots/sam-alex_dj"));
  const readEvent = (v) => getDoc(doc(v, "couples/coupleA/vendorSharedData/venueInfo"));
  const readTimeline = (v) => getDoc(doc(v, "couples/coupleA/sharedTimeline/t1"));
  const write = (v) => updateDoc(doc(v, "vendorSlots/sam-alex_dj"), { responses: { a: 1 } });

  test("a token with the matching epoch works everywhere", newOnly, async () => {
    const v = vendor("sam-alex_dj", E("sam-alex_dj"));
    await assertSucceeds(readOwn(v)); await assertSucceeds(readEvent(v)); await assertSucceeds(readTimeline(v)); await assertSucceeds(write(v));
  });
  test("an OLD-style token (no epoch claim) is refused on every vendor path", newOnly, async () => {
    const v = vendor("sam-alex_dj");
    await assertFails(readOwn(v)); await assertFails(readEvent(v)); await assertFails(readTimeline(v)); await assertFails(write(v));
    await assertFails(getDoc(doc(v, "vendorSlots/sam-alex_caterer")));
  });
  test("a wrong epoch is refused; another slot's epoch does not help", newOnly, async () => {
    await assertFails(readOwn(vendor("sam-alex_dj", "nope")));
    await assertFails(readOwn(vendor("sam-alex_dj", E("sam-alex_caterer"))));
    await assertFails(write(vendor("sam-alex_dj", "nope")));
  });
  test("rotating the epoch (PIN regenerated) locks out the old session immediately; a fresh login works", newOnly, async () => {
    const oldSession = vendor("sam-alex_dj", E("sam-alex_dj"));
    await assertSucceeds(readOwn(oldSession));
    await patchDoc("vendorSlotSecrets/sam-alex_dj", { sessionEpoch: "rotated" });
    await assertFails(readOwn(oldSession)); await assertFails(readEvent(oldSession)); await assertFails(write(oldSession));
    await assertSucceeds(readOwn(vendor("sam-alex_dj", "rotated")));
  });
  test("deleting the vendor ends the session, and a re-created slot does not inherit it", newOnly, async () => {
    const oldSession = vendor("sam-alex_dj", E("sam-alex_dj"));
    await rawDelete("vendorSlots/sam-alex_dj"); await rawDelete("vendorSlotSecrets/sam-alex_dj");
    await assertFails(readOwn(oldSession)); await assertFails(readEvent(oldSession));
    // couple re-adds the slot: new secrets doc has no epoch until the first login
    await rawSet("vendorSlots/sam-alex_dj", { ...SLOTS["sam-alex_dj"], vendorName: "New Co", responses: {} });
    await rawSet("vendorSlotSecrets/sam-alex_dj", { coupleUid: "coupleA", accessPin: "9999", failedAttempts: 0 });
    await assertFails(readOwn(oldSession)); await assertFails(readEvent(oldSession));
  });

  describe("transition: slots created before epochs existed", () => {
    beforeEach(() => seed({ withEpochs: false }));
    test("until first login mints an epoch, no vendor token is accepted (old or new style)", newOnly, async () => {
      await assertFails(readOwn(vendor("sam-alex_dj"))); await assertFails(readEvent(vendor("sam-alex_dj")));
      await assertFails(readOwn(vendor("sam-alex_dj", "anything")));
      await assertFails(readOwn(vendor("sam-alex_dj", "")));
    });
    test("once verifyVendorPin writes the epoch, the freshly minted token works", newOnly, async () => {
      await patchDoc("vendorSlotSecrets/sam-alex_dj", { sessionEpoch: "minted-on-login" });
      await assertSucceeds(readOwn(vendor("sam-alex_dj", "minted-on-login")));
      await assertSucceeds(write(vendor("sam-alex_dj", "minted-on-login")));
      await assertFails(readOwn(vendor("sam-alex_dj"))); // the pre-epoch session stays out
    });
    test("couples and admin are not affected by missing epochs", newOnly, async () => {
      await assertSucceeds(getDoc(doc(couple("coupleA"), "vendorSlots/sam-alex_dj")));
      await assertSucceeds(getDoc(doc(couple("coupleA"), "vendorSlotSecrets/sam-alex_dj")));
      await assertSucceeds(getDoc(doc(admin(), "vendorSlots/sam-alex_dj")));
    });
  });

  describe("couple PIN changes must rotate the epoch", () => {
    const secrets = (uid) => doc(couple(uid), "vendorSlotSecrets/sam-alex_dj");
    test("regenerating the PIN without a new epoch is refused", newOnly, async () => {
      await assertFails(updateDoc(secrets("coupleA"), { accessPin: "5555", failedAttempts: 0, lockedUntil: null }));
    });
    test("regenerating the PIN WITH a new epoch is allowed", newOnly, async () => {
      await assertSucceeds(updateDoc(secrets("coupleA"), { accessPin: "5555", failedAttempts: 0, lockedUntil: null, sessionEpoch: "fresh" }));
    });
    test("updates that leave the PIN alone are still allowed", newOnly, async () => {
      await assertSucceeds(updateDoc(secrets("coupleA"), { failedAttempts: 0, lockedUntil: null }));
    });
    test("another couple still cannot touch these secrets", newOnly, async () => {
      await assertFails(updateDoc(secrets("coupleB"), { accessPin: "5555", sessionEpoch: "x" }));
    });
    test("admin keeps full access", newOnly, async () => {
      await assertSucceeds(updateDoc(doc(admin(), "vendorSlotSecrets/sam-alex_dj"), { accessPin: "5555" }));
    });
  });
});

describe("C. on/off setting and pilot list", () => {
  const v = () => vendor("sam-alex_dj", E("sam-alex_dj"));
  const open = async () => { await assertSucceeds(getDoc(doc(v(), "vendorSlots/sam-alex_dj"))); await assertSucceeds(getDoc(doc(v(), "couples/coupleA/vendorSharedData/venueInfo"))); };
  const shut = async () => { await assertFails(getDoc(doc(v(), "vendorSlots/sam-alex_dj"))); await assertFails(getDoc(doc(v(), "couples/coupleA/vendorSharedData/venueInfo"))); await assertFails(updateDoc(doc(v(), "vendorSlots/sam-alex_dj"), { responses: { a: 1 } })); };

  test("settings doc missing => OFF", newOnly, async () => { await seed({ portal: null }); await shut(); });
  test("enabled:false => OFF", newOnly, async () => { await seed({ portal: { enabled: false } }); await shut(); });
  test("enabled must be exactly true (string 'true', 1, null are OFF)", newOnly, async () => {
    for (const bad of ["true", 1, null]) { await seed({ portal: { enabled: bad } }); await shut(); }
    await seed({ portal: {} }); await shut();
  });
  test("enabled:true with no pilot list => ON for every couple", newOnly, async () => {
    await seed({ portal: { enabled: true } }); await open();
    await assertSucceeds(getDoc(doc(vendor("jo-pat_dj", E("jo-pat_dj")), "vendorSlots/jo-pat_dj")));
  });
  test("pilot list: only the listed couples", newOnly, async () => {
    await seed({ portal: { enabled: true, pilotCoupleSlugs: ["sam-alex"] } }); await open();
    await assertFails(getDoc(doc(vendor("jo-pat_dj", E("jo-pat_dj")), "vendorSlots/jo-pat_dj")));
  });
  test("pilot list that excludes the couple, an EMPTY list, or a non-list => OFF (fails closed)", newOnly, async () => {
    for (const p of [["jo-pat"], [], "sam-alex", { 0: "sam-alex" }]) { await seed({ portal: { enabled: true, pilotCoupleSlugs: p } }); await shut(); }
  });
  test("pilotCoupleSlugs null or removed => everyone (documented way to go fully live)", newOnly, async () => {
    await seed({ portal: { enabled: true, pilotCoupleSlugs: null } }); await open();
  });
  test("pilot also needs enabled:true", newOnly, async () => { await seed({ portal: { enabled: false, pilotCoupleSlugs: ["sam-alex"] } }); await shut(); });
  test("a slot with no coupleSlug can never pass a pilot list", newOnly, async () => {
    await seed({ portal: { enabled: true, pilotCoupleSlugs: ["sam-alex"] } });
    await patchDoc("vendorSlots/sam-alex_dj", { coupleSlug: null }); await shut();
  });
  test("flipping OFF cuts a session that is already signed in, on the very next request", newOnly, async () => {
    await seed({ portal: { enabled: true } }); await open();
    await patchDoc("settings/vendorPortal", { enabled: false }); await shut();
    await patchDoc("settings/vendorPortal", { enabled: true }); await open();
  });
  test("couples and admin never depend on the setting", newOnly, async () => {
    await seed({ portal: { enabled: false } });
    await assertSucceeds(getDoc(doc(couple("coupleA"), "vendorSlots/sam-alex_dj")));
    await assertSucceeds(updateDoc(doc(couple("coupleA"), "vendorSlots/sam-alex_dj"), { vendorName: "x" }));
    await assertSucceeds(getDoc(doc(couple("coupleA"), "couples/coupleA/vendorSharedData/venueInfo")));
    await assertSucceeds(getDoc(doc(admin(), "vendorSlotSecrets/sam-alex_dj")));
  });
  test("only admin can change the setting; any signed-in user (even a vendor) can read it", async () => {
    await seed({ portal: { enabled: true } });
    await assertSucceeds(setDoc(doc(admin(), "settings/vendorPortal"), { enabled: true, pilotCoupleSlugs: ["sam-alex"] }));
    await assertFails(setDoc(doc(couple("coupleA"), "settings/vendorPortal"), { enabled: true }));
    await assertFails(setDoc(doc(v(), "settings/vendorPortal"), { enabled: true }));
    await assertSucceeds(getDoc(doc(couple("coupleA"), "settings/vendorPortal")));
    await assertFails(getDoc(doc(guest(), "settings/vendorPortal")));
  });
});
