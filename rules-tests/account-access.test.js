// Account / signup / slug rules tests. Run like rules.test.js (see README.md):
//   firebase emulators:exec --only firestore --project demo-the75-rules \
//     "cd rules-tests && node --test --test-reporter=spec account-access.test.js"
// RULES_FILE=<path> tests a different rules file.
const { test, describe, before, after, beforeEach } = require("node:test");
const fs = require("fs");
const path = require("path");
const { initializeTestEnvironment, assertSucceeds, assertFails } = require("@firebase/rules-unit-testing");
const fb = require("firebase/firestore");
const { doc, setDoc, updateDoc, getDoc, getDocs, collection, query, where, deleteDoc } = fb;
fb.setLogLevel("silent");

const RULES = process.env.RULES_FILE ? path.resolve(process.env.RULES_FILE) : path.join(__dirname, "..", "firestore.rules");
let env;
before(async () => { env = await initializeTestEnvironment({ projectId: "demo-the75-rules", firestore: { rules: fs.readFileSync(RULES, "utf8") } }); });
after(async () => { await env.cleanup(); });

const user = (uid) => env.authenticatedContext(uid, { email: uid + "@example.com", email_verified: false }).firestore();
const admin = () => env.authenticatedContext("adm", { email: "jess@theseventyfivevenue.com", email_verified: true }).firestore();
const vendorCtx = () => env.authenticatedContext("vendor_x", { vendorSlotId: "x", sessionEpoch: "e" }).firestore();
const guest = () => env.unauthenticatedContext().firestore();
const rsvp = (slug) => ({ coupleSlug: slug, guestName: "Guest One", rsvpStatus: "yes", plusOneName: "", mealChoice: "", plusOneMealChoice: "", allergies: "", plusOneAllergies: "", submittedAt: "now", status: "new" });
const newCouple = (uid, slug, over) => ({ uid, email: uid + "@example.com", status: "active", notes: [], slug, signupCode: "1234", ...(over || {}) });

async function seed() {
  await env.clearFirestore();
  await env.withSecurityRulesDisabled(async (c) => {
    const db = c.firestore();
    await setDoc(doc(db, "couples/coupleA"), { uid: "coupleA", slug: "sam-alex" });
    await setDoc(doc(db, "publicCouples/sam-alex"), { slug: "sam-alex", coupleNames: "Sam & Alex" });
    await setDoc(doc(db, "couples/older"), { uid: "older" }); // account from before slugs existed
    await setDoc(doc(db, "settings/signupCode"), { code: "1234" });
    await setDoc(doc(db, "settings/resources"), { items: [] });
    await setDoc(doc(db, "settings/venueInfo"), { a: 1 });
    await setDoc(doc(db, "settings/vendorPortal"), { enabled: true });
    await setDoc(doc(db, "rsvpSubmissions/r1"), rsvp("sam-alex"));
  });
}

describe("signup code", () => {
  beforeEach(seed);
  test("only admin can read it; couples, vendors and signed-out visitors cannot", async () => {
    await assertFails(getDoc(doc(user("coupleA"), "settings/signupCode")));
    await assertFails(getDoc(doc(user("someoneElse"), "settings/signupCode")));
    await assertFails(getDoc(doc(vendorCtx(), "settings/signupCode")));
    await assertFails(getDoc(doc(guest(), "settings/signupCode")));
    await assertSucceeds(getDoc(doc(admin(), "settings/signupCode")));
    await assertSucceeds(setDoc(doc(admin(), "settings/signupCode"), { code: "5678", updatedAt: "n" }));
  });
  test("every other settings doc stays readable to signed-in users", async () => {
    for (const d of ["resources", "venueInfo", "vendorPortal"]) await assertSucceeds(getDoc(doc(user("coupleA"), "settings/" + d)));
    await assertFails(getDoc(doc(guest(), "settings/resources")));
  });
  test("signup is still checked against the code (right code in, wrong code out)", async () => {
    await assertSucceeds(setDoc(doc(user("newbie"), "couples/newbie"), newCouple("newbie", "brand-new")));
    await assertFails(setDoc(doc(user("newbie2"), "couples/newbie2"), newCouple("newbie2", "brand-new-2", { signupCode: "0000" })));
    await assertFails(setDoc(doc(user("newbie3"), "couples/newbie3"), newCouple("newbie3", "brand-new-3", { signupCode: "" })));
  });
  test("a vendor session cannot open a couple account, even with the right code", async () => {
    await assertFails(setDoc(doc(vendorCtx(), "couples/vendor_x"), newCouple("vendor_x", "whatever")));
  });
});

describe("slug ownership", () => {
  beforeEach(seed);
  test("a couple doc cannot be created on a slug that already has a public page", async () => {
    await assertFails(setDoc(doc(user("other"), "couples/other"), newCouple("other", "sam-alex")));
    await assertSucceeds(setDoc(doc(user("other"), "couples/other"), newCouple("other", "sam-alex-2")));
  });
  test("an existing couple's slug cannot be changed (to a taken or to a free one); unchanged re-writes are fine", async () => {
    await assertFails(updateDoc(doc(user("coupleA"), "couples/coupleA"), { slug: "something-else" }));
    await assertSucceeds(setDoc(doc(user("other"), "couples/other"), newCouple("other", "other-slug")));
    await assertFails(updateDoc(doc(user("other"), "couples/other"), { slug: "sam-alex" }));
    await assertFails(updateDoc(doc(user("other"), "couples/other"), { slug: "" }));
    await assertSucceeds(updateDoc(doc(user("coupleA"), "couples/coupleA"), { slug: "sam-alex", notes: [] }));
    await assertSucceeds(updateDoc(doc(user("coupleA"), "couples/coupleA"), { guestList: [{ id: "1" }], "meeting1.coupleNames": "Sam & Alexandra" }));
  });
  test("an account that predates slugs can set one once, to a free slug only", async () => {
    await assertFails(updateDoc(doc(user("older"), "couples/older"), { slug: "sam-alex" }));
    await assertFails(updateDoc(doc(user("older"), "couples/older"), { slug: "x".repeat(201) }));
    await assertSucceeds(updateDoc(doc(user("older"), "couples/older"), { slug: "older-slug" }));
    await assertFails(updateDoc(doc(user("older"), "couples/older"), { slug: "another" }));
  });
  test("an account that does not own a slug cannot read its RSVPs or write its public page", async () => {
    await assertFails(setDoc(doc(user("other"), "couples/other"), newCouple("other", "sam-alex")));
    await assertFails(getDocs(query(collection(user("other"), "rsvpSubmissions"), where("coupleSlug", "==", "sam-alex"))));
    await assertFails(setDoc(doc(user("other"), "publicCouples/sam-alex"), { coupleNames: "changed" }));
  });
  test("admin can still set or change any slug and page", async () => {
    const a = admin();
    await assertSucceeds(updateDoc(doc(a, "couples/coupleA"), { slug: "renamed" }));
    await assertSucceeds(setDoc(doc(a, "publicCouples/renamed"), { slug: "renamed" }));
    await assertSucceeds(setDoc(doc(a, "couples/staff-added"), { uid: "staff-added", slug: "sam-alex" })); // admin is not subject to the signup checks
    await assertSucceeds(getDocs(collection(a, "couples")));
  });
});

describe("the live page's own sequences still work", () => {
  beforeEach(seed);
  test("new signup: couple doc, then public page, then a guest RSVP, then the couple reads it", async () => {
    const u = user("newbie");
    await assertSucceeds(setDoc(doc(u, "couples/newbie"), newCouple("newbie", "fresh-slug")));
    await assertSucceeds(setDoc(doc(u, "publicCouples/fresh-slug"), { slug: "fresh-slug", coupleNames: "A & B" }));
    await assertSucceeds(setDoc(doc(collection(guest(), "rsvpSubmissions")), rsvp("fresh-slug")));
    await assertSucceeds(getDocs(query(collection(u, "rsvpSubmissions"), where("coupleSlug", "==", "fresh-slug"))));
  });
  test("existing couple: edits their page, reads and clears their RSVPs, saves planning data", async () => {
    const u = user("coupleA");
    await assertSucceeds(setDoc(doc(u, "publicCouples/sam-alex"), { slug: "sam-alex", coupleNames: "Sam & Alex 2" }));
    await assertSucceeds(getDocs(query(collection(u, "rsvpSubmissions"), where("coupleSlug", "==", "sam-alex"))));
    await assertSucceeds(deleteDoc(doc(u, "rsvpSubmissions/r1")));
    await assertSucceeds(updateDoc(doc(u, "couples/coupleA"), { timelineItems: [], guestList: [] }));
  });
  test("an older account's one-time slug backfill: claim a slug, then create the page", async () => {
    const u = user("older");
    await assertSucceeds(updateDoc(doc(u, "couples/older"), { slug: "older-slug" }));
    await assertSucceeds(setDoc(doc(u, "publicCouples/older-slug"), { slug: "older-slug" }));
  });
  test("a couple whose public page was never created can still create it later", async () => {
    await assertSucceeds(setDoc(doc(user("nopage"), "couples/nopage"), newCouple("nopage", "no-page-yet")));
    await assertSucceeds(setDoc(doc(user("nopage"), "publicCouples/no-page-yet"), { slug: "no-page-yet" }));
  });
  test("the guest page is still gettable by anyone and still not listable", async () => {
    await assertSucceeds(getDoc(doc(guest(), "publicCouples/sam-alex")));
    await assertFails(getDocs(collection(guest(), "publicCouples")));
  });
});

// The slug check looks at whether a public page already exists for the slug.
describe("slug with no public page yet", () => {
  beforeEach(seed);
  test("a couple doc is accepted for a slug that has no public page yet", async () => {
    await assertSucceeds(setDoc(doc(user("early"), "couples/early"), newCouple("early", "not-yet-a-page")));
  });
});
