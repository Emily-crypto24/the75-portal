// Unit tests for functions/index.js. Run from the repo root:  node --test functions-tests/
//
// The REAL handlers run against the REAL firebase-functions + firebase-admin
// installed in functions/node_modules. Only two things are replaced, because
// they need credentials/network: the Firestore client (an in-memory fake that
// understands transactions and the real Timestamp / FieldValue.delete /
// FieldValue.increment sentinels) and Auth.createCustomToken (records the
// claims it was asked to sign). Needs `npm ci` in functions/ first.
const { test, describe, beforeEach } = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");

const fnDir = path.join(__dirname, "..", "functions");
const req = require("module").createRequire(path.join(fnDir, "index.js"));
const fsMod = req("firebase-admin/firestore");
const { Timestamp } = fsMod;

// ── fake Firestore ──────────────────────────────────────────────────────
const store = new Map();
const kind = (v) => v && v.constructor && v.constructor.name;
const apply = (cur, upd) => {
  const o = { ...cur };
  for (const [k, v] of Object.entries(upd)) {
    if (kind(v) === "DeleteTransform") delete o[k];
    else if (kind(v) === "NumericIncrementTransform") o[k] = (o[k] || 0) + v.operand;
    else o[k] = v;
  }
  return o;
};
const snap = (p) => ({ exists: store.has(p), data: () => (store.has(p) ? structuredClone2(store.get(p)) : undefined) });
function structuredClone2(o) { return Array.isArray(o) ? o.map(structuredClone2) : o instanceof Timestamp ? o : o && typeof o === "object" ? Object.fromEntries(Object.entries(o).map(([k, v]) => [k, structuredClone2(v)])) : o; }
const ref = (p) => ({
  path: p,
  get: async () => snap(p),
  update: async (u) => { if (!store.has(p)) throw new Error("5 NOT_FOUND: " + p); store.set(p, apply(store.get(p), u)); },
});
const fakeDb = {
  collection: (c) => ({ doc: (i) => ref(c + "/" + i) }),
  runTransaction: async (fn) => fn({
    get: async (r) => snap(r.path),
    set: (r, d) => store.set(r.path, apply({}, d)),
    update: (r, u) => { if (!store.has(r.path)) throw new Error("NOT_FOUND"); store.set(r.path, apply(store.get(r.path), u)); },
  }),
};
const minted = []; // every custom token request: { uid, claims }
fsMod.getFirestore = () => fakeDb;
req("firebase-admin/auth").getAuth = () => ({ createCustomToken: async (uid, claims) => { minted.push({ uid, claims }); return "TOKEN:" + uid; } });

const { verifyVendorPin, saveVendorSlotNotes } = req(path.join(fnDir, "index.js"));
const call = async (fn, o) => { try { return { ok: true, out: await fn.run(o) }; } catch (e) { return { ok: false, code: e.code, msg: e.message, reason: e.details && e.details.reason, isHttps: e.constructor.name === "HttpsError" }; } };

const SLOT = "sam-alex_caterer", SLOTP = "vendorSlots/" + SLOT, SECP = "vendorSlotSecrets/" + SLOT, KEY = "vendor:" + SLOT;
let ipN = 0;
const pinReq = (pin, name, ip) => ({ data: { slotId: SLOT, pin, companyName: name }, rawRequest: { ip: ip || "203.0.113." + (++ipN % 250) } });
function seed({ slot, secrets, portal = { enabled: true } } = {}) {
  store.clear(); minted.length = 0;
  store.set(SLOTP, { coupleUid: "u1", coupleSlug: "sam-alex", vendorName: "Hudson's Edge", category: "caterer", otherLabel: null, ...(slot || {}) });
  store.set(SECP, { accessPin: "1234", ...(secrets || {}) });
  if (portal) store.set("settings/vendorPortal", portal);
}

// ═════════════════════════════════════════════════════════════════════════
describe("verifyVendorPin: PIN, name and lockout behaviour (regression)", () => {
  beforeEach(() => seed());

  test("correct PIN + name => token, slot info; resets counters and deletes an expired lock", async () => {
    store.get(SECP).failedAttempts = 3; store.get(SECP).lockedUntil = Timestamp.fromMillis(Date.now() - 1000);
    const r = await call(verifyVendorPin, pinReq("1234", "Hudson's Edge"));
    assert.ok(r.ok, r.msg);
    assert.equal(r.out.token, "TOKEN:vendor_" + SLOT);
    assert.equal(r.out.category, "caterer"); assert.equal(r.out.coupleSlug, "sam-alex");
    assert.equal(store.get(SECP).failedAttempts, 0); assert.ok(!("lockedUntil" in store.get(SECP)));
  });
  test("wrong PIN and unknown slot give the identical error (no enumeration)", async () => {
    const a = await call(verifyVendorPin, pinReq("9999", "Hudson's Edge"));
    const b = await call(verifyVendorPin, { data: { slotId: "nope_slot", pin: "1234", companyName: "x" }, rawRequest: { ip: "198.51.100.9" } });
    assert.equal(a.code, "permission-denied"); assert.equal(a.msg, "Incorrect PIN.");
    assert.equal(b.code, a.code); assert.equal(b.msg, a.msg);
    assert.equal(store.get(SECP).failedAttempts, 1);
  });
  test("5 wrong PINs lock for 15 minutes, even for the right PIN afterwards", async () => {
    let last; for (let i = 0; i < 5; i++) last = await call(verifyVendorPin, pinReq("0000", "Hudson's Edge", "198.51.100." + i));
    assert.equal(last.code, "resource-exhausted"); assert.match(last.msg, /15 minutes/);
    const lu = store.get(SECP).lockedUntil; assert.ok(lu instanceof Timestamp);
    assert.ok(Math.abs(lu.toMillis() - (Date.now() + 15 * 60000)) < 5000);
    const r = await call(verifyVendorPin, pinReq("1234", "Hudson's Edge", "198.51.100.77"));
    assert.equal(r.code, "resource-exhausted");
  });
  test("wrong company name counts against its own lockout, not the PIN's; 5 trip it", async () => {
    const r = await call(verifyVendorPin, pinReq("1234", "Wrong Co"));
    assert.equal(r.code, "permission-denied");
    assert.equal(store.get(SECP).nameFailedAttempts, 1); assert.equal(store.get(SECP).failedAttempts, 0);
    let last; for (let i = 0; i < 4; i++) last = await call(verifyVendorPin, pinReq("1234", "Wrong Co", "192.0.2." + i));
    assert.equal(last.code, "resource-exhausted"); assert.ok(store.get(SECP).nameLockedUntil instanceof Timestamp);
  });
  test("an unclaimed slot takes the first company name entered", async () => {
    seed({ slot: { vendorName: "" } });
    const r = await call(verifyVendorPin, pinReq("1234", "New Florist Co"));
    assert.ok(r.ok); assert.equal(store.get(SLOTP).vendorName, "New Florist Co");
  });
  test("per-IP limit trips on call 21", async () => {
    let blocked = null;
    for (let i = 1; i <= 21; i++) { const x = await call(verifyVendorPin, pinReq("1234", "Hudson's Edge", "10.9.8.7")); if (!x.ok && x.code === "resource-exhausted") { blocked = i; break; } }
    assert.equal(blocked, 21); assert.equal(store.get("pinAttemptLog/10_9_8_7").count, 20);
  });
  test("malformed slotId / short PIN / empty name => invalid-argument", async () => {
    assert.equal((await call(verifyVendorPin, { data: { slotId: "bad slot!", pin: "1234", companyName: "x" } })).code, "invalid-argument");
    assert.equal((await call(verifyVendorPin, pinReq("12", "x"))).code, "invalid-argument");
    assert.equal((await call(verifyVendorPin, pinReq("1234", "   "))).code, "invalid-argument");
  });
});

describe("verifyVendorPin: company name matching (Hudson's Edge)", () => {
  const match = [
    ["straight", "Hudson's Edge"], ["curly apostrophe", "Hudson’s Edge"], ["lowercase + curly", "hudson’s edge"],
    ["UPPERCASE + curly", "HUDSON’S EDGE"], ["padded + curly", " Hudson’s Edge "], ["double space", "Hudson's  Edge"],
    ["tab + nbsp", "Hudson's\t Edge"], ["U+2018", "Hudson‘s Edge"], ["U+02BC", "Hudsonʼs Edge"], ["backtick", "Hudson`s Edge"],
  ];
  const refuse = [["no apostrophe", "Hudsons Edge"], ["extra word", "Hudson's Edge Catering"], ["different", "Smith Catering"], ["no space", "Hudson'sEdge"], ["typo", "Hudson's Edgy"]];
  for (const stored of ["Hudson's Edge", "Hudson’s Edge"]) {
    for (const [label, typed] of match) test(`stored ${JSON.stringify(stored)}: ${label} matches`, async () => { seed({ slot: { vendorName: stored } }); assert.ok((await call(verifyVendorPin, pinReq("1234", typed))).ok); });
    for (const [label, typed] of refuse) test(`stored ${JSON.stringify(stored)}: ${label} is refused`, async () => { seed({ slot: { vendorName: stored } }); assert.equal((await call(verifyVendorPin, pinReq("1234", typed))).code, "permission-denied"); });
  }
});

describe("verifyVendorPin: session epoch", () => {
  test("a slot created before epochs existed gets one on first login, and it is in the token", async () => {
    seed();
    assert.ok(!("sessionEpoch" in store.get(SECP)));
    const r = await call(verifyVendorPin, pinReq("1234", "Hudson's Edge"));
    assert.ok(r.ok, r.msg);
    const stored = store.get(SECP).sessionEpoch;
    assert.equal(typeof stored, "string"); assert.ok(stored.length >= 24);
    assert.deepEqual(minted.at(-1).claims, { vendorSlotId: SLOT, sessionEpoch: stored });
  });
  test("later logins reuse the same epoch (a second device doesn't kick the first out)", async () => {
    seed();
    await call(verifyVendorPin, pinReq("1234", "Hudson's Edge")); const first = store.get(SECP).sessionEpoch;
    await call(verifyVendorPin, pinReq("1234", "Hudson's Edge")); await call(verifyVendorPin, pinReq("1234", "Hudson's Edge"));
    assert.equal(store.get(SECP).sessionEpoch, first); assert.equal(minted.at(-1).claims.sessionEpoch, first);
  });
  test("an existing epoch is never overwritten", async () => {
    seed({ secrets: { sessionEpoch: "already-here-0123456789abc" } });
    await call(verifyVendorPin, pinReq("1234", "Hudson's Edge"));
    assert.equal(store.get(SECP).sessionEpoch, "already-here-0123456789abc"); assert.equal(minted.at(-1).claims.sessionEpoch, "already-here-0123456789abc");
  });
  test("a rotated epoch (couple regenerated the PIN) flows into the next login's token", async () => {
    seed({ secrets: { sessionEpoch: "old-epoch-000000000000000" } });
    store.get(SECP).sessionEpoch = "rotated-by-couple-00000"; store.get(SECP).accessPin = "4321";
    await call(verifyVendorPin, pinReq("4321", "Hudson's Edge"));
    assert.equal(minted.at(-1).claims.sessionEpoch, "rotated-by-couple-00000");
  });
  test("different slots get different epochs", async () => {
    seed(); await call(verifyVendorPin, pinReq("1234", "Hudson's Edge")); const a = store.get(SECP).sessionEpoch;
    seed(); await call(verifyVendorPin, pinReq("1234", "Hudson's Edge")); assert.notEqual(store.get(SECP).sessionEpoch, a);
  });
});

describe("verifyVendorPin: on/off switch and pilot list", () => {
  const closed = (r) => { assert.ok(!r.ok); assert.equal(r.code, "failed-precondition"); assert.equal(r.reason, "portal-closed"); assert.ok(r.isHttps); };
  test("settings doc missing => closed, and nothing is counted or minted", async () => {
    seed({ portal: null });
    closed(await call(verifyVendorPin, pinReq("1234", "Hudson's Edge")));
    closed(await call(verifyVendorPin, pinReq("9999", "Hudson's Edge")));
    assert.ok(!("failedAttempts" in store.get(SECP)) || store.get(SECP).failedAttempts === undefined);
    assert.ok(![...store.keys()].some((k) => k.startsWith("pinAttemptLog/")));
    assert.ok(!("sessionEpoch" in store.get(SECP))); assert.equal(minted.length, 0);
  });
  test("closed looks the same for an unknown slot (reveals nothing)", async () => {
    seed({ portal: { enabled: false } });
    const a = await call(verifyVendorPin, pinReq("1234", "Hudson's Edge"));
    const b = await call(verifyVendorPin, { data: { slotId: "nope_slot", pin: "1234", companyName: "x" }, rawRequest: { ip: "198.51.100.5" } });
    closed(a); closed(b); assert.equal(a.msg, b.msg);
  });
  for (const bad of [false, "true", 1, null, undefined]) test(`enabled: ${JSON.stringify(bad)} => closed`, async () => { seed({ portal: { enabled: bad } }); closed(await call(verifyVendorPin, pinReq("1234", "Hudson's Edge"))); });
  test("enabled:true, no pilot list => any couple", async () => { seed({ portal: { enabled: true } }); assert.ok((await call(verifyVendorPin, pinReq("1234", "Hudson's Edge"))).ok); });
  test("pilotCoupleSlugs null => any couple", async () => { seed({ portal: { enabled: true, pilotCoupleSlugs: null } }); assert.ok((await call(verifyVendorPin, pinReq("1234", "Hudson's Edge"))).ok); });
  test("pilot list containing the couple => in", async () => { seed({ portal: { enabled: true, pilotCoupleSlugs: ["other", "sam-alex"] } }); assert.ok((await call(verifyVendorPin, pinReq("1234", "Hudson's Edge"))).ok); });
  for (const p of [["someone-else"], [], "sam-alex", { 0: "sam-alex" }, 5]) {
    test(`pilot ${JSON.stringify(p)} => closed for this couple, and no token`, async () => {
      seed({ portal: { enabled: true, pilotCoupleSlugs: p } });
      closed(await call(verifyVendorPin, pinReq("1234", "Hudson's Edge"))); assert.equal(minted.length, 0);
    });
  }
  test("out-of-pilot slot: a WRONG PIN still looks like any wrong PIN (no way to learn the pilot list)", async () => {
    seed({ portal: { enabled: true, pilotCoupleSlugs: [] } });
    const r = await call(verifyVendorPin, pinReq("9999", "Hudson's Edge"));
    assert.equal(r.code, "permission-denied"); assert.equal(r.msg, "Incorrect PIN.");
  });
  test("a slot with no coupleSlug can never pass a pilot list", async () => {
    seed({ slot: { coupleSlug: undefined }, portal: { enabled: true, pilotCoupleSlugs: ["sam-alex"] } });
    closed(await call(verifyVendorPin, pinReq("1234", "Hudson's Edge")));
  });
});

// ═════════════════════════════════════════════════════════════════════════
describe("saveVendorSlotNotes", () => {
  const EP = "epoch-for-sam-alex-caterer";
  const base = [
    { id: "mine", text: "vendor note A", authorKey: KEY, author: "Caterer", lastEditedAt: "2026-10-01T00:00:00.000Z" },
    { id: "staffed", text: "vendor note B (corrected by staff)", authorKey: KEY, author: "Caterer", lastEditedAt: "2026-10-14T17:00:00.000Z", lastEditedBy: "Kara (Admin)" },
    { id: "couples", text: "couple's note", authorKey: "couple", author: "Couple", lastEditedAt: "2026-10-02T00:00:00.000Z" },
  ];
  const seedN = (notes, o = {}) => { seed({ secrets: { sessionEpoch: EP }, ...o }); store.get(SLOTP).notes = JSON.parse(JSON.stringify(notes)); };
  const auth = (over) => ({ uid: "vendor_" + SLOT, token: { vendorSlotId: SLOT, sessionEpoch: EP, ...(over || {}) } });
  const nreq = (notes, extra) => ({ auth: auth(), data: { slotId: SLOT, notes, field: "notes" }, ...(extra || {}) });
  const stored = () => store.get(SLOTP).notes;

  test("staff attribution survives a save that didn't touch that note", async () => {
    seedN(base);
    const r = await call(saveVendorSlotNotes, nreq([...base, { id: "new1", text: "new vendor note", author: "Caterer" }]));
    assert.ok(r.ok, r.msg);
    const st = stored().find((n) => n.id === "staffed");
    assert.equal(st.lastEditedBy, "Kara (Admin)"); assert.equal(st.lastEditedAt, "2026-10-14T17:00:00.000Z");
    assert.equal(stored().find((n) => n.id === "new1").authorKey, KEY);
    assert.equal(r.out.notes.length, 4); assert.equal(r.out.lastEditedBy, "Hudson's Edge");
  });
  test("author re-editing their own staff-touched note clears the stale staff stamp", async () => {
    seedN(base);
    const r = await call(saveVendorSlotNotes, nreq(base.map((n) => (n.id === "staffed" ? { ...n, text: "vendor rewrote B" } : n))));
    assert.ok(r.ok); const st = stored().find((n) => n.id === "staffed"); assert.equal(st.text, "vendor rewrote B"); assert.equal(st.lastEditedBy, undefined);
  });
  test("carried staff stamp is capped at 200 chars", async () => {
    seedN([{ id: "mine", text: "x", authorKey: KEY, author: "C", lastEditedAt: "t", lastEditedBy: "y".repeat(500) }]);
    assert.ok((await call(saveVendorSlotNotes, nreq([{ id: "mine", text: "x" }]))).ok); assert.equal(stored()[0].lastEditedBy.length, 200);
  });
  test("cannot edit or delete the couple's note", async () => {
    seedN(base);
    assert.equal((await call(saveVendorSlotNotes, nreq(base.map((n) => (n.id === "couples" ? { ...n, text: "tampered" } : n))))).code, "permission-denied");
    assert.equal((await call(saveVendorSlotNotes, nreq(base.filter((n) => n.id !== "couples")))).code, "permission-denied");
    assert.equal(stored().find((n) => n.id === "couples").text, "couple's note");
  });
  test("other slot's token / unauthenticated / bad field / duplicate ids / missing slot / barNotes", async () => {
    seedN(base);
    assert.equal((await call(saveVendorSlotNotes, { auth: auth({ vendorSlotId: "someone_else" }), data: { slotId: SLOT, notes: base, field: "notes" } })).code, "permission-denied");
    assert.equal((await call(saveVendorSlotNotes, { data: { slotId: SLOT, notes: base, field: "notes" } })).code, "permission-denied");
    assert.equal((await call(saveVendorSlotNotes, nreq(base, { data: { slotId: SLOT, notes: base, field: "responses" } }))).code, "invalid-argument");
    assert.equal((await call(saveVendorSlotNotes, nreq([{ id: "d", text: "a" }, { id: "d", text: "b" }]))).code, "invalid-argument");
    seedN([]); assert.ok((await call(saveVendorSlotNotes, nreq([], { data: { slotId: SLOT, notes: [{ id: "b1", text: "bar note" }], field: "barNotes" } }))).ok);
    assert.equal(store.get(SLOTP).barNotes[0].text, "bar note");
    seedN([]); store.delete(SLOTP); assert.equal((await call(saveVendorSlotNotes, nreq([]))).code, "not-found");
  });

  describe("session epoch", () => {
    const reset = (r) => { assert.ok(!r.ok); assert.equal(r.code, "unauthenticated"); assert.equal(r.reason, "session-reset"); };
    test("matching epoch saves", async () => { seedN(base); assert.ok((await call(saveVendorSlotNotes, nreq(base))).ok); });
    test("token without an epoch (a session from before epochs) is told to log in again", async () => {
      seedN(base); reset(await call(saveVendorSlotNotes, { auth: { uid: "v", token: { vendorSlotId: SLOT } }, data: { slotId: SLOT, notes: base, field: "notes" } }));
    });
    test("wrong epoch => session reset, and nothing is written", async () => {
      seedN(base); reset(await call(saveVendorSlotNotes, { ...nreq([...base, { id: "x", text: "sneaky" }]), auth: auth({ sessionEpoch: "stale" }) }));
      assert.equal(stored().length, 3);
    });
    test("PIN regenerated (epoch rotated) => the old session is refused", async () => {
      seedN(base); store.get(SECP).sessionEpoch = "rotated"; reset(await call(saveVendorSlotNotes, nreq(base)));
    });
    test("slot with no epoch stored yet (never logged in since epochs) => refused, even with an empty claim", async () => {
      seedN(base); delete store.get(SECP).sessionEpoch; reset(await call(saveVendorSlotNotes, nreq(base)));
      reset(await call(saveVendorSlotNotes, { ...nreq(base), auth: auth({ sessionEpoch: "" }) }));
    });
    test("secrets doc gone (vendor deleted and re-added) => refused", async () => {
      seedN(base); store.delete(SECP); reset(await call(saveVendorSlotNotes, nreq(base)));
    });
  });

  describe("on/off switch and pilot list", () => {
    const closed = (r) => { assert.ok(!r.ok); assert.equal(r.code, "failed-precondition"); assert.equal(r.reason, "portal-closed"); };
    test("switch missing / off => closed, nothing written", async () => {
      seedN(base, { portal: null }); closed(await call(saveVendorSlotNotes, nreq([...base, { id: "x", text: "n" }]))); assert.equal(stored().length, 3);
      seedN(base, { portal: { enabled: false } }); closed(await call(saveVendorSlotNotes, nreq(base)));
    });
    test("flipping it back on restores saving for the same session", async () => {
      seedN(base, { portal: { enabled: false } }); closed(await call(saveVendorSlotNotes, nreq(base)));
      store.set("settings/vendorPortal", { enabled: true }); assert.ok((await call(saveVendorSlotNotes, nreq(base))).ok);
    });
    test("pilot list: in => saves; out / empty => closed", async () => {
      seedN(base, { portal: { enabled: true, pilotCoupleSlugs: ["sam-alex"] } }); assert.ok((await call(saveVendorSlotNotes, nreq(base))).ok);
      seedN(base, { portal: { enabled: true, pilotCoupleSlugs: ["jo-pat"] } }); closed(await call(saveVendorSlotNotes, nreq(base)));
      seedN(base, { portal: { enabled: true, pilotCoupleSlugs: [] } }); closed(await call(saveVendorSlotNotes, nreq(base)));
    });
  });
});
