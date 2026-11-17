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
let queryCount = 0;
const queryCollection = (c, field, value, n) => {
  queryCount++;
  const docs = [...store.keys()].filter((k) => k.startsWith(c + "/") && !k.slice(c.length + 1).includes("/") && store.get(k)[field] === value)
    .slice(0, n).map((k) => ({ id: k.slice(c.length + 1), data: () => structuredClone2(store.get(k)) }));
  return { size: docs.length, empty: docs.length === 0, docs };
};
const fakeDb = {
  collection: (c) => ({
    doc: (i) => ref(c + "/" + i),
    where: (field, op, value) => { if (op !== "==") throw new Error("fake db: only == is supported"); return { limit: (n) => ({ get: async () => queryCollection(c, field, value, n) }) }; },
  }),
  runTransaction: async (fn) => fn({
    get: async (r) => snap(r.path),
    set: (r, d) => store.set(r.path, apply({}, d)),
    update: (r, u) => { if (!store.has(r.path)) throw new Error("NOT_FOUND"); store.set(r.path, apply(store.get(r.path), u)); },
  }),
};
const minted = []; // every custom token request: { uid, claims }
fsMod.getFirestore = () => fakeDb;
req("firebase-admin/auth").getAuth = () => ({ createCustomToken: async (uid, claims) => { minted.push({ uid, claims }); return "TOKEN:" + uid; } });

const loggerMod = req("firebase-functions/logger");
const logged = []; // every log call the handlers make: { level, args }
for (const level of ["info", "warn", "error", "log", "debug"]) loggerMod[level] = (...args) => { logged.push({ level, args }); };
const { verifyVendorPin, saveVendorSlotNotes, checkGuestGate } = req(path.join(fnDir, "index.js"));
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

// ═════════════════════════════════════════════════════════════════
describe("saveVendorSlotNotes: note id validation", () => {
  const EP = "epoch-for-sam-alex-caterer";
  const authN = () => ({ uid: "vendor_" + SLOT, token: { vendorSlotId: SLOT, sessionEpoch: EP } });
  const seedEmpty = () => { seed({ secrets: { sessionEpoch: EP } }); store.get(SLOTP).notes = [{ id: "keep1", text: "existing", authorKey: KEY, author: "C", lastEditedAt: "t" }]; };
  const save = (notes) => call(saveVendorSlotNotes, { auth: authN(), data: { slotId: SLOT, notes, field: "notes" } });
  const bad = [
    ["a single quote", "x'y"], ["a double quote", 'x"y'], ["a space", "a b"], ["a less-than sign", "a<b"], ["a greater-than sign", "a>b"],
    ["an ampersand", "a&b"], ["a backslash", "a\\b"], ["a newline", "a\nb"], ["a closing paren and semicolon", "');alert(1);('"], ["an accented letter", "n\u00e9"],
    ["an emoji", "n\u{1F600}"], ["a dot", "a.b"], ["a slash", "a/b"], ["101 characters", "n".repeat(101)], ["an empty string", ""],
  ];
  for (const [label, id] of bad) {
    test(`a NEW note with ${label} in its id is refused and nothing is saved`, async () => {
      seedEmpty();
      const r = await save([{ id: "keep1", text: "existing" }, { id, text: "hello", author: "C" }]);
      assert.equal(r.code, "invalid-argument");
      assert.equal(store.get(SLOTP).notes.length, 1); assert.equal(store.get(SLOTP).notes[0].id, "keep1");
    });
  }
  test("an id that is ALREADY stored (even an odd one) is kept; it never blocks the vendor from saving other notes", async () => {
    seed({ secrets: { sessionEpoch: EP } });
    const odd = "legacy \"odd\" id'1";
    store.get(SLOTP).notes = [{ id: odd, text: "old", authorKey: KEY, author: "C", lastEditedAt: "t" }, { id: "couplenote'x", text: "c", authorKey: "couple", author: "Couple", lastEditedAt: "t" }];
    const r = await save([{ id: odd, text: "old, edited" }, { id: "couplenote'x", text: "c" }, { id: "fresh1", text: "new", author: "C" }]);
    assert.ok(r.ok, r.msg);
    assert.deepEqual(store.get(SLOTP).notes.map((n) => n.id), [odd, "couplenote'x", "fresh1"]);
    assert.equal(store.get(SLOTP).notes[0].text, "old, edited");
    // ... but a NEW note with an odd id is still refused in the same request
    assert.equal((await save([{ id: odd, text: "old, edited" }, { id: "couplenote'x", text: "c" }, { id: "fresh1", text: "new" }, { id: "bad'new", text: "x" }])).code, "invalid-argument");
  });
  test("a non-string id is refused", async () => {
    seedEmpty(); assert.equal((await save([{ id: 5, text: "x" }])).code, "invalid-argument");
    assert.equal((await save([{ id: null, text: "x" }])).code, "invalid-argument");
  });
  for (const id of ["n1abc", "A_b-9", "n".repeat(100), "x", "nlq3k9z2ab"]) {
    test(`a note id like "${id.slice(0, 12)}${id.length > 12 ? "..." : ""}" is accepted exactly as sent`, async () => {
      seedEmpty();
      const r = await save([{ id: "keep1", text: "existing" }, { id, text: "ok", author: "C" }]);
      assert.ok(r.ok, r.msg); assert.ok(store.get(SLOTP).notes.some((n) => n.id === id));
    });
  }
  test("the same limit applies to the bar-notes field", async () => {
    seedEmpty(); const r = await call(saveVendorSlotNotes, { auth: authN(), data: { slotId: SLOT, notes: [{ id: "bad id", text: "x" }], field: "barNotes" } });
    assert.equal(r.code, "invalid-argument");
  });
});

// ═════════════════════════════════════════════════════════════════
describe("checkGuestGate", () => {
  let PAGE = "alexandsam"; let pageN = 0;   // a fresh page address per test: the limiter's memory lasts for the whole process
  let ip = 0;
  const gate = (over, rawIp) => call(checkGuestGate, { data: { slug: PAGE, name: "Pat Guest", date: "2027-05-08", ...(over || {}) }, rawRequest: { ip: rawIp || "198.51.100." + (++ip % 250) + "." + Math.floor(ip / 250) } });
  const seedGate = (over) => {
    store.clear(); logged.length = 0;
    store.set("couples/uA", {
      uid: "uA", slug: PAGE, email: "owner@example.com", meeting1: { coupleNames: "Alex & Sam", weddingDate: "2027-05-08" },
      blockedGuestNames: ["Troublemaker Tom", "  SPAMMY sue "],
      guestList: [{ id: "1", guestName: "Pat Guest", plusOneAllowed: true }, { id: "2", guestName: "Solo Sally", plusOneAllowed: false }, { id: "3", guestName: "Ned Nameless" }],
      notes: [{ text: "internal staff note" }], leadCoordinator: { name: "Coord C", email: "c@example.com", phone: "555-0100" }, ...(over || {}),
    });
    store.set("couples/uB", { uid: "uB", slug: "someoneelse", meeting1: { weddingDate: "2028-01-01" }, guestList: [{ id: "9", guestName: "Pat Guest", plusOneAllowed: true }] });
  };
  beforeEach(() => { PAGE = "alexandsam" + (++pageN); seedGate(); });

  test("right name and date => ok, and says whether this guest has a plus-one", async () => {
    assert.deepEqual((await gate()).out, { status: "ok", onList: true, plusOneAllowed: true });
    assert.deepEqual((await gate({ name: "Solo Sally" })).out, { status: "ok", onList: true, plusOneAllowed: false });
    assert.deepEqual((await gate({ name: "Ned Nameless" })).out, { status: "ok", onList: true, plusOneAllowed: false });
  });
  test("a name that is not on the list still gets in (as before), flagged as not on the list, with no plus-one", async () => {
    assert.deepEqual((await gate({ name: "Somebody Else" })).out, { status: "ok", onList: false, plusOneAllowed: false });
  });
  test("names are compared trimmed and case-insensitively, exactly like the page did", async () => {
    assert.deepEqual((await gate({ name: "  PAT guest  " })).out, { status: "ok", onList: true, plusOneAllowed: true });
    assert.equal((await gate({ name: "Pat  Guest" })).out.plusOneAllowed, false); // inner spacing is not collapsed (same as the old page)
  });
  test("wrong date => date-mismatch (and nothing else about the guest)", async () => {
    const r = await gate({ date: "2027-05-09" }); assert.deepEqual(r.out, { status: "date-mismatch" });
  });
  test("a couple with no wedding date set can never be opened", async () => {
    seedGate({ meeting1: { coupleNames: "x" } }); assert.equal((await gate()).out.status, "date-mismatch");
  });
  test("blocked names are refused, trimmed and case-insensitively, even with the right date, and before the date is checked", async () => {
    assert.deepEqual((await gate({ name: "troublemaker tom" })).out, { status: "blocked" });
    assert.deepEqual((await gate({ name: "Spammy Sue" })).out, { status: "blocked" });
    assert.deepEqual((await gate({ name: "Troublemaker Tom", date: "1999-01-01" })).out, { status: "blocked" });
  });
  test("unknown page => not-found", async () => { assert.deepEqual((await gate({ slug: "nosuchpage" })).out, { status: "not-found" }); });
  test("two couples with the same address => refused, nothing revealed", async () => {
    store.set("couples/uC", { uid: "uC", slug: PAGE, meeting1: { weddingDate: "2027-05-08" }, guestList: [] });
    const r = await gate(); assert.equal(r.code, "failed-precondition"); assert.equal(r.out, undefined);
  });
  test("the answer never contains the roster, the blocked list, notes, the coordinator, or any other guest's name", async () => {
    const outs = [await gate(), await gate({ name: "Troublemaker Tom" }), await gate({ date: "2000-01-01" }), await gate({ slug: "nosuchpage" })];
    const text = JSON.stringify(outs);
    for (const secret of ["Solo Sally", "Ned Nameless", "Troublemaker", "SPAMMY", "internal staff note", "Coord C", "555-0100", "owner@example.com", "Alex & Sam", "someoneelse"]) assert.ok(!text.includes(secret), secret);
    assert.deepEqual(Object.keys(outs[0].out).sort(), ["onList", "plusOneAllowed", "status"]);
  });
  test("it uses the couple's record at the moment of the call (a name blocked a second ago is blocked now)", async () => {
    assert.equal((await gate({ name: "Late Larry" })).out.status, "ok");
    store.get("couples/uA").blockedGuestNames.push("Late Larry"); assert.equal((await gate({ name: "Late Larry" })).out.status, "blocked");
  });
  test("bad input => invalid-argument", async () => {
    for (const o of [{ slug: "a/b" }, { slug: "" }, { slug: "has space" }, { slug: ".." }, { slug: "__x__" }, { name: "   " }, { name: undefined }, { date: "" }, { date: "May 8 2027" }, { date: "2027-5-8" }]) {
      const r = await gate(o); assert.equal(r.code, "invalid-argument", JSON.stringify(o));
    }
  });
  test("a very long name is cut to 200 characters, not an error", async () => {
    assert.equal((await gate({ name: "x".repeat(5000) })).out.status, "ok");
  });
  test("the 201st call for one page in a window is refused, whoever is calling; other pages are unaffected", async () => {
    let tripped = null;
    for (let i = 1; i <= 201; i++) { const r = await gate({}, "203.0.113." + (i % 250)); if (!r.ok && r.code === "resource-exhausted") { tripped = i; break; } }
    assert.equal(tripped, 201);
    assert.equal((await gate({}, "198.51.100.200")).code, "resource-exhausted");                       // any address
    assert.equal((await call(checkGuestGate, { data: { slug: PAGE, name: "Pat Guest", date: "2027-05-08" } })).code, "resource-exhausted"); // no address at all
    assert.ok((await gate({ slug: "someoneelse", date: "2028-01-01" })).ok);
  });
  test("the cap does not depend on the visitor's address at all (many addresses share it; a spoofed address does not escape it)", async () => {
    let ok = 0; for (let i = 0; i < 200; i++) { const r = await call(checkGuestGate, { data: { slug: PAGE, name: "n" + i, date: "2027-05-08" }, rawRequest: { ip: "10." + (i % 255) + ".0." + i, headers: { "x-forwarded-for": "1.2.3." + i } } }); if (r.ok) ok++; }
    assert.equal(ok, 200); assert.equal((await gate({}, "9.9.9.9")).code, "resource-exhausted");
  });
  test("a refused call does not read the database", async () => {
    for (let i = 0; i < 200; i++) await gate({});
    queryCount = 0; assert.equal((await gate({})).code, "resource-exhausted"); assert.equal(queryCount, 0);
  });
  test("made-up addresses neither use a real page's allowance nor push its counter out of memory", async () => {
    for (let i = 0; i < 200; i++) await gate({});                                   // real page is now at its cap
    for (let i = 0; i < 6000; i++) assert.equal((await gate({ slug: "junk" + i })).out.status, "not-found");
    assert.equal((await gate({})).code, "resource-exhausted");                      // still capped: the junk flood did not reset it
    assert.ok((await gate({ slug: "someoneelse", date: "2028-01-01" })).ok);        // and did not consume anyone else's allowance
  });
  test("the allowance comes back when the 10-minute window is over", async () => {
    const realNow = Date.now; let clock = realNow();
    Date.now = () => clock;
    try {
      for (let i = 0; i < 200; i++) await gate({});
      assert.equal((await gate({})).code, "resource-exhausted");
      clock += 10 * 60 * 1000 + 1000;
      assert.ok((await gate({})).ok);
    } finally { Date.now = realNow; }
  });
  test("if the table ever fills up, one old entry is dropped at a time: a page that is still capped stays capped", async () => {
    const realNow = Date.now; let clock = realNow(); Date.now = () => clock;
    try {
      for (let i = 0; i < 5000; i++) store.set("couples/p" + i, { uid: "p" + i, slug: "page" + i, meeting1: { weddingDate: "2027-01-01" }, guestList: [] });
      await gate({ slug: "page0", date: "2027-01-01" });                           // oldest tracked page
      for (let i = 0; i < 200; i++) await gate({ slug: "page1", date: "2027-01-01" }); clock += 1;
      assert.equal((await gate({ slug: "page1", date: "2027-01-01" })).code, "resource-exhausted");
      for (let i = 2; i < 5000; i++) { clock += 1; await gate({ slug: "page" + i, date: "2027-01-01" }); }   // 4999 more pages: one past the bound
      assert.equal((await gate({ slug: "page1", date: "2027-01-01" })).code, "resource-exhausted");          // page1 NOT wiped
    } finally { Date.now = realNow; }
  });
  test("logs carry a status and a short fingerprint only: no names, no page address, no dates, no IP", async () => {
    await gate(); await gate({ name: "Troublemaker Tom" }); await gate({ date: "2000-01-01" }); await gate({ slug: "nosuchpage" });
    const text = JSON.stringify(logged);
    assert.ok(logged.length >= 4);
    for (const secret of ["Pat Guest", "Troublemaker", PAGE, "nosuchpage", "2027-05-08", "2000-01-01", "198.51.100", "Alex"]) assert.ok(!text.includes(secret), secret);
    assert.ok(logged.every((l) => typeof l.args[1].page === "string" && l.args[1].page.length === 8));
  });
  test("a database error becomes a generic 'try again' (no internals leaked)", async () => {
    const orig = fakeDb.collection; fakeDb.collection = () => { throw new Error("secret internal detail xyz"); };
    try { const r = await gate(); assert.equal(r.code, "internal"); assert.ok(!r.msg.includes("secret")); } finally { fakeDb.collection = orig; }
  });
});
