/**
 * Wire-format tests for the anti-revoke DoH worker.
 *
 * These run with Node's built-in test runner and need no dependencies:
 *     node --test worker/test/
 *
 * The wire format is where a DoH sinkhole fails silently. A profile whose
 * server replies with a malformed message does not produce a visible error on
 * the device; the names simply fail to resolve, which looks identical to the
 * behaviour we are trying to produce, so the bug would go unnoticed.
 */

import assert from "node:assert/strict";
import test from "node:test";

import worker, {
  buildNxDomain,
  isAllowed,
  looksLikeProfile,
  parseAllowlist,
  parseQuestion,
} from "../src/index.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const TYPES = { A: 1, AAAA: 28 };

/** Encode a QNAME, using a compression pointer when `pointer` is given. */
function encodeName(name, pointer) {
  const bytes = [];
  if (name) {
    for (const label of name.split(".")) {
      bytes.push(label.length, ...new TextEncoder().encode(label));
    }
  }
  bytes.push(0);
  if (pointer !== undefined) bytes.push(0xc0, pointer);
  return bytes;
}

function buildQuery(name, { type = TYPES.A, id = 0x1234, rd = true } = {}) {
  return new Uint8Array([
    id >> 8, id & 0xff,
    0x01, rd ? 0x01 : 0x00, // RD
    0x00, 0x01,             // QDCOUNT
    0x00, 0x00,             // ANCOUNT
    0x00, 0x00,             // NSCOUNT
    0x00, 0x00,             // ARCOUNT
    ...encodeName(name),
    type >> 8, type & 0xff,
    0x00, 0x01,             // IN
  ]);
}

function readName(bytes, offset) {
  const labels = [];
  while (bytes[offset] !== 0) {
    const length = bytes[offset];
    labels.push(
      new TextDecoder().decode(bytes.subarray(offset + 1, offset + 1 + length)),
    );
    offset += 1 + length;
  }
  return { name: labels.join("."), end: offset + 1 };
}

function requestFor(url, init) {
  return new Request(url, init);
}

// ---------------------------------------------------------------------------
// parseQuestion
// ---------------------------------------------------------------------------

test("parses a simple question and reports the end of the section", () => {
  const query = buildQuery("ocsp.apple.com");
  const question = parseQuestion(query);
  assert.equal(question.name, "ocsp.apple.com");
  // Header + labels + root + QTYPE + QCLASS
  assert.equal(question.end, query.length);
});

test("lowercases the name so matching is case-insensitive", () => {
  assert.equal(parseQuestion(buildQuery("OCSP.Apple.COM")).name, "ocsp.apple.com");
});

test("handles a multi-label revocation hostname", () => {
  const name = "usw2-ppq-ext-prod.apple.com";
  assert.equal(parseQuestion(buildQuery(name)).name, name);
});

test("rejects a truncated header", () => {
  assert.equal(parseQuestion(new Uint8Array([1, 2, 3])), null);
});

test("rejects a question with no terminating root label", () => {
  const query = buildQuery("ocsp.apple.com").subarray(0, 20);
  assert.equal(parseQuestion(query), null);
});

test("rejects a compression pointer in the question section", () => {
  // RFC 1035 forbids pointers here; accepting one would let a crafted query
  // make the parser read from an attacker-chosen offset.
  const query = new Uint8Array([
    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0,
    0xc0, 0x0c,
    0x00, 0x01, 0x00, 0x01,
  ]);
  assert.equal(parseQuestion(query), null);
});

test("rejects a label that runs past the end of the message", () => {
  const query = new Uint8Array([
    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0,
    0x20, 0x61, 0x62, // claims 32 bytes, provides 2
  ]);
  assert.equal(parseQuestion(query), null);
});

// ---------------------------------------------------------------------------
// buildNxDomain
// ---------------------------------------------------------------------------

test("echoes the question and answers NXDOMAIN", () => {
  const query = buildQuery("ppq.apple.com");
  const { end } = parseQuestion(query);
  const reply = buildNxDomain(query, end);

  assert.equal(reply[0], 0x12, "transaction id must be preserved");
  assert.equal(reply[1], 0x34);
  assert.equal(reply[2] & 0x80, 0x80, "QR must be set");
  assert.equal(reply[2] & 0x01, 0x01, "RD must be echoed");
  assert.equal(reply[3] & 0x0f, 3, "RCODE must be NXDOMAIN");
  assert.equal(reply[3] & 0x80, 0x80, "RA should be set");

  assert.equal((reply[4] << 8) | reply[5], 1, "QDCOUNT must stay 1");
  assert.equal((reply[6] << 8) | reply[7], 0, "ANCOUNT must be 0");
  assert.equal((reply[8] << 8) | reply[9], 0, "NSCOUNT must be 0");
  assert.equal((reply[10] << 8) | reply[11], 0, "ARCOUNT must be 0");

  // The question must survive byte-for-byte, or resolvers reject the reply.
  assert.deepEqual(
    Array.from(reply.subarray(12, end)),
    Array.from(query.subarray(12, end)),
  );
});

test("NXDOMAIN reply length equals the question length", () => {
  const query = buildQuery("ocsp.apple.com");
  const reply = buildNxDomain(query, parseQuestion(query).end);
  assert.equal(reply.length, query.length);
});

test("a reply with no question is still well formed", () => {
  const reply = buildNxDomain(new Uint8Array(12), 12);
  assert.equal(reply.length, 12);
  assert.equal(reply[3] & 0x0f, 3);
});

test("an AAAA query is refused the same way as A", () => {
  const query = buildQuery("ocsp.apple.com", { type: TYPES.AAAA });
  const reply = buildNxDomain(query, parseQuestion(query).end);
  assert.equal(reply[3] & 0x0f, 3);
});

// ---------------------------------------------------------------------------
// allowlist
// ---------------------------------------------------------------------------

test("parseAllowlist splits, trims and lowercases", () => {
  assert.deepEqual(
    parseAllowlist(" Register.AppAttest.Apple.com , vpp.itunes.apple.com "),
    ["register.appattest.apple.com", "vpp.itunes.apple.com"],
  );
});

test("parseAllowlist tolerates an empty or missing value", () => {
  assert.deepEqual(parseAllowlist(""), []);
  assert.deepEqual(parseAllowlist(undefined), []);
  assert.deepEqual(parseAllowlist(",, ,"), []);
});

test("an allowlist entry also covers subdomains but not lookalikes", () => {
  const allow = ["appattest.apple.com"];
  assert.ok(isAllowed("appattest.apple.com", allow));
  assert.ok(isAllowed("register.appattest.apple.com", allow));
  assert.ok(isAllowed("data.appattest.apple.com", allow));
  // Must not match a domain that merely ends with the same characters.
  assert.ok(!isAllowed("notappattest.apple.com", allow));
  assert.ok(!isAllowed("appattest.apple.com.evil.test", allow));
});

// ---------------------------------------------------------------------------
// fetch handler
// ---------------------------------------------------------------------------

test("GET returns a DNS message and NXDOMAIN by default", async () => {
  const query = buildQuery("ppq.apple.com");
  const encoded = Buffer.from(query).toString("base64url");
  const response = await worker.fetch(
    requestFor(`https://doh.example/dns-query?dns=${encoded}`),
    {},
  );

  assert.equal(response.status, 200);
  assert.equal(response.headers.get("content-type"), "application/dns-message");

  const body = new Uint8Array(await response.arrayBuffer());
  assert.equal(body[3] & 0x0f, 3, "default answer must be NXDOMAIN");
  assert.equal(readName(body, 12).name, "ppq.apple.com");
});

test("POST accepts an application/dns-message body", async () => {
  const query = buildQuery("ocsp.apple.com");
  const response = await worker.fetch(
    requestFor("https://doh.example/dns-query", {
      method: "POST",
      headers: { "content-type": "application/dns-message" },
      body: query,
    }),
    {},
  );

  assert.equal(response.status, 200);
  const body = new Uint8Array(await response.arrayBuffer());
  assert.equal(body[3] & 0x0f, 3);
  assert.equal(readName(body, 12).name, "ocsp.apple.com");
});

test("a missing ?dns= parameter is a 400", async () => {
  const response = await worker.fetch(
    requestFor("https://doh.example/dns-query"),
    {},
  );
  assert.equal(response.status, 400);
});

test("a malformed base64 payload is a 400, not a crash", async () => {
  const response = await worker.fetch(
    requestFor("https://doh.example/dns-query?dns=!!!not-base64!!!"),
    {},
  );
  assert.equal(response.status, 400);
});

test("an unknown path is a 404", async () => {
  const response = await worker.fetch(requestFor("https://doh.example/"), {});
  assert.equal(response.status, 404);
});

test("/health reports the configured allowlist", async () => {
  const response = await worker.fetch(
    requestFor("https://doh.example/health"),
    { ALLOWLIST: "register.appattest.apple.com" },
  );
  assert.equal(response.status, 200);
  const payload = await response.json();
  assert.equal(payload.status, "ok");
  assert.deepEqual(payload.allowlist, ["register.appattest.apple.com"]);
});

// ---------------------------------------------------------------------------
// The behaviour the profile depends on
// ---------------------------------------------------------------------------

test("every domain the profile blocks is answered with NXDOMAIN", async () => {
  // Sampled from what the generated profile actually lists.
  const blocked = [
    "ocsp.apple.com",
    "ocsp2.apple.com",
    "crl.apple.com",
    "ppq.apple.com",
    "ppq-ext.v.aaplimg.com",
    "usw2-ppq-ext-prod.apple.com",
    "vpp.itunes.apple.com",
    "appattest.apple.com",
    "register.appattest.apple.com",
  ];

  for (const name of blocked) {
    const query = buildQuery(name);
    const response = await worker.fetch(
      requestFor(
        `https://doh.example/dns-query?dns=${Buffer.from(query).toString("base64url")}`,
      ),
      {},
    );
    const body = new Uint8Array(await response.arrayBuffer());
    assert.equal(body[3] & 0x0f, 3, `${name} should be NXDOMAIN`);
    assert.equal(readName(body, 12).name, name, `${name} must echo correctly`);
  }
});

test("an allowlisted host is forwarded upstream instead of blocked", async (t) => {
  const original = globalThis.fetch;
  let forwarded = null;
  globalThis.fetch = async (url, init) => {
    forwarded = { url, method: init.method };
    return new Response(new Uint8Array(12), {
      status: 200,
      headers: { "content-type": "application/dns-message" },
    });
  };
  t.after(() => { globalThis.fetch = original; });

  const query = buildQuery("register.appattest.apple.com");
  const response = await worker.fetch(
    requestFor(
      `https://doh.example/dns-query?dns=${Buffer.from(query).toString("base64url")}`,
    ),
    { ALLOWLIST: "register.appattest.apple.com" },
  );

  assert.equal(response.status, 200);
  assert.ok(forwarded, "the query should have been forwarded");
  assert.equal(forwarded.method, "POST");
  assert.match(forwarded.url, /cloudflare-dns\.com/);
});

test("a name outside the allowlist is still blocked", async (t) => {
  const original = globalThis.fetch;
  let called = false;
  globalThis.fetch = async () => { called = true; return new Response(""); };
  t.after(() => { globalThis.fetch = original; });

  const query = buildQuery("ppq.apple.com");
  const response = await worker.fetch(
    requestFor(
      `https://doh.example/dns-query?dns=${Buffer.from(query).toString("base64url")}`,
    ),
    { ALLOWLIST: "register.appattest.apple.com" },
  );

  assert.equal(called, false, "must not consult upstream for a blocked name");
  const body = new Uint8Array(await response.arrayBuffer());
  assert.equal(body[3] & 0x0f, 3);
});

// ---------------------------------------------------------------------------
// Profile download routes (/download, /download2)
//
// These exist because raw.githubusercontent.com serves .mobileconfig as
// text/plain with nosniff, not as application/x-apple-aspen-config. The
// validation matters more than the short URL: the profile is fetched from a
// third party at request time, so a failure could hand iOS an error page.
// ---------------------------------------------------------------------------

/** A minimal but structurally valid unsigned profile. */
function fakeProfile(pad = 400) {
  const xml =
    '<?xml version="1.0" encoding="UTF-8"?>\n' +
    '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" ' +
    '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n' +
    '<plist version="1.0"><dict>' +
    "<key>PayloadType</key><string>com.apple.dnsSettings.managed</string>" +
    `<key>Pad</key><string>${"x".repeat(pad)}</string>` +
    "</dict></plist>\n";
  return new TextEncoder().encode(xml);
}

function withFetch(handler, fn) {
  const original = globalThis.fetch;
  globalThis.fetch = handler;
  return fn().finally(() => { globalThis.fetch = original; });
}

test("looksLikeProfile accepts an unsigned XML profile", () => {
  assert.equal(looksLikeProfile(fakeProfile()), true);
});

test("looksLikeProfile accepts a CMS-signed profile", () => {
  // DER always begins with a SEQUENCE tag.
  const bytes = new Uint8Array(600);
  bytes[0] = 0x30;
  bytes[1] = 0x82;
  bytes.set(new TextEncoder().encode("com.apple.dnsSettings.managed"), 200);
  assert.equal(looksLikeProfile(bytes), true);
});

test("looksLikeProfile rejects a 404 body", () => {
  assert.equal(looksLikeProfile(new TextEncoder().encode("404: Not Found")), false);
});

test("looksLikeProfile rejects an HTML error page", () => {
  const html = `<!DOCTYPE html><html><body>${"y".repeat(500)}</body></html>`;
  assert.equal(looksLikeProfile(new TextEncoder().encode(html)), false);
});

test("looksLikeProfile rejects an empty or tiny body", () => {
  assert.equal(looksLikeProfile(new Uint8Array(0)), false);
  assert.equal(looksLikeProfile(new Uint8Array(10)), false);
});

test("/download serves the profile with the Apple content type", async () => {
  await withFetch(
    async () => new Response(fakeProfile(), { status: 200 }),
    async () => {
      const res = await worker.fetch(requestFor("https://doh.example/download"), {});
      assert.equal(res.status, 200);
      // The whole point of the route: iOS needs this exact type.
      assert.equal(res.headers.get("content-type"), "application/x-apple-aspen-config");
      assert.match(res.headers.get("content-disposition"), /RevokeGuard\.mobileconfig/);
      // Must be a valid profile, not an error page.
      const body = new Uint8Array(await res.arrayBuffer());
      assert.equal(looksLikeProfile(body), true);
    },
  );
});

test("/download2 serves the enhanced profile with its own filename", async () => {
  await withFetch(
    async () => new Response(fakeProfile(), { status: 200 }),
    async () => {
      const res = await worker.fetch(requestFor("https://doh.example/download2"), {});
      assert.equal(res.status, 200);
      assert.equal(res.headers.get("content-type"), "application/x-apple-aspen-config");
      assert.match(res.headers.get("content-disposition"), /Enhanced/);
    },
  );
});

test("a missing upstream file becomes 502, never a broken profile", async () => {
  // This is the failure that matters: GitHub answers 404 with a short text
  // body. Forwarding that as a profile would install nothing useful on the
  // device while looking like a successful download.
  await withFetch(
    async () => new Response(fakeProfile(), { status: 404 }),
    async () => {
      const res = await worker.fetch(requestFor("https://doh.example/download"), {});
      assert.equal(res.status, 502, "404 with a valid-looking body must still be 502");
    },
  );
});

test("an upstream 200 carrying an HTML page is rejected", async () => {
  await withFetch(
    async () => new Response(`<html>${"z".repeat(500)}</html>`, { status: 200 }),
    async () => {
      const res = await worker.fetch(requestFor("https://doh.example/download"), {});
      assert.equal(res.status, 502);
    },
  );
});

test("a truncated body is rejected", async () => {
  await withFetch(
    async () => new Response(new TextEncoder().encode("<?xml"), { status: 200 }),
    async () => {
      const res = await worker.fetch(requestFor("https://doh.example/download"), {});
      assert.equal(res.status, 502);
    },
  );
});

test("a network failure becomes 502, not an unhandled rejection", async () => {
  await withFetch(
    async () => { throw new Error("connection reset"); },
    async () => {
      const res = await worker.fetch(requestFor("https://doh.example/download"), {});
      assert.equal(res.status, 502);
    },
  );
});

test("the raw base is configurable for other forks", async () => {
  let requested = null;
  await withFetch(
    async (url) => { requested = String(url); return new Response(fakeProfile()); },
    async () => {
      await worker.fetch(requestFor("https://doh.example/download"),
        { RAW_BASE: "https://raw.example/other/repo/main" });
    },
  );
  assert.match(requested, /^https:\/\/raw\.example\/other\/repo\/main\/output\//);
});

test("the two routes request different repository paths", async () => {
  const seen = [];
  await withFetch(
    async (url) => { seen.push(String(url)); return new Response(fakeProfile()); },
    async () => {
      await worker.fetch(requestFor("https://doh.example/download"), {});
      await worker.fetch(requestFor("https://doh.example/download2"), {});
    },
  );
  assert.match(seen[0], /output\/RevokeGuard_Auto-Sync\.mobileconfig$/);
  assert.match(seen[1], /output\/enhanced\/RevokeGuard_Enhanced\.mobileconfig$/);
});
