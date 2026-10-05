/**
 * Anti-revoke DNS-over-HTTPS endpoint (Cloudflare Worker).
 *
 * Why a blanket NXDOMAIN answer is safe
 * -------------------------------------
 * The generated configuration profile routes a fixed list of Apple revocation
 * and verification hostnames here through `SupplementalMatchDomains`. Apple
 * documents that key as a *match* list: "A list of domain strings used to
 * determine which DNS queries use the DNS server."
 *
 * So the device only ever sends queries for the hostnames listed in the
 * profile -- nothing else on the device reaches this server. Blocking
 * everything is therefore the correct behaviour, not an oversight, and it
 * keeps the profile as the single source of truth: there is no second list
 * here to drift out of sync with it.
 *
 * The one genuine weakness of a blanket sinkhole is a hostname that lives
 * inside a blocked suffix but must still resolve (for example
 * `register.appattest.apple.com` under a blocked `appattest.apple.com`). The
 * optional ALLOWLIST variable is the escape hatch for exactly that case: names
 * on it are forwarded to UPSTREAM and resolve normally.
 */

const UPSTREAM = "https://cloudflare-dns.com/dns-query";
const MAX_LABELS = 128;
const DNS_HEADER_LENGTH = 12;
const RCODE_NXDOMAIN = 3;

/**
 * Read the question name and the offset just past the question section.
 * Returns null for anything malformed; the caller then answers NXDOMAIN
 * without echoing a question, which is still a valid refusal.
 */
export function parseQuestion(message) {
  if (message.length < DNS_HEADER_LENGTH) return null;

  let offset = DNS_HEADER_LENGTH;
  const labels = [];

  for (;;) {
    if (offset >= message.length) return null;
    const length = message[offset];

    if (length === 0) {
      offset += 1;
      break;
    }
    // A compression pointer is never valid in a query's question section.
    if ((length & 0xc0) !== 0) return null;
    if (offset + 1 + length > message.length) return null;

    labels.push(
      new TextDecoder().decode(message.subarray(offset + 1, offset + 1 + length)),
    );
    offset += 1 + length;

    if (labels.length > MAX_LABELS) return null;
  }

  // QTYPE + QCLASS
  if (offset + 4 > message.length) return null;

  return { name: labels.join(".").toLowerCase(), end: offset + 4 };
}

/** Build an NXDOMAIN reply that echoes the original question section. */
export function buildNxDomain(query, questionEnd) {
  const reply = new Uint8Array(questionEnd);
  reply.set(query.subarray(0, questionEnd));

  const recursionDesired = query[2] & 0x01;
  reply[2] = 0x80 | recursionDesired; // QR=1, OPCODE=0, AA=0, TC=0, RD=echo
  reply[3] = 0x80 | RCODE_NXDOMAIN;   // RA=1, RCODE=NXDOMAIN

  const questionCount = (query[4] << 8) | query[5];
  reply[4] = (questionCount >> 8) & 0xff;
  reply[5] = questionCount & 0xff;

  // ANCOUNT, NSCOUNT, ARCOUNT all zero.
  for (let i = 6; i < DNS_HEADER_LENGTH; i += 1) reply[i] = 0;

  return reply;
}

/** `example.com` on the allowlist also covers `a.example.com`. */
export function isAllowed(name, allowlist) {
  if (!name) return false;
  return allowlist.some(
    (entry) => name === entry || name.endsWith(`.${entry}`),
  );
}

export function parseAllowlist(value) {
  return String(value || "")
    .split(",")
    .map((entry) => entry.trim().toLowerCase().replace(/^\.+|\.+$/g, ""))
    .filter(Boolean);
}

const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;

function decodeBase64Url(value) {
  if (!BASE64URL_PATTERN.test(value)) return null;
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const remainder = normalized.length % 4;
  const padded = remainder ? normalized + "=".repeat(4 - remainder) : normalized;
  try {
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
    return bytes;
  } catch {
    return null;
  }
}

/** RFC 8484 allows both GET (?dns=) and POST (application/dns-message). */
async function readQuery(request) {
  if (request.method === "GET") {
    const encoded = new URL(request.url).searchParams.get("dns");
    if (!encoded) return null;
    return decodeBase64Url(encoded);
  }
  if (request.method === "POST") {
    const body = await request.arrayBuffer();
    return new Uint8Array(body);
  }
  return null;
}

function dnsResponse(bytes) {
  return new Response(bytes, {
    status: 200,
    headers: {
      "content-type": "application/dns-message",
      // Queries are matched against the profile's own list, so nothing here
      // should be cached by an intermediary.
      "cache-control": "no-store",
    },
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/health") {
      return new Response(
        JSON.stringify({
          status: "ok",
          role: "anti-revoke DoH sinkhole",
          allowlist: parseAllowlist(env && env.ALLOWLIST),
        }),
        { headers: { "content-type": "application/json" } },
      );
    }

    if (url.pathname !== "/dns-query") {
      return new Response("Not Found\n", { status: 404 });
    }

    const query = await readQuery(request);
    if (!query) {
      return new Response("Bad Request: expected a DNS query\n", { status: 400 });
    }

    const question = parseQuestion(query);
    const allowlist = parseAllowlist(env && env.ALLOWLIST);

    // Forward allowlisted names so they keep resolving; block everything else.
    if (question && isAllowed(question.name, allowlist)) {
      const upstream = await fetch(UPSTREAM, {
        method: "POST",
        headers: {
          "content-type": "application/dns-message",
          accept: "application/dns-message",
        },
        body: query,
      });
      return new Response(upstream.body, {
        status: upstream.status,
        headers: {
          "content-type": "application/dns-message",
          "cache-control": "no-store",
        },
      });
    }

    if (!question) {
      // Unparseable query: still refuse, rather than leaking it upstream.
      return dnsResponse(buildNxDomain(query, Math.min(query.length, DNS_HEADER_LENGTH)));
    }

    return dnsResponse(buildNxDomain(query, question.end));
  },
};
