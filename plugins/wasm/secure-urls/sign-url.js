const crypto = require("node:crypto");
const net = require("node:net");

const [rawURL, keyName] = process.argv.slice(2);
const { SECURE_KEY, PREFIX, CLIENT_IP, TTL = "3600" } = process.env;

if (!rawURL || !keyName || !SECURE_KEY) {
  throw new Error("Usage: SECURE_KEY=... node sign-url.js <url> <key-name>");
}

const ttl = Number(TTL);
if (!Number.isSafeInteger(ttl) || ttl <= 0) throw new Error("Invalid TTL");
if (CLIENT_IP && !net.isIP(CLIENT_IP)) throw new Error("Invalid CLIENT_IP");

const url = new URL(rawURL);
if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || url.hash) {
  throw new Error("URL must be HTTP(S), without credentials or a fragment");
}

for (const name of ["EX-Expires", "EX-KeyName", "EX-Sign", "EX-UrlPrefix", "EX-Client-IP"]) {
  if (url.searchParams.has(name)) throw new Error(`URL already contains ${name}`);
}
if (/%(?![0-9a-f]{2})/i.test(url.search) || url.search.includes(";")) {
  throw new Error("Invalid URL query encoding");
}

const base = url.origin + url.pathname;
const expires = Math.floor(Date.now() / 1000) + ttl;
let prefixParam = "";

if (PREFIX) {
  if (url.search) throw new Error("Prefix URLs cannot contain extra query parameters");
  const prefixURL = new URL(PREFIX);
  if (prefixURL.search || prefixURL.hash || prefixURL.username || prefixURL.password ||
      !(`${url.origin}${decodeURIComponent(url.pathname)}`).startsWith(PREFIX)) {
    throw new Error("PREFIX must match the request scheme, host, and path");
  }
  prefixParam = Buffer.from(PREFIX).toString("base64").replace(/\+/g, "-").replace(/\//g, "_");
}

const tail = `EX-Expires=${expires}&EX-KeyName=${encodeURIComponent(keyName)}` +
  (CLIENT_IP ? `&EX-Client-IP=${encodeURIComponent(CLIENT_IP)}` : "");
const query = PREFIX
  ? `EX-UrlPrefix=${encodeURIComponent(prefixParam)}&${tail}`
  : (url.search ? `${url.search.slice(1)}&` : "") + tail;
const unsigned = `${base}?${query}`;
const payload = PREFIX
  ? `${base}?EX-UrlPrefix=${prefixParam}&EX-Expires=${expires}&EX-KeyName=${keyName}` +
      (CLIENT_IP ? `&EX-Client-IP=${CLIENT_IP}` : "")
  : unsigned;
const signature = crypto.createHmac("sha256", SECURE_KEY).update(payload).digest("hex");
console.log(`${unsigned}&EX-Sign=${signature}`);