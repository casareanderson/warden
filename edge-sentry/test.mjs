// Exercise the Worker's scoring in isolation by importing the module and
// driving fetch() with a stub, so the rules are proven rather than assumed.
import worker from "./worker.js";

const posts = [];
globalThis.fetch = async (u, opts) => {
  if (typeof u === "string" && u.startsWith("https://discord")) {
    posts.push(JSON.parse(opts.body).content);
    return new Response("ok");
  }
  return new Response("origin");          // the pass-through
};

const env = { ALERT_WEBHOOK: "https://discord.example/wh", SELF_IPS: "203.0.113.10" };
const waits = [];
const ctx = { waitUntil: (p) => waits.push(p) };

async function hit(path, { ua = "Mozilla/5.0", ip = "203.0.113.9" } = {}) {
  posts.length = 0; waits.length = 0;
  const req = new Request("https://photos.example.com" + path, {
    headers: { "user-agent": ua, "cf-connecting-ip": ip },
  });
  req.cf = { country: "RU", asOrganization: "Example AS" };
  const res = await worker.fetch(req, env, ctx);
  await Promise.all(waits);
  return { alerted: posts.length > 0, msg: posts[0], passed: res.status === 200 };
}

const cases = [
  ["/.env",                                   true,  "secret file probe"],
  ["/index.php?id=1 union select 1",          true,  "sqli in query"],
  ["/../../etc/passwd",                       true,  "traversal"],
  ["/wp-login.php",                           true,  "wordpress probe"],
  ["/.well-known/openid-configuration",       false, "OIDC discovery MUST NOT alert"],
  ["/.well-known/acme-challenge/xyz",         false, "ACME MUST NOT alert"],
  ["/api/assets/abc/thumbnail?size=thumbnail",false, "normal Immich request"],
  ["/_next/static/chunk.js",                  false, "SPA chunk (NetBird cold load)"],
];

let bad = 0;
for (const [path, want, label] of cases) {
  const r = await hit(path);
  const ok = r.alerted === want && r.passed;
  if (!ok) bad++;
  console.log(`${ok ? "PASS" : "FAIL"}  alert=${String(r.alerted).padEnd(5)} passthrough=${r.passed}  ${label}`);
}

// scanner UA on an otherwise innocent path
let r = await hit("/", { ua: "sqlmap/1.7" });
console.log(`${r.alerted ? "PASS" : "FAIL"}  scanner user-agent on /`);
if (!r.alerted) bad++;

// our own address must be suppressed
r = await hit("/.env", { ip: "203.0.113.10" });
console.log(`${!r.alerted ? "PASS" : "FAIL"}  own WAN address suppressed`);
if (r.alerted) bad++;

// scoring throws -> request still served (fail-open)
const boom = new Request("https://photos.example.com/.env");
Object.defineProperty(boom, "url", { get() { throw new Error("boom"); } });
const res = await worker.fetch(boom, env, ctx);
console.log(`${res.status === 200 ? "PASS" : "FAIL"}  fails open when scoring throws`);
if (res.status !== 200) bad++;

console.log(bad === 0 ? "\nALL TESTS PASSED" : `\n${bad} FAILURE(S)`);
process.exit(bad ? 1 : 0);
