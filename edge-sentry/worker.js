/**
 * edge-sentry — a Cloudflare Worker that gives the estate SIEM eyes at the edge.
 *
 * WHY THIS EXISTS ALONGSIDE THE WAF RULES
 * The WAF custom rules block. This Worker *reports*, in real time, from the
 * one vantage point the estate otherwise cannot see. Everything inbound
 * arrives through the Cloudflare tunnel, so by the time a request reaches
 * NPMplus or cloudflared the edge has already made its decision and the
 * client's real address survives only in a header. A Worker runs before all
 * of that and sees the request as Cloudflare sees it: true client IP, country,
 * ASN, bot score, and whether the edge challenged it.
 *
 * It is DETECT-AND-REPORT ONLY. It never blocks — blocking is the WAF's job,
 * where the rules are visible in the dashboard and can be switched off without
 * a redeploy. A Worker that blocks is a Worker that can lock you out of your
 * own estate at 3am with no UI to turn it off.
 *
 * ⚠️ FAIL-OPEN, ALWAYS. Every code path returns fetch(request). If the
 * scoring throws, if the alert POST hangs, if a binding is missing — the
 * request still goes through. A monitoring tool must never be able to take
 * the site down, and this one is in the request path of every proxied
 * hostname on the zone.
 */

// Same scoring vocabulary warden uses on the log side, so a finding here and
// a finding there are directly comparable rather than two private dialects.
const HOSTILE_PATHS = [
  [/\/\.env/i, 7, "secret-file-probe"],
  [/\/\.git\//i, 7, "secret-file-probe"],
  [/\/\.aws\//i, 7, "secret-file-probe"],
  [/\/etc\/passwd|\/etc\/shadow/i, 8, "sensitive-file"],
  [/\.\.\/|%2e%2e/i, 6, "path-traversal"],
  [/@fs\//i, 7, "vite-fs-read"],
  [/\/wp-(admin|login|content)/i, 3, "wordpress-probe"],
  [/\/phpmyadmin|\/pma\/|\/adminer/i, 4, "db-admin-probe"],
  [/\/actuator|\/console|\/solr|\/jenkins/i, 4, "app-probe"],
  [/union\s+select|sleep\(|benchmark\(/i, 8, "sqli-attempt"],
];

const HOSTILE_UA =
  /sqlmap|nikto|nmap|masscan|zgrab|nuclei|dirbuster|gobuster|wpscan/i;

// Paths that must NEVER be scored. /.well-known/ carries ACME certificate
// validation and OIDC discovery: flagging it would generate noise every time
// a certificate renews or Authelia is discovered, which is constantly.
const NEVER_SCORE = [/^\/\.well-known\//i];

function score(url, ua) {
  if (NEVER_SCORE.some((rx) => rx.test(url.pathname))) return null;

  // ⚠️ Match the DECODED request, not the raw one. `url.search` keeps percent
  // encoding, so `?id=1 union select 1` arrives as `union%20select` and a
  // /union\s+select/ regex never fires — an injection probe would sail
  // straight past. Caught by the unit test, not by reading the code.
  // Both forms are scored: decoding alone would miss a literal `%2e%2e`.
  const raw = url.pathname + url.search;
  let decoded = raw;
  try {
    decoded = decodeURIComponent(raw.replace(/\+/g, " "));
  } catch (_) {
    // Malformed percent-encoding — keep the raw form rather than giving up.
  }
  const target = raw === decoded ? raw : raw + "\n" + decoded;

  let points = 0;
  const kinds = [];
  for (const [rx, pts, name] of HOSTILE_PATHS) {
    if (rx.test(target)) {
      points += pts;
      kinds.push(name);
    }
  }
  if (HOSTILE_UA.test(ua)) {
    points += 5;
    kinds.push("hostile-user-agent");
  }
  return points > 0 ? { points, kinds } : null;
}

async function report(env, cf, req, url, hit) {
  if (!env.ALERT_WEBHOOK) return;
  const ip = req.headers.get("cf-connecting-ip") || "?";

  // Suppress our own address the same way siemalert does. SELF_IPS is a
  // comma-separated secret so the dynamic WAN lease can be updated without a
  // redeploy.
  const selves = (env.SELF_IPS || "").split(",").map((s) => s.trim());
  if (selves.includes(ip)) return;

  const body = {
    content:
      `🌐 **Edge** \`${ip}\`` +
      (cf?.country ? ` [${cf.country}]` : "") +
      ` — ${hit.kinds.join(",")} (score ${hit.points})\n` +
      `\`${req.method} ${url.hostname}${url.pathname}\`` +
      (cf?.asOrganization ? ` · ${cf.asOrganization}` : "") +
      (cf?.botManagement?.score != null ? ` · bot ${cf.botManagement.score}` : ""),
  };

  await fetch(env.ALERT_WEBHOOK, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const ua = request.headers.get("user-agent") || "";
      const hit = score(url, ua);
      if (hit) {
        // waitUntil: reporting must not add latency to the response, and a
        // slow Discord must not hold the request open.
        ctx.waitUntil(report(env, request.cf, request, url, hit).catch(() => {}));
      }
    } catch (_) {
      // Deliberately swallowed — see the fail-open note in the header.
    }
    return fetch(request);
  },
};
