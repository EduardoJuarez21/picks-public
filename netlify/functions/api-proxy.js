// Rate limiting: max 20 requests per IP per minute
const rateLimitMap = new Map();
const RATE_LIMIT = 20;
const RATE_WINDOW = 60 * 1000;

function isRateLimited(ip) {
  const now = Date.now();
  const entry = rateLimitMap.get(ip) || { count: 0, start: now };
  if (now - entry.start > RATE_WINDOW) {
    rateLimitMap.set(ip, { count: 1, start: now });
    return false;
  }
  entry.count++;
  rateLimitMap.set(ip, entry);
  if (rateLimitMap.size > 1000) {
    for (const [k, v] of rateLimitMap) {
      if (now - v.start > RATE_WINDOW) rateLimitMap.delete(k);
    }
  }
  return entry.count > RATE_LIMIT;
}

exports.handler = async function handler(event) {
  const ip = getHeader(event.headers, "x-forwarded-for").split(",")[0].trim()
           || getHeader(event.headers, "x-nf-client-connection-ip")
           || "unknown";
  if (isRateLimited(ip)) {
    return json(429, { status: "error", error: "too many requests" });
  }

  const path = extractProxyPath(event);
  const route = getRouteKey(path);
  const backendBaseRaw = selectBackendBase(route);
  const authHeader = "X-API-Token";
  const authToken = selectAuthToken(route);

  if (!backendBaseRaw || !authToken) {
    return json(500, { status: "error", error: "service unavailable" });
  }

  const backendBase = backendBaseRaw.replace(/\/+$/, "");
  const query = event.rawQueryString || event.rawQuery || stringifyQuery(event.queryStringParameters || {});
  const targetUrl = `${backendBase}/${path}${query ? `?${query}` : ""}`;

  const upstreamHeaders = new Headers();
  const contentType = getHeader(event.headers, "content-type");
  const accept = getHeader(event.headers, "accept");
  if (contentType) upstreamHeaders.set("content-type", contentType);
  if (accept) upstreamHeaders.set("accept", accept);

  upstreamHeaders.set(authHeader, authToken);
  upstreamHeaders.set("authorization", `Bearer ${authToken}`);

  const method = event.httpMethod || "GET";
  const body = decodeBody(event);
  const hasBody = body !== undefined && method !== "GET" && method !== "HEAD";

  try {
    const upstreamRes = await fetch(targetUrl, {
      method,
      headers: upstreamHeaders,
      body: hasBody ? body : undefined,
    });
    const text = await upstreamRes.text();
    const responseHeaders = {
      "content-type": upstreamRes.headers.get("content-type") || "application/json; charset=utf-8",
      "cache-control": "no-store",
    };
    return {
      statusCode: upstreamRes.status,
      headers: responseHeaders,
      body: text,
    };
  } catch {
    return json(502, { status: "error", error: "service unavailable" });
  }
};

function extractProxyPath(event) {
  const splat = event?.pathParameters?.splat;
  if (splat) return String(splat).replace(/^\/+/, "");

  const eventPath = String(event?.path || "");
  const fnMarker = "/.netlify/functions/api-proxy/";
  const fnIdx = eventPath.indexOf(fnMarker);
  if (fnIdx !== -1) {
    return eventPath.slice(fnIdx + fnMarker.length).replace(/^\/+/, "");
  }

  if (eventPath.startsWith("/api/")) {
    return eventPath.slice("/api/".length).replace(/^\/+/, "");
  }

  return eventPath.replace(/^\/+/, "");
}

function getRouteKey(path) {
  const first = String(path || "")
    .split("/")[0]
    .trim()
    .toLowerCase();
  if (first === "nba") return "nba";
  if (first === "nfl") return "nfl";
  return "default";
}

function selectBackendBase(route) {
  if (route === "nba") {
    return firstNonEmpty(process.env.NBA_BACKEND_BASE, process.env.BACKEND_BASE_NBA, process.env.BACKEND_BASE, process.env.API_BASE);
  }
  if (route === "nfl") {
    return firstNonEmpty(process.env.NFL_BACKEND_BASE, process.env.BACKEND_BASE_NFL, process.env.BACKEND_BASE, process.env.API_BASE);
  }
  return firstNonEmpty(process.env.BACKEND_BASE, process.env.API_BASE);
}

function selectAuthToken(route) {
  if (route === "nba") {
    return firstNonEmpty(process.env.NBA_API_AUTH_TOKEN, process.env.API_AUTH_TOKEN_NBA, process.env.API_AUTH_TOKEN);
  }
  if (route === "nfl") {
    return firstNonEmpty(process.env.NFL_API_AUTH_TOKEN, process.env.API_AUTH_TOKEN_NFL, process.env.API_AUTH_TOKEN);
  }
  return firstNonEmpty(process.env.API_AUTH_TOKEN);
}


function firstNonEmpty(...values) {
  for (const value of values) {
    const cleaned = String(value || "").trim();
    if (cleaned) return cleaned;
  }
  return "";
}

function decodeBody(event) {
  if (!event.body) return undefined;
  if (event.isBase64Encoded) {
    return Buffer.from(event.body, "base64");
  }
  return event.body;
}

function getHeader(headers, name) {
  if (!headers) return "";
  const lowerName = name.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (k && k.toLowerCase() === lowerName) return Array.isArray(v) ? v[0] : (v || "");
  }
  return "";
}

function stringifyQuery(query) {
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) {
    if (v === undefined || v === null) continue;
    params.append(k, String(v));
  }
  return params.toString();
}

function json(statusCode, payload) {
  return {
    statusCode,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
    body: JSON.stringify(payload),
  };
}
