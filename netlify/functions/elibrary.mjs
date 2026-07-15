import crypto from "node:crypto";

const ALLOWED_ACTIONS = new Set([
  "bootstrap",
  "recordVisit",
  "recordRead",
  "submitFeedback",
  "health",
]);

const MAX_BODY_BYTES = 20_000;
const UPSTREAM_TIMEOUT_MS = 25_000;
let bootstrapCache = null;
let bootstrapCacheExpiresAt = 0;

function jsonResponse(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      ...extraHeaders,
    },
  });
}

function getEnvironment(name) {
  return String(process.env[name] || "").trim();
}

function getAllowedOrigins() {
  const values = [
    ...getEnvironment("ALLOWED_ORIGINS").split(","),
    getEnvironment("URL"),
    getEnvironment("DEPLOY_PRIME_URL"),
  ];

  return new Set(
    values
      .map((value) => value.trim().replace(/\/+$/, ""))
      .filter(Boolean),
  );
}

function originIsAllowed(request) {
  const origin = String(request.headers.get("origin") || "").replace(/\/+$/, "");
  if (!origin) return true;

  const allowed = getAllowedOrigins();
  return allowed.size === 0 || allowed.has(origin);
}

function getClientFingerprint(request, secret) {
  const forwarded = String(
    request.headers.get("x-nf-client-connection-ip") ||
      request.headers.get("x-forwarded-for") ||
      "",
  )
    .split(",")[0]
    .trim();
  const userAgent = String(request.headers.get("user-agent") || "unknown").slice(0, 300);

  return crypto
    .createHmac("sha256", secret)
    .update(`${forwarded || "unknown"}|${userAgent}`)
    .digest("hex")
    .slice(0, 64);
}

function canonicalRequest(action, timestamp, nonce, clientKey, payloadText) {
  return [action, timestamp, nonce, clientKey, payloadText].join("\n");
}

function signRequest(secret, canonical) {
  return crypto.createHmac("sha256", secret).update(canonical).digest("hex");
}

async function callAppsScript({ action, payload, request }) {
  const gasUrl = getEnvironment("GAS_WEB_APP_URL");
  const secret = getEnvironment("API_SHARED_SECRET");

  if (!/^https:\/\/script\.google\.com\/macros\/s\/[A-Za-z0-9_-]+\/exec(?:\?.*)?$/.test(gasUrl)) {
    throw new Error("GAS_WEB_APP_URL belum valid pada Environment Variables Netlify.");
  }
  if (secret.length < 32) {
    throw new Error("API_SHARED_SECRET minimal 32 karakter dan belum dikonfigurasi dengan benar.");
  }

  const timestamp = Math.floor(Date.now() / 1000);
  const nonce = crypto.randomBytes(24).toString("hex");
  const clientKey = getClientFingerprint(request, secret);
  const payloadText = JSON.stringify(payload || {});
  const canonical = canonicalRequest(action, timestamp, nonce, clientKey, payloadText);
  const signature = signRequest(secret, canonical);

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);

  try {
    const upstream = await fetch(gasUrl, {
      method: "POST",
      headers: {
        "Content-Type": "text/plain; charset=utf-8",
        Accept: "application/json",
        "User-Agent": "E-Library-Netlify-Gateway/4.0",
      },
      body: JSON.stringify({
        action,
        timestamp,
        nonce,
        clientKey,
        payload: payloadText,
        signature,
      }),
      redirect: "follow",
      signal: controller.signal,
    });

    const text = await upstream.text();
    let result;
    try {
      result = JSON.parse(text);
    } catch {
      throw new Error("Backend Apps Script mengembalikan respons yang tidak valid.");
    }

    if (!upstream.ok) {
      throw new Error(result?.pesan || `Backend gagal dengan status ${upstream.status}.`);
    }
    return result;
  } catch (error) {
    if (error?.name === "AbortError") {
      throw new Error("Backend Apps Script terlalu lama merespons.");
    }
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

export default async function handler(request) {
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        Allow: "POST, OPTIONS",
        "Cache-Control": "no-store",
      },
    });
  }

  if (request.method !== "POST") {
    return jsonResponse(
      { status: "error", pesan: "Metode permintaan tidak diizinkan." },
      405,
      { Allow: "POST, OPTIONS" },
    );
  }

  if (!originIsAllowed(request)) {
    return jsonResponse(
      { status: "error", pesan: "Origin permintaan tidak diizinkan." },
      403,
    );
  }

  const rawBody = await request.text();
  if (!rawBody || Buffer.byteLength(rawBody, "utf8") > MAX_BODY_BYTES) {
    return jsonResponse(
      { status: "error", pesan: "Permintaan kosong atau terlalu besar." },
      413,
    );
  }

  let body;
  try {
    body = JSON.parse(rawBody);
  } catch {
    return jsonResponse(
      { status: "error", pesan: "Format permintaan tidak valid." },
      400,
    );
  }

  const action = String(body?.action || "").replace(/[^A-Za-z0-9_.-]/g, "").slice(0, 50);
  if (!ALLOWED_ACTIONS.has(action)) {
    return jsonResponse(
      { status: "error", pesan: "Aksi API tidak dikenali." },
      400,
    );
  }

  const payload = body?.payload && typeof body.payload === "object" ? body.payload : {};

  // Cache singkat di instance Function untuk mengurangi panggilan bootstrap berulang.
  if (action === "bootstrap" && bootstrapCache && Date.now() < bootstrapCacheExpiresAt) {
    return jsonResponse(bootstrapCache, 200, {
      "Cache-Control": "public, max-age=30, stale-while-revalidate=120",
    });
  }

  try {
    const result = await callAppsScript({ action, payload, request });

    if (action === "bootstrap" && result?.status === "success") {
      bootstrapCache = result;
      bootstrapCacheExpiresAt = Date.now() + 60_000;
    }

    const status = result?.status === "success" ? 200 : 400;
    return jsonResponse(
      result,
      status,
      action === "bootstrap" && status === 200
        ? { "Cache-Control": "public, max-age=30, stale-while-revalidate=120" }
        : {},
    );
  } catch (error) {
    console.error("E-Library gateway error:", error);
    return jsonResponse(
      {
        status: "error",
        pesan:
          process.env.NODE_ENV === "development"
            ? String(error?.message || error)
            : "Layanan perpustakaan sedang tidak dapat dihubungi.",
      },
      502,
    );
  }
}
