/*
 * Outils partagés : réponses JSON, vérification du jeton Firebase,
 * accès compte de service Google et Firestore (API REST).
 */

const enc = new TextEncoder();
const dec = new TextDecoder();

export function json(payload, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

/* ------------------------------------------------------------------ */
/*  Base64                                                             */
/* ------------------------------------------------------------------ */

function bytesToB64Url(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function b64ToBytes(value) {
  let normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const missing = normalized.length % 4;

  if (missing) normalized += "=".repeat(4 - missing);

  return Uint8Array.from(atob(normalized), (char) => char.charCodeAt(0));
}

/* ------------------------------------------------------------------ */
/*  Jeton d'identité Firebase                                          */
/* ------------------------------------------------------------------ */

const JWKS_URL =
  "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com";

export async function verifyIdToken(token, projectId) {
  const [headerPart, payloadPart, signaturePart] = token.split(".");

  if (!headerPart || !payloadPart || !signaturePart) {
    throw new Error("malformed");
  }

  const header = JSON.parse(dec.decode(b64ToBytes(headerPart)));
  const payload = JSON.parse(dec.decode(b64ToBytes(payloadPart)));

  if (header.alg !== "RS256") throw new Error("alg");

  const response = await fetch(JWKS_URL, {
    cf: { cacheTtl: 3600, cacheEverything: true },
  });
  const jwks = await response.json();
  const jwk = jwks.keys.find((key) => key.kid === header.kid);

  if (!jwk) throw new Error("kid");

  const key = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );

  const valid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    b64ToBytes(signaturePart),
    enc.encode(`${headerPart}.${payloadPart}`)
  );

  if (!valid) throw new Error("signature");

  const now = Math.floor(Date.now() / 1000);

  if (
    payload.exp <= now ||
    payload.iat > now + 60 ||
    payload.aud !== projectId ||
    payload.iss !== `https://securetoken.google.com/${projectId}` ||
    !payload.sub
  ) {
    throw new Error("claims");
  }

  return payload;
}

/*
 * Lit l'en-tête Authorization et renvoie les informations de
 * l'utilisateur (claims.sub = uid), ou null s'il n'est pas authentifié.
 */
export async function authenticate(request, env) {
  const authorization = request.headers.get("Authorization") ?? "";
  const token = authorization.startsWith("Bearer ")
    ? authorization.slice(7)
    : "";

  if (!token) return null;

  return verifyIdToken(token, env.FIREBASE_PROJECT_ID).catch(() => null);
}

/* ------------------------------------------------------------------ */
/*  Compte de service Google (Firestore + FCM)                         */
/* ------------------------------------------------------------------ */

let cachedAccessToken = null;

export async function getAccessToken(env) {
  const now = Math.floor(Date.now() / 1000);

  if (cachedAccessToken && cachedAccessToken.expiresAt - 60 > now) {
    return cachedAccessToken.value;
  }

  const header = bytesToB64Url(
    enc.encode(JSON.stringify({ alg: "RS256", typ: "JWT" }))
  );

  const claims = bytesToB64Url(
    enc.encode(
      JSON.stringify({
        iss: env.FIREBASE_CLIENT_EMAIL,
        scope:
          "https://www.googleapis.com/auth/datastore https://www.googleapis.com/auth/firebase.messaging",
        aud: "https://oauth2.googleapis.com/token",
        iat: now,
        exp: now + 3600,
      })
    )
  );

  const pem = env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n")
    .replace(/-----[A-Z ]+-----/g, "")
    .replace(/\s+/g, "");

  const privateKey = await crypto.subtle.importKey(
    "pkcs8",
    b64ToBytes(pem),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    privateKey,
    enc.encode(`${header}.${claims}`)
  );

  const response = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion: `${header}.${claims}.${bytesToB64Url(signature)}`,
    }),
  });

  if (!response.ok) throw new Error(`oauth_${response.status}`);

  const result = await response.json();

  cachedAccessToken = {
    value: result.access_token,
    expiresAt: now + (result.expires_in ?? 3600),
  };

  return cachedAccessToken.value;
}

/* ------------------------------------------------------------------ */
/*  Firestore (API REST)                                               */
/* ------------------------------------------------------------------ */

function documentsRoot(env) {
  return `https://firestore.googleapis.com/v1/projects/${env.FIREBASE_PROJECT_ID}/databases/(default)/documents`;
}

/* Nom complet d'un document, utilisé dans les écritures. */
export function docName(env, path) {
  return `projects/${env.FIREBASE_PROJECT_ID}/databases/(default)/documents/${path}`;
}

export async function getDoc(env, accessToken, path) {
  const response = await fetch(`${documentsRoot(env)}/${path}`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  if (response.status === 404) return null;
  if (!response.ok) throw new Error(`firestore_${response.status}`);

  return response.json();
}

/*
 * Écritures atomiques. Chaque écriture peut porter une précondition
 * (currentDocument) : si un autre processus a modifié le document entretemps,
 * rien n'est écrit et { ok: false, conflict: true } est renvoyé.
 */
export async function commit(env, accessToken, writes) {
  const response = await fetch(`${documentsRoot(env)}:commit`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ writes }),
  });

  if (response.ok) return { ok: true };

  const error = await response.json().catch(() => ({}));
  const status = error?.error?.status;

  if (
    status === "FAILED_PRECONDITION" ||
    status === "ABORTED" ||
    status === "ALREADY_EXISTS"
  ) {
    return { ok: false, conflict: true };
  }

  throw new Error(`firestore_commit_${response.status}_${status ?? ""}`);
}

export async function runQuery(env, accessToken, structuredQuery) {
  const response = await fetch(`${documentsRoot(env)}:runQuery`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ structuredQuery }),
  });

  if (!response.ok) throw new Error(`firestore_query_${response.status}`);

  const rows = await response.json();

  return rows.filter((row) => row.document).map((row) => row.document);
}

/* Valeurs Firestore. */
export const fv = {
  str: (value) => ({ stringValue: String(value) }),
  int: (value) => ({ integerValue: String(Math.trunc(value)) }),
  time: (date = new Date()) => ({ timestampValue: date.toISOString() }),
};

export function stringField(doc, name) {
  return doc?.fields?.[name]?.stringValue ?? "";
}

export function intField(doc, name) {
  const value = doc?.fields?.[name]?.integerValue;

  return value === undefined ? 0 : Number(value);
}

export function stringArray(doc, name) {
  return (doc?.fields?.[name]?.arrayValue?.values ?? [])
    .map((value) => value.stringValue)
    .filter(Boolean);
}
