/*
 * Worker Cloudflare — Match 360
 *
 *   POST /notify                      notifications push (appel, message)
 *   GET  /wallet/providers            opérateurs de retrait disponibles
 *   POST /wallet/withdraw             retrait Mobile Money
 *   POST /webhooks/pawapay/<secret>   callback pawaPay
 *   (planifié) réconciliation des retraits toutes les 10 minutes
 *
 * Fichiers à placer ensemble dans src/ : index.js, google.js, wallet.js
 *
 * Variables : FIREBASE_PROJECT_ID, PARTICIPANTS_FIELD, PAWAPAY_BASE_URL,
 *             WITHDRAWALS_ENABLED, WITHDRAW_MIN_XOF
 * Secrets   : FIREBASE_CLIENT_EMAIL, FIREBASE_PRIVATE_KEY,
 *             PAWAPAY_API_TOKEN, WEBHOOK_SECRET
 */

import {
  json,
  authenticate,
  getAccessToken,
  getDoc,
  stringField,
  stringArray,
} from "./google.js";

import {
  handleProviders,
  handleWithdraw,
  handlePawapayWebhook,
  reconcilePayouts,
} from "./wallet.js";

const WEBHOOK_PREFIX = "/webhooks/pawapay/";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const { pathname } = url;

    try {
      if (request.method === "POST" && pathname.startsWith(WEBHOOK_PREFIX)) {
        return await handlePawapayWebhook(
          request,
          env,
          pathname.slice(WEBHOOK_PREFIX.length)
        );
      }

      if (request.method === "POST" && pathname === "/notify") {
        return await handleNotify(request, env);
      }

      if (request.method === "GET" && pathname === "/wallet/providers") {
        const claims = await authenticate(request, env);

        if (!claims) return json({ error: "unauthorized" }, 401);

        return await handleProviders(env);
      }

      if (request.method === "POST" && pathname === "/wallet/withdraw") {
        const claims = await authenticate(request, env);

        if (!claims) return json({ error: "unauthorized" }, 401);

        return await handleWithdraw(request, env, claims);
      }

      return json({ error: "not_found" }, 404);
    } catch (error) {
      console.error("worker error", error?.message ?? error);
      return json({ error: "server_error" }, 500);
    }
  },

  async scheduled(event, env, ctx) {
    ctx.waitUntil(reconcilePayouts(env));
  },
};

/* ------------------------------------------------------------------ */
/*  Notifications push                                                 */
/* ------------------------------------------------------------------ */

async function handleNotify(request, env) {
  const claims = await authenticate(request, env);

  if (!claims) return json({ error: "unauthorized" }, 401);

  const body = await request.json().catch(() => null);
  const idPattern = /^[A-Za-z0-9_-]{1,128}$/;

  if (
    !body ||
    (body.type !== "call" && body.type !== "message") ||
    !idPattern.test(body.matchId ?? "") ||
    (body.type === "message" && !idPattern.test(body.messageId ?? ""))
  ) {
    return json({ error: "bad_request" }, 400);
  }

  const accessToken = await getAccessToken(env);

  // L'appelant fait-il partie de cette conversation ?
  const matchDoc = await getDoc(env, accessToken, `matches/${body.matchId}`);
  const participants = stringArray(matchDoc, env.PARTICIPANTS_FIELD || "users");

  if (!participants.includes(claims.sub)) {
    return json({ error: "forbidden" }, 403);
  }

  const recipientUid = participants.find((uid) => uid !== claims.sub);

  if (!recipientUid) return json({ error: "no_recipient" }, 404);

  const [senderDoc, recipientDoc] = await Promise.all([
    getDoc(env, accessToken, `users/${claims.sub}`),
    getDoc(env, accessToken, `users/${recipientUid}`),
  ]);

  const fcmToken = stringField(recipientDoc, "fcmToken");

  if (!fcmToken) return json({ sent: false, reason: "no_token" });

  const senderName = stringField(senderDoc, "firstName") || "Match 360";

  let data;
  let ttl;

  if (body.type === "call") {
    const call = await getDoc(env, accessToken, `calls/${body.matchId}`);

    if (
      stringField(call, "callerUid") !== claims.sub ||
      stringField(call, "status") !== "ringing"
    ) {
      return json({ error: "no_active_call" }, 409);
    }

    const audioOnly = call.fields?.audioOnly?.booleanValue ?? true;

    data = {
      type: "call",
      matchId: body.matchId,
      callerName: senderName,
      audioOnly: String(audioOnly),
    };
    ttl = "45s";
  } else {
    const message = await getDoc(
      env,
      accessToken,
      `matches/${body.matchId}/messages/${body.messageId}`
    );

    if (stringField(message, "senderUid") !== claims.sub) {
      return json({ error: "no_message" }, 404);
    }

    data = {
      type: "message",
      matchId: body.matchId,
      senderName,
      text: stringField(message, "text").slice(0, 140),
    };
    ttl = "86400s";
  }

  return json(await sendFcm(env, accessToken, fcmToken, data, ttl));
}

async function sendFcm(env, accessToken, token, data, ttl) {
  const response = await fetch(
    `https://fcm.googleapis.com/v1/projects/${env.FIREBASE_PROJECT_ID}/messages:send`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        message: {
          token,
          data, // message « data » : l'appli construit elle-même la notification
          android: { priority: "HIGH", ttl },
        },
      }),
    }
  );

  if (response.ok) return { sent: true };

  const error = await response.json().catch(() => ({}));

  return {
    sent: false,
    reason: error?.error?.status ?? `http_${response.status}`,
  };
  }
    
