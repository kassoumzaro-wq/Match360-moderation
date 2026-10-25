/*
 * Portefeuille en FCFA (XOF) et retraits Mobile Money.
 * Pays : Burkina Faso (BFA), Côte d'Ivoire (CIV), Mali (MLI).
 * Prestataire : pawaPay (API v2).
 *
 * Principes :
 *  - le solde n'est JAMAIS modifiable par l'appli, seulement par ce Worker ;
 *  - chaque retrait débite le portefeuille AVANT l'appel au prestataire,
 *    dans une écriture atomique, puis rembourse si le retrait échoue ;
 *  - les statuts sont toujours revérifiés auprès de pawaPay (on ne fait pas
 *    confiance au contenu d'un callback) et réconciliés par une tâche planifiée ;
 *  - les retraits sont désactivés tant que WITHDRAWALS_ENABLED n'est pas "true".
 *
 * Firestore :
 *   wallets/{uid}         { balance (entier, FCFA), currency, updatedAt }
 *   wallet_ledger/{id}    { uid, type, amount (signé), balanceAfter, payoutId, createdAt }
 *   payouts/{payoutId}    { uid, amount, currency, country, provider, phoneNumber,
 *                           status, failureCode, createdAt, updatedAt }
 *   users/{uid}.kycStatus = "verified"  (écrit uniquement par toi / le serveur)
 *
 * Variables : PAWAPAY_BASE_URL, WITHDRAWALS_ENABLED, WITHDRAW_MIN_XOF
 * Secrets   : PAWAPAY_API_TOKEN, WEBHOOK_SECRET
 */

import {
  json,
  getAccessToken,
  getDoc,
  commit,
  runQuery,
  docName,
  fv,
  stringField,
  intField,
} from "./google.js";

const ALLOWED_COUNTRIES = ["BFA", "CIV", "MLI"];
const CURRENCY = "XOF";
const RECONCILE_AFTER_MS = 15 * 60 * 1000;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/* ------------------------------------------------------------------ */
/*  pawaPay                                                            */
/* ------------------------------------------------------------------ */

function pawa(env, path, init = {}) {
  const base = env.PAWAPAY_BASE_URL || "https://api.sandbox.pawapay.io";

  return fetch(`${base}${path}`, {
    ...init,
    headers: {
      Authorization: `Bearer ${env.PAWAPAY_API_TOKEN}`,
      "Content-Type": "application/json",
    },
  });
}

/*
 * Opérateurs réellement activés sur TON compte pawaPay pour les retraits,
 * avec leurs limites. Rien n'est écrit en dur : si un opérateur n'est pas
 * disponible dans un pays, il n'apparaît tout simplement pas.
 */
async function getPayoutConfig(env, country) {
  const response = await pawa(
    env,
    `/v2/active-conf?country=${country}&operationType=PAYOUT`
  );

  if (!response.ok) return null;

  const config = await response.json();
  const entry = (config.countries ?? []).find((c) => c.country === country);

  if (!entry) return null;

  const providers = [];

  for (const provider of entry.providers ?? []) {
    const currency = (provider.currencies ?? []).find(
      (c) => c.currency === CURRENCY
    );
    const payout = currency?.operationTypes?.PAYOUT;

    if (!payout) continue;

    providers.push({
      provider: provider.provider,
      displayName: provider.displayName ?? provider.provider,
      minAmount: Number(payout.minAmount ?? 0),
      maxAmount: Number(payout.maxAmount ?? 0),
    });
  }

  return { country, prefix: entry.prefix, providers };
}

/* ------------------------------------------------------------------ */
/*  GET /wallet/providers                                              */
/* ------------------------------------------------------------------ */

export async function handleProviders(env) {
  const configs = await Promise.all(
    ALLOWED_COUNTRIES.map((country) =>
      getPayoutConfig(env, country).catch(() => null)
    )
  );

  return json({
    currency: CURRENCY,
    countries: configs.filter((c) => c && c.providers.length > 0),
  });
}

/* ------------------------------------------------------------------ */
/*  POST /wallet/withdraw                                              */
/* ------------------------------------------------------------------ */

export async function handleWithdraw(request, env, claims) {
  if (env.WITHDRAWALS_ENABLED !== "true") {
    return json({ error: "withdrawals_disabled" }, 503);
  }

  const body = await request.json().catch(() => null);
  const amount = Number(body?.amount);
  const country = body?.country;
  const provider = body?.provider;
  const phone = String(body?.phoneNumber ?? "").replace(/\D/g, "");

  if (
    !Number.isInteger(amount) ||
    amount <= 0 ||
    !ALLOWED_COUNTRIES.includes(country) ||
    typeof provider !== "string" ||
    !/^[A-Z0-9_]{3,40}$/.test(provider) ||
    phone.length < 8 ||
    phone.length > 15
  ) {
    return json({ error: "bad_request" }, 400);
  }

  const platformMin = Number(env.WITHDRAW_MIN_XOF || 0);

  if (amount < platformMin) {
    return json({ error: "amount_out_of_range", min: platformMin }, 400);
  }

  const accessToken = await getAccessToken(env);

  // 1. Identité vérifiée ?
  const user = await getDoc(env, accessToken, `users/${claims.sub}`);

  if (stringField(user, "kycStatus") !== "verified") {
    return json({ error: "kyc_required" }, 403);
  }

  // 2. Opérateur disponible et montant dans les limites ?
  const config = await getPayoutConfig(env, country);
  const providerConfig = config?.providers.find((p) => p.provider === provider);

  if (!providerConfig) return json({ error: "provider_unavailable" }, 400);

  if (amount < providerConfig.minAmount || amount > providerConfig.maxAmount) {
    return json(
      {
        error: "amount_out_of_range",
        min: Math.max(providerConfig.minAmount, platformMin),
        max: providerConfig.maxAmount,
      },
      400
    );
  }

  // 3. Opérateur en panne ?
  const availability = await pawa(
    env,
    `/v2/availability?country=${country}&operationType=PAYOUT`
  )
    .then((r) => (r.ok ? r.json() : []))
    .catch(() => []);

  const state = availability
    .find((c) => c.country === country)
    ?.providers?.find((p) => p.provider === provider)?.operationTypes?.PAYOUT;

  if (state === "CLOSED") return json({ error: "provider_closed" }, 503);

  // 4. Numéro valide, et bien du pays choisi ?
  const predict = await pawa(env, "/v2/predict-provider", {
    method: "POST",
    body: JSON.stringify({ phoneNumber: phone }),
  });

  if (!predict.ok) return json({ error: "invalid_phone" }, 400);

  const predicted = await predict.json();

  if (predicted.country !== country) {
    return json({ error: "phone_country_mismatch" }, 400);
  }

  // 5. Débit du portefeuille + création du retrait (écriture atomique).
  const payoutId = crypto.randomUUID();

  const debit = await debitWallet(env, accessToken, claims.sub, amount, {
    payoutId,
    country,
    provider,
    phoneNumber: predicted.phoneNumber,
  });

  if (!debit.ok) return json({ error: debit.error }, debit.status);

  // 6. Envoi à pawaPay.
  try {
    const response = await pawa(env, "/v2/payouts", {
      method: "POST",
      body: JSON.stringify({
        payoutId,
        amount: String(amount),
        currency: CURRENCY,
        recipient: {
          type: "MMO",
          accountDetails: {
            phoneNumber: predicted.phoneNumber,
            provider,
          },
        },
      }),
    });

    const result = await response.json().catch(() => ({}));

    if (
      response.ok &&
      (result.status === "ACCEPTED" || result.status === "DUPLICATE_IGNORED")
    ) {
      await transitionPayout(env, accessToken, payoutId, ["PENDING"], "ACCEPTED");

      return json({ payoutId, status: "ACCEPTED" });
    }

    if (result.status === "REJECTED") {
      await refundPayout(
        env,
        accessToken,
        payoutId,
        result.failureReason?.failureCode ?? "REJECTED"
      );

      return json({ payoutId, status: "FAILED" }, 502);
    }

    // Réponse incertaine (erreur 500, UNKNOWN_ERROR…) : on vérifie.
    const status = await syncPayout(env, accessToken, payoutId, {
      refundIfNotFound: true,
    });

    return json({ payoutId, status });
  } catch (error) {
    console.error("payout initiation error", error?.message ?? error);

    const status = await syncPayout(env, accessToken, payoutId, {
      refundIfNotFound: true,
    }).catch(() => "PENDING");

    return json({ payoutId, status });
  }
}

/* ------------------------------------------------------------------ */
/*  Opérations atomiques sur le portefeuille                           */
/* ------------------------------------------------------------------ */

async function debitWallet(env, accessToken, uid, amount, payout) {
  for (let attempt = 0; attempt < 4; attempt++) {
    const wallet = await getDoc(env, accessToken, `wallets/${uid}`);

    if (!wallet) {
      return { ok: false, error: "insufficient_funds", status: 402 };
    }

    const balance = intField(wallet, "balance");

    if (balance < amount) {
      return { ok: false, error: "insufficient_funds", status: 402 };
    }

    const now = fv.time();

    const result = await commit(env, accessToken, [
      {
        update: {
          name: docName(env, `wallets/${uid}`),
          fields: { balance: fv.int(balance - amount), updatedAt: now },
        },
        updateMask: { fieldPaths: ["balance", "updatedAt"] },
        currentDocument: { updateTime: wallet.updateTime },
      },
      {
        update: {
          name: docName(env, `payouts/${payout.payoutId}`),
          fields: {
            uid: fv.str(uid),
            amount: fv.int(amount),
            currency: fv.str(CURRENCY),
            country: fv.str(payout.country),
            provider: fv.str(payout.provider),
            phoneNumber: fv.str(payout.phoneNumber),
            status: fv.str("PENDING"),
            createdAt: now,
            updatedAt: now,
          },
        },
        currentDocument: { exists: false },
      },
      ledgerWrite(env, {
        uid,
        type: "withdrawal_hold",
        amount: -amount,
        balanceAfter: balance - amount,
        payoutId: payout.payoutId,
        now,
      }),
    ]);

    if (result.ok) return { ok: true };
  }

  return { ok: false, error: "busy", status: 409 };
}

function ledgerWrite(env, entry) {
  return {
    update: {
      name: docName(env, `wallet_ledger/${crypto.randomUUID()}`),
      fields: {
        uid: fv.str(entry.uid),
        type: fv.str(entry.type),
        amount: fv.int(entry.amount),
        balanceAfter: fv.int(entry.balanceAfter),
        payoutId: fv.str(entry.payoutId),
        createdAt: entry.now,
      },
    },
    currentDocument: { exists: false },
  };
}

/*
 * Rembourse un retrait échoué. Idempotent : un retrait déjà réglé
 * (COMPLETED ou FAILED) n'est jamais remboursé deux fois.
 */
async function refundPayout(env, accessToken, payoutId, failureCode) {
  for (let attempt = 0; attempt < 4; attempt++) {
    const payout = await getDoc(env, accessToken, `payouts/${payoutId}`);

    if (!payout) return false;

    const status = stringField(payout, "status");

    if (status === "COMPLETED" || status === "FAILED") return false;

    const uid = stringField(payout, "uid");
    const amount = intField(payout, "amount");
    const wallet = await getDoc(env, accessToken, `wallets/${uid}`);

    if (!wallet) return false;

    const balance = intField(wallet, "balance");
    const now = fv.time();

    const result = await commit(env, accessToken, [
      {
        update: {
          name: docName(env, `wallets/${uid}`),
          fields: { balance: fv.int(balance + amount), updatedAt: now },
        },
        updateMask: { fieldPaths: ["balance", "updatedAt"] },
        currentDocument: { updateTime: wallet.updateTime },
      },
      {
        update: {
          name: docName(env, `payouts/${payoutId}`),
          fields: {
            status: fv.str("FAILED"),
            failureCode: fv.str(failureCode),
            updatedAt: now,
          },
        },
        updateMask: { fieldPaths: ["status", "failureCode", "updatedAt"] },
        currentDocument: { updateTime: payout.updateTime },
      },
      ledgerWrite(env, {
        uid,
        type: "withdrawal_refund",
        amount,
        balanceAfter: balance + amount,
        payoutId,
        now,
      }),
    ]);

    if (result.ok) return true;
  }

  return false;
}

/* Change le statut d'un retrait seulement s'il est dans un état attendu. */
async function transitionPayout(
  env,
  accessToken,
  payoutId,
  allowedFrom,
  newStatus,
  extra = {}
) {
  for (let attempt = 0; attempt < 3; attempt++) {
    const payout = await getDoc(env, accessToken, `payouts/${payoutId}`);

    if (!payout) return false;
    if (!allowedFrom.includes(stringField(payout, "status"))) return false;

    const fields = { status: fv.str(newStatus), updatedAt: fv.time(), ...extra };

    const result = await commit(env, accessToken, [
      {
        update: { name: docName(env, `payouts/${payoutId}`), fields },
        updateMask: { fieldPaths: Object.keys(fields) },
        currentDocument: { updateTime: payout.updateTime },
      },
    ]);

    if (result.ok) return true;
  }

  return false;
}

/* ------------------------------------------------------------------ */
/*  Synchronisation avec pawaPay                                       */
/* ------------------------------------------------------------------ */

/*
 * Interroge pawaPay et met à jour le retrait (et rembourse si échec).
 * Renvoie le statut local après synchronisation.
 */
async function syncPayout(
  env,
  accessToken,
  payoutId,
  { refundIfNotFound = false } = {}
) {
  const payout = await getDoc(env, accessToken, `payouts/${payoutId}`);

  if (!payout) return "UNKNOWN";

  const current = stringField(payout, "status");

  if (current === "COMPLETED" || current === "FAILED") return current;

  const response = await pawa(env, `/v2/payouts/${payoutId}`);

  if (!response.ok) return current;

  const result = await response.json().catch(() => null);

  if (!result) return current;

  if (result.status === "NOT_FOUND") {
    // Jamais arrivé chez pawaPay : on peut rembourser sans risque.
    if (refundIfNotFound) {
      await refundPayout(env, accessToken, payoutId, "NOT_FOUND");
      return "FAILED";
    }

    return current;
  }

  if (result.status !== "FOUND") return current;

  const remote = result.data?.status;

  if (remote === "COMPLETED") {
    await transitionPayout(
      env,
      accessToken,
      payoutId,
      ["PENDING", "ACCEPTED"],
      "COMPLETED",
      {
        providerTransactionId: fv.str(result.data?.providerTransactionId ?? ""),
      }
    );

    return "COMPLETED";
  }

  if (remote === "FAILED") {
    await refundPayout(
      env,
      accessToken,
      payoutId,
      result.data?.failureReason?.failureCode ?? "FAILED"
    );

    return "FAILED";
  }

  // ACCEPTED, ENQUEUED, PROCESSING, IN_RECONCILIATION : en cours.
  await transitionPayout(env, accessToken, payoutId, ["PENDING"], "ACCEPTED");

  return "ACCEPTED";
}

/*
 * POST /webhooks/pawapay/<WEBHOOK_SECRET>
 * Le corps du callback ne sert qu'à connaître le payoutId : le vrai
 * statut est redemandé à pawaPay avec notre jeton.
 */
export async function handlePawapayWebhook(request, env, secretFromPath) {
  if (!env.WEBHOOK_SECRET || secretFromPath !== env.WEBHOOK_SECRET) {
    return json({ error: "forbidden" }, 403);
  }

  const body = await request.json().catch(() => null);
  const payoutId = body?.payoutId;

  if (typeof payoutId === "string" && UUID_PATTERN.test(payoutId)) {
    const accessToken = await getAccessToken(env);

    await syncPayout(env, accessToken, payoutId);
  }

  return json({ ok: true });
}

/*
 * Tâche planifiée (toutes les 10 minutes) : règle les retraits restés
 * « en attente » depuis plus de 15 minutes (callback perdu, panne réseau…).
 */
export async function reconcilePayouts(env) {
  const accessToken = await getAccessToken(env);

  const documents = await runQuery(env, accessToken, {
    from: [{ collectionId: "payouts" }],
    where: {
      fieldFilter: {
        field: { fieldPath: "status" },
        op: "IN",
        value: {
          arrayValue: {
            values: [{ stringValue: "PENDING" }, { stringValue: "ACCEPTED" }],
          },
        },
      },
    },
    limit: 50,
  });

  const cutoff = Date.now() - RECONCILE_AFTER_MS;

  for (const document of documents) {
    const createdAt = Date.parse(document.fields?.createdAt?.timestampValue ?? "");

    if (!createdAt || createdAt > cutoff) continue;

    const payoutId = document.name.split("/").pop();

    await syncPayout(env, accessToken, payoutId, {
      refundIfNotFound: true,
    }).catch((error) =>
      console.error("reconcile error", payoutId, error?.message ?? error)
    );
  }
}
