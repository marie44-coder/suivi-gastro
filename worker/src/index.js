/**
 * SUIVI RGO / EoE — Cloudflare Worker (lecture seule)
 * ----------------------------------------------------
 * Lit une feuille du Google Sheet suivi_symptomes_EoE_RGO via un compte de
 * service (JWT signé RS256 -> échange contre un token OAuth -> appel Sheets API v4).
 *
 * Code strictement identique à celui du worker migraines : seule la
 * configuration (secrets) change, pas la logique.
 *
 * Appel : GET https://<ton-worker>.workers.dev/?sheet=Remontées acides (RGO)
 *         GET https://<ton-worker>.workers.dev/?sheet=Crises EoE
 *
 * Réponse : { values: [[header1, header2, ...], [row1col1, row1col2, ...], ...] }
 *
 * SECRETS à configurer (wrangler secret put ... ou dashboard Cloudflare) :
 *   GOOGLE_CLIENT_EMAIL   -> le "client_email" du compte de service
 *                            (le même que pour le worker migraines si tu réutilises
 *                            le même compte de service Google Cloud)
 *   GOOGLE_PRIVATE_KEY    -> le "private_key" correspondant (garder les \n tels quels)
 *   SHEET_ID              -> l'ID DU CLASSEUR suivi_symptomes_EoE_RGO (dans son URL,
 *                            entre /d/ et /edit) — DIFFÉRENT du SHEET_ID migraines
 *
 * Le Google Sheet suivi_symptomes_EoE_RGO doit être partagé en Lecteur avec
 * l'adresse GOOGLE_CLIENT_EMAIL (comme pour le classeur migraines).
 */

const TOKEN_URL = 'https://oauth2.googleapis.com/token';
const SCOPE = 'https://www.googleapis.com/auth/spreadsheets.readonly';

// Cache mémoire du token d'accès (valable ~1h, on le garde 50 min par sécurité)
let cachedToken = null;
let cachedTokenExpiry = 0;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // CORS (nécessaire si index.html / saisie.html sont servis depuis GitHub Pages)
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type'
    };
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    const sheetName = url.searchParams.get('sheet');
    if (!sheetName) {
      return jsonResponse({ error: { message: "Paramètre 'sheet' manquant (ex: ?sheet=Crises EoE)" } }, 400, corsHeaders);
    }

    try {
      const accessToken = await getAccessToken(env);
      const range = encodeURIComponent(sheetName);
      const apiUrl = `https://sheets.googleapis.com/v4/spreadsheets/${env.SHEET_ID}/values/${range}`;

      const resp = await fetch(apiUrl, {
        headers: { Authorization: `Bearer ${accessToken}` }
      });

      if (!resp.ok) {
        const errBody = await resp.text();
        return jsonResponse({ error: { message: `Erreur Sheets API (${resp.status}) : ${errBody}` } }, resp.status, corsHeaders);
      }

      const data = await resp.json();
      return jsonResponse(data, 200, corsHeaders);
    } catch (err) {
      return jsonResponse({ error: { message: err.message } }, 500, corsHeaders);
    }
  }
};

function jsonResponse(obj, status, extraHeaders) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: Object.assign({ 'Content-Type': 'application/json' }, extraHeaders || {})
  });
}

async function getAccessToken(env) {
  const now = Math.floor(Date.now() / 1000);
  if (cachedToken && now < cachedTokenExpiry - 60) {
    return cachedToken;
  }

  const jwt = await buildSignedJwt(env, now);

  const body = new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
    assertion: jwt
  });

  const resp = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString()
  });

  if (!resp.ok) {
    const errText = await resp.text();
    throw new Error('Échange de token OAuth échoué : ' + errText);
  }

  const tokenData = await resp.json();
  cachedToken = tokenData.access_token;
  cachedTokenExpiry = now + (tokenData.expires_in || 3600);
  return cachedToken;
}

async function buildSignedJwt(env, now) {
  const header = { alg: 'RS256', typ: 'JWT' };
  const claimSet = {
    iss: env.GOOGLE_CLIENT_EMAIL,
    scope: SCOPE,
    aud: TOKEN_URL,
    iat: now,
    exp: now + 3600
  };

  const encodedHeader = base64url(JSON.stringify(header));
  const encodedClaimSet = base64url(JSON.stringify(claimSet));
  const signingInput = `${encodedHeader}.${encodedClaimSet}`;

  const key = await importPrivateKey(env.GOOGLE_PRIVATE_KEY);
  const signature = await crypto.subtle.sign(
    { name: 'RSASSA-PKCS1-v1_5' },
    key,
    new TextEncoder().encode(signingInput)
  );

  const encodedSignature = base64urlFromArrayBuffer(signature);
  return `${signingInput}.${encodedSignature}`;
}

async function importPrivateKey(pem) {
  // Les secrets Cloudflare stockent souvent les retours à la ligne comme "\n" littéral
  const normalizedPem = pem.replace(/\\n/g, '\n');
  const pemContents = normalizedPem
    .replace('-----BEGIN PRIVATE KEY-----', '')
    .replace('-----END PRIVATE KEY-----', '')
    .replace(/\s/g, '');

  const binaryDer = base64ToArrayBuffer(pemContents);

  return crypto.subtle.importKey(
    'pkcs8',
    binaryDer,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign']
  );
}

function base64ToArrayBuffer(base64) {
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

function base64url(str) {
  return base64urlFromArrayBuffer(new TextEncoder().encode(str));
}

function base64urlFromArrayBuffer(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}
