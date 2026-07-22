// Automatyczny weryfikator serwerowy PGP (część TEST-PLAN.md, którą da się sprawdzić tokenem).
// NIE wymaga HSM/przegladarki — sprawdza STRUKTURE i KRYPTO wiadomosci ktore plugin wyprodukowal.
//
// Uzycie:
//   export ZM_URL="https://mailserver.encedo.com"
//   export ZM_TOKEN="<swiezy ZM_AUTH_TOKEN>"
//   node verify-pgp-mailbox.mjs [limit]
//
// Sprawdza:
//  ENCRYPTED (multipart/encrypted): poprawna struktura, brak wycieku jawnej tresci/zalacznikow,
//    outer Subject (== "..." => encryptSubject uzyty).
//  SIGNED detached (multipart/signed): KRYPTOGRAFICZNA weryfikacja podpisu wzgledem klucza
//    nadawcy (WKD -> VKS by-email -> VKS by-keyid).
import crypto from 'node:crypto';
import * as openpgp from 'openpgp';

const URL_BASE = process.env.ZM_URL?.replace(/\/$/, '');
const TOK = process.env.ZM_TOKEN;
const LIMIT = parseInt(process.argv[2] || '40', 10);
if (!URL_BASE || !TOK) { console.error('Ustaw ZM_URL i ZM_TOKEN'); process.exit(1); }

const ZB = 'ybndrfg8ejkmcpqxot1uwisza345h769';
const zbase32 = (d) => { let bits=0,v=0,s=''; for(const b of d){v=(v<<8)|b;bits+=8;while(bits>=5){s+=ZB[(v>>>(bits-5))&31];bits-=5;}} if(bits)s+=ZB[(v<<(5-bits))&31]; return s; };

async function soap(name, body) {
  const env = `<?xml version="1.0"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"><soap:Header><context xmlns="urn:zimbra"><authToken>${TOK}</authToken></context></soap:Header><soap:Body>${body}</soap:Body></soap:Envelope>`;
  const r = await fetch(`${URL_BASE}/service/soap/${name}`, { method:'POST', headers:{'Content-Type':'application/soap+xml; charset=utf-8'}, body: env });
  return r.text();
}
const raw = (id) => fetch(`${URL_BASE}/service/home/~/?auth=qp&zauthtoken=${encodeURIComponent(TOK)}&id=${id}&fmt=raw`).then(r=>r.text());

async function wkdKey(email) {
  const [local, domain] = email.split('@'); if (!domain) return null;
  const h = zbase32(crypto.createHash('sha1').update(local.toLowerCase()).digest());
  for (const u of [`https://openpgpkey.${domain}/.well-known/openpgpkey/${domain}/hu/${h}?l=${local}`,
                   `https://${domain}/.well-known/openpgpkey/hu/${h}?l=${local}`]) {
    try { const r = await fetch(u, { signal: AbortSignal.timeout(6000) }); if (r.ok) return new Uint8Array(await r.arrayBuffer()); } catch {}
  }
  return null;
}
async function vksByEmail(email) { try { const r = await fetch(`https://keys.openpgp.org/vks/v1/by-email/${encodeURIComponent(email)}`); if(r.ok){const a=await r.text(); if(a.includes('BEGIN PGP')) return (await openpgp.readKey({armoredKey:a})).write();} } catch {} return null; }
async function vksByKeyId(id) { try { const r = await fetch(`https://keys.openpgp.org/vks/v1/by-keyid/${id.toUpperCase()}`); if(r.ok){const a=await r.text(); if(a.includes('BEGIN PGP')) return (await openpgp.readKey({armoredKey:a})).write();} } catch {} return null; }

function header(d, name) { const m = d.match(new RegExp(`^${name}:\\s*(.*(?:\\r?\\n[ \\t].*)*)`, 'im')); return m ? m[1].replace(/\r?\n[ \t]+/g,' ').trim() : null; }
function fromAddr(d) { const f = header(d,'From')||''; const m = f.match(/<([^>]+)>/) || f.match(/([^\s<]+@[^\s>]+)/); return m ? m[1] : null; }

function extractDetachedSigned(d) {
  const m = d.match(/multipart\/signed[^]*?boundary="?([^";\r\n]+)"?/i); if (!m) return null;
  const delim = `--${m[1].trim()}`;
  const first = d.indexOf(delim); if (first < 0) return null;
  const partStart = d.indexOf('\n', first) + 1;
  const second = d.indexOf(`\n${delim}`, partStart); if (second < 0) return null;
  let end = second; if (d[end]==='\n') end--; if (d[end]==='\r') end--;
  const signed = d.slice(partStart, end+1);
  const s = d.indexOf('-----BEGIN PGP SIGNATURE-----', second);
  const E = '-----END PGP SIGNATURE-----'; const e = d.indexOf(E, s);
  if (s<0||e<0) return null;
  return { signed, sig: d.slice(s, e+E.length) };
}

async function verifySig(signed, armoredSig, senderEmail) {
  let signature; try { signature = await openpgp.readSignature({ armoredSignature: armoredSig }); } catch { return 'BAD-SIG-PARSE'; }
  const issuer = signature.packets?.[0]?.issuerKeyID?.toHex?.() ?? null;
  const cands = [];
  const add = async (bytes) => { if(!bytes) return; try { cands.push(await openpgp.readKey({binaryKey: bytes})); } catch{} };
  if (senderEmail) { await add(await wkdKey(senderEmail)); await add(await vksByEmail(senderEmail)); }
  const matches = (k)=> !!issuer && k.getKeys().some(s=>s.getKeyID().toHex()===issuer);
  if (issuer && !cands.some(matches)) await add(await vksByKeyId(issuer));
  const signer = issuer ? cands.find(matches) : cands[0];
  if (!signer) return `UNVERIFIED (issuer ${issuer||'?'}, brak klucza)`;
  try {
    const message = await openpgp.createMessage({ binary: new TextEncoder().encode(signed) });
    const res = await openpgp.verify({ message, signature, verificationKeys: [signer] });
    return (await res.signatures[0].verified) ? `VALID (${issuer})` : `INVALID (${issuer})`;
  } catch (e) { return `INVALID (${e.message})`; }
}

// ── main ──
const search = await soap('SearchRequest', `<SearchRequest xmlns="urn:zimbraMail" types="message" sortBy="dateDesc" limit="${LIMIT}"><query>pgp OR encrypted OR "PGP MESSAGE" OR "pgp-signature"</query></SearchRequest>`);
const ids = [...search.matchAll(/<m [^>]*id="(\d+)"/g)].map(m=>m[1]);
console.log(`Znaleziono kandydatow: ${ids.length}\n`);
let enc=0, sig=0, leaks=0, protSub=0, sigOk=0, sigBad=0, sigUnv=0;

for (const id of ids) {
  let d; try { d = await raw(id); } catch { continue; }
  const top = header(d, 'Content-Type') || '';
  const subj = header(d, 'Subject') || '';
  const from = fromAddr(d);
  if (/multipart\/encrypted/i.test(top) || d.includes('application/pgp-encrypted')) {
    enc++;
    const hasVer = /application\/pgp-encrypted/i.test(d);
    const hasBlob = d.includes('BEGIN PGP MESSAGE') || /application\/octet-stream/i.test(d);
    // wyciek: czy poza multipart/encrypted jest jawny text/plain body albo zalacznik z trescia?
    const bodyIdx = d.indexOf('\r\n\r\n');
    const outerBody = d.slice(bodyIdx);
    const leak = /Content-Disposition:\s*attachment/i.test(outerBody.replace(/application\/pgp-encrypted|application\/octet-stream/gi,'')) &&
                 !/multipart\/encrypted/i.test(top) ? true : false;
    const isProt = subj.trim() === '...' || /protected-headers/i.test(d.slice(0, bodyIdx));
    if (isProt) protSub++;
    if (leak) leaks++;
    console.log(`ENC  #${id} | from=${from} | subj="${subj.slice(0,24)}"${isProt?' [protected-subject]':''} | struct=${hasVer&&hasBlob?'OK':'??'}${leak?' | ⚠ MOZLIWY WYCIEK':''}`);
  } else if (/multipart\/signed/i.test(top) || d.includes('application/pgp-signature')) {
    sig++;
    const ex = extractDetachedSigned(d);
    let verdict = 'NIE-WYCIETO';
    if (ex) verdict = await verifySig(ex.signed, ex.sig, from);
    if (verdict.startsWith('VALID')) sigOk++; else if (verdict.startsWith('INVALID')) sigBad++; else sigUnv++;
    console.log(`SIGN #${id} | from=${from} | subj="${subj.slice(0,24)}" | ${verdict}`);
  }
}
console.log(`\n── PODSUMOWANIE ──`);
console.log(`Zaszyfrowane: ${enc} (protected-subject: ${protSub}, mozliwe wycieki: ${leaks})`);
console.log(`Podpisane(detached): ${sig} → VALID ${sigOk} | INVALID ${sigBad} | UNVERIFIED ${sigUnv}`);
