/**
 * index.js — Public API of encedo-pgp-js.
 *
 * Entry point for bundled distribution.
 * HEM (hem-sdk.js) is intentionally NOT included — it is a separate dependency
 * passed as a parameter to functions that need HSM access.
 */

export { buildCertificate, armorCertificate, signCleartextMessage } from './cert-builder.js';

export {
  encryptMessage,
  encryptMessageHSM,
  decryptMessage,
  decryptAndVerify,
  decryptAndVerifyHSM,
  verifySignedMessage,
  verifySignedMessageHSM,
  importKeyFromWKD,
} from './openpgp-bridge.js';

export { lookupKey, wkdHash } from './wkd-client.js';

export { publishKey, revokeKey } from './wkd-publish.js';

export { DESCR, encodeDescr, decodeDescr, findByDescr } from './keychain.js';
