// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function importKeyFromWKD(hem: any, token: string, email: string): Promise<{ kidSign: string; kidEcdh: string }>;

export function buildCertificate(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  hem: any,
  signToken: string,
  kidSign: string,
  kidEcdh: string,
  email: string,
  opts?: { ecdhToken?: string; timestamp?: number; expiryTimestamp?: number; displayName?: string }
): Promise<{ cert: Uint8Array }>;

export function publishKey(wkdBase: string, email: string, cert: Uint8Array, authToken?: string): Promise<void>;

export function revokeKey(wkdBase: string, email: string, authToken?: string): Promise<void>;

export function armorCertificate(cert: Uint8Array): string;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function signCleartextMessage(hem: any, token: string, kidSign: string, keyId8: Uint8Array, message: string): Promise<string>;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function findSelfSign(keys: any[], email: string): any | null;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function findSelfEcdh(keys: any[], email: string): any | null;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function findPeerSign(keys: any[], email: string): any | null;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function findPeerEcdh(keys: any[], email: string): any | null;

export function encryptAndSign(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  hem: any,
  signToken: string,
  kidSign: string,
  keyId8: Uint8Array,
  recipients: Array<string>,
  plaintext: string
): Promise<string>;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function buildHsmSignaturePkt(hem: any, signToken: string, kidSign: string, keyId8: Uint8Array, plaintext: string): Promise<{ sigPkt: Uint8Array; dataBytes: Uint8Array }>;

/**
 * Parse and validate a WKD public key for `email`: primary-key self-consistency
 * (verifyPrimaryKey), a UID matching the address with a valid self-certification,
 * and — when requireEncryptionKey — a usable encryption subkey. Throws otherwise.
 * Returns the parsed openpgp key. Uses the host-provided (external) openpgp, so the
 * returned key is compatible with the caller's own openpgp instance.
 */
export function readValidatedWkdKey(
  keyBytes: Uint8Array,
  email: string,
  opts?: { requireEncryptionKey?: boolean }
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
): Promise<any>;
