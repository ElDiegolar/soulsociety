/**
 * soulsociety crypto core.
 *
 * Every primitive comes from libsodium. Nothing custom.
 *
 *  RK  root key        = Argon2id(passphrase, salt)            never leaves the client
 *  DK  data key        = 32 random bytes, versioned per soul    encrypts every event/snapshot
 *  device keypair      = X25519                                 DK is sealed to each approved device
 *  recovery key        = Argon2id(recovery code, salt)          second wrap of DK
 *
 *  wrap(DK, RK)        = XChaCha20-Poly1305 secretbox
 *  seal(DK, devicePk)  = libsodium sealed box (ephemeral X25519 + XSalsa20-Poly1305)
 *  encrypt(event, DK)  = XChaCha20-Poly1305-IETF with AAD binding (soul, device, seq, dkVersion)
 */
import { createRequire } from 'node:module';
import type _sodiumT from 'libsodium-wrappers-sumo';

// The package's ESM entry references a sibling file that is not shipped (0.7.x packaging bug);
// the CommonJS build is self-contained, so load that explicitly.
const _sodium = createRequire(import.meta.url)('libsodium-wrappers-sumo') as typeof _sodiumT;

let ready: Promise<typeof _sodium> | null = null;
export async function sodium(): Promise<typeof _sodium> {
  if (!ready) ready = _sodium.ready.then(() => _sodium);
  return ready;
}

export const DK_BYTES = 32;
export const SALT_BYTES = 16;

export interface Argon2Params {
  opslimit: number;
  memlimit: number;
}

/** Interactive-but-serious defaults: ~0.5–1s on a laptop, 256 MiB. */
export const ARGON2_DEFAULT: Argon2Params = { opslimit: 3, memlimit: 256 * 1024 * 1024 };
/** Used only by tests. */
export const ARGON2_TEST: Argon2Params = { opslimit: 1, memlimit: 8 * 1024 * 1024 };

export class CryptoError extends Error {
  override name = 'CryptoError';
}

// ---------- encoding helpers ----------

export function b64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64');
}
export function unb64(s: string): Uint8Array {
  const out = Buffer.from(s, 'base64');
  if (out.length === 0 && s.length > 0) throw new CryptoError('invalid base64');
  return new Uint8Array(out);
}
export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}
export function fromUtf8(b: Uint8Array): string {
  return new TextDecoder('utf-8', { fatal: true }).decode(b);
}

// ---------- randomness ----------

export async function randomBytes(n: number): Promise<Uint8Array> {
  const s = await sodium();
  return s.randombytes_buf(n);
}

export async function newDataKey(): Promise<Uint8Array> {
  return randomBytes(DK_BYTES);
}

export async function newSalt(): Promise<Uint8Array> {
  return randomBytes(SALT_BYTES);
}

// ---------- key derivation ----------

export async function deriveKey(secret: string, salt: Uint8Array, params: Argon2Params = ARGON2_DEFAULT): Promise<Uint8Array> {
  const s = await sodium();
  if (salt.length !== s.crypto_pwhash_SALTBYTES) throw new CryptoError('bad salt length');
  // Normalise so the same passphrase typed on different OSes derives the same key.
  const normalised = secret.normalize('NFKC');
  return s.crypto_pwhash(DK_BYTES, utf8(normalised), salt, params.opslimit, params.memlimit, s.crypto_pwhash_ALG_ARGON2ID13);
}

/** 26 chars of Crockford base32 from 128 random bits, grouped for humans. */
export async function newRecoveryCode(): Promise<string> {
  const s = await sodium();
  const raw = s.randombytes_buf(16);
  const alphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  let bits = 0;
  let acc = 0;
  let out = '';
  for (const byte of raw) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += alphabet[(acc >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += alphabet[(acc << (5 - bits)) & 31];
  return out.match(/.{1,4}/g)!.join('-');
}

/** Canonical form of a recovery code: strips separators, uppercases, maps lookalikes. */
export function normaliseRecoveryCode(code: string): string {
  return code
    .toUpperCase()
    .replace(/[^0-9A-Z]/g, '')
    .replace(/O/g, '0')
    .replace(/[IL]/g, '1');
}

// ---------- symmetric wrap (secretbox) ----------

export async function wrapKey(key: Uint8Array, wrappingKey: Uint8Array): Promise<Uint8Array> {
  const s = await sodium();
  const nonce = s.randombytes_buf(s.crypto_secretbox_NONCEBYTES);
  const box = s.crypto_secretbox_easy(key, nonce, wrappingKey);
  return concat(nonce, box);
}

export async function unwrapKey(wrapped: Uint8Array, wrappingKey: Uint8Array): Promise<Uint8Array> {
  const s = await sodium();
  const n = s.crypto_secretbox_NONCEBYTES;
  if (wrapped.length < n + s.crypto_secretbox_MACBYTES) throw new CryptoError('wrapped key too short');
  try {
    return s.crypto_secretbox_open_easy(wrapped.subarray(n), wrapped.subarray(0, n), wrappingKey);
  } catch {
    throw new CryptoError('unwrap failed: wrong key or corrupted data');
  }
}

// ---------- device keypairs + sealed boxes ----------

export interface DeviceKeypair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export async function newDeviceKeypair(): Promise<DeviceKeypair> {
  const s = await sodium();
  const kp = s.crypto_box_keypair();
  return { publicKey: kp.publicKey, privateKey: kp.privateKey };
}

export async function sealToDevice(key: Uint8Array, devicePublicKey: Uint8Array): Promise<Uint8Array> {
  const s = await sodium();
  if (devicePublicKey.length !== s.crypto_box_PUBLICKEYBYTES) throw new CryptoError('bad device public key');
  return s.crypto_box_seal(key, devicePublicKey);
}

export async function openSealed(sealed: Uint8Array, kp: DeviceKeypair): Promise<Uint8Array> {
  const s = await sodium();
  try {
    return s.crypto_box_seal_open(sealed, kp.publicKey, kp.privateKey);
  } catch {
    throw new CryptoError('sealed box open failed: not for this device or corrupted');
  }
}

// ---------- payload encryption (AEAD with AAD binding) ----------

export interface EventBinding {
  soulId: string;
  deviceId: string;
  seq: number;
  dkVersion: number;
}

/**
 * AAD ties the ciphertext to its position. A host cannot move an event to another
 * device/seq/soul or re-tag its key version without the AEAD failing.
 */
export function bindingAad(b: EventBinding): Uint8Array {
  return utf8(`soulsociety/v1|${b.soulId}|${b.deviceId}|${b.seq}|${b.dkVersion}`);
}

export interface Ciphertext {
  nonce: Uint8Array;
  ciphertext: Uint8Array;
}

export async function encryptPayload(plaintext: Uint8Array, dk: Uint8Array, aad: Uint8Array): Promise<Ciphertext> {
  const s = await sodium();
  if (dk.length !== DK_BYTES) throw new CryptoError('bad data key length');
  const nonce = s.randombytes_buf(s.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const ciphertext = s.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, null, nonce, dk);
  return { nonce, ciphertext };
}

export async function decryptPayload(ct: Ciphertext, dk: Uint8Array, aad: Uint8Array): Promise<Uint8Array> {
  const s = await sodium();
  if (ct.nonce.length !== s.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) throw new CryptoError('bad nonce length');
  try {
    return s.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ct.ciphertext, aad, ct.nonce, dk);
  } catch {
    throw new CryptoError('decrypt failed: wrong key, wrong binding, or corrupted data');
  }
}

// ---------- hashing ----------

export async function hash(data: Uint8Array): Promise<Uint8Array> {
  const s = await sodium();
  return s.crypto_generichash(32, data);
}

export async function hashHex(data: Uint8Array): Promise<string> {
  return Buffer.from(await hash(data)).toString('hex');
}

/** Constant-time compare for token hashes etc. */
export async function equals(a: Uint8Array, b: Uint8Array): Promise<boolean> {
  const s = await sodium();
  if (a.length !== b.length) return false;
  return s.memcmp(a, b);
}

export async function zero(buf: Uint8Array): Promise<void> {
  const s = await sodium();
  s.memzero(buf);
}

// ---------- util ----------

export function concat(...parts: Uint8Array[]): Uint8Array {
  const len = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(len);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}
