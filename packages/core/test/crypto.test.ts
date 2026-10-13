import { describe, expect, it } from 'vitest';
import {
  ARGON2_TEST,
  bindingAad,
  decryptPayload,
  deriveKey,
  encryptPayload,
  newDataKey,
  newDeviceKeypair,
  newRecoveryCode,
  newSalt,
  normaliseRecoveryCode,
  openSealed,
  sealToDevice,
  unwrapKey,
  utf8,
  wrapKey,
  CryptoError,
} from '../src/crypto.js';

describe('crypto', () => {
  it('derives the same key for the same passphrase and salt, different for different salt', async () => {
    const salt = await newSalt();
    const a = await deriveKey('correct horse', salt, ARGON2_TEST);
    const b = await deriveKey('correct horse', salt, ARGON2_TEST);
    const c = await deriveKey('correct horse', await newSalt(), ARGON2_TEST);
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(true);
    expect(Buffer.from(a).equals(Buffer.from(c))).toBe(false);
  });

  it('normalises unicode so composed/decomposed passphrases match', async () => {
    const salt = await newSalt();
    const a = await deriveKey('café', salt, ARGON2_TEST);
    const b = await deriveKey('café', salt, ARGON2_TEST);
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(true);
  });

  it('wraps and unwraps a key; wrong key fails cleanly', async () => {
    const dk = await newDataKey();
    const salt = await newSalt();
    const rk = await deriveKey('pw', salt, ARGON2_TEST);
    const wrong = await deriveKey('pw2', salt, ARGON2_TEST);
    const wrapped = await wrapKey(dk, rk);
    expect(Buffer.from(await unwrapKey(wrapped, rk)).equals(Buffer.from(dk))).toBe(true);
    await expect(unwrapKey(wrapped, wrong)).rejects.toBeInstanceOf(CryptoError);
  });

  it('seals to a device and only that device can open', async () => {
    const dk = await newDataKey();
    const a = await newDeviceKeypair();
    const b = await newDeviceKeypair();
    const sealed = await sealToDevice(dk, a.publicKey);
    expect(Buffer.from(await openSealed(sealed, a)).equals(Buffer.from(dk))).toBe(true);
    await expect(openSealed(sealed, b)).rejects.toBeInstanceOf(CryptoError);
  });

  it('AEAD binds ciphertext to its position: moving an event fails', async () => {
    const dk = await newDataKey();
    const aad = bindingAad({ soulId: 's', deviceId: 'd', seq: 7, dkVersion: 1 });
    const ct = await encryptPayload(utf8('{"hello":1}'), dk, aad);
    expect(Buffer.from(await decryptPayload(ct, dk, aad)).toString()).toBe('{"hello":1}');
    const moved = bindingAad({ soulId: 's', deviceId: 'd', seq: 8, dkVersion: 1 });
    await expect(decryptPayload(ct, dk, moved)).rejects.toBeInstanceOf(CryptoError);
    const retagged = bindingAad({ soulId: 's', deviceId: 'd', seq: 7, dkVersion: 2 });
    await expect(decryptPayload(ct, dk, retagged)).rejects.toBeInstanceOf(CryptoError);
  });

  it('tampered ciphertext fails', async () => {
    const dk = await newDataKey();
    const aad = bindingAad({ soulId: 's', deviceId: 'd', seq: 1, dkVersion: 1 });
    const ct = await encryptPayload(utf8('x'), dk, aad);
    ct.ciphertext[0] = ct.ciphertext[0]! ^ 0xff;
    await expect(decryptPayload(ct, dk, aad)).rejects.toBeInstanceOf(CryptoError);
  });

  it('recovery codes are 26 chars of Crockford base32 and normalise lookalikes', async () => {
    const code = await newRecoveryCode();
    expect(code.replace(/-/g, '')).toMatch(/^[0-9A-HJKMNP-TV-Z]{26}$/);
    expect(normaliseRecoveryCode('ab-cd o1 Il')).toBe('ABCD0111');
    expect(normaliseRecoveryCode(code)).toBe(code.replace(/-/g, ''));
  });
});
