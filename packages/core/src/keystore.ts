/**
 * Device keystore: the X25519 device keypair plus the unsealed data keys this device holds,
 * encrypted at rest with a device passphrase (Argon2id → secretbox).
 *
 * This is the realistic answer for headless Linux/WSL. On desktop OSes a keychain-backed
 * implementation of the same interface can be substituted.
 *
 * File: <dir>/<soulId>/<deviceId>.keys.json  (0600)
 */
import { promises as fs } from 'node:fs';
import path from 'node:path';
import {
  ARGON2_DEFAULT,
  type Argon2Params,
  b64,
  deriveKey,
  newSalt,
  unb64,
  unwrapKey,
  wrapKey,
  type DeviceKeypair,
  CryptoError,
} from './crypto.js';

export interface DeviceSecrets {
  deviceId: string;
  soulId: string;
  keypair: DeviceKeypair;
  /** dkVersion → raw DK */
  dataKeys: Record<number, Uint8Array>;
}

interface KeyFile {
  v: 1;
  deviceId: string;
  soulId: string;
  salt: string;
  argon2: Argon2Params;
  /** secretbox(JSON(secrets), kek) */
  blob: string;
}

export interface Keystore {
  save(secrets: DeviceSecrets, passphrase: string): Promise<void>;
  load(soulId: string, deviceId: string, passphrase: string): Promise<DeviceSecrets>;
  exists(soulId: string, deviceId: string): Promise<boolean>;
}

export class FileKeystore implements Keystore {
  constructor(
    private readonly dir: string,
    private readonly argon2: Argon2Params = ARGON2_DEFAULT,
  ) {}

  private file(soulId: string, deviceId: string): string {
    return path.join(this.dir, soulId, `${deviceId}.keys.json`);
  }

  async exists(soulId: string, deviceId: string): Promise<boolean> {
    try {
      await fs.access(this.file(soulId, deviceId));
      return true;
    } catch {
      return false;
    }
  }

  async save(secrets: DeviceSecrets, passphrase: string): Promise<void> {
    const file = this.file(secrets.soulId, secrets.deviceId);
    await fs.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
    const salt = await newSalt();
    const kek = await deriveKey(passphrase, salt, this.argon2);
    const plain = JSON.stringify({
      pk: b64(secrets.keypair.publicKey),
      sk: b64(secrets.keypair.privateKey),
      dks: Object.fromEntries(Object.entries(secrets.dataKeys).map(([v, k]) => [v, b64(k)])),
    });
    const blob = await wrapKey(new TextEncoder().encode(plain), kek);
    const out: KeyFile = {
      v: 1,
      deviceId: secrets.deviceId,
      soulId: secrets.soulId,
      salt: b64(salt),
      argon2: this.argon2,
      blob: b64(blob),
    };
    const tmp = file + '.tmp';
    await fs.writeFile(tmp, JSON.stringify(out, null, 2), { mode: 0o600 });
    await fs.rename(tmp, file);
  }

  async load(soulId: string, deviceId: string, passphrase: string): Promise<DeviceSecrets> {
    const file = this.file(soulId, deviceId);
    const kf = JSON.parse(await fs.readFile(file, 'utf8')) as KeyFile;
    if (kf.v !== 1) throw new CryptoError(`unsupported keyfile version ${String(kf.v)}`);
    const kek = await deriveKey(passphrase, unb64(kf.salt), kf.argon2);
    const plain = JSON.parse(new TextDecoder().decode(await unwrapKey(unb64(kf.blob), kek))) as {
      pk: string;
      sk: string;
      dks: Record<string, string>;
    };
    return {
      deviceId: kf.deviceId,
      soulId: kf.soulId,
      keypair: { publicKey: unb64(plain.pk), privateKey: unb64(plain.sk) },
      dataKeys: Object.fromEntries(Object.entries(plain.dks).map(([v, k]) => [Number(v), unb64(k)])),
    };
  }
}

/** In-memory keystore for tests and ephemeral sessions (custodial mode). */
export class MemoryKeystore implements Keystore {
  private map = new Map<string, DeviceSecrets>();
  async save(secrets: DeviceSecrets): Promise<void> {
    this.map.set(`${secrets.soulId}/${secrets.deviceId}`, structuredClone(secrets));
  }
  async load(soulId: string, deviceId: string): Promise<DeviceSecrets> {
    const s = this.map.get(`${soulId}/${deviceId}`);
    if (!s) throw new CryptoError('no secrets for device');
    return structuredClone(s);
  }
  async exists(soulId: string, deviceId: string): Promise<boolean> {
    return this.map.has(`${soulId}/${deviceId}`);
  }
}
