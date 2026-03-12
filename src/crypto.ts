const IV_LENGTH = 12; // 96-bit IV recommended for AES-GCM
const ALGORITHM = 'AES-GCM';

async function deriveKey(secret: string): Promise<CryptoKey> {
  const keyMaterial = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(secret)
  );

  return crypto.subtle.importKey('raw', keyMaterial, ALGORITHM, false, [
    'encrypt',
    'decrypt',
  ]);
}

function toHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

export async function encrypt(
  secret: string,
  data: Record<string, unknown>
): Promise<string> {
  const key = await deriveKey(secret);
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const plaintext = new TextEncoder().encode(JSON.stringify(data));

  const ciphertext = await crypto.subtle.encrypt(
    { name: ALGORITHM, iv },
    key,
    plaintext
  );

  return toHex(iv.buffer) + toHex(ciphertext);
}

export async function decrypt<T = Record<string, unknown>>(
  secret: string,
  encryptedText: string
): Promise<T | false> {
  try {
    const ivHexLength = IV_LENGTH * 2;
    if (encryptedText.length <= ivHexLength) {
      return false;
    }

    const iv = fromHex(encryptedText.substring(0, ivHexLength));
    const ciphertext = fromHex(encryptedText.substring(ivHexLength));

    const key = await deriveKey(secret);
    const plaintext = await crypto.subtle.decrypt(
      { name: ALGORITHM, iv },
      key,
      ciphertext
    );

    return JSON.parse(new TextDecoder().decode(plaintext));
  } catch {
    return false;
  }
}
