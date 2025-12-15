import crypto from 'crypto';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16; // For AES, IV length is 16 bytes
const GCM_TAG_LENGTH = 16; // GCM authentication tag length is 16 bytes

function keyToBuffer(key: string) {
  return crypto.createHash('sha256').update(key).digest();
}

export function encrypt(key: string, data: Record<string, unknown>) {
  const keyBuffer = keyToBuffer(key);

  const plainText = JSON.stringify(data);
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, keyBuffer, iv);

  let encrypted = cipher.update(plainText, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  const tag = cipher.getAuthTag();

  return iv.toString('hex') + encrypted + tag.toString('hex');
}

export function decrypt<T = Record<string, unknown>>(
  key: string,
  encryptedText: string
): T | false {
  try {
    const minLength = (IV_LENGTH + GCM_TAG_LENGTH) * 2 + 2;
    if (encryptedText.length < minLength) {
      return false;
    }

    const keyBuffer = keyToBuffer(key);

    const iv = Buffer.from(encryptedText.substring(0, IV_LENGTH * 2), 'hex');
    const tag = Buffer.from(
      encryptedText.substring(encryptedText.length - GCM_TAG_LENGTH * 2),
      'hex'
    );
    const encrypted = Buffer.from(
      encryptedText.substring(
        IV_LENGTH * 2,
        encryptedText.length - GCM_TAG_LENGTH * 2
      ),
      'hex'
    );

    if (
      iv.length !== IV_LENGTH ||
      tag.length !== GCM_TAG_LENGTH ||
      encrypted.length === 0
    ) {
      return false;
    }

    const decipher = crypto.createDecipheriv(ALGORITHM, keyBuffer, iv);

    decipher.setAuthTag(tag);

    let decrypted = decipher.update(encrypted);
    decrypted = Buffer.concat([decrypted, decipher.final()]);

    return JSON.parse(decrypted.toString('utf8'));
  } catch (error) {
    return false;
  }
}
