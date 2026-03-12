import { describe, expect, it } from 'bun:test';

import { decrypt, encrypt } from './crypto';

const secret = '1234567890';
const data = {
  name: 'John Doe',
  email: 'john.doe@example.com',
};

describe('crypto', () => {
  it('should encrypt and decrypt data', async () => {
    const encrypted = await encrypt(secret, data);
    const decrypted = await decrypt(secret, encrypted);
    expect(decrypted).toEqual(data);
  });

  it('should produce different ciphertexts for the same input (random IV)', async () => {
    const a = await encrypt(secret, data);
    const b = await encrypt(secret, data);
    expect(a).not.toBe(b);
  });

  it('should handle nested objects', async () => {
    const nested = { user: { id: 1, roles: ['admin', 'user'] }, active: true };
    const encrypted = await encrypt(secret, nested);
    const decrypted = await decrypt(secret, encrypted);
    expect(decrypted).toEqual(nested);
  });

  it('should handle empty object', async () => {
    const encrypted = await encrypt(secret, {});
    const decrypted = await decrypt(secret, encrypted);
    expect(decrypted).toEqual({});
  });

  it('should handle unicode values', async () => {
    const unicode = { name: '日本語テスト', emoji: '🔐🎉' };
    const encrypted = await encrypt(secret, unicode);
    const decrypted = await decrypt(secret, encrypted);
    expect(decrypted).toEqual(unicode);
  });

  it('should return false if the ciphertext is tampered with', async () => {
    const encrypted = await encrypt(secret, data);
    // Flip a character in the middle of the ciphertext (after the IV hex)
    const mid = Math.floor(encrypted.length / 2);
    const tampered =
      encrypted.substring(0, mid) +
      (encrypted[mid] === 'a' ? 'b' : 'a') +
      encrypted.substring(mid + 1);
    const decrypted = await decrypt(secret, tampered);
    expect(decrypted).toBe(false);
  });

  it('should return false if the data is appended to', async () => {
    const encrypted = await encrypt(secret, data);
    const decrypted = await decrypt(secret, encrypted + 'invalid');
    expect(decrypted).toBe(false);
  });

  it('should return false if the secret is wrong', async () => {
    const encrypted = await encrypt(secret, data);
    const decrypted = await decrypt('wrong-secret', encrypted);
    expect(decrypted).toBe(false);
  });

  it('should return false for too-short input', async () => {
    expect(await decrypt(secret, '')).toBe(false);
    expect(await decrypt(secret, 'abc')).toBe(false);
    // Exactly IV hex length (24 chars) but no ciphertext
    expect(await decrypt(secret, 'a'.repeat(24))).toBe(false);
  });

  it('should return false for non-hex input', async () => {
    const decrypted = await decrypt(
      secret,
      'zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz'
    );
    expect(decrypted).toBe(false);
  });

  it('should work with different secrets on same data', async () => {
    const enc1 = await encrypt('secret-one', data);
    const enc2 = await encrypt('secret-two', data);

    expect(await decrypt<typeof data>('secret-one', enc1)).toEqual(data);
    expect(await decrypt<typeof data>('secret-two', enc2)).toEqual(data);
    expect(await decrypt('secret-one', enc2)).toBe(false);
    expect(await decrypt('secret-two', enc1)).toBe(false);
  });
});
