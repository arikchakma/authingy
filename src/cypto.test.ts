import { describe, expect, it } from 'bun:test';
import { decrypt, encrypt } from './crypto';

const secret = '1234567890';
const data = { name: 'John Doe', email: 'john.doe@example.com' };

describe('crypto', () => {
  it('should encrypt and decrypt data', async () => {
    const encrypted = await encrypt(secret, data);
    const decrypted = await decrypt(secret, encrypted);
    expect(decrypted).toEqual(data);
  });
  it('should return "false" if the data is invalid', async () => {
    const encrypted = await encrypt(secret, data);
    const decrypted = await decrypt(secret, encrypted + 'invalid');
    expect(decrypted).toBe(false);
    expect(decrypted).toBeFalsy();
  });
  it('should return "false" if the secret is invalid', async () => {
    const encrypted = await encrypt(secret, data);
    const decrypted = await decrypt(secret + 'invalid', encrypted);
    expect(decrypted).toBe(false);
    expect(decrypted).toBeFalsy();
  });
});
