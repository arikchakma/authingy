import { describe, expect, it } from 'bun:test';

import { decrypt, encrypt } from './crypto';

const secret = '1234567890';
const data = {
  name: 'John Doe',
  email: 'john.doe@example.com',
};

describe('crypto', () => {
  it('should encrypt and decrypt data', () => {
    const encrypted = encrypt(secret, data);
    const decrypted = decrypt(secret, encrypted);
    expect(decrypted).toEqual(data);
  });
  it('should return "false" if the data is invalid', () => {
    const encrypted = encrypt(secret, data);
    const decrypted = decrypt(secret, encrypted + 'invalid');
    expect(decrypted).toBe(false);
    expect(decrypted).toBeFalsy();
  });
  it('should return "false" if the secret is invalid', () => {
    const encrypted = encrypt(secret, data);
    const decrypted = decrypt(secret + 'invalid', encrypted);
    expect(decrypted).toBe(false);
    expect(decrypted).toBeFalsy();
  });
});
