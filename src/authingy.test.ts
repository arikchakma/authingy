import { describe, expect, it } from 'bun:test';
import type * as oauth from 'oauth4webapi';

import { defineAuthingyConfig } from './authingy';
import { decrypt } from './crypto';
import { AuthingyError } from './error';
import type { OAuthProvider } from './providers/types';

function createMockProvider(
  id: string,
  overrides?: Partial<OAuthProvider>
): OAuthProvider {
  return {
    id,
    _authorization: async ({ state, codeVerifier }) => {
      return `https://example.com/authorize?state=${state}&code_verifier=${codeVerifier}`;
    },
    _callback: async () => {
      return {
        access_token: 'mock-access-token',
        token_type: 'bearer',
      } as oauth.TokenEndpointResponse;
    },
    _user: async () => {
      return { id: '123', name: 'Test User', email: 'test@example.com' };
    },
    ...overrides,
  };
}

describe('defineAuthingyConfig', () => {
  const secret = 'test-secret-key-for-authingy';

  it('should create auth config with providers', () => {
    const auth = defineAuthingyConfig({
      secret,
      providers: [createMockProvider('mock')],
    });

    expect(auth.authorize).toBeFunction();
    expect(auth.callback).toBeFunction();
    expect(auth['~providers']).toHaveLength(1);
  });

  describe('authorize', () => {
    it('should return url, encrypted state, and codeVerifier', async () => {
      const auth = defineAuthingyConfig({
        secret,
        providers: [createMockProvider('mock')],
      });

      const result = await auth.authorize('mock');

      expect(result.url).toContain('https://example.com/authorize');
      expect(result.state).toBeString();
      expect(result.codeVerifier).toBeString();
    });

    it('should encrypt additional data into state', async () => {
      const auth = defineAuthingyConfig({
        secret,
        providers: [createMockProvider('mock')],
      });

      const result = await auth.authorize('mock', {
        returnTo: '/dashboard',
      });

      const decrypted = await decrypt<{
        state: string;
        returnTo: string;
      }>(secret, result.state);
      expect(decrypted).not.toBe(false);
      if (decrypted) {
        expect(decrypted.state).toBeString();
        expect(decrypted.returnTo).toBe('/dashboard');
      }
    });

    it('should use provided state and codeVerifier', async () => {
      const auth = defineAuthingyConfig({
        secret,
        providers: [createMockProvider('mock')],
      });

      const result = await auth.authorize('mock', {}, {
        state: 'custom-state',
        codeVerifier: 'custom-verifier',
      });

      expect(result.codeVerifier).toBe('custom-verifier');

      const decrypted = await decrypt<{ state: string }>(
        secret,
        result.state
      );
      expect(decrypted).not.toBe(false);
      if (decrypted) {
        expect(decrypted.state).toBe('custom-state');
      }
    });

    it('should throw PROVIDER_NOT_FOUND for unknown provider', async () => {
      const auth = defineAuthingyConfig({
        secret,
        providers: [createMockProvider('mock')],
      });

      try {
        await auth.authorize('unknown' as any);
        expect.unreachable('should have thrown');
      } catch (err) {
        expect(err).toBeInstanceOf(AuthingyError);
        expect((err as AuthingyError).code).toBe('PROVIDER_NOT_FOUND');
      }
    });
  });

  describe('callback', () => {
    it('should return user, token, and extra data', async () => {
      const auth = defineAuthingyConfig({
        secret,
        providers: [createMockProvider('mock')],
      });

      const { state, codeVerifier } = await auth.authorize('mock', {
        extra: 'value',
      });

      const result = await auth.callback('mock', {
        url: new URL('https://example.com/callback?code=abc&state=xyz'),
        codeVerifier,
        state,
      });

      expect(result.user).toEqual({
        id: '123',
        name: 'Test User',
        email: 'test@example.com',
      });
      expect(result.token.access_token).toBe('mock-access-token');
      expect(result.data).toEqual({ extra: 'value' });
    });

    it('should throw PROVIDER_NOT_FOUND for unknown provider', async () => {
      const auth = defineAuthingyConfig({
        secret,
        providers: [createMockProvider('mock')],
      });

      try {
        await auth.callback('unknown' as any, {
          url: new URL('https://example.com/callback'),
          codeVerifier: 'test',
          state: 'test',
        });
        expect.unreachable('should have thrown');
      } catch (err) {
        expect(err).toBeInstanceOf(AuthingyError);
        expect((err as AuthingyError).code).toBe('PROVIDER_NOT_FOUND');
      }
    });

    it('should throw INVALID_STATE for bad encrypted state', async () => {
      const auth = defineAuthingyConfig({
        secret,
        providers: [createMockProvider('mock')],
      });

      try {
        await auth.callback('mock', {
          url: new URL('https://example.com/callback'),
          codeVerifier: 'test',
          state: 'totally-invalid-encrypted-state',
        });
        expect.unreachable('should have thrown');
      } catch (err) {
        expect(err).toBeInstanceOf(AuthingyError);
        expect((err as AuthingyError).code).toBe('INVALID_STATE');
      }
    });

    it('should throw INVALID_STATE when decrypted state has no state field', async () => {
      const auth = defineAuthingyConfig({
        secret,
        providers: [createMockProvider('mock')],
      });

      // Encrypt data without a `state` field
      const { encrypt } = await import('./crypto');
      const badState = await encrypt(secret, { noState: true });

      try {
        await auth.callback('mock', {
          url: new URL('https://example.com/callback'),
          codeVerifier: 'test',
          state: badState,
        });
        expect.unreachable('should have thrown');
      } catch (err) {
        expect(err).toBeInstanceOf(AuthingyError);
        expect((err as AuthingyError).code).toBe('INVALID_STATE');
      }
    });
  });

  describe('multiple providers', () => {
    it('should route to the correct provider', async () => {
      const users = {
        providerA: { id: 'a', name: 'User A' },
        providerB: { id: 'b', name: 'User B' },
      };

      const auth = defineAuthingyConfig({
        secret,
        providers: [
          createMockProvider('providerA', {
            _user: async () => users.providerA,
          }),
          createMockProvider('providerB', {
            _user: async () => users.providerB,
          }),
        ],
      });

      const { state: stateA, codeVerifier: cvA } =
        await auth.authorize('providerA');
      const resultA = await auth.callback('providerA', {
        url: new URL('https://example.com/callback?code=a&state=x'),
        codeVerifier: cvA,
        state: stateA,
      });
      expect(resultA.user).toEqual(users.providerA);

      const { state: stateB, codeVerifier: cvB } =
        await auth.authorize('providerB');
      const resultB = await auth.callback('providerB', {
        url: new URL('https://example.com/callback?code=b&state=y'),
        codeVerifier: cvB,
        state: stateB,
      });
      expect(resultB.user).toEqual(users.providerB);
    });
  });
});
