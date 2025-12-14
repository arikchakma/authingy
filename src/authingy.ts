import * as oauth from 'oauth4webapi';
import { decrypt, encrypt } from './crypto';
import { AuthingyError } from './error';
import type { BaseUser, OAuthProvider } from './provider';

export type AuthorizeResult = {
  url: string;
  state: string;
  codeVerifier: string;
};

export type CallbackOptions = {
  url: URL;
  codeVerifier: string;
  state: string;
};

export type CallbackResult<U extends BaseUser = BaseUser> = {
  user: U;
  token: oauth.TokenEndpointResponse;
  data?: Record<string, unknown>;
};

export type Identifier<T extends readonly OAuthProvider<any>[]> =
  T[number]['id'];

type UserForProvider<
  T extends readonly OAuthProvider<any>[],
  ID extends Identifier<T>,
> = Extract<T[number], { id: ID }> extends OAuthProvider<infer U> ? U : never;

export type AuthingyReturn<T extends readonly OAuthProvider<any>[]> = {
  '~providers': T;
  authorize: (
    id: Identifier<T>,
    data?: Record<string, unknown>
  ) => Promise<AuthorizeResult>;
  callback: <ID extends Identifier<T>>(
    id: ID,
    options: CallbackOptions
  ) => Promise<CallbackResult<UserForProvider<T, ID>>>;
};

export type AuthingyConfig<T extends readonly OAuthProvider<any>[]> = {
  secret: string;
  providers: T;
};

/**
 * Defines an Authingy configuration with a secret and a list of providers
 *
 * @example
 * ```ts
 * const auth = defineAuthingyConfig({
 *   secret: 'my-secret',
 *   providers: [
 *     google({...}),
 *     github({...}),
 *     linkedin({...}),
 *   ],
 * });
 * ```
 */
export function defineAuthingyConfig<
  const T extends readonly OAuthProvider<any>[],
>(config: AuthingyConfig<T>): AuthingyReturn<T> {
  const { secret, providers } = config;

  const providerMap = new Map<Identifier<T>, T[number]>();
  for (const provider of providers) {
    providerMap.set(provider.id, provider);
  }

  return {
    '~providers': providers,
    authorize: async (id, data = {}) => {
      const provider = providerMap.get(id);
      if (!provider) {
        throw new AuthingyError(`Provider "${String(id)}" not found`);
      }

      const state = oauth.generateRandomState();
      const encryptedWithState = await encrypt(secret, {
        state,
        ...data,
      });

      const codeVerifier = oauth.generateRandomCodeVerifier();

      const url = await provider._authorization({
        state,
        codeVerifier,
      });

      return {
        url,
        state: encryptedWithState,
        codeVerifier,
      };
    },
    callback: async (id, options) => {
      const provider = providerMap.get(id);
      if (!provider) {
        throw new AuthingyError(`Provider "${String(id)}" not found`);
      }

      const { url, codeVerifier, state: encryptedWithState } = options;

      const decryptedState = await decrypt(secret, encryptedWithState);
      if (!decryptedState) {
        throw new AuthingyError('Invalid state');
      }

      if (
        !('state' in decryptedState) ||
        typeof decryptedState.state !== 'string'
      ) {
        throw new AuthingyError('Invalid state');
      }

      const token = await provider._callback({
        url,
        codeVerifier,
        state: decryptedState.state,
      });

      const user = await provider._user({
        token,
      });

      const { state, ...data } = decryptedState;

      return {
        user,
        token,
        data,
      };
    },
  };
}
