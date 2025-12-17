import * as oauth from 'oauth4webapi';
import { AuthingyError } from '../error';
import { buildAuthorizationUrl, getAuthorizationServer } from '../utils';
import type { OAuthProvider, OAuthProviderConfig } from './types';

export type VercelUserProfile = {
  sub: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  preferred_username?: string;
  picture?: string;
};

/**
 * Vercel OAuth provider (Sign in with Vercel)
 *
 * @see https://vercel.com/docs/sign-in-with-vercel
 *
 * @example
 * ```ts
 * const vercelProvider = vercel({
 *   clientId: process.env.VERCEL_CLIENT_ID,
 *   clientSecret: process.env.VERCEL_CLIENT_SECRET,
 *   redirectUri: 'https://myapp.com/auth/callback/vercel',
 * });
 * ```
 */
export function vercel(config: OAuthProviderConfig) {
  const {
    clientId,
    clientSecret,
    redirectUri,
    scopes: providedScopes,
  } = config;

  const issuer = new URL('https://vercel.com');
  const client: oauth.Client = { client_id: clientId };
  const clientAuth = oauth.ClientSecretPost(clientSecret);

  const defaultScopes = ['openid', 'email', 'profile'];
  const scopes = [...defaultScopes, ...(providedScopes ?? [])];
  let as: oauth.AuthorizationServer | undefined;

  const authorizationServer = async () => {
    if (!as) {
      as = await getAuthorizationServer(issuer);
    }
    return as;
  };

  return {
    id: 'vercel',
    _authorization: async (options) => {
      const { codeVerifier, state } = options;

      if (!codeVerifier) {
        throw new AuthingyError(
          'MISSING_CODE_VERIFIER',
          'Code verifier is required'
        );
      }

      const as = await authorizationServer();

      if (!as.authorization_endpoint) {
        throw new AuthingyError(
          'MISSING_AUTHORIZATION_ENDPOINT',
          'Authorization endpoint not found'
        );
      }

      return buildAuthorizationUrl({
        authorizationEndpoint: as.authorization_endpoint,
        clientId: client.client_id,
        redirectUri,
        scopes,
        codeVerifier,
        state,
      });
    },

    _callback: async (options) => {
      const { url, codeVerifier, state } = options;
      const as = await authorizationServer();
      const params = oauth.validateAuthResponse(
        as,
        client,
        url,
        state
      );

      const response = await oauth.authorizationCodeGrantRequest(
        as,
        client,
        clientAuth,
        params,
        redirectUri,
        codeVerifier
      );

      const result = await oauth.processAuthorizationCodeResponse(
        as,
        client,
        response
      );

      return result;
    },

    _user: async (options) => {
      const { token } = options;
      const { access_token } = token;
      const claims = oauth.getValidatedIdTokenClaims(token)!;
      const { sub } = claims;
      const as = await authorizationServer();
      const userResponse = await oauth.userInfoRequest(
        as,
        client,
        access_token
      );

      const userResult = await oauth.processUserInfoResponse(
        as,
        client,
        sub,
        userResponse
      );

      return userResult as VercelUserProfile;
    },
  } satisfies OAuthProvider<VercelUserProfile>;
}