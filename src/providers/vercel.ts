import * as oauth from 'oauth4webapi';
import { AuthingyError } from '../error';
import { buildAuthorizationUrl } from '../utils';
import type { OAuthProvider, OAuthProviderConfig } from './types';

export type VercelUserProfile = {
  sub: string;
  name?: string;
  email?: string;
  picture?: string;
  team_id?: string;
  [key: string]: unknown;
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

  // Vercel does not expose a discovery document; configure endpoints manually
  const as: oauth.AuthorizationServer = {
    issuer: 'https://vercel.com',
    authorization_endpoint: 'https://vercel.com/oauth/authorize',
    token_endpoint: 'https://api.vercel.com/login/oauth/token',
    userinfo_endpoint: 'https://api.vercel.com/login/oauth/userinfo',
  };

  const client: oauth.Client = { client_id: clientId };
  const clientAuth = oauth.ClientSecretPost(clientSecret);

  const defaultScopes = ['openid', 'email', 'profile'];
  const scopes = [...defaultScopes, ...(providedScopes ?? [])];

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

      const params = oauth.validateAuthResponse(as, client, url, state);

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

