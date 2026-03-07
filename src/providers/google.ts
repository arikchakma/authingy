import * as oauth from 'oauth4webapi';

import type { OAuthProvider, OAuthProviderConfig } from './types';

import { AuthingyError } from '../error';
import { buildAuthorizationUrl, getAuthorizationServer } from '../utils';

export type GoogleUserProfile = {
  aud: string;
  azp: string;
  email: string;
  email_verified: boolean;
  exp: number;
  /**
   * The family name of the user, or last name in most
   * Western languages.
   */
  family_name: string;
  /**
   * The given name of the user, or first name in most
   * Western languages.
   */
  given_name: string;
  /**
   * The hosted domain of the user
   */
  hd?: string | undefined;
  iat: number;
  iss: string;
  jti?: string | undefined;
  locale?: string | undefined;
  name: string;
  nbf?: number | undefined;
  picture: string;
  sub: string;
};

/**
 * Google OAuth provider
 *
 * Google OpenID Connect implementation following the Authorization Code Flow
 * with PKCE (Proof Key for Code Exchange) for enhanced security.
 *
 * @see https://developers.google.com/identity/openid-connect/openid-connect
 * @see https://developers.google.com/identity/protocols/oauth2/scopes
 *
 * @example
 * ```ts
 * const googleProvider = google({
 *   clientId: process.env.GOOGLE_CLIENT_ID,
 *   clientSecret: process.env.GOOGLE_CLIENT_SECRET,
 *   redirectUri: 'https://myapp.com/auth/callback/google',
 * });
 * ```
 */
export type GoogleProviderConfig = OAuthProviderConfig & {
  /** Additional query parameters for the authorization URL */
  extraParams?: Record<string, string>;
};

export function google(config: GoogleProviderConfig) {
  const {
    clientId,
    clientSecret,
    redirectUri,
    scopes: providedScopes,
    extraParams: providedExtraParams,
  } = config;

  const issuer = new URL('https://accounts.google.com');
  const client: oauth.Client = {
    client_id: clientId,
  };
  const clientAuth = oauth.ClientSecretPost(clientSecret);

  const defaultScopes = ['openid', 'email', 'profile'];
  const scopes = [...new Set([...defaultScopes, ...(providedScopes ?? [])])];

  let as: oauth.AuthorizationServer | undefined;
  const authorizationServer = async () => {
    if (!as) {
      as = await getAuthorizationServer(issuer);
    }

    return as;
  };

  return {
    id: 'google',
    _authorization: async (options) => {
      const { codeVerifier, state } = options;

      as = await authorizationServer();
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
        extraParams: {
          access_type: 'offline',
          prompt: 'select_account',
          include_granted_scopes: 'true',
          ...providedExtraParams,
        },
      });
    },
    _callback: async (options) => {
      const { url, codeVerifier, state } = options;
      const as = await authorizationServer();
      const params = oauth.validateAuthResponse(as, client, url, state);

      const response = await oauth.authorizationCodeGrantRequest(
        as,
        client,
        clientAuth,
        params,
        config.redirectUri,
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

      const as = await authorizationServer();
      const { access_token } = token;
      const claims = oauth.getValidatedIdTokenClaims(token);
      if (!claims) {
        throw new AuthingyError(
          'USER_FETCH_FAILED',
          'Missing ID token claims in Google token response'
        );
      }
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

      return userResult as GoogleUserProfile;
    },
  } satisfies OAuthProvider<GoogleUserProfile>;
}
