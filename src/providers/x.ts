import type { TokenEndpointResponse } from 'oauth4webapi';

import type { OAuthProvider, OAuthProviderConfig } from './types';

import { AuthingyError } from '../error';
import { buildAuthorizationUrl } from '../utils';

/**
 * X (Twitter) user profile returned from the X API v2
 * @see https://developer.x.com/en/docs/twitter-api/users/lookup/api-reference/get-users-me
 */
export type XUserProfile = {
  id: string;
  /** Display name */
  name: string;
  /** The username/handle (without @) */
  username: string;
  /** URL to the user's profile image */
  profile_image_url?: string;
  /** Whether the user is verified */
  verified?: boolean;
  /** Type of verification (blue, business, government, none) */
  verified_type?: string;
  /** User's bio/description */
  description?: string;
  /** Account creation date in ISO 8601 format */
  created_at?: string;
  /** User's location (self-reported) */
  location?: string;
  /** URL to the user's profile */
  url?: string;
  /** Whether the account is protected/private */
  protected?: boolean;
  /** Public metrics for the user */
  public_metrics?: {
    followers_count: number;
    following_count: number;
    tweet_count: number;
    listed_count: number;
    like_count: number;
  };
};

/**
 * X (Twitter) OAuth provider configuration
 */
export type XProviderConfig = OAuthProviderConfig & {
  /**
   * Additional user fields to request from the X API
   * @see https://developer.x.com/en/docs/twitter-api/users/lookup/api-reference/get-users-me
   */
  userFields?: string[];
};

/**
 * X (Twitter) OAuth 2.0 provider
 *
 * X OAuth 2.0 implementation following the Authorization Code Flow
 * with PKCE (Proof Key for Code Exchange) for enhanced security.
 *
 * @see https://developer.x.com/en/docs/authentication/oauth-2-0/authorization-code
 * @see https://developer.x.com/en/docs/authentication/oauth-2-0/user-access-token
 *
 * @example
 * ```ts
 * const xProvider = x({
 *   clientId: process.env.X_CLIENT_ID,
 *   clientSecret: process.env.X_CLIENT_SECRET,
 *   redirectUri: 'https://myapp.com/auth/callback/x',
 *   scopes: ['tweet.read', 'users.read'],
 *   userFields: ['pinned_tweet_id', 'most_recent_tweet_id'],
 * });
 * ```
 */
export function x(config: XProviderConfig) {
  const {
    clientId,
    clientSecret,
    redirectUri,
    scopes: providedScopes,
    userFields: providedUserFields,
  } = config;

  // X doesn't support OIDC discovery, so we manually configure the endpoints
  // @see https://developer.x.com/en/docs/authentication/oauth-2-0/authorization-code
  const authorizationEndpoint = 'https://x.com/i/oauth2/authorize';
  const tokenEndpoint = 'https://api.x.com/2/oauth2/token';

  // Default scopes for basic user information
  // `users.read` grants access to read user profile data
  // `tweet.read` is required by X for most OAuth apps
  // `offline.access` grants refresh tokens
  const defaultScopes = ['users.read', 'tweet.read', 'offline.access'];
  const scopes = [...defaultScopes, ...(providedScopes ?? [])];

  // Default user fields to request from the X API
  const defaultUserFields = [
    'id',
    'name',
    'username',
    'profile_image_url',
    'verified',
    'verified_type',
    'description',
    'created_at',
    'location',
    'url',
    'protected',
    'public_metrics',
  ];
  const userFields = [...defaultUserFields, ...(providedUserFields ?? [])];

  return {
    id: 'x',
    _authorization: async (options) => {
      const { codeVerifier, state } = options;

      if (!codeVerifier) {
        throw new AuthingyError(
          'MISSING_CODE_VERIFIER',
          'Code verifier is required'
        );
      }

      return buildAuthorizationUrl({
        authorizationEndpoint,
        clientId,
        redirectUri,
        scopes,
        codeVerifier,
        state,
      });
    },
    _callback: async (options) => {
      const { url, codeVerifier, state } = options;

      // Validate the callback URL has required params
      const code = url.searchParams.get('code');
      const returnedState = url.searchParams.get('state');

      if (!code) {
        throw new AuthingyError(
          'TOKEN_EXCHANGE_FAILED',
          'Missing authorization code in callback'
        );
      }

      if (returnedState !== state) {
        throw new AuthingyError('INVALID_STATE', 'State mismatch in callback');
      }

      // X requires Basic Auth with client credentials
      // @see https://developer.x.com/en/docs/authentication/oauth-2-0/user-access-token
      const basicAuth = Buffer.from(`${clientId}:${clientSecret}`).toString(
        'base64'
      );

      const tokenResponse = await fetch(tokenEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: `Basic ${basicAuth}`,
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          redirect_uri: redirectUri,
          code_verifier: codeVerifier,
        }),
      });

      if (!tokenResponse.ok) {
        const errorBody = await tokenResponse.text();
        throw new AuthingyError(
          'TOKEN_EXCHANGE_FAILED',
          'Failed to exchange authorization code for tokens',
          {
            status: tokenResponse.status,
            statusText: tokenResponse.statusText,
            body: errorBody,
          }
        );
      }

      const result = (await tokenResponse.json()) as TokenEndpointResponse;
      return result;
    },
    _user: async (options) => {
      const { token } = options;
      const { access_token } = token;

      // Fetch user profile from X API v2
      // @see https://developer.x.com/en/docs/twitter-api/users/lookup/api-reference/get-users-me
      const userUrl = new URL('https://api.x.com/2/users/me');
      userUrl.searchParams.set('user.fields', userFields.join(','));

      const userResponse = await fetch(userUrl.toString(), {
        headers: {
          Authorization: `Bearer ${access_token}`,
        },
      });

      if (!userResponse.ok) {
        throw new AuthingyError(
          'USER_FETCH_FAILED',
          'Failed to fetch X user profile',
          {
            status: userResponse.status,
            statusText: userResponse.statusText,
          }
        );
      }

      const response = (await userResponse.json()) as { data: XUserProfile };
      return response.data;
    },
  } satisfies OAuthProvider<XUserProfile>;
}
