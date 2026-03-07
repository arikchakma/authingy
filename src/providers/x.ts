import * as oauth from 'oauth4webapi';

import type { OAuthProviderConfig } from './types';

import { AuthingyError } from '../error';
import { buildAuthorizationUrl } from '../utils';
import { defineProvider } from './types';

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
export const x = defineProvider<XUserProfile, XProviderConfig>((config) => {
  const {
    clientId,
    clientSecret,
    redirectUri,
    scopes: providedScopes,
    userFields: providedUserFields,
  } = config;

  // X doesn't support OIDC discovery, so we manually configure the endpoints
  // @see https://developer.x.com/en/docs/authentication/oauth-2-0/authorization-code
  const as: oauth.AuthorizationServer = {
    issuer: 'https://x.com',
    authorization_endpoint: 'https://x.com/i/oauth2/authorize',
    token_endpoint: 'https://api.x.com/2/oauth2/token',
  };

  const client: oauth.Client = {
    client_id: clientId,
  };

  // Default scopes for basic user information
  // `users.read` grants access to read user profile data
  // `tweet.read` is required by X for most OAuth apps
  // `offline.access` grants refresh tokens
  const defaultScopes = ['users.read', 'tweet.read', 'offline.access'];
  const scopes = [...new Set([...defaultScopes, ...(providedScopes ?? [])])];

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
  const userFields = [
    ...new Set([...defaultUserFields, ...(providedUserFields ?? [])]),
  ];

  return {
    id: 'x',

    _authorization: async (options) => {
      const { codeVerifier, state } = options;

      return buildAuthorizationUrl({
        authorizationEndpoint: as.authorization_endpoint!,
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

      // X requires Basic Auth — oauth4webapi's auth methods are incompatible
      // @see https://developer.x.com/en/docs/authentication/oauth-2-0/user-access-token
      const response = await fetch(as.token_endpoint!, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: `Basic ${btoa(`${clientId}:${clientSecret}`)}`,
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: String(params.get('code')),
          redirect_uri: redirectUri,
          code_verifier: codeVerifier,
        }),
      });

      const result = await oauth.processAuthorizationCodeResponse(
        as,
        client,
        response,
        {
          requireIdToken: false,
        }
      );

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
        const body = await userResponse.text().catch(() => '');
        throw new AuthingyError(
          'USER_FETCH_FAILED',
          'Failed to fetch X user profile',
          {
            status: userResponse.status,
            statusText: userResponse.statusText,
            body,
          }
        );
      }

      const response = (await userResponse.json()) as { data: XUserProfile };
      return response.data;
    },
  };
});
