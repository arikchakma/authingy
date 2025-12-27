import type { TokenEndpointResponse } from 'oauth4webapi';

import type { OAuthProvider, OAuthProviderConfig } from './types';

import { AuthingyError } from '../error';
import { buildAuthorizationUrl } from '../utils';

/**
 * Discord user profile returned from the Discord API
 * @see https://discord.com/developers/docs/resources/user#user-object
 */
export type DiscordUserProfile = {
  id: string;
  /** The user's username, not unique across the platform */
  username: string;
  /** The user's Discord-tag (discriminator) */
  discriminator: string;
  /** The user's display name, if set */
  global_name: string | null;
  /** The user's avatar hash */
  avatar: string | null;
  /** Whether the user belongs to an OAuth2 application */
  bot?: boolean;
  /** Whether the user is an Official Discord System user */
  system?: boolean;
  /** Whether the user has two factor enabled on their account */
  mfa_enabled?: boolean;
  /** The user's banner hash */
  banner?: string | null;
  /** The user's banner color encoded as an integer */
  accent_color?: number | null;
  /** The user's chosen language option */
  locale?: string;
  /** Whether the email on this account has been verified */
  verified?: boolean;
  /** The user's email */
  email?: string | null;
  /** The flags on a user's account */
  flags?: number;
  /** The type of Nitro subscription on a user's account */
  premium_type?: number;
  /** The public flags on a user's account */
  public_flags?: number;
  /** The user's avatar decoration hash */
  avatar_decoration?: string | null;
};

/**
 * Discord OAuth provider configuration
 */
export type DiscordProviderConfig = OAuthProviderConfig;

/**
 * Discord OAuth 2.0 provider
 *
 * Discord OAuth 2.0 implementation following the Authorization Code Flow
 * with PKCE (Proof Key for Code Exchange) for enhanced security.
 *
 * @see https://discord.com/developers/docs/topics/oauth2
 * @see https://discord.com/developers/docs/topics/oauth2#authorization-code-grant
 *
 * @example
 * ```ts
 * const discordProvider = discord({
 *   clientId: process.env.DISCORD_CLIENT_ID,
 *   clientSecret: process.env.DISCORD_CLIENT_SECRET,
 *   redirectUri: 'https://myapp.com/auth/callback/discord',
 *   scopes: ['identify', 'email'],
 * });
 * ```
 */
export function discord(config: DiscordProviderConfig) {
  const {
    clientId,
    clientSecret,
    redirectUri,
    scopes: providedScopes,
  } = config;

  // Discord OAuth2 endpoints
  // @see https://discord.com/developers/docs/topics/oauth2#shared-resources-oauth2-urls
  const authorizationEndpoint = 'https://discord.com/oauth2/authorize';
  const tokenEndpoint = 'https://discord.com/api/oauth2/token';
  const userinfoEndpoint = 'https://discord.com/api/users/@me';

  // Default scopes for basic user information
  // `identify` grants access to read user profile data (excluding email)
  // `email` grants access to read user's email address
  const defaultScopes = ['identify', 'email'];
  const scopes = [...defaultScopes, ...(providedScopes ?? [])];

  return {
    id: 'discord',
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

      // Discord uses client credentials in the POST body
      // @see https://discord.com/developers/docs/topics/oauth2#authorization-code-grant-access-token-exchange-example
      const tokenResponse = await fetch(tokenEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          redirect_uri: redirectUri,
          client_id: clientId,
          client_secret: clientSecret,
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

      // Fetch user profile from Discord API
      // @see https://discord.com/developers/docs/resources/user#get-current-user
      const userResponse = await fetch(userinfoEndpoint, {
        headers: {
          Authorization: `Bearer ${access_token}`,
        },
      });

      if (!userResponse.ok) {
        throw new AuthingyError(
          'USER_FETCH_FAILED',
          'Failed to fetch Discord user profile',
          {
            status: userResponse.status,
            statusText: userResponse.statusText,
          }
        );
      }

      const userProfile = (await userResponse.json()) as DiscordUserProfile;
      return userProfile;
    },
  } satisfies OAuthProvider<DiscordUserProfile>;
}
