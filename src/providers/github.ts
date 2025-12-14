import * as oauth from 'oauth4webapi';
import { AuthingyError } from '../error';
import type { OAuthProvider, OAuthProviderConfig } from '../provider';
import { buildAuthorizationUrl } from '../utils';

const GITHUB_API_VERSION = '2022-11-28';

/**
 * GitHub user profile returned from the GitHub API
 * @see https://docs.github.com/en/rest/users/users#get-the-authenticated-user
 */
type GitHubUser = {
  id: number;
  /** The username/handle */
  login: string;
  avatar_url: string;
  /** URL to the user's GitHub profile */
  html_url: string;
  name: string | null;
  /** May be null if not set or private */
  email: string | null;
  bio: string | null;
  twitter_username: string | null;
  company: string | null;
  location: string | null;
  /** Blog/website URL */
  blog: string | null;
  public_repos: number;
  followers: number;
  following: number;
  created_at: string;
  updated_at: string;
};

/**
 * GitHub email object from the emails API
 * @see https://docs.github.com/en/rest/users/emails#list-email-addresses-for-the-authenticated-user
 */
type GitHubEmail = {
  email: string;
  primary: boolean;
  verified: boolean;
  visibility: 'public' | 'private' | null;
};

/**
 * Extended GitHub user profile that includes verified email
 */
export type GitHubUserProfile = GitHubUser & {
  /**
   * The user's primary verified email address
   * This is fetched separately when `user:email` scope is granted
   */
  verified_email?: string;
  /**
   * All email addresses associated with the user's account
   * Only available when `user:email` scope is granted
   */
  emails?: GitHubEmail[];
};

/**
 * GitHub OAuth provider configuration
 */
export type GitHubProviderConfig = OAuthProviderConfig;

/**
 * GitHub OAuth provider
 *
 * GitHub OAuth 2.0 implementation following the OAuth 2.0 Authorization Code Flow
 * with PKCE (Proof Key for Code Exchange) for enhanced security.
 *
 * @see https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps
 * @see https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/scopes-for-oauth-apps
 *
 * @example
 * ```ts
 * const githubProvider = github({
 *   clientId: process.env.GITHUB_CLIENT_ID,
 *   clientSecret: process.env.GITHUB_CLIENT_SECRET,
 *   redirectUri: 'https://myapp.com/auth/callback/github',
 *   scopes: ['read:user', 'user:email'],
 * });
 * ```
 */
export function github(config: GitHubProviderConfig) {
  const {
    clientId,
    clientSecret,
    redirectUri,
    scopes: providedScopes,
  } = config;

  // GitHub doesn't support OIDC discovery, so we manually configure the endpoints
  // @see https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps
  const as: oauth.AuthorizationServer = {
    issuer: 'https://github.com',
    authorization_endpoint: 'https://github.com/login/oauth/authorize',
    token_endpoint: 'https://github.com/login/oauth/access_token',
    userinfo_endpoint: 'https://api.github.com/user',
  };

  const client: oauth.Client = { client_id: clientId };
  const clientAuth = oauth.ClientSecretPost(clientSecret);

  // Default scopes for basic user information
  // `read:user` grants access to read user profile data
  // `user:email` grants access to read user email addresses
  const defaultScopes = ['read:user', 'user:email'];
  const scopes = [...defaultScopes, ...(providedScopes ?? [])];

  return {
    id: 'github',
    _authorization: async (options) => {
      const { codeVerifier, state } = options;

      if (!codeVerifier) {
        throw new AuthingyError('codeVerifier is required');
      }

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

      // Fetch user profile from GitHub API
      // @see https://docs.github.com/en/rest/users/users#get-the-authenticated-user
      const userResponse = await fetch(as.userinfo_endpoint!, {
        headers: {
          Authorization: `Bearer ${access_token}`,
          Accept: 'application/vnd.github+json',
          'X-GitHub-Api-Version': GITHUB_API_VERSION,
        },
      });

      if (!userResponse.ok) {
        throw new AuthingyError('Failed to fetch GitHub user profile', {
          status: userResponse.status,
          statusText: userResponse.statusText,
        });
      }

      const userProfile = (await userResponse.json()) as GitHubUserProfile;

      const result: GitHubUserProfile = { ...userProfile };

      // If user:email scope is granted, fetch email addresses
      // This is necessary because the user profile may not include email
      // if the user hasn't set a public email
      if (scopes.includes('user:email')) {
        try {
          const emailsResponse = await fetch(
            'https://api.github.com/user/emails',
            {
              headers: {
                Authorization: `Bearer ${access_token}`,
                Accept: 'application/vnd.github+json',
                'X-GitHub-Api-Version': GITHUB_API_VERSION,
              },
            }
          );

          if (emailsResponse.ok) {
            const emails = (await emailsResponse.json()) as GitHubEmail[];
            result.emails = emails;

            const primaryEmail = emails.find(
              (email) => email.primary && email.verified
            );
            if (primaryEmail) {
              result.verified_email = primaryEmail.email;
            }
          }
        } catch {}
      }

      return result;
    },
  } satisfies OAuthProvider<GitHubUserProfile>;
}
