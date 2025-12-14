import * as oauth from 'oauth4webapi';
import { AuthFlowyError } from '../error';
import type { OAuthProvider, OAuthProviderConfig } from '../provider';
import { getAuthorizationServer } from '../utils';

type LinkedInUserProfile = {
  sub: string;
  name: string;
  given_name: string;
  family_name: string;
  picture: string;
  locale: string;
  email: string;
  email_verified: boolean;
};

export type LinkedInUser = LinkedInUserProfile;

/**
 * LinkedIn OAuth provider
 *
 * @see https://learn.microsoft.com/en-us/linkedin/consumer/integrations/self-serve/sign-in-with-linkedin-v2
 *
 * @example
 * ```ts
 * const linkedinProvider = linkedin({
 *   clientId: process.env.LINKEDIN_CLIENT_ID,
 *   clientSecret: process.env.LINKEDIN_CLIENT_SECRET,
 *   redirectUri: 'https://myapp.com/auth/callback/linkedin',
 * });
 * ```
 */
export function linkedin(config: OAuthProviderConfig) {
  const {
    clientId,
    clientSecret,
    redirectUri,
    scopes: providedScopes,
  } = config;

  const issuer = new URL('https://www.linkedin.com/oauth');
  const client: oauth.Client = { client_id: clientId };
  const clientAuth = oauth.ClientSecretPost(clientSecret);

  const defaultScopes = ['openid', 'profile', 'email'];
  const scopes = [...defaultScopes, ...(providedScopes ?? [])];

  let as: oauth.AuthorizationServer | undefined;
  const authorizationServer = async () => {
    if (!as) {
      as = await getAuthorizationServer(issuer);
    }
    return as;
  };

  return {
    id: 'linkedin',
    _authorization: async (options) => {
      const { codeVerifier, state } = options;

      if (!codeVerifier) {
        throw new AuthFlowyError('codeVerifier is required');
      }

      as = await authorizationServer();
      if (!as.authorization_endpoint) {
        throw new AuthFlowyError('Authorization endpoint not found');
      }

      const code_challenge =
        await oauth.calculatePKCECodeChallenge(codeVerifier);

      const authorizationUrl = new URL(as.authorization_endpoint);
      authorizationUrl.searchParams.set('client_id', client.client_id);
      authorizationUrl.searchParams.set('redirect_uri', redirectUri);
      authorizationUrl.searchParams.set('response_type', 'code');
      authorizationUrl.searchParams.set('scope', scopes.join(' '));
      authorizationUrl.searchParams.set('code_challenge', code_challenge);
      authorizationUrl.searchParams.set('code_challenge_method', 'S256');
      authorizationUrl.searchParams.set('state', state);

      return authorizationUrl.href;
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

      const as = await authorizationServer();
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

      return userResult as LinkedInUserProfile;
    },
  } satisfies OAuthProvider<LinkedInUser>;
}
