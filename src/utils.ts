import * as oauth from 'oauth4webapi';

type Algorithm =
  | 'oauth2' /* For .well-known/oauth-authorization-server discovery */
  | 'oidc' /* For .well-known/openid-configuration discovery */
  | undefined; /* Defaults to 'oidc' */

export async function getAuthorizationServer(
  issuer: URL,
  algorithm: Algorithm = 'oidc'
) {
  const response = await oauth.discoveryRequest(issuer, { algorithm });
  return oauth.processDiscoveryResponse(issuer, response);
}

export type BuildAuthorizationUrlOptions = {
  authorizationEndpoint: string;
  clientId: string;
  redirectUri: string;
  scopes: string[];
  codeVerifier: string;
  state: string;
  /** Additional provider-specific query parameters */
  extraParams?: Record<string, string>;
};

/**
 * Builds an OAuth 2.0 Authorization URL with PKCE support
 *
 * This is a generic function that constructs the authorization URL
 * with all standard OAuth 2.0 / OIDC parameters plus PKCE code challenge.
 *
 * @example
 * ```ts
 * const url = await buildAuthorizationUrl({
 *   authorizationEndpoint: 'https://provider.com/authorize',
 *   clientId: 'my-client-id',
 *   redirectUri: 'https://myapp.com/callback',
 *   scopes: ['openid', 'profile', 'email'],
 *   codeVerifier: 'random-verifier-string',
 *   state: 'random-state-string',
 *   extraParams: { prompt: 'consent' },
 * });
 * ```
 */
export async function buildAuthorizationUrl(
  options: BuildAuthorizationUrlOptions
): Promise<string> {
  const {
    authorizationEndpoint,
    clientId,
    redirectUri,
    scopes,
    codeVerifier,
    state,
    extraParams,
  } = options;

  const codeChallenge = await oauth.calculatePKCECodeChallenge(codeVerifier);

  const authorizationUrl = new URL(authorizationEndpoint);
  authorizationUrl.searchParams.set('client_id', clientId);
  authorizationUrl.searchParams.set('redirect_uri', redirectUri);
  authorizationUrl.searchParams.set('response_type', 'code');
  authorizationUrl.searchParams.set('scope', scopes.join(' '));
  authorizationUrl.searchParams.set('code_challenge', codeChallenge);
  authorizationUrl.searchParams.set('code_challenge_method', 'S256');
  authorizationUrl.searchParams.set('state', state);

  if (extraParams) {
    for (const [key, value] of Object.entries(extraParams)) {
      authorizationUrl.searchParams.set(key, value);
    }
  }

  return authorizationUrl.href;
}
