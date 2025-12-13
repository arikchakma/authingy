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
