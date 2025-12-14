import type { TokenEndpointResponse } from 'oauth4webapi';

export type BaseUser = Record<string, unknown>;

export type ProviderAuthorizationOptions = {
  state: string;
  codeVerifier: string;
};

export type ProviderCallbackOptions = {
  url: URL;
  codeVerifier: string;
  state: string;
};

export type ProviderUserOptions = {
  token: TokenEndpointResponse;
};

export type LiteralString = '' | (string & Record<never, never>);

export type OAuthProvider<TUser extends BaseUser = BaseUser> = {
  readonly id: LiteralString;
  _authorization: (options: ProviderAuthorizationOptions) => Promise<string>;
  _callback: (
    options: ProviderCallbackOptions
  ) => Promise<TokenEndpointResponse>;
  _user: (options: ProviderUserOptions) => Promise<TUser>;
};

export type OAuthProviderConfig = {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  scopes?: string[];
};
