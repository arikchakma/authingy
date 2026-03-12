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

export function defineProvider<TUser extends BaseUser>(
  provider: OAuthProvider<TUser>
): OAuthProvider<TUser>;
export function defineProvider<TUser extends BaseUser, TConfig>(
  factory: (config: TConfig) => OAuthProvider<TUser>
): (config: TConfig) => OAuthProvider<TUser>;
export function defineProvider<TUser extends BaseUser, TConfig>(
  providerOrFactory:
    | OAuthProvider<TUser>
    | ((config: TConfig) => OAuthProvider<TUser>)
) {
  return providerOrFactory;
}

export type OAuthProviderConfig = {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  scopes?: string[];
};
