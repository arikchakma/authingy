import type { TokenEndpointResponse } from 'oauth4webapi';

export type BaseUser = Record<string, unknown>;

type AuthorizationUrlOptions = {
  state: string;
  codeVerifier: string;
};

type CallbackOptions = {
  url: URL;
  codeVerifier: string;
  state: string;
};

type UserOptions = {
  token: TokenEndpointResponse;
};

export type LiteralString = '' | (string & Record<never, never>);

export type OAuthProvider<TUser extends BaseUser = BaseUser> = {
  readonly id: LiteralString;
  _authorization: (options: AuthorizationUrlOptions) => Promise<string>;
  _callback: (options: CallbackOptions) => Promise<TokenEndpointResponse>;
  _user: (options: UserOptions) => Promise<TUser>;
};

export type OAuthProviderConfig = {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  scopes?: string[];
};
