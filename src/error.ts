export class AuthingyError extends Error {
  public readonly code: AuthingyErrorCode;
  public readonly details?: Record<string, unknown>;

  constructor(
    code: AuthingyErrorCode,
    message: string,
    details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'AuthingyError';
    this.code = code;
    this.details = details;
  }
}

export type AuthingyErrorCode =
  | 'PROVIDER_NOT_FOUND'
  | 'INVALID_STATE'
  | 'TOKEN_EXCHANGE_FAILED'
  | 'USER_FETCH_FAILED'
  | 'MISSING_CODE_VERIFIER'
  | 'MISSING_AUTHORIZATION_ENDPOINT';
