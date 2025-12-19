import { describe, expect, it } from 'bun:test';
import * as oauth from 'oauth4webapi';

import { buildAuthorizationUrl } from './utils';

describe('utils', () => {
  it('should build authorization url', async () => {
    const codeVerifier = oauth.generateRandomCodeVerifier();
    const url = await buildAuthorizationUrl({
      authorizationEndpoint: 'https://example.com/authorize',
      clientId: '1234567890',
      redirectUri: 'https://example.com/callback',
      scopes: ['openid', 'profile', 'email'],
      codeVerifier,
      state: '1234567890',
      extraParams: {
        access_type: 'offline',
        prompt: 'consent',
        include_granted_scopes: 'true',
      },
    });

    const searchParams = new URL(url).searchParams;
    expect(searchParams.get('client_id')).toBe('1234567890');
    expect(searchParams.get('redirect_uri')).toBe(
      'https://example.com/callback'
    );
    expect(searchParams.get('scope')).toBe('openid profile email');

    const codeChallenge = await oauth.calculatePKCECodeChallenge(codeVerifier);
    expect(searchParams.get('code_challenge')).toBe(codeChallenge);
    expect(searchParams.get('code_challenge_method')).toBe('S256');

    expect(searchParams.get('state')).toBe('1234567890');
    expect(searchParams.get('response_type')).toBe('code');
    expect(searchParams.get('access_type')).toBe('offline');
    expect(searchParams.get('prompt')).toBe('consent');
    expect(searchParams.get('include_granted_scopes')).toBe('true');
  });
});
