import type { Identifier } from '../src';
import { defineAuthingyConfig, github, google, vercel } from '../src';

const PORT = 5173;

const auth = defineAuthingyConfig({
  secret: Bun.env.AUTH_SECRET_KEY!,
  providers: [
    google({
      clientId: Bun.env.GOOGLE_CLIENT_ID!,
      clientSecret: Bun.env.GOOGLE_CLIENT_SECRET!,
      redirectUri: `http://localhost:${PORT}/api/v1/auth/google/callback`,
    }),
    github({
      clientId: Bun.env.GITHUB_CLIENT_ID!,
      clientSecret: Bun.env.GITHUB_CLIENT_SECRET!,
      redirectUri: `http://localhost:${PORT}/api/v1/auth/github/callback`,
    }),
    vercel({
      clientId: Bun.env.VERCEL_CLIENT_ID !,
      clientSecret: Bun.env.VERCEL_CLIENT_SECRET !,
      redirectUri: `http://localhost:${PORT}/api/v1/auth/vercel/callback`,
    }),
  ],
});

const COOKIE_NAME_STATE = '_authingy_state_';
const COOKIE_NAME_CODE_VERIFIER = '_authingy_code_verifier_';
const COOKIE_OPTIONS = {
  httpOnly: true,
  secure: Bun.env.NODE_ENV === 'production',
  sameSite: 'lax',
} as const;

const server = Bun.serve({
  port: PORT,
  routes: {
    '/api/v1/auth/:provider': async (req) => {
      const { provider: _provider } = req.params;
      const provider = _provider as Identifier<(typeof auth)['~providers']>;

      const { url, state, codeVerifier } = await auth.authorize(provider, {
        some_random_data: 'some_random_data',
      });

      const cookies = req.cookies;
      const expires = new Date(Date.now() + 60 * 1000 * 10); // 10 minutes
      cookies.set(COOKIE_NAME_STATE, state, {
        ...COOKIE_OPTIONS,
        expires,
      });
      cookies.set(COOKIE_NAME_CODE_VERIFIER, codeVerifier, {
        ...COOKIE_OPTIONS,
        expires,
      });

      return Response.redirect(url, 302);
    },
    '/api/v1/auth/:provider/callback': async (req) => {
      const { provider: _provider } = req.params;
      const provider = _provider as Identifier<(typeof auth)['~providers']>;

      const cookies = req.cookies;
      const state = cookies.get(COOKIE_NAME_STATE);
      const codeVerifier = cookies.get(COOKIE_NAME_CODE_VERIFIER);
      if (!state || !codeVerifier) {
        return new Response('Invalid state or code verifier', { status: 400 });
      }

      const { user, data } = await auth.callback(provider, {
        url: new URL(req.url),
        codeVerifier,
        state,
      });

      cookies.delete(COOKIE_NAME_STATE, { path: '/' });
      cookies.delete(COOKIE_NAME_CODE_VERIFIER, { path: '/' });

      return Response.json({ user, data });
    },
  },
});

const colors = {
  cyan: '\x1b[36m',
  yellow: '\x1b[33m',
  green: '\x1b[32m',
  dim: '\x1b[2m',
  reset: '\x1b[0m',
};

const providerEndpoints = auth['~providers']
  .map((provider) => {
    return `For ${colors.yellow}"${provider.id}"${colors.reset} provider, you can use the following URL:

  ${colors.cyan}${server.url}api/v1/auth/${provider.id}${colors.reset}

  ${colors.dim}To test the callback, you can use:${colors.reset}

  ${colors.cyan}${server.url}api/v1/auth/${provider.id}/callback${colors.reset}
  `.trim();
  })
  .join('\n\n  ');

console.log(
  `\nTo test the server, you can use the following URL:

  ${server.url}

  ${providerEndpoints}\n`
);
