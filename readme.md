<div align="center">
  <h2>🔐 AuthFlowy</h2>
  <p>A type-safe, minimal, opinionated OAuth library with plugin-based providers for JavaScript and TypeScript.</p>
  <a href="https://npmjs.com/package/authflowy"><strong>npm</strong></a>
</div>

### What Does It Do?

**AuthFlowy** (pronounced "auth flow-y") simplifies OAuth 2.0 authentication with a clean, type-safe API. It supports multiple providers out of the box.

```ts
import { defineAuthFlowyConfig, google, github } from 'authflowy';

const auth = defineAuthFlowyConfig({
  secret: process.env.AUTH_SECRET,
  providers: [
    google({
      clientId: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      redirectUri: 'https://myapp.com/auth/callback/google',
    }),
    github({
      clientId: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
      redirectUri: 'https://myapp.com/auth/callback/github',
    }),
  ],
});

// redirect the user to the authorization url
const { url, state, codeVerifier } = await auth.authorize('google');

// one eternity later, the user lands back on the
// callback url, we can now handle the callback
const { user, token } = await auth.callback('google', {
  url: new URL(req.url),
  state,
  codeVerifier,
});

console.log(user);
// {
//   email: 'user@example.com',
//   name: 'John Doe',
//   picture: 'https://...',
//   ...
// }
```

> [!NOTE]
> This library is designed for my personal projects. If you need more flexibility, you can use the underlying `oauth4webapi` library directly.

### Installation

```bash
# npm
npm install authflowy

# pnpm
pnpm add authflowy

# bun
bun add authflowy
```

### Acknowledgements

This project was inspired by and builds upon:

- [oauth4webapi](https://github.com/panva/oauth4webapi) - The underlying OAuth 2.0 / OpenID Connect implementation that powers this library

Special thanks to the maintainers and contributors of this project for their excellent work in the OAuth ecosystem.

### Contributing

Feel free to submit pull requests, create issues, or spread the word.

### License

MIT &copy; [Arik Chakma](https://x.com/imarikchakma)
