# Node.js password hashing

Password hashing using the native crypto module.

## Getting started

### Prerequisites

- [Node.js 24+](https://nodejs.org/en/download)
- [pnpm 10+](https://pnpm.io/installation)

### Setup

1. Clone the repo
2. Install dependencies with `pnpm install`
3. Set up git hooks with `pnpm exec lefthook install`
4. Run tests with `pnpm test`

## Resources

### Scrypt

- https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#scrypt
- https://github.com/pilcrowonpaper/oslo/blob/main/src/password/scrypt.ts
- https://github.com/better-auth/better-auth/blob/canary/packages/better-auth/src/crypto/password.ts
- https://docs.adonisjs.com/guides/security/hashing#scrypt

### Argon

- https://www.rfc-editor.org/rfc/rfc9106.html#section-4-5
- https://github.com/ranisalt/node-argon2/blob/master/argon2.cjs#L29
- https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id
- https://docs.adonisjs.com/guides/security/hashing#argon
