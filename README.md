# Pipe app

A small Express app with bearer-token authentication and role-based access control.
Requires Node.js 22 or newer.

```sh
npm ci
npm test
npm start
```

The existing `/` landing page remains public. All `/api` routes require an
`Authorization: Bearer <token>` header. Missing, invalid, or malformed credentials
return **401**; authenticated users without the required permission receive **403**.
API responses are marked `Cache-Control: no-store`.

## Roles and routes

| Route             | Permission      | viewer | editor | admin |
| ----------------- | --------------- | ------ | ------ | ----- |
| `GET /api/me`     | `profile:read`  | Yes    | Yes    | Yes   |
| `GET /api/editor` | `content:write` | No     | Yes    | Yes   |
| `GET /api/admin`  | `users:manage`  | No     | No     | Yes   |

`/api/me` returns the authenticated user's ID and role, never credentials or hashes.
The editor and admin endpoints are access probes; they do not modify data. There
are no existing business resources or user database in this app.

## Provision credentials

An operator assigns identities and roles through the `RBAC_USERS` environment
variable. It is a JSON array containing `id`, `role`, and `tokenSha256` for each
user. There is no public registration or role-assignment endpoint.

Generate a random 32-byte token and its SHA-256 hash locally:

```sh
node -e 'const c = require("node:crypto"); const t = c.randomBytes(32).toString("hex"); console.log("Token:", t); console.log("SHA-256:", c.createHash("sha256").update(t).digest("hex"));'
```

Give the token to its intended user through a secure channel. Store only its
lowercase hexadecimal SHA-256 hash in deployment configuration:

```sh
export RBAC_USERS='[{"id":"alice","role":"admin","tokenSha256":"<generated SHA-256 hash>"}]'
npm start
```

The placeholder must be replaced before starting the app. Use a separate random
token per user and grant the least privileged role needed. Never use passwords or
predictable strings as tokens: SHA-256 here verifies high-entropy API tokens; it is
not password storage. Keep tokens out of source control, request URLs, and logs.
Use HTTPS at the deployment proxy for all remote requests.

Missing configuration defaults to no users: the public landing page works, but
all API access is denied. Invalid configuration, unknown roles, duplicate user IDs,
and duplicate token hashes stop startup. Restart all application instances after
changing configuration to apply role changes, token rotation, or revocation.
To revoke a token, remove the corresponding entry; to rotate it, replace its hash.
Tokens have no automatic expiry. For interactive login, SSO, or larger deployments,
replace this authentication adapter with a trusted identity provider while keeping
the permission guards.

## Protect new routes

Define permissions in `rbac.js`, then add a route **after** the `/api`
authentication middleware in `app.js`:

```js
app.post('/api/content', requirePermission('content:write'), handler);
```

Every business route must declare a permission guard. Unknown permissions deny
access for every role, including admin. Never accept a user ID or role supplied in
request headers, query parameters, or request bodies as authorization evidence.
Resource ownership or tenant checks must be added alongside role checks when
resources are introduced.

## Development

```sh
npm test
npm run format
npm run format:check
```

Tests exercise HTTP authentication, the complete route/role access matrix,
configuration validation, and attempts to bypass role checks.
