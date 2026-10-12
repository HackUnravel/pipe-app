const assert = require('node:assert/strict');
const { createHash, randomBytes } = require('node:crypto');
const { once } = require('node:events');
const { test } = require('node:test');
const { createApp } = require('../app');
const { parseUsers, requirePermission } = require('../rbac');

const roles = ['viewer', 'editor', 'admin'];
const tokens = Object.fromEntries(
    roles.map((role) => [role, randomBytes(32).toString('hex')]),
);
const users = roles.map((role) => ({
    id: `${role}-user`,
    role,
    tokenSha256: createHash('sha256').update(tokens[role]).digest('hex'),
}));

/**
 * Start an isolated HTTP test server and register cleanup with the test context.
 * @param {import('node:test').TestContext} t The owning test's lifecycle context.
 * @param {string} [rbacUsers] JSON identities; defaults to the test role fixtures.
 * @returns {Promise<{app: import('express').Express, request: Function}>} The app
 * and a fetch helper whose paths are relative to the ephemeral local server.
 */
async function serve(t, rbacUsers = JSON.stringify(users)) {
    const app = createApp({ rbacUsers });
    const server = app.listen(0, '127.0.0.1');
    t.after(() => new Promise((resolve) => server.close(resolve)));
    await once(server, 'listening');
    const url = `http://127.0.0.1:${server.address().port}`;
    return {
        app,
        request: (path, options) => fetch(`${url}${path}`, options),
    };
}

/**
 * Construct request headers using the test token for the requested role.
 * @param {'viewer'|'editor'|'admin'} role Fixture identity to authenticate as.
 * @param {Record<string, string>} [extraHeaders] Headers to add or override.
 * @returns {{headers: Record<string, string>}} Options for the request helper.
 */
function authorized(role, extraHeaders = {}) {
    return {
        headers: { Authorization: `Bearer ${tokens[role]}`, ...extraHeaders },
    };
}

test('landing page remains public and unchanged', async (t) => {
    const { request } = await serve(t);
    const response = await request('/');
    assert.equal(response.status, 200);
    assert.equal(
        await response.text(),
        'Hello, pipeline.... pqrs - new deployment 1 !!!',
    );
});

test('every role obeys the route permission matrix', async (t) => {
    const { request } = await serve(t);
    const matrix = {
        '/api/me': [200, 200, 200],
        '/api/editor': [403, 200, 200],
        '/api/admin': [403, 403, 200],
    };
    for (const [route, statuses] of Object.entries(matrix)) {
        for (const [index, role] of roles.entries()) {
            const response = await request(route, authorized(role));
            assert.equal(response.status, statuses[index], `${role}: ${route}`);
            assert.equal(response.headers.get('cache-control'), 'no-store');
            const body = await response.json();
            if (statuses[index] === 403) {
                assert.deepEqual(body, { error: 'Forbidden' });
            } else if (route === '/api/me') {
                assert.deepEqual(body, { user: { id: `${role}-user`, role } });
            }
            const serialized = JSON.stringify(body);
            for (const token of Object.values(tokens)) {
                assert.ok(!serialized.includes(token));
            }
            for (const user of users) {
                assert.ok(!serialized.includes(user.tokenSha256));
            }
        }
    }
});

test('all API routes reject absent, invalid, and malformed credentials', async (t) => {
    const { request } = await serve(t);
    for (const route of [
        '/api/me',
        '/api/editor',
        '/api/admin',
        '/api/unknown',
    ]) {
        for (const authorization of [
            undefined,
            'Bearer invalid',
            'Bearer',
            `Basic ${tokens.admin}`,
            `Bearer ${tokens.admin} extra`,
            `Bearer ${tokens.admin}, Bearer ${tokens.admin}`,
        ]) {
            const response = await request(route, {
                headers: authorization ? { Authorization: authorization } : {},
            });
            assert.equal(response.status, 401);
            assert.equal(
                response.headers.get('www-authenticate'),
                'Bearer realm="pipe-app"',
            );
            assert.deepEqual(await response.json(), { error: 'Unauthorized' });
        }
    }
});

test('bearer scheme is case insensitive but tokens are case sensitive', async (t) => {
    const { request } = await serve(t);
    const allowed = await request('/api/me', {
        headers: { Authorization: `bearer ${tokens.viewer}` },
    });
    assert.equal(allowed.status, 200);
    const rejected = await request('/api/me', {
        headers: { Authorization: `Bearer ${tokens.viewer.toUpperCase()}` },
    });
    assert.equal(rejected.status, 401);
});

test('request headers, query strings, and bodies cannot elevate a viewer', async (t) => {
    const { app, request } = await serve(t);
    app.post(
        '/api/protected',
        requirePermission('users:manage'),
        (req, res) => {
            res.sendStatus(204);
        },
    );
    const response = await request(
        '/api/admin?role=admin&user=admin-user&token=' + tokens.admin,
        authorized('viewer', { 'X-Role': 'admin', 'X-User-Id': 'admin-user' }),
    );
    assert.equal(response.status, 403);
    const posted = await request('/api/protected', {
        ...authorized('viewer', { 'Content-Type': 'application/json' }),
        method: 'POST',
        body: JSON.stringify({ id: 'admin-user', role: 'admin' }),
    });
    assert.equal(posted.status, 403);
    const queryOnly = await request('/api/me?token=' + tokens.admin);
    assert.equal(queryOnly.status, 401);
});

test('unknown permissions deny every role and unauthenticated guards deny access', async (t) => {
    const { app, request } = await serve(t);
    app.get(
        '/api/unknown',
        requirePermission('unknown:permission'),
        (req, res) => {
            res.sendStatus(204);
        },
    );
    app.get('/guard-only', requirePermission('profile:read'), (req, res) => {
        res.sendStatus(204);
    });
    for (const role of roles) {
        assert.equal(
            (await request('/api/unknown', authorized(role))).status,
            403,
        );
    }
    assert.equal((await request('/guard-only')).status, 401);
});

test('empty configuration allows public access but denies all API users', async (t) => {
    assert.deepEqual(parseUsers(), []);
    const { request } = await serve(t, '[]');
    assert.equal((await request('/')).status, 200);
    assert.equal((await request('/api/me', authorized('admin'))).status, 401);
});

test('configuration rejects invalid entries and duplicates without echoing input', () => {
    const valid = users[0];
    const invalid = [
        '',
        'not-json-sensitive-value',
        '{}',
        'null',
        '[null]',
        JSON.stringify([{ ...valid, role: 'owner' }]),
        JSON.stringify([{ ...valid, role: '__proto__' }]),
        JSON.stringify([{ ...valid, role: 'constructor' }]),
        JSON.stringify([{ ...valid, id: ' ' }]),
        JSON.stringify([{ ...valid, id: 1 }]),
        JSON.stringify([
            { ...valid, tokenSha256: 'plaintext-sensitive-value' },
        ]),
        JSON.stringify([
            { ...valid, tokenSha256: valid.tokenSha256.toUpperCase() },
        ]),
        JSON.stringify([valid, { ...users[1], id: valid.id }]),
        JSON.stringify([
            valid,
            { ...users[1], tokenSha256: valid.tokenSha256 },
        ]),
    ];
    for (const value of invalid) {
        assert.throws(
            () => createApp({ rbacUsers: value }),
            (error) => {
                assert.ok(
                    error.message.startsWith('RBAC_USERS') ||
                        error.message.startsWith('Each RBAC_USERS'),
                );
                assert.ok(!error.message.includes('sensitive-value'));
                assert.ok(!error.message.includes(valid.tokenSha256));
                return true;
            },
        );
    }
});

test('a new app applies role changes and token revocation from configuration', async (t) => {
    const reduced = users.map((user) => ({ ...user, role: 'viewer' }));
    const downgraded = await serve(t, JSON.stringify(reduced));
    assert.equal(
        (await downgraded.request('/api/admin', authorized('admin'))).status,
        403,
    );
    const revoked = await serve(
        t,
        JSON.stringify(users.filter((user) => user.role !== 'admin')),
    );
    assert.equal(
        (await revoked.request('/api/me', authorized('admin'))).status,
        401,
    );
});
