const { createHash } = require('node:crypto');

const ROLE_PERMISSIONS = Object.freeze({
    viewer: Object.freeze(['profile:read']),
    editor: Object.freeze(['profile:read', 'content:write']),
    admin: Object.freeze(['profile:read', 'content:write', 'users:manage']),
});

// Configuration is trusted deployment input. Roles never come from the request.
function parseUsers(value = '[]') {
    let users;
    try {
        users = JSON.parse(value);
    } catch {
        throw new Error('RBAC_USERS must be a JSON array');
    }
    if (!Array.isArray(users)) {
        throw new Error('RBAC_USERS must be a JSON array');
    }

    const ids = new Set();
    const hashes = new Set();
    return users.map((user) => {
        if (
            !user ||
            typeof user.id !== 'string' ||
            user.id.trim() === '' ||
            typeof user.role !== 'string' ||
            !Object.hasOwn(ROLE_PERMISSIONS, user.role) ||
            typeof user.tokenSha256 !== 'string' ||
            !/^[a-f0-9]{64}$/.test(user.tokenSha256)
        ) {
            throw new Error(
                'Each RBAC_USERS entry needs a nonempty id, a viewer/editor/admin role, and a lowercase SHA-256 token hash',
            );
        }
        if (ids.has(user.id) || hashes.has(user.tokenSha256)) {
            throw new Error('RBAC_USERS ids and token hashes must be unique');
        }
        ids.add(user.id);
        hashes.add(user.tokenSha256);
        return Object.freeze({
            id: user.id,
            role: user.role,
            tokenSha256: user.tokenSha256,
        });
    });
}

function createAuthentication(users) {
    const principals = new Map(
        users.map(({ id, role, tokenSha256 }) => [
            tokenSha256,
            Object.freeze({ id, role }),
        ]),
    );

    return (req, res, next) => {
        res.set('Cache-Control', 'no-store');
        const match = /^Bearer ([A-Za-z0-9._~+\/-]+=*)$/i.exec(
            req.get('Authorization') || '',
        );
        const principal = match
            ? principals.get(
                  createHash('sha256').update(match[1]).digest('hex'),
              )
            : undefined;
        if (!principal) {
            res.set('WWW-Authenticate', 'Bearer realm="pipe-app"');
            return res.status(401).json({ error: 'Unauthorized' });
        }
        req.user = principal;
        next();
    };
}

function requirePermission(permission) {
    return (req, res, next) => {
        if (!req.user) {
            res.set('WWW-Authenticate', 'Bearer realm="pipe-app"');
            return res.status(401).json({ error: 'Unauthorized' });
        }
        const permissions = Object.hasOwn(ROLE_PERMISSIONS, req.user.role)
            ? ROLE_PERMISSIONS[req.user.role]
            : [];
        if (!permissions.includes(permission)) {
            return res.status(403).json({ error: 'Forbidden' });
        }
        next();
    };
}

module.exports = { parseUsers, createAuthentication, requirePermission };
