const express = require('express');
const {
    parseUsers,
    createAuthentication,
    requirePermission,
} = require('./rbac');

/**
 * Build the app with validated server-owned identities and protected API routes.
 * @param {object} [options] Application configuration.
 * @param {string} [options.rbacUsers] JSON users; defaults to RBAC_USERS or no users.
 * @returns {import('express').Express} An app ready to listen for requests.
 * @throws {Error} If the user configuration is invalid.
 */
function createApp({ rbacUsers = process.env.RBAC_USERS } = {}) {
    const app = express();
    const users = parseUsers(rbacUsers);
    app.disable('x-powered-by');

    app.get('/', (req, res) => {
        res.send('Hello, pipeline.... pqrs - new deployment 1 !!!');
    });

    // Every current and future /api route must authenticate first.
    app.use('/api', createAuthentication(users));
    app.get('/api/me', requirePermission('profile:read'), (req, res) => {
        res.json({ user: req.user });
    });
    // Access probes demonstrate how to guard future business operations.
    app.get('/api/editor', requirePermission('content:write'), (req, res) => {
        res.json({ message: 'Editor access granted' });
    });
    app.get('/api/admin', requirePermission('users:manage'), (req, res) => {
        res.json({ message: 'Admin access granted' });
    });

    return app;
}

module.exports = { createApp };
