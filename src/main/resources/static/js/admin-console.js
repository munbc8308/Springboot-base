(function () {
    'use strict';

    const csrfToken = document.querySelector('meta[name="_csrf"]').content;
    const csrfHeader = document.querySelector('meta[name="_csrf_header"]').content;

    // ── Helpers ─────────────────────────────────────────────

    function api(method, url, body) {
        const opts = {
            method: method,
            headers: { 'Content-Type': 'application/json' }
        };
        opts.headers[csrfHeader] = csrfToken;
        if (body) opts.body = JSON.stringify(body);
        return fetch(url, opts).then(r => {
            if (!r.ok) throw new Error('HTTP ' + r.status);
            return r.json();
        });
    }

    function fmt(instant) {
        if (!instant) return '-';
        var d = new Date(instant);
        return d.toLocaleString();
    }

    function esc(s) {
        if (s == null) return '';
        var el = document.createElement('span');
        el.textContent = String(s);
        return el.innerHTML;
    }

    function toast(msg, type) {
        var el = document.getElementById('toast');
        el.textContent = msg;
        el.className = 'toast toast-' + (type || 'success');
        setTimeout(function () { el.className = 'toast hidden'; }, 3000);
    }

    // ── Tab Navigation ──────────────────────────────────────

    var navLinks = document.querySelectorAll('.sidebar-nav a[data-tab]');
    var tabSections = document.querySelectorAll('.tab-section');

    navLinks.forEach(function (link) {
        link.addEventListener('click', function (e) {
            e.preventDefault();
            var tab = this.getAttribute('data-tab');
            navLinks.forEach(function (l) { l.classList.remove('active'); });
            this.classList.add('active');
            tabSections.forEach(function (s) { s.classList.remove('active'); });
            document.getElementById('tab-' + tab).classList.add('active');
            loaders[tab]();
            history.replaceState(null, '', '#' + tab);
        });
    });

    // ── Modal ───────────────────────────────────────────────

    var modalBackdrop = document.getElementById('modal-backdrop');
    var modalTitle = document.getElementById('modal-title');
    var modalBody = document.getElementById('modal-body');
    var modalSubmit = document.getElementById('modal-submit');
    var currentModalHandler = null;

    function openModal(title, bodyHtml, submitLabel, onSubmit) {
        modalTitle.textContent = title;
        modalBody.innerHTML = bodyHtml;
        modalSubmit.textContent = submitLabel || 'Save';
        modalBackdrop.classList.remove('hidden');
        currentModalHandler = onSubmit;
    }

    function closeModal() {
        modalBackdrop.classList.add('hidden');
        currentModalHandler = null;
    }

    document.getElementById('modal-close').addEventListener('click', closeModal);
    document.getElementById('modal-cancel').addEventListener('click', closeModal);
    modalBackdrop.addEventListener('click', function (e) {
        if (e.target === modalBackdrop) closeModal();
    });
    modalSubmit.addEventListener('click', function () {
        if (currentModalHandler) currentModalHandler();
    });

    // ── Dashboard ───────────────────────────────────────────

    function loadDashboard() {
        api('GET', '/admin/api/stats').then(function (data) {
            var grid = document.getElementById('stats-grid');
            grid.innerHTML =
                statCard('Users', data.total_users, '&#9775;') +
                statCard('Sessions', data.active_sessions, '&#8987;') +
                statCard('Clients', data.total_clients, '&#9881;') +
                statCard('IdPs', data.total_identity_providers, '&#8644;');

            var tbody = document.getElementById('recent-events-body');
            if (!data.recent_events || data.recent_events.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" class="empty-state"><p>No recent events</p></td></tr>';
                return;
            }
            tbody.innerHTML = data.recent_events.map(function (e) {
                return '<tr>' +
                    '<td>' + fmt(e.timestamp) + '</td>' +
                    '<td><span class="badge badge-info">' + esc(e.eventType) + '</span></td>' +
                    '<td>' + esc(e.username || '-') + '</td>' +
                    '<td><span class="badge ' + (e.outcome === 'SUCCESS' ? 'badge-success' : 'badge-error') + '">' + esc(e.outcome) + '</span></td>' +
                    '<td>' + esc(e.details || '') + '</td>' +
                    '</tr>';
            }).join('');
        });
    }

    function statCard(label, value, icon) {
        return '<div class="stat-card">' +
            '<span class="stat-icon">' + icon + '</span>' +
            '<div class="stat-label">' + label + '</div>' +
            '<div class="stat-value">' + (value != null ? value : '-') + '</div>' +
            '</div>';
    }

    // ── Users ───────────────────────────────────────────────

    var usersPage = 0;
    var usersTotalPages = 1;

    function loadUsers(page) {
        if (page == null) page = 0;
        usersPage = page;
        var search = document.getElementById('user-search').value;
        var url = '/admin/api/users?page=' + page + '&size=20';
        if (search) url += '&search=' + encodeURIComponent(search);

        api('GET', url).then(function (data) {
            var items = data.content || data;
            usersTotalPages = data.totalPages || 1;
            var tbody = document.getElementById('users-body');

            if ((!items || items.length === 0) && (!data.content)) {
                tbody.innerHTML = '<tr><td colspan="7" class="empty-state"><p>No users found</p></td></tr>';
                return;
            }

            tbody.innerHTML = items.map(function (u) {
                var enabled = u.enabled != null ? u.enabled : true;
                return '<tr>' +
                    '<td>' + u.id + '</td>' +
                    '<td>' + esc(u.username) + '</td>' +
                    '<td>' + esc(u.email || '-') + '</td>' +
                    '<td><span class="badge ' + (enabled ? 'badge-success' : 'badge-error') + '">' + (enabled ? 'Active' : 'Locked') + '</span></td>' +
                    '<td>' + (u.mfa_enabled ? '<span class="badge badge-info">MFA</span>' : '-') + '</td>' +
                    '<td>' + fmt(u.created_at) + '</td>' +
                    '<td class="btn-actions">' +
                        (enabled ?
                            '<button class="btn btn-sm btn-orange" onclick="adminConsole.lockUser(' + u.id + ')">Lock</button>' :
                            '<button class="btn btn-sm btn-green" onclick="adminConsole.unlockUser(' + u.id + ')">Unlock</button>') +
                        '<button class="btn btn-sm btn-blue" onclick="adminConsole.resetPassword(' + u.id + ')">Reset PW</button>' +
                        '<button class="btn btn-sm btn-red" onclick="adminConsole.revokeSessions(' + u.id + ')">Revoke</button>' +
                    '</td></tr>';
            }).join('');

            renderPagination('users-pagination', usersPage, usersTotalPages, loadUsers);
        });
    }

    document.getElementById('user-search').addEventListener('keydown', function (e) {
        if (e.key === 'Enter') loadUsers(0);
    });

    // ── User Actions ────────────────────────────────────────

    function lockUser(id) {
        api('POST', '/admin/api/users/' + id + '/lock').then(function () {
            toast('User locked');
            loadUsers(usersPage);
        }).catch(function () { toast('Failed to lock user', 'error'); });
    }

    function unlockUser(id) {
        api('POST', '/admin/api/users/' + id + '/unlock').then(function () {
            toast('User unlocked');
            loadUsers(usersPage);
        }).catch(function () { toast('Failed to unlock user', 'error'); });
    }

    function resetPassword(id) {
        openModal('Reset Password',
            '<div class="form-group"><label>New Password</label><input type="password" id="reset-pw-input" minlength="8"/></div>',
            'Reset', function () {
                var pw = document.getElementById('reset-pw-input').value;
                if (pw.length < 8) { toast('Password must be at least 8 characters', 'error'); return; }
                api('POST', '/admin/api/users/' + id + '/reset-password', { password: pw }).then(function () {
                    toast('Password reset');
                    closeModal();
                }).catch(function () { toast('Failed to reset password', 'error'); });
            });
    }

    function revokeSessions(id) {
        api('POST', '/admin/api/users/' + id + '/revoke-sessions').then(function () {
            toast('Sessions revoked');
        }).catch(function () { toast('Failed to revoke sessions', 'error'); });
    }

    // ── Clients ─────────────────────────────────────────────

    function loadClients() {
        api('GET', '/admin/api/clients').then(function (clients) {
            var tbody = document.getElementById('clients-body');
            if (!clients || clients.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" class="empty-state"><p>No clients found</p></td></tr>';
                return;
            }
            tbody.innerHTML = clients.map(function (c) {
                return '<tr>' +
                    '<td>' + c.id + '</td>' +
                    '<td><code>' + esc(c.clientId) + '</code></td>' +
                    '<td>' + esc(c.clientName || '-') + '</td>' +
                    '<td>' + esc(c.scopes || '-') + '</td>' +
                    '<td><span class="badge ' + (c.enabled ? 'badge-success' : 'badge-error') + '">' + (c.enabled ? 'Enabled' : 'Disabled') + '</span></td>' +
                    '<td class="btn-actions">' +
                        '<button class="btn btn-sm btn-blue" onclick="adminConsole.editClient(' + c.id + ')">Edit</button>' +
                        '<button class="btn btn-sm btn-red" onclick="adminConsole.deleteClient(' + c.id + ')">Delete</button>' +
                    '</td></tr>';
            }).join('');
        });
    }

    document.getElementById('btn-create-client').addEventListener('click', function () {
        openModal('Create Client', clientFormHtml(), 'Create', function () {
            var body = readClientForm();
            api('POST', '/admin/api/clients', body).then(function () {
                toast('Client created');
                closeModal();
                loadClients();
            }).catch(function () { toast('Failed to create client', 'error'); });
        });
    });

    function editClient(id) {
        api('GET', '/admin/api/clients/' + id).then(function (c) {
            openModal('Edit Client', clientFormHtml(c), 'Update', function () {
                var body = readClientForm();
                api('PUT', '/admin/api/clients/' + id, body).then(function () {
                    toast('Client updated');
                    closeModal();
                    loadClients();
                }).catch(function () { toast('Failed to update client', 'error'); });
            });
        });
    }

    function deleteClient(id) {
        if (!confirm('Delete this client?')) return;
        api('DELETE', '/admin/api/clients/' + id).then(function () {
            toast('Client deleted');
            loadClients();
        }).catch(function () { toast('Failed to delete client', 'error'); });
    }

    function clientFormHtml(c) {
        c = c || {};
        return '<div class="form-group"><label>Client ID</label><input type="text" id="cf-client-id" value="' + esc(c.clientId || '') + '"/></div>' +
            '<div class="form-group"><label>Client Name</label><input type="text" id="cf-client-name" value="' + esc(c.clientName || '') + '"/></div>' +
            '<div class="form-group"><label>Client Secret (leave blank to keep)</label><input type="password" id="cf-client-secret"/></div>' +
            '<div class="form-group"><label>Scopes (space-separated)</label><input type="text" id="cf-scopes" value="' + esc(c.scopes || '') + '"/></div>' +
            '<div class="form-group"><label>Redirect URIs (comma-separated)</label><textarea id="cf-redirect-uris">' + esc((c.redirectUris || []).join(', ')) + '</textarea></div>' +
            '<div class="form-group"><label>Grant Types (comma-separated)</label><input type="text" id="cf-grant-types" value="' + esc((c.grantTypes || []).join(', ')) + '"/></div>';
    }

    function readClientForm() {
        var body = {
            client_id: document.getElementById('cf-client-id').value,
            client_name: document.getElementById('cf-client-name').value,
            scopes: document.getElementById('cf-scopes').value
        };
        var secret = document.getElementById('cf-client-secret').value;
        if (secret) body.client_secret = secret;

        var uris = document.getElementById('cf-redirect-uris').value.trim();
        if (uris) body.redirect_uris = uris.split(',').map(function (s) { return s.trim(); }).filter(Boolean);

        var grants = document.getElementById('cf-grant-types').value.trim();
        if (grants) body.grant_types = grants.split(',').map(function (s) { return s.trim(); }).filter(Boolean);

        return body;
    }

    // ── Sessions ────────────────────────────────────────────

    function loadSessions() {
        api('GET', '/admin/api/sessions').then(function (sessions) {
            var tbody = document.getElementById('sessions-body');
            if (!sessions || sessions.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" class="empty-state"><p>No active sessions</p></td></tr>';
                return;
            }
            tbody.innerHTML = sessions.map(function (s) {
                var sid = esc(s.session_id || '');
                var short = sid.length > 16 ? sid.substring(0, 16) + '...' : sid;
                return '<tr>' +
                    '<td title="' + sid + '"><code>' + short + '</code></td>' +
                    '<td>' + (s.user_id || '-') + '</td>' +
                    '<td>' + esc(s.ip_address || '-') + '</td>' +
                    '<td>' + fmt(s.auth_time) + '</td>' +
                    '<td>' + fmt(s.expires_at) + '</td>' +
                    '<td><button class="btn btn-sm btn-red" onclick="adminConsole.revokeSession(\'' + sid + '\')">Revoke</button></td>' +
                    '</tr>';
            }).join('');
        });
    }

    function revokeSession(sessionId) {
        api('POST', '/admin/api/sessions/' + sessionId + '/revoke').then(function () {
            toast('Session revoked');
            loadSessions();
        }).catch(function () { toast('Failed to revoke session', 'error'); });
    }

    // ── Events ──────────────────────────────────────────────

    var eventsPage = 0;
    var eventsTotalPages = 1;

    function loadEvents(page) {
        if (page == null) page = 0;
        eventsPage = page;
        var typeFilter = document.getElementById('event-type-filter').value;
        var userFilter = document.getElementById('event-user-filter').value;
        var url = '/admin/api/events?page=' + page + '&size=20';
        if (typeFilter) url += '&type=' + encodeURIComponent(typeFilter);
        if (userFilter) url += '&username=' + encodeURIComponent(userFilter);

        api('GET', url).then(function (data) {
            var items = data.content || [];
            eventsTotalPages = data.totalPages || 1;
            var tbody = document.getElementById('events-body');
            if (items.length === 0) {
                tbody.innerHTML = '<tr><td colspan="7" class="empty-state"><p>No events found</p></td></tr>';
                renderPagination('events-pagination', 0, 1, loadEvents);
                return;
            }
            tbody.innerHTML = items.map(function (e) {
                return '<tr>' +
                    '<td>' + fmt(e.timestamp) + '</td>' +
                    '<td><span class="badge badge-info">' + esc(e.eventType) + '</span></td>' +
                    '<td>' + esc(e.username || '-') + '</td>' +
                    '<td>' + esc(e.clientId || '-') + '</td>' +
                    '<td>' + esc(e.ipAddress || '-') + '</td>' +
                    '<td><span class="badge ' + (e.outcome === 'SUCCESS' ? 'badge-success' : 'badge-error') + '">' + esc(e.outcome) + '</span></td>' +
                    '<td>' + esc(e.details || '') + '</td>' +
                    '</tr>';
            }).join('');

            renderPagination('events-pagination', eventsPage, eventsTotalPages, loadEvents);
        });
    }

    document.getElementById('btn-filter-events').addEventListener('click', function () {
        loadEvents(0);
    });

    // ── Identity Providers ──────────────────────────────────

    function loadIdps() {
        api('GET', '/admin/api/identity-providers').then(function (idps) {
            var tbody = document.getElementById('idps-body');
            if (!idps || idps.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" class="empty-state"><p>No identity providers found</p></td></tr>';
                return;
            }
            tbody.innerHTML = idps.map(function (p) {
                return '<tr>' +
                    '<td>' + p.id + '</td>' +
                    '<td>' + esc(p.alias) + '</td>' +
                    '<td><span class="badge badge-info">' + esc(p.providerType) + '</span></td>' +
                    '<td><span class="badge ' + (p.enabled ? 'badge-success' : 'badge-error') + '">' + (p.enabled ? 'Enabled' : 'Disabled') + '</span></td>' +
                    '<td class="btn-actions">' +
                        '<button class="btn btn-sm btn-blue" onclick="adminConsole.editIdp(' + p.id + ')">Edit</button>' +
                        '<button class="btn btn-sm btn-red" onclick="adminConsole.deleteIdp(' + p.id + ')">Delete</button>' +
                    '</td></tr>';
            }).join('');
        });
    }

    document.getElementById('btn-create-idp').addEventListener('click', function () {
        openModal('Create Identity Provider', idpFormHtml(), 'Create', function () {
            var body = readIdpForm();
            api('POST', '/admin/api/identity-providers', body).then(function () {
                toast('Identity provider created');
                closeModal();
                loadIdps();
            }).catch(function () { toast('Failed to create provider', 'error'); });
        });
    });

    function editIdp(id) {
        api('GET', '/admin/api/identity-providers/' + id).then(function (p) {
            openModal('Edit Identity Provider', idpFormHtml(p), 'Update', function () {
                var body = readIdpForm();
                api('PUT', '/admin/api/identity-providers/' + id, body).then(function () {
                    toast('Identity provider updated');
                    closeModal();
                    loadIdps();
                }).catch(function () { toast('Failed to update provider', 'error'); });
            });
        });
    }

    function deleteIdp(id) {
        if (!confirm('Delete this identity provider?')) return;
        api('DELETE', '/admin/api/identity-providers/' + id).then(function () {
            toast('Identity provider deleted');
            loadIdps();
        }).catch(function () { toast('Failed to delete provider', 'error'); });
    }

    function idpFormHtml(p) {
        p = p || {};
        return '<div class="form-group"><label>Alias</label><input type="text" id="idp-alias" value="' + esc(p.alias || '') + '"/></div>' +
            '<div class="form-group"><label>Provider Type</label><select id="idp-type"><option value="OIDC"' + (p.providerType === 'OIDC' ? ' selected' : '') + '>OIDC</option><option value="GOOGLE"' + (p.providerType === 'GOOGLE' ? ' selected' : '') + '>GOOGLE</option><option value="GITHUB"' + (p.providerType === 'GITHUB' ? ' selected' : '') + '>GITHUB</option></select></div>' +
            '<div class="form-group"><label>Client ID</label><input type="text" id="idp-client-id" value="' + esc(p.clientId || '') + '"/></div>' +
            '<div class="form-group"><label>Client Secret</label><input type="password" id="idp-client-secret" value="' + esc(p.clientSecret || '') + '"/></div>' +
            '<div class="form-group"><label>Authorization URL</label><input type="text" id="idp-auth-url" value="' + esc(p.authorizationUrl || '') + '"/></div>' +
            '<div class="form-group"><label>Token URL</label><input type="text" id="idp-token-url" value="' + esc(p.tokenUrl || '') + '"/></div>' +
            '<div class="form-group"><label>UserInfo URL</label><input type="text" id="idp-userinfo-url" value="' + esc(p.userinfoUrl || '') + '"/></div>' +
            '<div class="form-group"><label>Scopes</label><input type="text" id="idp-scopes" value="' + esc(p.scopes || '') + '"/></div>' +
            '<div class="form-group"><label>Enabled</label><select id="idp-enabled"><option value="true"' + (p.enabled !== false ? ' selected' : '') + '>Yes</option><option value="false"' + (p.enabled === false ? ' selected' : '') + '>No</option></select></div>';
    }

    function readIdpForm() {
        return {
            alias: document.getElementById('idp-alias').value,
            provider_type: document.getElementById('idp-type').value,
            client_id: document.getElementById('idp-client-id').value,
            client_secret: document.getElementById('idp-client-secret').value,
            authorization_url: document.getElementById('idp-auth-url').value,
            token_url: document.getElementById('idp-token-url').value,
            userinfo_url: document.getElementById('idp-userinfo-url').value,
            scopes: document.getElementById('idp-scopes').value,
            enabled: document.getElementById('idp-enabled').value === 'true'
        };
    }

    // ── Pagination Helper ───────────────────────────────────

    function renderPagination(containerId, currentPage, totalPages, loadFn) {
        var el = document.getElementById(containerId);
        if (totalPages <= 1) { el.innerHTML = ''; return; }
        el.innerHTML =
            '<button ' + (currentPage === 0 ? 'disabled' : '') + ' id="' + containerId + '-prev">Prev</button>' +
            '<span class="page-info">Page ' + (currentPage + 1) + ' / ' + totalPages + '</span>' +
            '<button ' + (currentPage >= totalPages - 1 ? 'disabled' : '') + ' id="' + containerId + '-next">Next</button>';

        var prev = document.getElementById(containerId + '-prev');
        var next = document.getElementById(containerId + '-next');
        if (prev) prev.addEventListener('click', function () { loadFn(currentPage - 1); });
        if (next) next.addEventListener('click', function () { loadFn(currentPage + 1); });
    }

    // ── Tab Loaders Map ─────────────────────────────────────

    var loaders = {
        dashboard: loadDashboard,
        users: function () { loadUsers(0); },
        clients: loadClients,
        sessions: loadSessions,
        events: function () { loadEvents(0); },
        idps: loadIdps
    };

    // ── Public API (for onclick handlers) ───────────────────

    window.adminConsole = {
        lockUser: lockUser,
        unlockUser: unlockUser,
        resetPassword: resetPassword,
        revokeSessions: revokeSessions,
        editClient: editClient,
        deleteClient: deleteClient,
        revokeSession: revokeSession,
        editIdp: editIdp,
        deleteIdp: deleteIdp
    };

    // ── Init ────────────────────────────────────────────────

    var hash = window.location.hash.replace('#', '');
    if (hash && loaders[hash]) {
        navLinks.forEach(function (l) { l.classList.remove('active'); });
        tabSections.forEach(function (s) { s.classList.remove('active'); });
        var targetLink = document.querySelector('a[data-tab="' + hash + '"]');
        if (targetLink) targetLink.classList.add('active');
        document.getElementById('tab-' + hash).classList.add('active');
        loaders[hash]();
    } else {
        loadDashboard();
    }
})();
