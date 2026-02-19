package com.spring.lica.admin;

import com.spring.lica.domain.entity.*;
import com.spring.lica.domain.entity.IdentityProvider;
import com.spring.lica.domain.repository.*;
import com.spring.lica.domain.repository.IdentityProviderRepository;
import com.spring.lica.oauth2.service.SsoSessionService;
import com.spring.lica.security.AuditLogService;
import com.spring.lica.security.BruteForceProtectionService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/admin/api")
@RequiredArgsConstructor
public class AdminApiController {

    private final UserRepository userRepository;
    private final OAuthClientRepository oAuthClientRepository;
    private final RoleRepository roleRepository;
    private final GroupRepository groupRepository;
    private final SsoSessionRepository ssoSessionRepository;
    private final AuditLogService auditLogService;
    private final BruteForceProtectionService bruteForceProtectionService;
    private final SsoSessionService ssoSessionService;
    private final PasswordEncoder passwordEncoder;
    private final IdentityProviderRepository identityProviderRepository;

    // ── Dashboard Stats ─────────────────────────────────────

    @GetMapping("/stats")
    public ResponseEntity<?> dashboardStats() {
        long totalUsers = userRepository.count();
        long activeSessions = ssoSessionRepository.findAll().stream()
            .filter(s -> !s.isRevoked()).count();
        long totalClients = oAuthClientRepository.count();
        long totalIdps = identityProviderRepository.count();

        var recentEvents = auditLogService.findAll(PageRequest.of(0, 5));

        Map<String, Object> stats = new LinkedHashMap<>();
        stats.put("total_users", totalUsers);
        stats.put("active_sessions", activeSessions);
        stats.put("total_clients", totalClients);
        stats.put("total_identity_providers", totalIdps);
        stats.put("recent_events", recentEvents.getContent());
        return ResponseEntity.ok(stats);
    }

    // ── Users ──────────────────────────────────────────────

    @GetMapping("/users")
    public ResponseEntity<?> listUsers(@RequestParam(defaultValue = "0") int page,
                                       @RequestParam(defaultValue = "20") int size,
                                       @RequestParam(required = false) String search) {
        var pageable = PageRequest.of(page, size, Sort.by("id"));
        Page<User> users;
        if (search != null && !search.isBlank()) {
            // Simple search by username (could extend to email)
            users = userRepository.findAll(pageable); // TODO: add search spec
        } else {
            users = userRepository.findAll(pageable);
        }

        var result = users.map(u -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", u.getId());
            m.put("username", u.getUsername());
            m.put("email", u.getEmail());
            m.put("enabled", u.isEnabled());
            m.put("email_verified", u.isEmailVerified());
            m.put("mfa_enabled", u.isMfaEnabled());
            m.put("created_at", u.getCreatedAt());
            return m;
        });
        return ResponseEntity.ok(result);
    }

    @GetMapping("/users/{id}")
    public ResponseEntity<?> getUser(@PathVariable Long id) {
        return userRepository.findById(id)
            .map(ResponseEntity::ok)
            .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping("/users/{id}/reset-password")
    public ResponseEntity<?> resetUserPassword(@PathVariable Long id, @RequestBody Map<String, String> body) {
        return userRepository.findById(id).map(user -> {
            String newPassword = body.get("password");
            if (newPassword == null || newPassword.length() < 8) {
                return ResponseEntity.badRequest().body(Map.of("error", "Password must be at least 8 characters"));
            }
            user.setPasswordHash(passwordEncoder.encode(newPassword));
            userRepository.save(user);
            return ResponseEntity.ok(Map.of("message", "Password reset for " + user.getUsername()));
        }).orElse(ResponseEntity.notFound().build());
    }

    @PostMapping("/users/{id}/lock")
    public ResponseEntity<?> lockUser(@PathVariable Long id) {
        return userRepository.findById(id).map(user -> {
            user.setEnabled(false);
            userRepository.save(user);
            return ResponseEntity.ok(Map.of("message", "User locked: " + user.getUsername()));
        }).orElse(ResponseEntity.notFound().build());
    }

    @PostMapping("/users/{id}/unlock")
    public ResponseEntity<?> unlockUser(@PathVariable Long id) {
        return userRepository.findById(id).map(user -> {
            user.setEnabled(true);
            userRepository.save(user);
            bruteForceProtectionService.unlock(user.getUsername());
            return ResponseEntity.ok(Map.of("message", "User unlocked: " + user.getUsername()));
        }).orElse(ResponseEntity.notFound().build());
    }

    @PostMapping("/users/{id}/revoke-sessions")
    public ResponseEntity<?> revokeUserSessions(@PathVariable Long id) {
        ssoSessionService.revokeAllUserSessions(id);
        return ResponseEntity.ok(Map.of("message", "All sessions revoked for user " + id));
    }

    // ── Clients ────────────────────────────────────────────

    @GetMapping("/clients")
    public ResponseEntity<?> listClients() {
        List<OAuthClient> clients = oAuthClientRepository.findAll();
        return ResponseEntity.ok(clients);
    }

    @GetMapping("/clients/{id}")
    public ResponseEntity<?> getClient(@PathVariable Long id) {
        return oAuthClientRepository.findById(id)
            .map(ResponseEntity::ok)
            .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping("/clients")
    public ResponseEntity<?> createClient(@RequestBody Map<String, Object> body) {
        OAuthClient client = OAuthClient.builder()
            .clientId((String) body.get("client_id"))
            .clientName((String) body.get("client_name"))
            .clientSecretHash(body.containsKey("client_secret") ?
                passwordEncoder.encode((String) body.get("client_secret")) : null)
            .scopes(body.getOrDefault("scopes", "").toString())
            .tokenEndpointAuthMethod(body.getOrDefault("token_endpoint_auth_method", "client_secret_basic").toString())
            .build();

        if (body.containsKey("redirect_uris")) {
            @SuppressWarnings("unchecked")
            List<String> uris = (List<String>) body.get("redirect_uris");
            client.setRedirectUris(new HashSet<>(uris));
        }
        if (body.containsKey("grant_types")) {
            @SuppressWarnings("unchecked")
            List<String> grants = (List<String>) body.get("grant_types");
            client.setGrantTypes(new HashSet<>(grants));
        }

        client = oAuthClientRepository.save(client);
        return ResponseEntity.ok(client);
    }

    @PutMapping("/clients/{id}")
    public ResponseEntity<?> updateClient(@PathVariable Long id, @RequestBody Map<String, Object> body) {
        return oAuthClientRepository.findById(id).map(client -> {
            if (body.containsKey("client_name")) client.setClientName((String) body.get("client_name"));
            if (body.containsKey("scopes")) client.setScopes(body.get("scopes").toString());
            if (body.containsKey("enabled")) client.setEnabled((Boolean) body.get("enabled"));
            if (body.containsKey("first_party")) client.setFirstParty((Boolean) body.get("first_party"));
            if (body.containsKey("redirect_uris")) {
                @SuppressWarnings("unchecked")
                List<String> uris = (List<String>) body.get("redirect_uris");
                client.getRedirectUris().clear();
                client.getRedirectUris().addAll(uris);
            }
            if (body.containsKey("grant_types")) {
                @SuppressWarnings("unchecked")
                List<String> grants = (List<String>) body.get("grant_types");
                client.getGrantTypes().clear();
                client.getGrantTypes().addAll(grants);
            }
            oAuthClientRepository.save(client);
            return ResponseEntity.ok(client);
        }).orElse(ResponseEntity.notFound().build());
    }

    @DeleteMapping("/clients/{id}")
    public ResponseEntity<?> deleteClient(@PathVariable Long id) {
        oAuthClientRepository.deleteById(id);
        return ResponseEntity.ok(Map.of("message", "Client deleted"));
    }

    // ── Roles ──────────────────────────────────────────────

    @GetMapping("/roles")
    public ResponseEntity<?> listRoles() {
        return ResponseEntity.ok(roleRepository.findAll());
    }

    @PostMapping("/roles")
    public ResponseEntity<?> createRole(@RequestBody Map<String, String> body) {
        Role role = Role.builder()
            .name(body.get("name"))
            .description(body.get("description"))
            .type(RoleType.valueOf(body.getOrDefault("type", "REALM")))
            .build();
        role = roleRepository.save(role);
        return ResponseEntity.ok(role);
    }

    @DeleteMapping("/roles/{id}")
    public ResponseEntity<?> deleteRole(@PathVariable Long id) {
        roleRepository.deleteById(id);
        return ResponseEntity.ok(Map.of("message", "Role deleted"));
    }

    // ── Groups ─────────────────────────────────────────────

    @GetMapping("/groups")
    public ResponseEntity<?> listGroups() {
        return ResponseEntity.ok(groupRepository.findByParentIsNull());
    }

    // ── Events (Audit Log) ─────────────────────────────────

    @GetMapping("/events")
    public ResponseEntity<?> listEvents(@RequestParam(defaultValue = "0") int page,
                                        @RequestParam(defaultValue = "50") int size,
                                        @RequestParam(required = false) String type,
                                        @RequestParam(required = false) String username) {
        var pageable = PageRequest.of(page, size);

        Page<AuditLog> events;
        if (type != null && !type.isBlank()) {
            events = auditLogService.findByEventType(type, pageable);
        } else if (username != null && !username.isBlank()) {
            events = auditLogService.findByUsername(username, pageable);
        } else {
            events = auditLogService.findAll(pageable);
        }

        return ResponseEntity.ok(events);
    }

    // ── Sessions ───────────────────────────────────────────

    @GetMapping("/sessions")
    public ResponseEntity<?> listActiveSessions() {
        List<SsoSession> sessions = ssoSessionRepository.findAll().stream()
            .filter(s -> !s.isRevoked())
            .collect(Collectors.toList());

        var result = sessions.stream().map(s -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", s.getId());
            m.put("session_id", s.getSessionId());
            m.put("user_id", s.getUserId());
            m.put("ip_address", s.getIpAddress());
            m.put("auth_time", s.getAuthTime());
            m.put("last_active_at", s.getLastActiveAt());
            m.put("expires_at", s.getExpiresAt());
            return m;
        }).toList();

        return ResponseEntity.ok(result);
    }

    @PostMapping("/sessions/{sessionId}/revoke")
    public ResponseEntity<?> revokeSession(@PathVariable String sessionId) {
        ssoSessionService.revokeSession(sessionId);
        return ResponseEntity.ok(Map.of("message", "Session revoked"));
    }

    // ── Attack Detection ───────────────────────────────────

    @GetMapping("/attack-detection/{username}")
    public ResponseEntity<?> getAttackStatus(@PathVariable String username) {
        boolean locked = bruteForceProtectionService.isLocked(username);
        return ResponseEntity.ok(Map.of("username", username, "locked", locked));
    }

    @PostMapping("/attack-detection/{username}/unlock")
    public ResponseEntity<?> unlockAttackDetection(@PathVariable String username) {
        bruteForceProtectionService.unlock(username);
        return ResponseEntity.ok(Map.of("message", "Attack detection cleared for " + username));
    }

    // ── Identity Providers ──────────────────────────────────

    @GetMapping("/identity-providers")
    public ResponseEntity<?> listIdentityProviders() {
        return ResponseEntity.ok(identityProviderRepository.findAll());
    }

    @GetMapping("/identity-providers/{id}")
    public ResponseEntity<?> getIdentityProvider(@PathVariable Long id) {
        return identityProviderRepository.findById(id)
            .map(ResponseEntity::ok)
            .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping("/identity-providers")
    public ResponseEntity<?> createIdentityProvider(@RequestBody Map<String, Object> body) {
        IdentityProvider idp = IdentityProvider.builder()
            .alias((String) body.get("alias"))
            .providerType(body.getOrDefault("provider_type", "OIDC").toString())
            .clientId((String) body.get("client_id"))
            .clientSecret((String) body.get("client_secret"))
            .authorizationUrl((String) body.get("authorization_url"))
            .tokenUrl((String) body.get("token_url"))
            .userinfoUrl((String) body.get("userinfo_url"))
            .jwksUrl((String) body.get("jwks_url"))
            .scopes((String) body.get("scopes"))
            .claimMappings((String) body.get("claim_mappings"))
            .enabled(body.containsKey("enabled") ? (Boolean) body.get("enabled") : true)
            .build();
        idp = identityProviderRepository.save(idp);
        return ResponseEntity.ok(idp);
    }

    @PutMapping("/identity-providers/{id}")
    public ResponseEntity<?> updateIdentityProvider(@PathVariable Long id, @RequestBody Map<String, Object> body) {
        return identityProviderRepository.findById(id).map(idp -> {
            if (body.containsKey("client_id")) idp.setClientId((String) body.get("client_id"));
            if (body.containsKey("client_secret")) idp.setClientSecret((String) body.get("client_secret"));
            if (body.containsKey("authorization_url")) idp.setAuthorizationUrl((String) body.get("authorization_url"));
            if (body.containsKey("token_url")) idp.setTokenUrl((String) body.get("token_url"));
            if (body.containsKey("userinfo_url")) idp.setUserinfoUrl((String) body.get("userinfo_url"));
            if (body.containsKey("jwks_url")) idp.setJwksUrl((String) body.get("jwks_url"));
            if (body.containsKey("scopes")) idp.setScopes((String) body.get("scopes"));
            if (body.containsKey("claim_mappings")) idp.setClaimMappings((String) body.get("claim_mappings"));
            if (body.containsKey("enabled")) idp.setEnabled((Boolean) body.get("enabled"));
            identityProviderRepository.save(idp);
            return ResponseEntity.ok(idp);
        }).orElse(ResponseEntity.notFound().build());
    }

    @DeleteMapping("/identity-providers/{id}")
    public ResponseEntity<?> deleteIdentityProvider(@PathVariable Long id) {
        identityProviderRepository.deleteById(id);
        return ResponseEntity.ok(Map.of("message", "Identity provider deleted"));
    }
}
