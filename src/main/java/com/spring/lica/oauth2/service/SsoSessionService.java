package com.spring.lica.oauth2.service;

import com.spring.lica.domain.entity.SsoSession;
import com.spring.lica.domain.entity.SsoSessionClient;
import com.spring.lica.domain.repository.SsoSessionClientRepository;
import com.spring.lica.domain.repository.SsoSessionRepository;
import com.spring.lica.sso.SsoProperties;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class SsoSessionService {

    private final SsoSessionRepository ssoSessionRepository;
    private final SsoSessionClientRepository ssoSessionClientRepository;
    private final SsoProperties ssoProperties;

    @Transactional
    public SsoSession createSession(Long userId, String ipAddress, String userAgent) {
        Instant now = Instant.now();
        long absoluteTimeoutMs = ssoProperties.session().absoluteTimeout();

        // Enforce concurrent session limit
        List<SsoSession> activeSessions = ssoSessionRepository
            .findByUserIdAndRevokedFalseOrderByCreatedAtAsc(userId);

        int maxSessions = ssoProperties.session().maxConcurrentSessions();
        if (activeSessions.size() >= maxSessions) {
            int toRevoke = activeSessions.size() - maxSessions + 1;
            for (int i = 0; i < toRevoke; i++) {
                SsoSession oldest = activeSessions.get(i);
                oldest.setRevoked(true);
                ssoSessionRepository.save(oldest);
                log.info("Revoked oldest SSO session {} for user {} (concurrent limit)", oldest.getSessionId(), userId);
            }
        }

        SsoSession session = SsoSession.builder()
            .sessionId(UUID.randomUUID().toString())
            .userId(userId)
            .ipAddress(ipAddress)
            .userAgent(userAgent != null && userAgent.length() > 500 ? userAgent.substring(0, 500) : userAgent)
            .authTime(now)
            .lastActiveAt(now)
            .expiresAt(now.plusMillis(absoluteTimeoutMs))
            .build();

        session = ssoSessionRepository.save(session);
        log.debug("Created SSO session {} for user {}", session.getSessionId(), userId);
        return session;
    }

    @Transactional(readOnly = true)
    public Optional<SsoSession> validateSession(String sessionId) {
        if (sessionId == null) {
            return Optional.empty();
        }

        Optional<SsoSession> optSession = ssoSessionRepository.findBySessionId(sessionId);
        if (optSession.isEmpty()) {
            return Optional.empty();
        }

        SsoSession session = optSession.get();

        if (session.isRevoked()) {
            log.debug("SSO session {} is revoked", sessionId);
            return Optional.empty();
        }

        Instant now = Instant.now();

        // Check absolute timeout
        if (now.isAfter(session.getExpiresAt())) {
            log.debug("SSO session {} expired (absolute timeout)", sessionId);
            return Optional.empty();
        }

        // Check idle timeout
        long idleTimeoutMs = ssoProperties.session().idleTimeout();
        if (now.isAfter(session.getLastActiveAt().plusMillis(idleTimeoutMs))) {
            log.debug("SSO session {} expired (idle timeout)", sessionId);
            return Optional.empty();
        }

        return Optional.of(session);
    }

    @Transactional
    public void touchSession(SsoSession session) {
        session.setLastActiveAt(Instant.now());
        ssoSessionRepository.save(session);
    }

    @Transactional
    public void addClientToSession(SsoSession session, String clientId) {
        if (ssoSessionClientRepository.existsBySessionAndClientId(session, clientId)) {
            return;
        }

        SsoSessionClient client = SsoSessionClient.builder()
            .session(session)
            .clientId(clientId)
            .joinedAt(Instant.now())
            .build();
        ssoSessionClientRepository.save(client);
        log.debug("Added client {} to SSO session {}", clientId, session.getSessionId());
    }

    @Transactional
    public void revokeSession(String sessionId) {
        ssoSessionRepository.findBySessionId(sessionId).ifPresent(session -> {
            session.setRevoked(true);
            ssoSessionRepository.save(session);
            log.info("Revoked SSO session {}", sessionId);
        });
    }

    @Transactional
    public void revokeAllUserSessions(Long userId) {
        ssoSessionRepository.revokeByUserId(userId);
        log.info("Revoked all SSO sessions for user {}", userId);
    }

    @Transactional(readOnly = true)
    public List<SsoSessionClient> getSessionClients(SsoSession session) {
        return ssoSessionClientRepository.findBySession(session);
    }

    public Cookie createSsoCookie(String sessionId) {
        Cookie cookie = new Cookie(ssoProperties.session().cookieName(), sessionId);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setMaxAge(-1); // session cookie
        return cookie;
    }

    public void clearSsoCookie(HttpServletResponse response) {
        Cookie cookie = new Cookie(ssoProperties.session().cookieName(), "");
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setMaxAge(0);
        response.addCookie(cookie);
    }

    public String extractSessionIdFromCookies(Cookie[] cookies) {
        if (cookies == null) return null;
        String cookieName = ssoProperties.session().cookieName();
        for (Cookie cookie : cookies) {
            if (cookieName.equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }
}
