package com.spring.lica.oauth2.service;

import com.spring.lica.domain.entity.OAuthClient;
import com.spring.lica.domain.entity.RefreshToken;
import com.spring.lica.domain.entity.TokenBlacklist;
import com.spring.lica.domain.repository.RefreshTokenRepository;
import com.spring.lica.domain.repository.TokenBlacklistRepository;
import com.spring.lica.security.jwt.JwtTokenProvider;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenRevocationService {

    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenRepository refreshTokenRepository;
    private final TokenBlacklistRepository tokenBlacklistRepository;

    /**
     * Revoke a token (RFC 7009). Returns 200 regardless of token validity.
     */
    @Transactional
    public void revokeToken(String token, String tokenTypeHint, OAuthClient client) {
        if (!StringUtils.hasText(token)) {
            return;
        }

        // Try as refresh token first (or if hinted)
        if (!"access_token".equals(tokenTypeHint)) {
            if (tryRevokeRefreshToken(token, client)) {
                return;
            }
        }

        // Try as access token (JWT)
        if (!"refresh_token".equals(tokenTypeHint)) {
            tryRevokeAccessToken(token, client);
        }
    }

    private boolean tryRevokeRefreshToken(String token, OAuthClient client) {
        String tokenHash = OAuth2TokenService.hashToken(token);
        Optional<RefreshToken> optToken = refreshTokenRepository.findByTokenHash(tokenHash);
        if (optToken.isPresent()) {
            RefreshToken refreshToken = optToken.get();
            if (refreshToken.getClientId().equals(client.getClientId())) {
                // Revoke the entire family
                refreshTokenRepository.revokeByFamilyId(refreshToken.getFamilyId());
                log.info("Revoked refresh token family={} for client={}", refreshToken.getFamilyId(), client.getClientId());
                return true;
            }
        }
        return false;
    }

    private void tryRevokeAccessToken(String token, OAuthClient client) {
        if (!jwtTokenProvider.validateToken(token)) {
            return;
        }
        try {
            Claims claims = jwtTokenProvider.extractClaims(token);
            String jti = claims.getId();
            String clientId = claims.get("client_id", String.class);

            if (clientId != null && !clientId.equals(client.getClientId())) {
                return; // Token was not issued to this client
            }

            if (jti != null && !tokenBlacklistRepository.existsByJti(jti)) {
                TokenBlacklist blacklistEntry = TokenBlacklist.builder()
                    .jti(jti)
                    .expiresAt(claims.getExpiration().toInstant())
                    .build();
                tokenBlacklistRepository.save(blacklistEntry);
                log.info("Blacklisted access token jti={} for client={}", jti, client.getClientId());
            }
        } catch (Exception e) {
            log.debug("Failed to revoke access token: {}", e.getMessage());
        }
    }

    /**
     * Introspect a token (RFC 7662).
     */
    @Transactional(readOnly = true)
    public Map<String, Object> introspectToken(String token, String tokenTypeHint, OAuthClient client) {
        if (!StringUtils.hasText(token)) {
            return inactiveResponse();
        }

        // Try as access token (JWT) first
        if (!"refresh_token".equals(tokenTypeHint)) {
            Map<String, Object> result = tryIntrospectAccessToken(token, client);
            if (result != null) {
                return result;
            }
        }

        // Try as refresh token
        if (!"access_token".equals(tokenTypeHint)) {
            Map<String, Object> result = tryIntrospectRefreshToken(token, client);
            if (result != null) {
                return result;
            }
        }

        return inactiveResponse();
    }

    private Map<String, Object> tryIntrospectAccessToken(String token, OAuthClient client) {
        if (!jwtTokenProvider.validateToken(token)) {
            return null;
        }
        try {
            Claims claims = jwtTokenProvider.extractClaims(token);
            String jti = claims.getId();

            // Check blacklist
            if (jti != null && tokenBlacklistRepository.existsByJti(jti)) {
                return inactiveResponse();
            }

            String clientId = claims.get("client_id", String.class);
            if (clientId != null && !clientId.equals(client.getClientId())) {
                return inactiveResponse();
            }

            Map<String, Object> response = new LinkedHashMap<>();
            response.put("active", true);
            response.put("token_type", "Bearer");
            response.put("sub", claims.getSubject());
            response.put("iss", claims.getIssuer());
            response.put("exp", claims.getExpiration().getTime() / 1000);
            response.put("iat", claims.getIssuedAt().getTime() / 1000);
            if (jti != null) response.put("jti", jti);
            if (clientId != null) response.put("client_id", clientId);
            String scope = claims.get("scope", String.class);
            if (scope != null) response.put("scope", scope);
            return response;
        } catch (Exception e) {
            return null;
        }
    }

    private Map<String, Object> tryIntrospectRefreshToken(String token, OAuthClient client) {
        String tokenHash = OAuth2TokenService.hashToken(token);
        Optional<RefreshToken> optToken = refreshTokenRepository.findByTokenHash(tokenHash);
        if (optToken.isEmpty()) {
            return null;
        }

        RefreshToken refreshToken = optToken.get();
        if (refreshToken.isRevoked() || refreshToken.getExpiresAt().isBefore(Instant.now())) {
            return inactiveResponse();
        }
        if (!refreshToken.getClientId().equals(client.getClientId())) {
            return inactiveResponse();
        }

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("active", true);
        response.put("token_type", "refresh_token");
        response.put("client_id", refreshToken.getClientId());
        response.put("exp", refreshToken.getExpiresAt().getEpochSecond());
        if (refreshToken.getScope() != null) response.put("scope", refreshToken.getScope());
        return response;
    }

    private Map<String, Object> inactiveResponse() {
        return Map.of("active", false);
    }
}
