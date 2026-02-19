package com.spring.lica.oauth2.service;

import com.spring.lica.domain.entity.*;
import com.spring.lica.domain.repository.RefreshTokenRepository;
import com.spring.lica.domain.repository.UserRepository;
import com.spring.lica.oauth2.dto.TokenRequest;
import com.spring.lica.oauth2.dto.TokenResponse;
import com.spring.lica.security.jwt.JwtTokenProvider;
import com.spring.lica.sso.SsoProperties;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class OAuth2TokenService {

    private final JwtTokenProvider jwtTokenProvider;
    private final OAuthClientService oAuthClientService;
    private final AuthorizationCodeService authorizationCodeService;
    private final OidcClaimService oidcClaimService;
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final SsoProperties ssoProperties;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    @Transactional
    public TokenResponse handleToken(HttpServletRequest request, TokenRequest tokenRequest) {
        String grantType = tokenRequest.grantType();
        if (!StringUtils.hasText(grantType)) {
            throw new OAuthClientService.OAuth2Exception("invalid_request", "grant_type is required");
        }

        return switch (grantType) {
            case "authorization_code" -> handleAuthorizationCode(request, tokenRequest);
            case "client_credentials" -> handleClientCredentials(request, tokenRequest);
            case "refresh_token" -> handleRefreshToken(request, tokenRequest);
            default -> throw new OAuthClientService.OAuth2Exception("unsupported_grant_type",
                "Unsupported grant_type: " + grantType);
        };
    }

    private TokenResponse handleAuthorizationCode(HttpServletRequest request, TokenRequest tokenRequest) {
        OAuthClient client = oAuthClientService.authenticateClient(
            request, tokenRequest.clientId(), tokenRequest.clientSecret());
        oAuthClientService.validateGrantType(client, "authorization_code");

        if (!StringUtils.hasText(tokenRequest.code())) {
            throw new OAuthClientService.OAuth2Exception("invalid_request", "code is required");
        }

        AuthorizationCode authCode = authorizationCodeService.consumeCode(tokenRequest.code());

        // Verify code was issued to this client
        if (!authCode.getClientId().equals(client.getClientId())) {
            throw new OAuthClientService.OAuth2Exception("invalid_grant", "Code was not issued to this client");
        }

        // Verify redirect_uri matches
        if (StringUtils.hasText(tokenRequest.redirectUri())
                && !tokenRequest.redirectUri().equals(authCode.getRedirectUri())) {
            throw new OAuthClientService.OAuth2Exception("invalid_grant", "redirect_uri mismatch");
        }

        // PKCE verification
        authorizationCodeService.verifyPkce(authCode, tokenRequest.codeVerifier());

        // Load user and roles
        User user = userRepository.findById(authCode.getUserId())
            .orElseThrow(() -> new OAuthClientService.OAuth2Exception("server_error", "User not found"));
        List<String> roles = resolveRoles(user);

        String scope = authCode.getScope();
        String accessToken = jwtTokenProvider.generateOAuth2AccessToken(
            user.getUsername(), client.getClientId(), scope, roles);

        String refreshToken = generateRefreshToken(user.getId(), client.getClientId(), scope, null);

        // OIDC: issue ID Token if openid scope is present
        String idToken = null;
        if (oidcClaimService.isOidcRequest(scope)) {
            Map<String, Object> userClaims = oidcClaimService.resolveClaims(user, scope);
            idToken = jwtTokenProvider.generateIdToken(
                user.getUsername(), client.getClientId(), authCode.getNonce(), accessToken, userClaims);
        }

        long expiresIn = ssoProperties.token().accessTokenExpiration() / 1000;
        return new TokenResponse(accessToken, expiresIn, refreshToken, scope, idToken);
    }

    private TokenResponse handleClientCredentials(HttpServletRequest request, TokenRequest tokenRequest) {
        OAuthClient client = oAuthClientService.authenticateClient(
            request, tokenRequest.clientId(), tokenRequest.clientSecret());
        oAuthClientService.validateGrantType(client, "client_credentials");

        String scope = StringUtils.hasText(tokenRequest.scope()) ? tokenRequest.scope() : client.getScopes();
        oAuthClientService.validateScope(client, scope);

        // Client Credentials: subject is client_id, no user context
        String accessToken = jwtTokenProvider.generateOAuth2AccessToken(
            client.getClientId(), client.getClientId(), scope, List.of());

        long expiresIn = ssoProperties.token().accessTokenExpiration() / 1000;
        return new TokenResponse(accessToken, expiresIn, null, scope);
    }

    private TokenResponse handleRefreshToken(HttpServletRequest request, TokenRequest tokenRequest) {
        OAuthClient client = oAuthClientService.authenticateClient(
            request, tokenRequest.clientId(), tokenRequest.clientSecret());
        oAuthClientService.validateGrantType(client, "refresh_token");

        if (!StringUtils.hasText(tokenRequest.refreshToken())) {
            throw new OAuthClientService.OAuth2Exception("invalid_request", "refresh_token is required");
        }

        String tokenHash = hashToken(tokenRequest.refreshToken());
        RefreshToken storedToken = refreshTokenRepository.findByTokenHash(tokenHash)
            .orElseThrow(() -> new OAuthClientService.OAuth2Exception("invalid_grant", "Invalid refresh token"));

        // Replay detection: if token is already revoked, revoke entire family
        if (storedToken.isRevoked()) {
            log.warn("Refresh token replay detected for family={}", storedToken.getFamilyId());
            refreshTokenRepository.revokeByFamilyId(storedToken.getFamilyId());
            throw new OAuthClientService.OAuth2Exception("invalid_grant", "Refresh token has been revoked");
        }

        if (storedToken.getExpiresAt().isBefore(Instant.now())) {
            throw new OAuthClientService.OAuth2Exception("invalid_grant", "Refresh token expired");
        }

        if (!storedToken.getClientId().equals(client.getClientId())) {
            throw new OAuthClientService.OAuth2Exception("invalid_grant", "Token was not issued to this client");
        }

        // Rotate: revoke old token, issue new one
        storedToken.setRevoked(true);

        User user = userRepository.findById(storedToken.getUserId())
            .orElseThrow(() -> new OAuthClientService.OAuth2Exception("server_error", "User not found"));
        List<String> roles = resolveRoles(user);

        String scope = storedToken.getScope();
        String accessToken = jwtTokenProvider.generateOAuth2AccessToken(
            user.getUsername(), client.getClientId(), scope, roles);

        String newRefreshToken = generateRefreshToken(
            user.getId(), client.getClientId(), scope, storedToken.getFamilyId());

        storedToken.setReplacedBy(hashToken(newRefreshToken));
        refreshTokenRepository.save(storedToken);

        // OIDC: issue new ID Token on refresh if openid scope is present
        String idToken = null;
        if (oidcClaimService.isOidcRequest(scope)) {
            Map<String, Object> userClaims = oidcClaimService.resolveClaims(user, scope);
            idToken = jwtTokenProvider.generateIdToken(
                user.getUsername(), client.getClientId(), null, accessToken, userClaims);
        }

        long expiresIn = ssoProperties.token().accessTokenExpiration() / 1000;
        return new TokenResponse(accessToken, expiresIn, newRefreshToken, scope, idToken);
    }

    private String generateRefreshToken(Long userId, String clientId, String scope, String familyId) {
        byte[] randomBytes = new byte[32];
        SECURE_RANDOM.nextBytes(randomBytes);
        String rawToken = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);

        String tokenHash = hashToken(rawToken);
        long expirationMs = ssoProperties.token().refreshTokenExpiration();

        RefreshToken refreshToken = RefreshToken.builder()
            .tokenHash(tokenHash)
            .userId(userId)
            .clientId(clientId)
            .scope(scope)
            .expiresAt(Instant.now().plusMillis(expirationMs))
            .familyId(familyId != null ? familyId : UUID.randomUUID().toString())
            .build();

        refreshTokenRepository.save(refreshToken);
        return rawToken;
    }

    private List<String> resolveRoles(User user) {
        Set<Role> allRoles = new HashSet<>(user.getRoles());
        user.getGroups().forEach(group -> allRoles.addAll(group.getRoles()));
        return allRoles.stream()
            .map(role -> "ROLE_" + role.getName().toUpperCase())
            .collect(Collectors.toList());
    }

    static String hashToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(token.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm not available", e);
        }
    }
}
