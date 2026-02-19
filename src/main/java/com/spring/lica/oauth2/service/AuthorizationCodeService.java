package com.spring.lica.oauth2.service;

import com.spring.lica.domain.entity.AuthorizationCode;
import com.spring.lica.domain.repository.AuthorizationCodeRepository;
import com.spring.lica.sso.SsoProperties;
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
import java.util.Base64;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthorizationCodeService {

    private final AuthorizationCodeRepository authorizationCodeRepository;
    private final SsoProperties ssoProperties;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    @Transactional
    public AuthorizationCode createCode(String clientId, Long userId, String redirectUri,
                                         String scope, String codeChallenge,
                                         String codeChallengeMethod, String state,
                                         String nonce) {
        byte[] randomBytes = new byte[32];
        SECURE_RANDOM.nextBytes(randomBytes);
        String code = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);

        long expirationMs = ssoProperties.token().authorizationCodeExpiration();
        Instant expiresAt = Instant.now().plusMillis(expirationMs);

        AuthorizationCode authCode = AuthorizationCode.builder()
            .code(code)
            .clientId(clientId)
            .userId(userId)
            .redirectUri(redirectUri)
            .scope(scope)
            .codeChallenge(codeChallenge)
            .codeChallengeMethod(codeChallengeMethod)
            .state(state)
            .nonce(nonce)
            .expiresAt(expiresAt)
            .build();

        return authorizationCodeRepository.save(authCode);
    }

    @Transactional
    public AuthorizationCode consumeCode(String code) {
        AuthorizationCode authCode = authorizationCodeRepository.findByCode(code)
            .orElseThrow(() -> new OAuthClientService.OAuth2Exception("invalid_grant", "Invalid authorization code"));

        if (authCode.isUsed()) {
            throw new OAuthClientService.OAuth2Exception("invalid_grant", "Authorization code already used");
        }

        if (authCode.getExpiresAt().isBefore(Instant.now())) {
            throw new OAuthClientService.OAuth2Exception("invalid_grant", "Authorization code expired");
        }

        authCode.setUsed(true);
        authorizationCodeRepository.save(authCode);

        return authCode;
    }

    public void verifyPkce(AuthorizationCode authCode, String codeVerifier) {
        String codeChallenge = authCode.getCodeChallenge();
        String codeChallengeMethod = authCode.getCodeChallengeMethod();

        if (!StringUtils.hasText(codeChallenge)) {
            // PKCE was not used during authorization
            if (StringUtils.hasText(codeVerifier)) {
                throw new OAuthClientService.OAuth2Exception("invalid_grant",
                    "code_verifier provided but no code_challenge was sent");
            }
            return;
        }

        if (!StringUtils.hasText(codeVerifier)) {
            throw new OAuthClientService.OAuth2Exception("invalid_grant", "code_verifier is required");
        }

        if ("S256".equals(codeChallengeMethod)) {
            String computed = computeS256Challenge(codeVerifier);
            if (!computed.equals(codeChallenge)) {
                throw new OAuthClientService.OAuth2Exception("invalid_grant", "PKCE verification failed");
            }
        } else if ("plain".equals(codeChallengeMethod)) {
            if (!codeVerifier.equals(codeChallenge)) {
                throw new OAuthClientService.OAuth2Exception("invalid_grant", "PKCE verification failed");
            }
        } else {
            throw new OAuthClientService.OAuth2Exception("invalid_request",
                "Unsupported code_challenge_method: " + codeChallengeMethod);
        }
    }

    private String computeS256Challenge(String codeVerifier) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm not available", e);
        }
    }
}
