package com.spring.lica.oauth2.service;

import com.spring.lica.domain.entity.ClientType;
import com.spring.lica.domain.entity.OAuthClient;
import com.spring.lica.domain.repository.OAuthClientRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Slf4j
@Service
@RequiredArgsConstructor
public class OAuthClientService {

    private final OAuthClientRepository oAuthClientRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional(readOnly = true)
    public OAuthClient findByClientId(String clientId) {
        return oAuthClientRepository.findByClientId(clientId)
            .orElseThrow(() -> new OAuth2Exception("invalid_client", "Client not found: " + clientId));
    }

    /**
     * Authenticate client from request using client_secret_basic, client_secret_post, or none.
     */
    @Transactional(readOnly = true)
    public OAuthClient authenticateClient(HttpServletRequest request, String bodyClientId, String bodyClientSecret) {
        // Try Basic Auth first
        String authHeader = request.getHeader("Authorization");
        if (StringUtils.hasText(authHeader) && authHeader.startsWith("Basic ")) {
            String decoded = new String(Base64.getDecoder().decode(authHeader.substring(6)), StandardCharsets.UTF_8);
            String[] parts = decoded.split(":", 2);
            if (parts.length == 2) {
                return authenticateWithSecret(parts[0], parts[1]);
            }
        }

        // Try client_secret_post
        if (StringUtils.hasText(bodyClientId) && StringUtils.hasText(bodyClientSecret)) {
            return authenticateWithSecret(bodyClientId, bodyClientSecret);
        }

        // Try public client (no secret)
        if (StringUtils.hasText(bodyClientId)) {
            OAuthClient client = findByClientId(bodyClientId);
            if (client.getClientType() == ClientType.PUBLIC && "none".equals(client.getTokenEndpointAuthMethod())) {
                return client;
            }
            throw new OAuth2Exception("invalid_client", "Client authentication required");
        }

        throw new OAuth2Exception("invalid_client", "Missing client authentication");
    }

    private OAuthClient authenticateWithSecret(String clientId, String clientSecret) {
        OAuthClient client = findByClientId(clientId);
        if (!client.isEnabled()) {
            throw new OAuth2Exception("invalid_client", "Client is disabled");
        }
        if (client.getClientSecretHash() == null || !passwordEncoder.matches(clientSecret, client.getClientSecretHash())) {
            throw new OAuth2Exception("invalid_client", "Invalid client credentials");
        }
        return client;
    }

    public void validateRedirectUri(OAuthClient client, String redirectUri) {
        if (!StringUtils.hasText(redirectUri)) {
            if (client.getRedirectUris().size() == 1) {
                return; // use the single registered URI
            }
            throw new OAuth2Exception("invalid_request", "redirect_uri is required");
        }
        if (!client.getRedirectUris().contains(redirectUri)) {
            throw new OAuth2Exception("invalid_request", "Invalid redirect_uri");
        }
    }

    public void validateGrantType(OAuthClient client, String grantType) {
        if (!client.getGrantTypes().contains(grantType)) {
            throw new OAuth2Exception("unauthorized_client", "Grant type not allowed: " + grantType);
        }
    }

    public void validateScope(OAuthClient client, String requestedScope) {
        if (!StringUtils.hasText(requestedScope)) {
            return;
        }
        String[] allowedScopes = client.getScopes().split("\\s+");
        var allowedSet = java.util.Set.of(allowedScopes);
        for (String scope : requestedScope.split("\\s+")) {
            if (!allowedSet.contains(scope)) {
                throw new OAuth2Exception("invalid_scope", "Scope not allowed: " + scope);
            }
        }
    }

    public String resolveRedirectUri(OAuthClient client, String redirectUri) {
        if (StringUtils.hasText(redirectUri)) {
            return redirectUri;
        }
        if (client.getRedirectUris().size() == 1) {
            return client.getRedirectUris().iterator().next();
        }
        throw new OAuth2Exception("invalid_request", "redirect_uri is required");
    }

    public static class OAuth2Exception extends RuntimeException {
        private final String error;
        private final String errorDescription;

        public OAuth2Exception(String error, String errorDescription) {
            super(errorDescription);
            this.error = error;
            this.errorDescription = errorDescription;
        }

        public String getError() {
            return error;
        }

        public String getErrorDescription() {
            return errorDescription;
        }
    }
}
