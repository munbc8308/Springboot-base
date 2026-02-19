package com.spring.lica.oauth2.service;

import com.spring.lica.domain.entity.ClientType;
import com.spring.lica.domain.entity.OAuthClient;
import com.spring.lica.domain.repository.OAuthClientRepository;
import com.spring.lica.security.jwt.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.security.SecureRandom;
import java.util.*;

@Slf4j
@Service
@RequiredArgsConstructor
public class ClientRegistrationService {

    private final OAuthClientRepository oAuthClientRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    @Transactional
    @SuppressWarnings("unchecked")
    public Map<String, Object> registerClient(Map<String, Object> metadata) {
        String clientId = generateClientId();
        String clientSecret = generateClientSecret();

        OAuthClient client = OAuthClient.builder()
            .clientId(clientId)
            .clientSecretHash(passwordEncoder.encode(clientSecret))
            .clientName(getStringOrDefault(metadata, "client_name", "Registered Client"))
            .clientType(ClientType.CONFIDENTIAL)
            .tokenEndpointAuthMethod(getStringOrDefault(metadata, "token_endpoint_auth_method", "client_secret_basic"))
            .scopes(getStringOrDefault(metadata, "scope", "openid"))
            .build();

        // Redirect URIs
        Object redirectUrisObj = metadata.get("redirect_uris");
        if (redirectUrisObj instanceof List<?> uris) {
            uris.forEach(uri -> client.getRedirectUris().add(uri.toString()));
        }

        // Grant types
        Object grantTypesObj = metadata.get("grant_types");
        if (grantTypesObj instanceof List<?> types) {
            types.forEach(t -> client.getGrantTypes().add(t.toString()));
        } else {
            client.getGrantTypes().add("authorization_code");
        }

        // Response types
        Object responseTypesObj = metadata.get("response_types");
        if (responseTypesObj instanceof List<?> types) {
            types.forEach(t -> client.getResponseTypes().add(t.toString()));
        } else {
            client.getResponseTypes().add("code");
        }

        // Optional URIs
        if (metadata.containsKey("logo_uri")) client.setLogoUri(metadata.get("logo_uri").toString());
        if (metadata.containsKey("policy_uri")) client.setPolicyUri(metadata.get("policy_uri").toString());
        if (metadata.containsKey("tos_uri")) client.setTosUri(metadata.get("tos_uri").toString());

        // Generate Registration Access Token
        String registrationAccessToken = jwtTokenProvider.generateToken(clientId, List.of("ROLE_CLIENT_MANAGE"));
        client.setRegistrationAccessToken(registrationAccessToken);

        oAuthClientRepository.save(client);

        Map<String, Object> response = buildClientResponse(client);
        response.put("client_secret", clientSecret);
        response.put("registration_access_token", registrationAccessToken);
        response.put("registration_client_uri",
            metadata.getOrDefault("_issuer", "") + "/oauth2/register/" + clientId);
        return response;
    }

    @Transactional(readOnly = true)
    public Map<String, Object> getClient(String clientId, String registrationToken) {
        OAuthClient client = findAndVerifyRegistration(clientId, registrationToken);
        return buildClientResponse(client);
    }

    @Transactional
    @SuppressWarnings("unchecked")
    public Map<String, Object> updateClient(String clientId, String registrationToken, Map<String, Object> metadata) {
        OAuthClient client = findAndVerifyRegistration(clientId, registrationToken);

        if (metadata.containsKey("client_name")) {
            client.setClientName(metadata.get("client_name").toString());
        }
        if (metadata.containsKey("redirect_uris") && metadata.get("redirect_uris") instanceof List<?> uris) {
            client.getRedirectUris().clear();
            uris.forEach(uri -> client.getRedirectUris().add(uri.toString()));
        }
        if (metadata.containsKey("scope")) {
            client.setScopes(metadata.get("scope").toString());
        }
        if (metadata.containsKey("logo_uri")) client.setLogoUri(metadata.get("logo_uri").toString());
        if (metadata.containsKey("policy_uri")) client.setPolicyUri(metadata.get("policy_uri").toString());
        if (metadata.containsKey("tos_uri")) client.setTosUri(metadata.get("tos_uri").toString());

        oAuthClientRepository.save(client);
        return buildClientResponse(client);
    }

    @Transactional
    public void deleteClient(String clientId, String registrationToken) {
        OAuthClient client = findAndVerifyRegistration(clientId, registrationToken);
        oAuthClientRepository.delete(client);
    }

    private OAuthClient findAndVerifyRegistration(String clientId, String registrationToken) {
        OAuthClient client = oAuthClientRepository.findByClientId(clientId)
            .orElseThrow(() -> new OAuthClientService.OAuth2Exception("invalid_client", "Client not found"));

        if (!StringUtils.hasText(client.getRegistrationAccessToken())
                || !client.getRegistrationAccessToken().equals(registrationToken)) {
            throw new OAuthClientService.OAuth2Exception("invalid_token", "Invalid registration access token");
        }
        return client;
    }

    private Map<String, Object> buildClientResponse(OAuthClient client) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("client_id", client.getClientId());
        response.put("client_name", client.getClientName());
        response.put("redirect_uris", new ArrayList<>(client.getRedirectUris()));
        response.put("grant_types", new ArrayList<>(client.getGrantTypes()));
        response.put("response_types", new ArrayList<>(client.getResponseTypes()));
        response.put("scope", client.getScopes());
        response.put("token_endpoint_auth_method", client.getTokenEndpointAuthMethod());
        response.put("client_type", client.getClientType().name().toLowerCase());
        if (client.getLogoUri() != null) response.put("logo_uri", client.getLogoUri());
        if (client.getPolicyUri() != null) response.put("policy_uri", client.getPolicyUri());
        if (client.getTosUri() != null) response.put("tos_uri", client.getTosUri());
        return response;
    }

    private String generateClientId() {
        byte[] bytes = new byte[16];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String generateClientSecret() {
        byte[] bytes = new byte[32];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String getStringOrDefault(Map<String, Object> map, String key, String defaultValue) {
        Object value = map.get(key);
        return value != null ? value.toString() : defaultValue;
    }
}
