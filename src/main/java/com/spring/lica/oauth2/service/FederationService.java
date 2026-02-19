package com.spring.lica.oauth2.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.spring.lica.domain.entity.FederatedIdentity;
import com.spring.lica.domain.entity.IdentityProvider;
import com.spring.lica.domain.entity.User;
import com.spring.lica.domain.repository.FederatedIdentityRepository;
import com.spring.lica.domain.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

@Slf4j
@Service
@RequiredArgsConstructor
public class FederationService {

    private final FederatedIdentityRepository federatedIdentityRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final ObjectMapper objectMapper;

    private final RestTemplate restTemplate = new RestTemplate();

    // Pre-configured provider defaults
    private static final Map<String, ProviderDefaults> PROVIDER_DEFAULTS = Map.of(
        "google", new ProviderDefaults(
            "https://accounts.google.com/o/oauth2/v2/auth",
            "https://oauth2.googleapis.com/token",
            "https://openidconnect.googleapis.com/v1/userinfo",
            "openid email profile"
        ),
        "github", new ProviderDefaults(
            "https://github.com/login/oauth/authorize",
            "https://github.com/login/oauth/access_token",
            "https://api.github.com/user",
            "read:user user:email"
        ),
        "kakao", new ProviderDefaults(
            "https://kauth.kakao.com/oauth/authorize",
            "https://kauth.kakao.com/oauth/token",
            "https://kapi.kakao.com/v2/user/me",
            "openid profile_nickname account_email"
        ),
        "naver", new ProviderDefaults(
            "https://nid.naver.com/oauth2.0/authorize",
            "https://nid.naver.com/oauth2.0/token",
            "https://openapi.naver.com/v1/nid/me",
            "name email"
        )
    );

    public String buildAuthorizationUrl(IdentityProvider idp, String state, String nonce, String redirectUri) {
        String authUrl = resolveUrl(idp, idp.getAuthorizationUrl(), "authorization");
        String scopes = idp.getScopes() != null ? idp.getScopes() : getDefaultScopes(idp.getAlias());

        StringBuilder url = new StringBuilder(authUrl);
        url.append("?response_type=code");
        url.append("&client_id=").append(encode(idp.getClientId()));
        url.append("&redirect_uri=").append(encode(redirectUri));
        url.append("&scope=").append(encode(scopes));
        url.append("&state=").append(encode(state));
        if (nonce != null) {
            url.append("&nonce=").append(encode(nonce));
        }

        return url.toString();
    }

    public Map<String, Object> exchangeCodeForTokens(IdentityProvider idp, String code, String redirectUri) {
        String tokenUrl = resolveUrl(idp, idp.getTokenUrl(), "token");

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        // GitHub requires Accept: application/json
        headers.setAccept(List.of(MediaType.APPLICATION_JSON));

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "authorization_code");
        params.add("code", code);
        params.add("redirect_uri", redirectUri);
        params.add("client_id", idp.getClientId());
        if (idp.getClientSecret() != null) {
            params.add("client_secret", idp.getClientSecret());
        }

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);

        try {
            ResponseEntity<String> response = restTemplate.postForEntity(tokenUrl, request, String.class);
            return objectMapper.readValue(response.getBody(), new TypeReference<>() {});
        } catch (Exception e) {
            log.error("Token exchange failed for IdP {}: {}", idp.getAlias(), e.getMessage());
            throw new RuntimeException("Token exchange failed", e);
        }
    }

    public Map<String, Object> fetchUserInfo(IdentityProvider idp, String accessToken) {
        String userinfoUrl = resolveUrl(idp, idp.getUserinfoUrl(), "userinfo");

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        headers.setAccept(List.of(MediaType.APPLICATION_JSON));

        HttpEntity<Void> request = new HttpEntity<>(headers);

        try {
            ResponseEntity<String> response = restTemplate.exchange(
                userinfoUrl, HttpMethod.GET, request, String.class);
            Map<String, Object> raw = objectMapper.readValue(response.getBody(), new TypeReference<>() {});

            // Naver wraps response in "response" field
            if ("naver".equalsIgnoreCase(idp.getAlias()) && raw.containsKey("response")) {
                @SuppressWarnings("unchecked")
                Map<String, Object> nested = (Map<String, Object>) raw.get("response");
                return nested;
            }
            return raw;
        } catch (Exception e) {
            log.error("UserInfo fetch failed for IdP {}: {}", idp.getAlias(), e.getMessage());
            throw new RuntimeException("UserInfo fetch failed", e);
        }
    }

    @Transactional
    public User findOrCreateUser(IdentityProvider idp, Map<String, Object> userInfo) {
        String externalId = extractExternalId(idp, userInfo);
        String externalUsername = extractUsername(idp, userInfo);
        String email = extractEmail(idp, userInfo);

        // Check if federated identity already exists
        Optional<FederatedIdentity> existingLink = federatedIdentityRepository
            .findByIdpAliasAndExternalUserId(idp.getAlias(), externalId);

        if (existingLink.isPresent()) {
            return existingLink.get().getUser();
        }

        // Try to link by email
        User user;
        if (email != null) {
            user = userRepository.findByEmail(email).orElse(null);
        } else {
            user = null;
        }

        // Create new user if not found
        if (user == null) {
            String username = generateUniqueUsername(externalUsername, idp.getAlias());
            user = User.builder()
                .username(username)
                .email(email != null ? email : idp.getAlias() + "_" + externalId + "@federated.local")
                .passwordHash(passwordEncoder.encode(UUID.randomUUID().toString()))
                .emailVerified(email != null) // trust IdP email verification
                .enabled(true)
                .build();

            // Set profile from IdP data
            String name = (String) userInfo.getOrDefault("name", externalUsername);
            if (name != null) {
                user.setNickname(name);
            }
            String picture = (String) userInfo.get("picture");
            if (picture != null) {
                user.setPicture(picture);
            }

            user = userRepository.save(user);
            log.info("Created federated user {} linked to IdP {} (external: {})",
                user.getUsername(), idp.getAlias(), externalId);
        }

        // Create federated identity link
        FederatedIdentity link = FederatedIdentity.builder()
            .user(user)
            .idpAlias(idp.getAlias())
            .externalUserId(externalId)
            .externalUsername(externalUsername)
            .build();
        federatedIdentityRepository.save(link);

        return user;
    }

    private String extractExternalId(IdentityProvider idp, Map<String, Object> userInfo) {
        String alias = idp.getAlias().toLowerCase();
        return switch (alias) {
            case "github" -> String.valueOf(userInfo.get("id"));
            case "kakao" -> String.valueOf(userInfo.get("id"));
            case "naver" -> (String) userInfo.get("id");
            default -> {
                // Standard OIDC: "sub"
                Object sub = userInfo.get("sub");
                yield sub != null ? sub.toString() : String.valueOf(userInfo.get("id"));
            }
        };
    }

    private String extractUsername(IdentityProvider idp, Map<String, Object> userInfo) {
        String alias = idp.getAlias().toLowerCase();
        return switch (alias) {
            case "github" -> (String) userInfo.get("login");
            case "kakao" -> {
                @SuppressWarnings("unchecked")
                Map<String, Object> props = (Map<String, Object>) userInfo.get("kakao_account");
                if (props != null) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> profile = (Map<String, Object>) props.get("profile");
                    yield profile != null ? (String) profile.get("nickname") : null;
                }
                yield null;
            }
            case "naver" -> (String) userInfo.get("name");
            default -> (String) userInfo.getOrDefault("preferred_username",
                userInfo.getOrDefault("name", userInfo.get("email")));
        };
    }

    private String extractEmail(IdentityProvider idp, Map<String, Object> userInfo) {
        String alias = idp.getAlias().toLowerCase();
        if ("kakao".equals(alias)) {
            @SuppressWarnings("unchecked")
            Map<String, Object> account = (Map<String, Object>) userInfo.get("kakao_account");
            return account != null ? (String) account.get("email") : null;
        }
        return (String) userInfo.get("email");
    }

    private String generateUniqueUsername(String baseName, String idpAlias) {
        String base = baseName != null ? baseName : idpAlias + "_user";
        base = base.replaceAll("[^a-zA-Z0-9_]", "_");
        if (!userRepository.existsByUsername(base)) {
            return base;
        }
        for (int i = 1; i < 1000; i++) {
            String candidate = base + "_" + i;
            if (!userRepository.existsByUsername(candidate)) {
                return candidate;
            }
        }
        return base + "_" + UUID.randomUUID().toString().substring(0, 8);
    }

    private String resolveUrl(IdentityProvider idp, String configured, String type) {
        if (configured != null && !configured.isBlank()) {
            return configured;
        }
        ProviderDefaults defaults = PROVIDER_DEFAULTS.get(idp.getAlias().toLowerCase());
        if (defaults == null) {
            throw new IllegalStateException("No " + type + " URL configured for IdP: " + idp.getAlias());
        }
        return switch (type) {
            case "authorization" -> defaults.authorizationUrl;
            case "token" -> defaults.tokenUrl;
            case "userinfo" -> defaults.userinfoUrl;
            default -> throw new IllegalArgumentException("Unknown URL type: " + type);
        };
    }

    private String getDefaultScopes(String alias) {
        ProviderDefaults defaults = PROVIDER_DEFAULTS.get(alias.toLowerCase());
        return defaults != null ? defaults.scopes : "openid email profile";
    }

    private String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private record ProviderDefaults(String authorizationUrl, String tokenUrl,
                                     String userinfoUrl, String scopes) {}
}
