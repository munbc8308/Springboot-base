package com.spring.lica.oauth2.controller;

import com.spring.lica.sso.SsoProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequiredArgsConstructor
public class OAuth2MetadataController {

    private final SsoProperties ssoProperties;

    @GetMapping("/.well-known/oauth-authorization-server")
    public Map<String, Object> authorizationServerMetadata() {
        String issuer = ssoProperties.issuer();

        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("issuer", issuer);
        metadata.put("authorization_endpoint", issuer + "/oauth2/authorize");
        metadata.put("token_endpoint", issuer + "/oauth2/token");
        metadata.put("revocation_endpoint", issuer + "/oauth2/revoke");
        metadata.put("introspection_endpoint", issuer + "/oauth2/introspect");
        metadata.put("jwks_uri", issuer + "/oauth2/jwks");
        metadata.put("response_types_supported", List.of("code"));
        metadata.put("grant_types_supported", List.of(
            "authorization_code", "client_credentials", "refresh_token"));
        metadata.put("token_endpoint_auth_methods_supported", List.of(
            "client_secret_basic", "client_secret_post", "none"));
        metadata.put("revocation_endpoint_auth_methods_supported", List.of(
            "client_secret_basic", "client_secret_post"));
        metadata.put("introspection_endpoint_auth_methods_supported", List.of(
            "client_secret_basic", "client_secret_post"));
        metadata.put("code_challenge_methods_supported", List.of("S256", "plain"));

        return metadata;
    }

    @GetMapping("/.well-known/openid-configuration")
    public Map<String, Object> openIdConfiguration() {
        Map<String, Object> metadata = new LinkedHashMap<>(authorizationServerMetadata());
        String issuer = ssoProperties.issuer();

        metadata.put("userinfo_endpoint", issuer + "/userinfo");
        metadata.put("registration_endpoint", issuer + "/oauth2/register");
        metadata.put("scopes_supported", List.of("openid", "profile", "email", "phone", "address"));
        metadata.put("subject_types_supported", List.of("public"));
        metadata.put("id_token_signing_alg_values_supported", List.of("RS256"));
        metadata.put("end_session_endpoint", issuer + "/oauth2/logout");
        metadata.put("backchannel_logout_supported", true);
        metadata.put("backchannel_logout_session_supported", true);

        metadata.put("claims_supported", List.of(
            "sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "at_hash",
            "name", "given_name", "family_name", "nickname", "picture", "profile",
            "website", "gender", "birthdate", "zoneinfo", "locale", "updated_at",
            "email", "email_verified", "phone_number", "phone_number_verified", "address"));

        return metadata;
    }
}
