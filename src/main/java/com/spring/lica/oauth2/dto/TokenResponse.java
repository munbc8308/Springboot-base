package com.spring.lica.oauth2.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record TokenResponse(
    @JsonProperty("access_token") String accessToken,
    @JsonProperty("token_type") String tokenType,
    @JsonProperty("expires_in") long expiresIn,
    @JsonProperty("refresh_token") String refreshToken,
    @JsonProperty("scope") String scope,
    @JsonProperty("id_token") String idToken
) {
    public TokenResponse(String accessToken, long expiresIn, String refreshToken, String scope) {
        this(accessToken, "Bearer", expiresIn, refreshToken, scope, null);
    }

    public TokenResponse(String accessToken, long expiresIn, String refreshToken, String scope, String idToken) {
        this(accessToken, "Bearer", expiresIn, refreshToken, scope, idToken);
    }
}
