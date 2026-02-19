package com.spring.lica.oauth2.dto;

public record TokenRequest(
    String grantType,
    String code,
    String redirectUri,
    String clientId,
    String clientSecret,
    String codeVerifier,
    String refreshToken,
    String scope
) {}
