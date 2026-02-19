package com.spring.lica.oauth2.dto;

import java.io.Serializable;

public record AuthorizationRequest(
    String responseType,
    String clientId,
    String redirectUri,
    String scope,
    String state,
    String codeChallenge,
    String codeChallengeMethod,
    String nonce,
    String prompt,
    Long maxAge
) implements Serializable {}
