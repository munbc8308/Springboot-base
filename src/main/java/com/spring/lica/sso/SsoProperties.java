package com.spring.lica.sso;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "sso")
public record SsoProperties(
    String issuer,
    TokenProperties token,
    KeyProperties key,
    SessionProperties session
) {
    public record TokenProperties(
        long accessTokenExpiration,
        long refreshTokenExpiration,
        long authorizationCodeExpiration
    ) {
        public TokenProperties {
            if (accessTokenExpiration <= 0) accessTokenExpiration = 3600000L;
            if (refreshTokenExpiration <= 0) refreshTokenExpiration = 86400000L;
            if (authorizationCodeExpiration <= 0) authorizationCodeExpiration = 300000L;
        }
    }

    public record KeyProperties(
        String privateKeyPath,
        String publicKeyPath,
        String storePath,
        String kid
    ) {}

    public record SessionProperties(
        long idleTimeout,
        long absoluteTimeout,
        int maxConcurrentSessions,
        String cookieName
    ) {
        public SessionProperties {
            if (idleTimeout <= 0) idleTimeout = 1800000L;
            if (absoluteTimeout <= 0) absoluteTimeout = 28800000L;
            if (maxConcurrentSessions <= 0) maxConcurrentSessions = 5;
            if (cookieName == null || cookieName.isBlank()) cookieName = "LICA_SSO_SID";
        }
    }
}
