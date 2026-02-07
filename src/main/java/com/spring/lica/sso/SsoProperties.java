package com.spring.lica.sso;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "sso")
public record SsoProperties(
    String issuer,
    TokenProperties token,
    KeyProperties key
) {
    public record TokenProperties(
        long accessTokenExpiration,
        long refreshTokenExpiration
    ) {
        public TokenProperties {
            if (accessTokenExpiration <= 0) accessTokenExpiration = 3600000L;
            if (refreshTokenExpiration <= 0) refreshTokenExpiration = 86400000L;
        }
    }

    public record KeyProperties(
        String privateKeyPath,
        String publicKeyPath,
        String storePath,
        String kid
    ) {}
}
