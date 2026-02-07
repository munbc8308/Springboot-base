package com.spring.lica.security.jwk;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.List;
import java.util.Map;

@RestController
@RequiredArgsConstructor
public class JwksController {

    private final RsaKeyProvider rsaKeyProvider;

    @GetMapping("/oauth2/jwks")
    public Map<String, Object> jwks() {
        RSAPublicKey publicKey = rsaKeyProvider.getPublicKey();

        Map<String, Object> jwk = Map.of(
            "kty", "RSA",
            "use", "sig",
            "alg", "RS256",
            "kid", rsaKeyProvider.getKid(),
            "n", encodeUnsigned(publicKey.getModulus()),
            "e", encodeUnsigned(publicKey.getPublicExponent())
        );

        return Map.of("keys", List.of(jwk));
    }

    private String encodeUnsigned(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            byte[] trimmed = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, trimmed, 0, trimmed.length);
            bytes = trimmed;
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
