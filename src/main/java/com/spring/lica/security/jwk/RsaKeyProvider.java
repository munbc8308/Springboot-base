package com.spring.lica.security.jwk;

import com.spring.lica.sso.SsoProperties;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.UUID;

@Slf4j
@Component
@Getter
public class RsaKeyProvider {

    private final RSAPublicKey publicKey;
    private final RSAPrivateKey privateKey;
    private final String kid;

    public RsaKeyProvider(SsoProperties ssoProperties) {
        SsoProperties.KeyProperties keyProps = ssoProperties.key();

        this.kid = (keyProps != null && keyProps.kid() != null && !keyProps.kid().isBlank())
            ? keyProps.kid()
            : UUID.randomUUID().toString();

        KeyPair keyPair;
        if (keyProps != null && keyProps.privateKeyPath() != null && !keyProps.privateKeyPath().isBlank()
                && keyProps.publicKeyPath() != null && !keyProps.publicKeyPath().isBlank()) {
            log.info("Loading RSA key pair from PEM files");
            keyPair = loadFromPem(
                Path.of(keyProps.privateKeyPath()),
                Path.of(keyProps.publicKeyPath()));
        } else {
            log.info("Auto-generating RSA 2048 key pair");
            keyPair = generateKeyPair();
            if (keyProps != null && keyProps.storePath() != null && !keyProps.storePath().isBlank()) {
                saveToPem(keyPair, Path.of(keyProps.storePath()));
            }
        }

        this.publicKey = (RSAPublicKey) keyPair.getPublic();
        this.privateKey = (RSAPrivateKey) keyPair.getPrivate();
        log.info("RSA key pair initialized with kid={}", this.kid);
    }

    private KeyPair generateKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("RSA algorithm not available", e);
        }
    }

    private KeyPair loadFromPem(Path privatePath, Path publicPath) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            String privateKeyPem = Files.readString(privatePath)
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
            byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyPem);
            PrivateKey privKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));

            String publicKeyPem = Files.readString(publicPath)
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyPem);
            PublicKey pubKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));

            return new KeyPair(pubKey, privKey);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load RSA keys from PEM files", e);
        }
    }

    private void saveToPem(KeyPair keyPair, Path directory) {
        try {
            Files.createDirectories(directory);
            Path privatePath = directory.resolve("private.pem");
            Path publicPath = directory.resolve("public.pem");

            if (!Files.exists(privatePath)) {
                String privatePem = "-----BEGIN PRIVATE KEY-----\n"
                    + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(keyPair.getPrivate().getEncoded())
                    + "\n-----END PRIVATE KEY-----\n";
                Files.writeString(privatePath, privatePem);

                String publicPem = "-----BEGIN PUBLIC KEY-----\n"
                    + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(keyPair.getPublic().getEncoded())
                    + "\n-----END PUBLIC KEY-----\n";
                Files.writeString(publicPath, publicPem);
                log.info("RSA keys saved to {}", directory.toAbsolutePath());
            } else {
                log.info("RSA key files already exist at {}, skipping save", directory.toAbsolutePath());
            }
        } catch (IOException e) {
            log.warn("Failed to save RSA keys to disk: {}", e.getMessage());
        }
    }
}
