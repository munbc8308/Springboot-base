package com.spring.lica.auth;

import com.spring.lica.domain.entity.TotpCredential;
import com.spring.lica.domain.repository.TotpCredentialRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base32;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class TotpService {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final Base32 BASE32 = new Base32();
    private static final int SECRET_SIZE = 20; // 160 bits

    private final TotpCredentialRepository totpCredentialRepository;

    @Transactional
    public TotpSetupResult setupTotp(Long userId, String issuer, String username) {
        // Generate random secret
        byte[] secretBytes = new byte[SECRET_SIZE];
        SECURE_RANDOM.nextBytes(secretBytes);
        String secret = BASE32.encodeAsString(secretBytes);

        // Remove any existing unverified credentials
        totpCredentialRepository.findAllByUserId(userId).stream()
            .filter(c -> !c.isVerified())
            .forEach(c -> totpCredentialRepository.delete(c));

        // Create new credential (unverified)
        TotpCredential credential = TotpCredential.builder()
            .userId(userId)
            .secret(secret)
            .build();
        totpCredentialRepository.save(credential);

        // Build otpauth URI
        String otpAuthUri = String.format("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
            issuer, username, secret, issuer);

        return new TotpSetupResult(secret, otpAuthUri);
    }

    @Transactional
    public boolean verifySetup(Long userId, String code) {
        Optional<TotpCredential> credOpt = totpCredentialRepository.findAllByUserId(userId).stream()
            .filter(c -> !c.isVerified())
            .findFirst();

        if (credOpt.isEmpty()) {
            return false;
        }

        TotpCredential credential = credOpt.get();
        if (validateCode(credential.getSecret(), code)) {
            credential.setVerified(true);
            totpCredentialRepository.save(credential);
            return true;
        }
        return false;
    }

    @Transactional(readOnly = true)
    public boolean validateTotp(Long userId, String code) {
        Optional<TotpCredential> credOpt = totpCredentialRepository.findByUserIdAndVerifiedTrue(userId);
        if (credOpt.isEmpty()) {
            return false;
        }
        return validateCode(credOpt.get().getSecret(), code);
    }

    @Transactional(readOnly = true)
    public boolean hasVerifiedTotp(Long userId) {
        return totpCredentialRepository.findByUserIdAndVerifiedTrue(userId).isPresent();
    }

    @Transactional
    public void removeTotp(Long userId) {
        totpCredentialRepository.deleteAllByUserId(userId);
    }

    private boolean validateCode(String base32Secret, String code) {
        if (code == null || code.length() != 6) {
            return false;
        }

        try {
            int codeInt = Integer.parseInt(code);
            byte[] secretBytes = BASE32.decode(base32Secret);
            long currentStep = System.currentTimeMillis() / 1000 / 30;

            // Allow +-1 step tolerance
            for (int i = -1; i <= 1; i++) {
                int generated = generateTotpCode(secretBytes, currentStep + i);
                if (generated == codeInt) {
                    return true;
                }
            }
        } catch (NumberFormatException e) {
            return false;
        }
        return false;
    }

    private int generateTotpCode(byte[] secret, long timeStep) {
        try {
            byte[] timeBytes = ByteBuffer.allocate(8).putLong(timeStep).array();

            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(secret, "HmacSHA1"));
            byte[] hash = mac.doFinal(timeBytes);

            int offset = hash[hash.length - 1] & 0x0F;
            int binary = ((hash[offset] & 0x7F) << 24)
                | ((hash[offset + 1] & 0xFF) << 16)
                | ((hash[offset + 2] & 0xFF) << 8)
                | (hash[offset + 3] & 0xFF);

            return binary % 1_000_000;
        } catch (Exception e) {
            throw new IllegalStateException("TOTP generation failed", e);
        }
    }

    public record TotpSetupResult(String secret, String otpAuthUri) {}
}
