package com.spring.lica.auth;

import com.spring.lica.domain.entity.RecoveryCode;
import com.spring.lica.domain.repository.RecoveryCodeRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class RecoveryCodeService {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final int CODE_COUNT = 10;
    private static final int CODE_LENGTH = 8;

    private final RecoveryCodeRepository recoveryCodeRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public List<String> generateCodes(Long userId) {
        // Delete existing codes
        recoveryCodeRepository.deleteAllByUserId(userId);

        List<String> plainCodes = new ArrayList<>();
        for (int i = 0; i < CODE_COUNT; i++) {
            String code = generateRandomCode();
            plainCodes.add(code);

            RecoveryCode rc = RecoveryCode.builder()
                .userId(userId)
                .codeHash(passwordEncoder.encode(code))
                .build();
            recoveryCodeRepository.save(rc);
        }

        log.info("Generated {} recovery codes for user {}", CODE_COUNT, userId);
        return plainCodes;
    }

    @Transactional
    public boolean verifyCode(Long userId, String code) {
        List<RecoveryCode> unused = recoveryCodeRepository.findByUserIdAndUsedFalse(userId);

        for (RecoveryCode rc : unused) {
            if (passwordEncoder.matches(code, rc.getCodeHash())) {
                rc.setUsed(true);
                recoveryCodeRepository.save(rc);
                log.info("Recovery code used for user {}", userId);
                return true;
            }
        }
        return false;
    }

    @Transactional(readOnly = true)
    public int remainingCodes(Long userId) {
        return recoveryCodeRepository.findByUserIdAndUsedFalse(userId).size();
    }

    private String generateRandomCode() {
        StringBuilder sb = new StringBuilder();
        String chars = "abcdefghijklmnopqrstuvwxyz0123456789";
        for (int i = 0; i < CODE_LENGTH; i++) {
            if (i == 4) sb.append('-');
            sb.append(chars.charAt(SECURE_RANDOM.nextInt(chars.length())));
        }
        return sb.toString();
    }
}
