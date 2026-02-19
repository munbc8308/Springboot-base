package com.spring.lica.security;

import com.spring.lica.domain.entity.LoginAttempt;
import com.spring.lica.domain.repository.LoginAttemptRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

@Slf4j
@Service
@RequiredArgsConstructor
public class BruteForceProtectionService {

    private static final int MAX_FAILURES = 5;
    private static final long LOCK_DURATION_MINUTES = 15;

    private final LoginAttemptRepository loginAttemptRepository;

    @Transactional(readOnly = true)
    public boolean isLocked(String username) {
        return loginAttemptRepository.findByUsername(username)
            .map(attempt -> {
                if (attempt.getLockedUntil() != null && attempt.getLockedUntil().isAfter(Instant.now())) {
                    return true;
                }
                return false;
            })
            .orElse(false);
    }

    @Transactional(readOnly = true)
    public long getDelaySeconds(String username) {
        return loginAttemptRepository.findByUsername(username)
            .map(attempt -> {
                int failures = attempt.getFailureCount();
                if (failures < 2) return 0L;
                // Exponential backoff: 1, 2, 4, 8... seconds
                return Math.min((long) Math.pow(2, failures - 2), 30L);
            })
            .orElse(0L);
    }

    @Transactional
    public void recordFailure(String username, String ipAddress) {
        LoginAttempt attempt = loginAttemptRepository.findByUsername(username)
            .orElseGet(() -> LoginAttempt.builder()
                .username(username)
                .ipAddress(ipAddress)
                .build());

        attempt.setFailureCount(attempt.getFailureCount() + 1);
        attempt.setLastFailureAt(Instant.now());
        attempt.setIpAddress(ipAddress);

        if (attempt.getFailureCount() >= MAX_FAILURES) {
            attempt.setLockedUntil(Instant.now().plusSeconds(LOCK_DURATION_MINUTES * 60));
            log.warn("Account locked for user {} after {} failed attempts", username, attempt.getFailureCount());
        }

        loginAttemptRepository.save(attempt);
    }

    @Transactional
    public void recordSuccess(String username) {
        loginAttemptRepository.findByUsername(username).ifPresent(attempt -> {
            attempt.setFailureCount(0);
            attempt.setLockedUntil(null);
            attempt.setLastFailureAt(null);
            loginAttemptRepository.save(attempt);
        });
    }

    @Transactional
    public void unlock(String username) {
        loginAttemptRepository.findByUsername(username).ifPresent(attempt -> {
            attempt.setFailureCount(0);
            attempt.setLockedUntil(null);
            loginAttemptRepository.save(attempt);
            log.info("Account unlocked for user {}", username);
        });
    }
}
