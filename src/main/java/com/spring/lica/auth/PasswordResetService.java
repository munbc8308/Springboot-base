package com.spring.lica.auth;

import com.spring.lica.domain.entity.PasswordResetToken;
import com.spring.lica.domain.entity.User;
import com.spring.lica.domain.repository.PasswordResetTokenRepository;
import com.spring.lica.domain.repository.UserRepository;
import com.spring.lica.oauth2.service.SsoSessionService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;

@Slf4j
@Service
@RequiredArgsConstructor
public class PasswordResetService {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final UserRepository userRepository;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private final SsoSessionService ssoSessionService;

    @Transactional
    public void requestReset(String email) {
        // Always respond the same way to prevent user enumeration
        userRepository.findByEmail(email).ifPresentOrElse(
            user -> {
                String token = generateSecureToken();
                PasswordResetToken resetToken = PasswordResetToken.builder()
                    .token(token)
                    .userId(user.getId())
                    .expiresAt(Instant.now().plus(30, ChronoUnit.MINUTES))
                    .build();
                passwordResetTokenRepository.save(resetToken);
                emailService.sendPasswordResetEmail(email, token);
                log.info("Password reset requested for user {}", user.getUsername());
            },
            () -> log.warn("Password reset requested for non-existent email: {}", email)
        );
    }

    @Transactional
    public void resetPassword(String token, String newPassword) {
        PasswordResetToken resetToken = passwordResetTokenRepository.findByToken(token)
            .orElseThrow(() -> new PasswordResetException("Invalid reset token"));

        if (resetToken.isUsed()) {
            throw new PasswordResetException("Token has already been used");
        }

        if (resetToken.getExpiresAt().isBefore(Instant.now())) {
            throw new PasswordResetException("Reset token has expired");
        }

        validatePassword(newPassword);

        resetToken.setUsed(true);
        passwordResetTokenRepository.save(resetToken);

        User user = userRepository.findById(resetToken.getUserId())
            .orElseThrow(() -> new PasswordResetException("User not found"));
        user.setPasswordHash(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        // Invalidate all existing sessions
        ssoSessionService.revokeAllUserSessions(user.getId());

        // Send notification
        emailService.sendPasswordChangedNotification(user.getEmail());
        log.info("Password reset completed for user {}", user.getUsername());
    }

    @Transactional
    public void changePasswordByUsername(String username, String currentPassword, String newPassword) {
        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new PasswordResetException("User not found"));
        changePasswordInternal(user, currentPassword, newPassword);
    }

    @Transactional
    public void changePassword(Long userId, String currentPassword, String newPassword) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new PasswordResetException("User not found"));
        changePasswordInternal(user, currentPassword, newPassword);
    }

    private void changePasswordInternal(User user, String currentPassword, String newPassword) {
        if (!passwordEncoder.matches(currentPassword, user.getPasswordHash())) {
            throw new PasswordResetException("Current password is incorrect");
        }

        validatePassword(newPassword);

        user.setPasswordHash(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        emailService.sendPasswordChangedNotification(user.getEmail());
        log.info("Password changed for user {}", user.getUsername());
    }

    private void validatePassword(String password) {
        if (password == null || password.length() < 8) {
            throw new PasswordResetException("Password must be at least 8 characters");
        }
        if (password.chars().allMatch(Character::isLetter)) {
            throw new PasswordResetException("Password must contain at least one number or special character");
        }
    }

    private String generateSecureToken() {
        byte[] bytes = new byte[32];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public static class PasswordResetException extends RuntimeException {
        public PasswordResetException(String message) {
            super(message);
        }
    }
}
