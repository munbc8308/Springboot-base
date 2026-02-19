package com.spring.lica.auth;

import com.spring.lica.domain.entity.EmailVerificationToken;
import com.spring.lica.domain.entity.User;
import com.spring.lica.domain.repository.EmailVerificationTokenRepository;
import com.spring.lica.domain.repository.UserRepository;
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
public class UserRegistrationService {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final int MIN_PASSWORD_LENGTH = 8;

    private final UserRepository userRepository;
    private final EmailVerificationTokenRepository emailVerificationTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;

    @Transactional
    public void register(String username, String email, String password) {
        // Validate password policy
        validatePassword(password);

        // Prevent user enumeration: always return success-like response
        // But still check and throw if username is taken (needed for form logic)
        if (userRepository.existsByUsername(username)) {
            throw new RegistrationException("Username is already taken");
        }

        // For email, we silently skip if already exists (user enumeration prevention)
        if (userRepository.existsByEmail(email)) {
            log.warn("Registration attempted with existing email: {}", email);
            // Still send a "verification" email to prevent enumeration
            emailService.sendVerificationEmail(email, "already-registered");
            return;
        }

        User user = User.builder()
            .username(username)
            .email(email)
            .passwordHash(passwordEncoder.encode(password))
            .build();
        user = userRepository.save(user);

        // Generate verification token
        String token = generateSecureToken();
        EmailVerificationToken verificationToken = EmailVerificationToken.builder()
            .token(token)
            .userId(user.getId())
            .expiresAt(Instant.now().plus(24, ChronoUnit.HOURS))
            .build();
        emailVerificationTokenRepository.save(verificationToken);

        emailService.sendVerificationEmail(email, token);
        log.info("User registered: {} ({})", username, email);
    }

    @Transactional
    public void verifyEmail(String token) {
        EmailVerificationToken verificationToken = emailVerificationTokenRepository.findByToken(token)
            .orElseThrow(() -> new RegistrationException("Invalid verification token"));

        if (verificationToken.isUsed()) {
            throw new RegistrationException("Token has already been used");
        }

        if (verificationToken.getExpiresAt().isBefore(Instant.now())) {
            throw new RegistrationException("Verification token has expired");
        }

        verificationToken.setUsed(true);
        emailVerificationTokenRepository.save(verificationToken);

        User user = userRepository.findById(verificationToken.getUserId())
            .orElseThrow(() -> new RegistrationException("User not found"));
        user.setEmailVerified(true);
        userRepository.save(user);

        log.info("Email verified for user {}", user.getUsername());
    }

    private void validatePassword(String password) {
        if (password == null || password.length() < MIN_PASSWORD_LENGTH) {
            throw new RegistrationException("Password must be at least " + MIN_PASSWORD_LENGTH + " characters");
        }
        if (password.chars().allMatch(Character::isLetter)) {
            throw new RegistrationException("Password must contain at least one number or special character");
        }
    }

    private String generateSecureToken() {
        byte[] bytes = new byte[32];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public static class RegistrationException extends RuntimeException {
        public RegistrationException(String message) {
            super(message);
        }
    }
}
