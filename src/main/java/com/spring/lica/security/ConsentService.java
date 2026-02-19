package com.spring.lica.security;

import com.spring.lica.domain.entity.UserConsent;
import com.spring.lica.domain.repository.UserConsentRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.*;

@Slf4j
@Service
@RequiredArgsConstructor
public class ConsentService {

    private final UserConsentRepository userConsentRepository;

    @Transactional(readOnly = true)
    public boolean hasValidConsent(Long userId, String clientId, String requestedScopes) {
        Optional<UserConsent> consentOpt = userConsentRepository.findByUserIdAndClientId(userId, clientId);
        if (consentOpt.isEmpty()) {
            return false;
        }

        UserConsent consent = consentOpt.get();

        // Check expiration
        if (consent.getExpiresAt() != null && consent.getExpiresAt().isBefore(Instant.now())) {
            return false;
        }

        // Check scope coverage
        Set<String> grantedScopes = Set.of(consent.getScopes().split("\\s+"));
        Set<String> requested = Set.of(requestedScopes.split("\\s+"));

        return grantedScopes.containsAll(requested);
    }

    @Transactional
    public void grantConsent(Long userId, String clientId, String scopes) {
        UserConsent consent = userConsentRepository.findByUserIdAndClientId(userId, clientId)
            .orElseGet(() -> UserConsent.builder()
                .userId(userId)
                .clientId(clientId)
                .build());

        consent.setScopes(scopes);
        consent.setGrantedAt(Instant.now());

        userConsentRepository.save(consent);
        log.info("Consent granted: user={} client={} scopes={}", userId, clientId, scopes);
    }

    @Transactional
    public void revokeConsent(Long consentId) {
        userConsentRepository.deleteById(consentId);
    }

    @Transactional(readOnly = true)
    public List<UserConsent> getUserConsents(Long userId) {
        return userConsentRepository.findByUserId(userId);
    }
}
