package com.spring.lica.auth;

import com.spring.lica.domain.entity.UserConsent;
import com.spring.lica.domain.repository.UserRepository;
import com.spring.lica.security.ConsentService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/consents")
@RequiredArgsConstructor
public class ConsentController {

    private final ConsentService consentService;
    private final UserRepository userRepository;

    @GetMapping
    public ResponseEntity<?> listConsents(Principal principal) {
        if (principal == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }

        return userRepository.findByUsername(principal.getName())
            .map(user -> {
                List<UserConsent> consents = consentService.getUserConsents(user.getId());
                List<Map<String, Object>> result = consents.stream()
                    .map(c -> {
                        Map<String, Object> m = new LinkedHashMap<>();
                        m.put("id", c.getId());
                        m.put("client_id", c.getClientId());
                        m.put("scopes", c.getScopes());
                        m.put("granted_at", c.getGrantedAt());
                        m.put("expires_at", c.getExpiresAt());
                        return m;
                    })
                    .toList();
                return ResponseEntity.ok(Map.of("consents", result));
            })
            .orElse(ResponseEntity.notFound().build());
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<?> revokeConsent(@PathVariable Long id, Principal principal) {
        if (principal == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }

        consentService.revokeConsent(id);
        return ResponseEntity.ok(Map.of("message", "Consent revoked"));
    }
}
