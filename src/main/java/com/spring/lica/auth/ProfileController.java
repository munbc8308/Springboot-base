package com.spring.lica.auth;

import com.spring.lica.domain.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.Map;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class ProfileController {

    private final ProfileService profileService;
    private final UserRepository userRepository;

    @GetMapping("/me")
    public ResponseEntity<?> getProfile(Principal principal) {
        if (principal == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }
        return userRepository.findByUsername(principal.getName())
            .map(user -> ResponseEntity.ok(profileService.getProfile(user.getId())))
            .orElse(ResponseEntity.notFound().build());
    }

    @PutMapping("/me")
    public ResponseEntity<?> updateProfile(@RequestBody Map<String, String> updates, Principal principal) {
        if (principal == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }
        return userRepository.findByUsername(principal.getName())
            .map(user -> {
                profileService.updateProfile(user.getId(), updates);
                return ResponseEntity.ok(Map.of("message", "Profile updated"));
            })
            .orElse(ResponseEntity.notFound().build());
    }

    @DeleteMapping("/me")
    public ResponseEntity<?> deactivateAccount(Principal principal) {
        if (principal == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }
        return userRepository.findByUsername(principal.getName())
            .map(user -> {
                profileService.deactivateAccount(user.getId());
                return ResponseEntity.ok(Map.of("message", "Account deactivated"));
            })
            .orElse(ResponseEntity.notFound().build());
    }
}
