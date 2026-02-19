package com.spring.lica.auth;

import com.spring.lica.domain.entity.User;
import com.spring.lica.domain.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.*;

@RestController
@RequestMapping("/api/mfa")
@RequiredArgsConstructor
public class MfaController {

    private final TotpService totpService;
    private final RecoveryCodeService recoveryCodeService;
    private final UserRepository userRepository;

    @PostMapping("/totp/setup")
    public ResponseEntity<?> setupTotp(Principal principal) {
        User user = resolveUser(principal);
        if (user == null) return unauthorized();

        TotpService.TotpSetupResult result = totpService.setupTotp(user.getId(), "LicaSSO", user.getUsername());

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("secret", result.secret());
        response.put("otp_auth_uri", result.otpAuthUri());
        response.put("message", "Scan the QR code with your authenticator app, then verify with a code");

        return ResponseEntity.ok(response);
    }

    @PostMapping("/totp/verify")
    public ResponseEntity<?> verifyTotpSetup(@RequestBody Map<String, String> body, Principal principal) {
        User user = resolveUser(principal);
        if (user == null) return unauthorized();

        String code = body.get("code");
        if (code == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "code is required"));
        }

        if (totpService.verifySetup(user.getId(), code)) {
            // Enable MFA on user
            user.setMfaEnabled(true);
            userRepository.save(user);

            // Generate recovery codes
            List<String> recoveryCodes = recoveryCodeService.generateCodes(user.getId());

            Map<String, Object> response = new LinkedHashMap<>();
            response.put("message", "TOTP MFA enabled successfully");
            response.put("recovery_codes", recoveryCodes);
            response.put("warning", "Save these recovery codes securely. They will not be shown again.");

            return ResponseEntity.ok(response);
        }

        return ResponseEntity.badRequest().body(Map.of("error", "Invalid TOTP code"));
    }

    @PostMapping("/totp/validate")
    public ResponseEntity<?> validateTotp(@RequestBody Map<String, String> body, Principal principal) {
        User user = resolveUser(principal);
        if (user == null) return unauthorized();

        String code = body.get("code");
        if (code == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "code is required"));
        }

        boolean valid = totpService.validateTotp(user.getId(), code);
        return ResponseEntity.ok(Map.of("valid", valid));
    }

    @PostMapping("/recovery-codes")
    public ResponseEntity<?> regenerateRecoveryCodes(Principal principal) {
        User user = resolveUser(principal);
        if (user == null) return unauthorized();

        List<String> codes = recoveryCodeService.generateCodes(user.getId());

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("recovery_codes", codes);
        response.put("warning", "Save these recovery codes securely. Previous codes are now invalid.");

        return ResponseEntity.ok(response);
    }

    @PostMapping("/recovery-codes/verify")
    public ResponseEntity<?> verifyRecoveryCode(@RequestBody Map<String, String> body, Principal principal) {
        User user = resolveUser(principal);
        if (user == null) return unauthorized();

        String code = body.get("code");
        if (code == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "code is required"));
        }

        boolean valid = recoveryCodeService.verifyCode(user.getId(), code);
        if (valid) {
            int remaining = recoveryCodeService.remainingCodes(user.getId());
            return ResponseEntity.ok(Map.of("valid", true, "remaining_codes", remaining));
        }
        return ResponseEntity.badRequest().body(Map.of("valid", false, "error", "Invalid recovery code"));
    }

    @GetMapping("/methods")
    public ResponseEntity<?> getMfaMethods(Principal principal) {
        User user = resolveUser(principal);
        if (user == null) return unauthorized();

        List<Map<String, Object>> methods = new ArrayList<>();

        if (totpService.hasVerifiedTotp(user.getId())) {
            Map<String, Object> totp = new LinkedHashMap<>();
            totp.put("id", "totp");
            totp.put("type", "totp");
            totp.put("name", "Authenticator App");
            methods.add(totp);
        }

        int recoveryCodes = recoveryCodeService.remainingCodes(user.getId());
        if (recoveryCodes > 0) {
            Map<String, Object> recovery = new LinkedHashMap<>();
            recovery.put("id", "recovery");
            recovery.put("type", "recovery_codes");
            recovery.put("name", "Recovery Codes");
            recovery.put("remaining", recoveryCodes);
            methods.add(recovery);
        }

        return ResponseEntity.ok(Map.of("mfa_enabled", user.isMfaEnabled(), "methods", methods));
    }

    @DeleteMapping("/methods/{id}")
    public ResponseEntity<?> deleteMfaMethod(@PathVariable String id, Principal principal) {
        User user = resolveUser(principal);
        if (user == null) return unauthorized();

        if ("totp".equals(id)) {
            totpService.removeTotp(user.getId());
            // If no more MFA methods, disable MFA
            if (!totpService.hasVerifiedTotp(user.getId())) {
                user.setMfaEnabled(false);
                userRepository.save(user);
            }
            return ResponseEntity.ok(Map.of("message", "TOTP removed"));
        }

        return ResponseEntity.badRequest().body(Map.of("error", "Unknown MFA method: " + id));
    }

    private User resolveUser(Principal principal) {
        if (principal == null) return null;
        return userRepository.findByUsername(principal.getName()).orElse(null);
    }

    private ResponseEntity<?> unauthorized() {
        return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
    }
}
