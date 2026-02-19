package com.spring.lica.oauth2.controller;

import com.spring.lica.auth.PasswordResetService;
import com.spring.lica.auth.UserRegistrationService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@RequiredArgsConstructor
public class AccountController {

    private final UserRegistrationService registrationService;
    private final PasswordResetService passwordResetService;

    // ── Registration ────────────────────────────────────────

    @GetMapping("/oauth2/signup")
    public String registerPage() {
        return "oauth2-register";
    }

    @PostMapping("/oauth2/signup")
    public String register(@RequestParam String username,
                           @RequestParam String email,
                           @RequestParam String password,
                           @RequestParam("password_confirm") String passwordConfirm,
                           Model model) {
        if (!password.equals(passwordConfirm)) {
            model.addAttribute("error", "Passwords do not match.");
            model.addAttribute("username", username);
            model.addAttribute("email", email);
            return "oauth2-register";
        }

        try {
            registrationService.register(username, email, password);
            model.addAttribute("title", "Registration Successful");
            model.addAttribute("message", "Your account has been created. Please check your email to verify your address.");
            model.addAttribute("linkUrl", "/oauth2/login");
            model.addAttribute("linkText", "Go to Login");
            return "oauth2-message";
        } catch (UserRegistrationService.RegistrationException e) {
            model.addAttribute("error", e.getMessage());
            model.addAttribute("username", username);
            model.addAttribute("email", email);
            return "oauth2-register";
        }
    }

    // ── Email Verification ──────────────────────────────────

    @GetMapping("/oauth2/verify-email")
    public String verifyEmail(@RequestParam("token") String token, Model model) {
        try {
            registrationService.verifyEmail(token);
            model.addAttribute("title", "Email Verified");
            model.addAttribute("message", "Your email has been verified successfully. You can now log in.");
            model.addAttribute("linkUrl", "/oauth2/login");
            model.addAttribute("linkText", "Go to Login");
        } catch (UserRegistrationService.RegistrationException e) {
            model.addAttribute("title", "Verification Failed");
            model.addAttribute("error", e.getMessage());
            model.addAttribute("linkUrl", "/oauth2/login");
            model.addAttribute("linkText", "Go to Login");
        }
        return "oauth2-message";
    }

    // ── Forgot Password ─────────────────────────────────────

    @GetMapping("/oauth2/forgot-password")
    public String forgotPasswordPage() {
        return "oauth2-forgot-password";
    }

    @PostMapping("/oauth2/forgot-password")
    public String forgotPassword(@RequestParam String email, Model model) {
        passwordResetService.requestReset(email);
        model.addAttribute("title", "Reset Link Sent");
        model.addAttribute("message", "If an account with that email exists, a password reset link has been sent.");
        model.addAttribute("linkUrl", "/oauth2/login");
        model.addAttribute("linkText", "Back to Login");
        return "oauth2-message";
    }

    // ── Reset Password ──────────────────────────────────────

    @GetMapping("/oauth2/reset-password")
    public String resetPasswordPage(@RequestParam("token") String token, Model model) {
        model.addAttribute("token", token);
        return "oauth2-reset-password";
    }

    @PostMapping("/oauth2/reset-password")
    public String resetPassword(@RequestParam String token,
                                @RequestParam("new_password") String newPassword,
                                @RequestParam("password_confirm") String passwordConfirm,
                                Model model) {
        if (!newPassword.equals(passwordConfirm)) {
            model.addAttribute("error", "Passwords do not match.");
            model.addAttribute("token", token);
            return "oauth2-reset-password";
        }

        try {
            passwordResetService.resetPassword(token, newPassword);
            model.addAttribute("title", "Password Reset Complete");
            model.addAttribute("message", "Your password has been reset successfully. You can now log in with your new password.");
            model.addAttribute("linkUrl", "/oauth2/login");
            model.addAttribute("linkText", "Go to Login");
            return "oauth2-message";
        } catch (PasswordResetService.PasswordResetException e) {
            model.addAttribute("error", e.getMessage());
            model.addAttribute("token", token);
            return "oauth2-reset-password";
        }
    }
}
