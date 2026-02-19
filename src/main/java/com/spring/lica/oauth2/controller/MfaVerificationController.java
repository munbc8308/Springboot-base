package com.spring.lica.oauth2.controller;

import com.spring.lica.auth.RecoveryCodeService;
import com.spring.lica.auth.TotpService;
import com.spring.lica.oauth2.config.SsoAuthenticationSuccessHandler;
import com.spring.lica.oauth2.service.SsoSessionService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Slf4j
@Controller
@RequiredArgsConstructor
public class MfaVerificationController {

    private static final String MFA_PENDING_SESSION_KEY = "MFA_PENDING_USER_ID";

    private final TotpService totpService;
    private final RecoveryCodeService recoveryCodeService;
    private final SsoSessionService ssoSessionService;

    @GetMapping("/oauth2/mfa")
    public String showMfaPage(HttpSession session, Model model) {
        Long userId = (Long) session.getAttribute(MFA_PENDING_SESSION_KEY);
        if (userId == null) {
            return "redirect:/oauth2/login";
        }

        String username = (String) session.getAttribute("MFA_PENDING_USERNAME");
        model.addAttribute("username", username);
        return "oauth2-mfa";
    }

    @PostMapping("/oauth2/mfa")
    public String verifyMfa(@RequestParam("code") String code,
                            @RequestParam(value = "type", defaultValue = "totp") String type,
                            HttpServletRequest request,
                            HttpServletResponse response,
                            HttpSession session,
                            Model model) {

        Long userId = (Long) session.getAttribute(MFA_PENDING_SESSION_KEY);
        String username = (String) session.getAttribute("MFA_PENDING_USERNAME");

        if (userId == null) {
            return "redirect:/oauth2/login";
        }

        boolean valid;
        if ("recovery".equals(type)) {
            valid = recoveryCodeService.verifyCode(userId, code);
        } else {
            valid = totpService.validateTotp(userId, code);
        }

        if (!valid) {
            model.addAttribute("username", username);
            model.addAttribute("error", "Invalid code. Please try again.");
            return "oauth2-mfa";
        }

        // MFA verified — clear pending state
        session.removeAttribute(MFA_PENDING_SESSION_KEY);
        session.removeAttribute("MFA_PENDING_USERNAME");

        // Create SSO session
        SsoAuthenticationSuccessHandler.createSsoSessionForMfa(
            request, response, userId, username, ssoSessionService);

        log.info("MFA verified for user {}", username);

        // Redirect to original saved request or default
        SavedRequest savedRequest = new HttpSessionRequestCache().getRequest(request, response);
        if (savedRequest != null) {
            return "redirect:" + savedRequest.getRedirectUrl();
        }

        return "redirect:/oauth2/login?mfa_success";
    }
}
