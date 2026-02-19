package com.spring.lica.oauth2.config;

import com.spring.lica.oauth2.service.SsoSessionService;
import com.spring.lica.security.AuditLogService;
import com.spring.lica.security.BruteForceProtectionService;
import com.spring.lica.security.auth.SsoUserPrincipal;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Slf4j
@Component
public class SsoAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    private static final String MFA_PENDING_SESSION_KEY = "MFA_PENDING_USER_ID";

    private final SsoSessionService ssoSessionService;
    private final BruteForceProtectionService bruteForceProtectionService;
    private final AuditLogService auditLogService;

    public SsoAuthenticationSuccessHandler(SsoSessionService ssoSessionService,
                                           BruteForceProtectionService bruteForceProtectionService,
                                           AuditLogService auditLogService) {
        this.ssoSessionService = ssoSessionService;
        this.bruteForceProtectionService = bruteForceProtectionService;
        this.auditLogService = auditLogService;
        setDefaultTargetUrl("/oauth2/login");
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        if (authentication.getPrincipal() instanceof SsoUserPrincipal principal) {
            String ip = getClientIpAddressStatic(request);
            String userAgent = request.getHeader("User-Agent");

            // Clear brute force counters on success
            bruteForceProtectionService.recordSuccess(principal.getUsername());

            // Check if MFA is required
            if (principal.isMfaEnabled()) {
                request.getSession().setAttribute(MFA_PENDING_SESSION_KEY, principal.getUserId());
                request.getSession().setAttribute("MFA_PENDING_USERNAME", principal.getUsername());
                auditLogService.logAuth("LOGIN_MFA_REQUIRED", principal.getUsername(), ip, userAgent, "PENDING", "MFA verification required");
                log.info("MFA required for user {}, redirecting to MFA verification", principal.getUsername());
                response.sendRedirect(request.getContextPath() + "/oauth2/mfa");
                return;
            }

            // No MFA — create SSO session directly
            createSsoSession(request, response, principal);
            auditLogService.logAuth("LOGIN_SUCCESS", principal.getUsername(), ip, userAgent, "SUCCESS", null);
        }

        super.onAuthenticationSuccess(request, response, authentication);
    }

    private void createSsoSession(HttpServletRequest request, HttpServletResponse response,
                                   SsoUserPrincipal principal) {
        String ipAddress = getClientIpAddressStatic(request);
        String userAgent = request.getHeader("User-Agent");

        var ssoSession = ssoSessionService.createSession(principal.getUserId(), ipAddress, userAgent);
        response.addCookie(ssoSessionService.createSsoCookie(ssoSession.getSessionId()));

        log.info("SSO session created for user {} from {}", principal.getUsername(), ipAddress);
    }

    public static void createSsoSessionForMfa(HttpServletRequest request, HttpServletResponse response,
                                        Long userId, String username,
                                        SsoSessionService ssoSessionService) {
        String ipAddress = getClientIpAddressStatic(request);
        String userAgent = request.getHeader("User-Agent");

        var ssoSession = ssoSessionService.createSession(userId, ipAddress, userAgent);
        response.addCookie(ssoSessionService.createSsoCookie(ssoSession.getSessionId()));

        log.info("SSO session created after MFA for user {} from {}", username, ipAddress);
    }

    private static String getClientIpAddressStatic(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isBlank()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
