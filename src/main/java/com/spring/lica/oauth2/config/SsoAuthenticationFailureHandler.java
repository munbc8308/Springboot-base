package com.spring.lica.oauth2.config;

import com.spring.lica.security.AuditLogService;
import com.spring.lica.security.BruteForceProtectionService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class SsoAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    private final BruteForceProtectionService bruteForceProtectionService;
    private final AuditLogService auditLogService;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {

        String username = request.getParameter("username");
        String ip = getClientIp(request);
        String userAgent = request.getHeader("User-Agent");

        if (username != null) {
            bruteForceProtectionService.recordFailure(username, ip);
            auditLogService.logAuth("LOGIN_FAILURE", username, ip, userAgent, "FAILURE", exception.getMessage());
        }

        setDefaultFailureUrl("/oauth2/login?error");
        super.onAuthenticationFailure(request, response, exception);
    }

    private String getClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isBlank()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
