package com.spring.lica.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class RateLimitFilter extends OncePerRequestFilter {

    private final RateLimitService rateLimitService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String path = request.getRequestURI();
        String ip = getClientIp(request);

        int maxRequests;
        long windowSeconds;
        String key;

        if ("/oauth2/token".equals(path)) {
            // Token endpoint: 60 requests per minute per IP
            maxRequests = 60;
            windowSeconds = 60;
            key = "token:" + ip;
        } else if ("/api/auth/register".equals(path)) {
            // Registration: 10 per hour per IP
            maxRequests = 10;
            windowSeconds = 3600;
            key = "register:" + ip;
        } else if ("/api/auth/forgot-password".equals(path)) {
            // Password reset: 5 per hour per IP
            maxRequests = 5;
            windowSeconds = 3600;
            key = "reset:" + ip;
        } else if ("/oauth2/login".equals(path) && "POST".equals(request.getMethod())) {
            // Login: 20 per minute per IP
            maxRequests = 20;
            windowSeconds = 60;
            key = "login:" + ip;
        } else {
            filterChain.doFilter(request, response);
            return;
        }

        RateLimitService.RateLimitResult result = rateLimitService.checkLimit(key, maxRequests, windowSeconds);

        response.setHeader("X-RateLimit-Limit", String.valueOf(result.limit()));
        response.setHeader("X-RateLimit-Remaining", String.valueOf(result.remaining()));
        response.setHeader("X-RateLimit-Reset", String.valueOf(result.resetEpoch()));

        if (!result.allowed()) {
            response.setStatus(429);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"too_many_requests\",\"error_description\":\"Rate limit exceeded\"}");
            return;
        }

        filterChain.doFilter(request, response);
    }

    private String getClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isBlank()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
