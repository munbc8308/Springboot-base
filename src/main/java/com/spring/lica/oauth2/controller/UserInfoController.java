package com.spring.lica.oauth2.controller;

import com.spring.lica.domain.entity.User;
import com.spring.lica.domain.repository.UserRepository;
import com.spring.lica.oauth2.service.OAuthClientService;
import com.spring.lica.oauth2.service.OidcClaimService;
import com.spring.lica.security.jwt.JwtTokenProvider;
import io.jsonwebtoken.Claims;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequiredArgsConstructor
public class UserInfoController {

    private final JwtTokenProvider jwtTokenProvider;
    private final UserRepository userRepository;
    private final OidcClaimService oidcClaimService;

    @GetMapping("/userinfo")
    public Map<String, Object> getUserInfoGet(HttpServletRequest request) {
        return getUserInfo(request);
    }

    @PostMapping("/userinfo")
    public Map<String, Object> getUserInfoPost(HttpServletRequest request) {
        return getUserInfo(request);
    }

    private Map<String, Object> getUserInfo(HttpServletRequest request) {
        String token = resolveToken(request);
        if (token == null || !jwtTokenProvider.validateToken(token)) {
            throw new OAuthClientService.OAuth2Exception("invalid_token", "Invalid or missing access token");
        }

        Claims claims = jwtTokenProvider.extractClaims(token);
        String username = claims.getSubject();
        String scope = claims.get("scope", String.class);

        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new OAuthClientService.OAuth2Exception("invalid_token", "User not found"));

        return oidcClaimService.resolveClaims(user, scope);
    }

    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
