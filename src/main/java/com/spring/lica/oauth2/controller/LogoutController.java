package com.spring.lica.oauth2.controller;

import com.spring.lica.domain.entity.OAuthClient;
import com.spring.lica.domain.entity.SsoSession;
import com.spring.lica.domain.entity.SsoSessionClient;
import com.spring.lica.domain.repository.OAuthClientRepository;
import com.spring.lica.oauth2.service.LogoutService;
import com.spring.lica.oauth2.service.SsoSessionService;
import com.spring.lica.security.jwt.JwtTokenProvider;
import io.jsonwebtoken.Claims;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;
import java.util.Optional;

@Slf4j
@Controller
@RequiredArgsConstructor
public class LogoutController {

    private final SsoSessionService ssoSessionService;
    private final LogoutService logoutService;
    private final JwtTokenProvider jwtTokenProvider;
    private final OAuthClientRepository oAuthClientRepository;

    @GetMapping("/oauth2/logout")
    public String showLogoutConfirm(@RequestParam(value = "id_token_hint", required = false) String idTokenHint,
                                    @RequestParam(value = "post_logout_redirect_uri", required = false) String postLogoutRedirectUri,
                                    @RequestParam(value = "state", required = false) String state,
                                    HttpServletRequest request,
                                    Model model) {

        String ssoSessionId = ssoSessionService.extractSessionIdFromCookies(request.getCookies());
        Optional<SsoSession> ssoSessionOpt = ssoSessionService.validateSession(ssoSessionId);

        if (ssoSessionOpt.isEmpty()) {
            // No active session, redirect to login or post_logout_redirect_uri
            if (StringUtils.hasText(postLogoutRedirectUri)) {
                return buildPostLogoutRedirect(postLogoutRedirectUri, state);
            }
            return "redirect:/oauth2/login?logout";
        }

        SsoSession ssoSession = ssoSessionOpt.get();
        List<SsoSessionClient> clients = ssoSessionService.getSessionClients(ssoSession);

        // Resolve client names for display
        List<String> clientNames = clients.stream()
            .map(sc -> oAuthClientRepository.findByClientId(sc.getClientId())
                .map(OAuthClient::getClientName)
                .orElse(sc.getClientId()))
            .toList();

        model.addAttribute("clientNames", clientNames);
        model.addAttribute("idTokenHint", idTokenHint);
        model.addAttribute("postLogoutRedirectUri", postLogoutRedirectUri);
        model.addAttribute("state", state);

        return "oauth2-logout-confirm";
    }

    @PostMapping("/oauth2/logout")
    public String performLogout(@RequestParam(value = "id_token_hint", required = false) String idTokenHint,
                                @RequestParam(value = "post_logout_redirect_uri", required = false) String postLogoutRedirectUri,
                                @RequestParam(value = "state", required = false) String state,
                                @RequestParam("confirm") String confirm,
                                HttpServletRequest request,
                                HttpServletResponse response,
                                HttpSession httpSession) {

        if (!"yes".equals(confirm)) {
            return "redirect:/";
        }

        String ssoSessionId = ssoSessionService.extractSessionIdFromCookies(request.getCookies());

        // Determine subject from id_token_hint if available
        String sub = null;
        if (StringUtils.hasText(idTokenHint)) {
            try {
                Claims claims = jwtTokenProvider.extractClaims(idTokenHint);
                sub = claims.getSubject();
            } catch (Exception e) {
                log.warn("Failed to decode id_token_hint: {}", e.getMessage());
            }
        }

        // Perform SSO logout (revoke session + back-channel notifications)
        if (ssoSessionId != null) {
            logoutService.performLogout(ssoSessionId, sub);
        }

        // Clear SSO cookie
        ssoSessionService.clearSsoCookie(response);

        // Invalidate HTTP session
        httpSession.invalidate();

        log.info("User logged out (SSO session: {})", ssoSessionId);

        // Validate post_logout_redirect_uri against registered clients
        if (StringUtils.hasText(postLogoutRedirectUri) && isValidPostLogoutUri(postLogoutRedirectUri, idTokenHint)) {
            return buildPostLogoutRedirect(postLogoutRedirectUri, state);
        }

        return "redirect:/oauth2/login?logout";
    }

    private boolean isValidPostLogoutUri(String uri, String idTokenHint) {
        if (!StringUtils.hasText(idTokenHint)) {
            return false;
        }
        try {
            Claims claims = jwtTokenProvider.extractClaims(idTokenHint);
            var audiences = claims.getAudience();
            if (audiences == null || audiences.isEmpty()) return false;

            String clientId = audiences.iterator().next();
            return oAuthClientRepository.findByClientId(clientId)
                .map(client -> uri.equals(client.getPostLogoutRedirectUri()))
                .orElse(false);
        } catch (Exception e) {
            return false;
        }
    }

    private String buildPostLogoutRedirect(String uri, String state) {
        if (StringUtils.hasText(state)) {
            return "redirect:" + uri + "?state=" + state;
        }
        return "redirect:" + uri;
    }
}
