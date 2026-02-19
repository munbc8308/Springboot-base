package com.spring.lica.oauth2.controller;

import com.spring.lica.domain.entity.IdentityProvider;
import com.spring.lica.domain.entity.User;
import com.spring.lica.domain.repository.IdentityProviderRepository;
import com.spring.lica.oauth2.service.FederationService;
import com.spring.lica.oauth2.service.SsoSessionService;
import com.spring.lica.sso.SsoProperties;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.Map;
import java.util.UUID;

@Slf4j
@Controller
@RequestMapping("/oauth2/federation")
@RequiredArgsConstructor
public class FederationController {

    private final IdentityProviderRepository identityProviderRepository;
    private final FederationService federationService;
    private final SsoSessionService ssoSessionService;
    private final SsoProperties ssoProperties;

    @GetMapping("/{alias}")
    public String redirectToIdp(@PathVariable String alias,
                                @RequestParam(required = false) String redirect_uri,
                                HttpServletRequest request,
                                HttpServletResponse response) {
        IdentityProvider idp = identityProviderRepository.findByAlias(alias)
            .filter(IdentityProvider::isEnabled)
            .orElse(null);

        if (idp == null) {
            return "redirect:/oauth2/login?error=unknown_provider";
        }

        String state = UUID.randomUUID().toString();
        String nonce = UUID.randomUUID().toString();
        String callbackUri = ssoProperties.issuer() + "/oauth2/federation/" + alias + "/callback";

        // Store state and original redirect_uri in session
        request.getSession().setAttribute("federation_state", state);
        request.getSession().setAttribute("federation_nonce", nonce);
        if (redirect_uri != null) {
            request.getSession().setAttribute("federation_redirect_uri", redirect_uri);
        }

        String authUrl = federationService.buildAuthorizationUrl(idp, state, nonce, callbackUri);
        return "redirect:" + authUrl;
    }

    @GetMapping("/{alias}/callback")
    public String handleCallback(@PathVariable String alias,
                                  @RequestParam(required = false) String code,
                                  @RequestParam(required = false) String state,
                                  @RequestParam(required = false) String error,
                                  HttpServletRequest request,
                                  HttpServletResponse response) {
        if (error != null) {
            log.warn("Federation callback error from {}: {}", alias, error);
            return "redirect:/oauth2/login?error=federation_denied";
        }

        // Validate state
        String expectedState = (String) request.getSession().getAttribute("federation_state");
        if (expectedState == null || !expectedState.equals(state)) {
            log.warn("Federation state mismatch for {}", alias);
            return "redirect:/oauth2/login?error=invalid_state";
        }

        IdentityProvider idp = identityProviderRepository.findByAlias(alias)
            .filter(IdentityProvider::isEnabled)
            .orElse(null);

        if (idp == null) {
            return "redirect:/oauth2/login?error=unknown_provider";
        }

        try {
            String callbackUri = ssoProperties.issuer() + "/oauth2/federation/" + alias + "/callback";

            // Exchange code for tokens
            Map<String, Object> tokens = federationService.exchangeCodeForTokens(idp, code, callbackUri);
            String accessToken = (String) tokens.get("access_token");

            // Fetch user info
            Map<String, Object> userInfo = federationService.fetchUserInfo(idp, accessToken);

            // Find or create user
            User user = federationService.findOrCreateUser(idp, userInfo);

            // Create SSO session
            var ssoSession = ssoSessionService.createSession(
                user.getId(),
                request.getRemoteAddr(),
                request.getHeader("User-Agent")
            );

            // Set SSO cookie
            Cookie cookie = new Cookie(ssoProperties.session().cookieName(), ssoSession.getSessionId());
            cookie.setPath("/");
            cookie.setHttpOnly(true);
            cookie.setMaxAge((int) (ssoProperties.session().absoluteTimeout() / 1000));
            response.addCookie(cookie);

            // Clean up session attributes
            request.getSession().removeAttribute("federation_state");
            request.getSession().removeAttribute("federation_nonce");

            // Redirect to original destination or default
            String redirectUri = (String) request.getSession().getAttribute("federation_redirect_uri");
            request.getSession().removeAttribute("federation_redirect_uri");

            if (redirectUri != null) {
                return "redirect:" + redirectUri;
            }
            return "redirect:/";

        } catch (Exception e) {
            log.error("Federation callback failed for {}: {}", alias, e.getMessage(), e);
            return "redirect:/oauth2/login?error=federation_failed";
        }
    }
}
