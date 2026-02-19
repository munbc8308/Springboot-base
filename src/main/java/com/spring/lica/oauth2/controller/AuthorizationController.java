package com.spring.lica.oauth2.controller;

import com.spring.lica.domain.entity.AuthorizationCode;
import com.spring.lica.domain.entity.IdentityProvider;
import com.spring.lica.domain.entity.OAuthClient;
import com.spring.lica.domain.entity.SsoSession;
import com.spring.lica.domain.repository.IdentityProviderRepository;
import com.spring.lica.oauth2.dto.AuthorizationRequest;
import com.spring.lica.oauth2.service.AuthorizationCodeService;
import com.spring.lica.oauth2.service.OAuthClientService;
import com.spring.lica.oauth2.service.SsoSessionService;
import com.spring.lica.security.ConsentService;
import com.spring.lica.security.auth.SsoUserPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.util.UriComponentsBuilder;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Slf4j
@Controller
@RequiredArgsConstructor
public class AuthorizationController {

    private static final String AUTH_REQUEST_SESSION_KEY = "OAUTH2_AUTH_REQUEST";

    private final OAuthClientService oAuthClientService;
    private final AuthorizationCodeService authorizationCodeService;
    private final SsoSessionService ssoSessionService;
    private final ConsentService consentService;
    private final IdentityProviderRepository identityProviderRepository;

    @GetMapping("/oauth2/login")
    public String loginPage(Model model) {
        List<IdentityProvider> idps = identityProviderRepository.findByEnabledTrue();
        model.addAttribute("identityProviders", idps);
        return "oauth2-login";
    }

    @GetMapping("/oauth2/authorize")
    public String authorize(@RequestParam("response_type") String responseType,
                            @RequestParam("client_id") String clientId,
                            @RequestParam(value = "redirect_uri", required = false) String redirectUri,
                            @RequestParam(value = "scope", required = false) String scope,
                            @RequestParam(value = "state", required = false) String state,
                            @RequestParam(value = "code_challenge", required = false) String codeChallenge,
                            @RequestParam(value = "code_challenge_method", required = false) String codeChallengeMethod,
                            @RequestParam(value = "nonce", required = false) String nonce,
                            @RequestParam(value = "prompt", required = false) String prompt,
                            @RequestParam(value = "max_age", required = false) Long maxAge,
                            @AuthenticationPrincipal SsoUserPrincipal principal,
                            HttpServletRequest request,
                            HttpServletResponse response,
                            HttpSession session,
                            Model model) {

        // Validate response_type
        if (!"code".equals(responseType)) {
            return redirectWithError(redirectUri, state, "unsupported_response_type",
                "Only 'code' response_type is supported");
        }

        // Validate client
        OAuthClient client;
        try {
            client = oAuthClientService.findByClientId(clientId);
            oAuthClientService.validateRedirectUri(client, redirectUri);
            oAuthClientService.validateGrantType(client, "authorization_code");
            if (StringUtils.hasText(scope)) {
                oAuthClientService.validateScope(client, scope);
            }
        } catch (OAuthClientService.OAuth2Exception e) {
            if (StringUtils.hasText(redirectUri)) {
                return redirectWithError(redirectUri, state, e.getError(), e.getErrorDescription());
            }
            model.addAttribute("error", e.getErrorDescription());
            return "oauth2-login";
        }

        String resolvedRedirectUri = oAuthClientService.resolveRedirectUri(client, redirectUri);
        String resolvedScope = StringUtils.hasText(scope) ? scope : client.getScopes();

        // SSO Session validation
        String ssoSessionId = ssoSessionService.extractSessionIdFromCookies(request.getCookies());
        Optional<SsoSession> ssoSessionOpt = ssoSessionService.validateSession(ssoSessionId);

        // Handle prompt=none: must have valid SSO session, no UI interaction
        if ("none".equals(prompt)) {
            if (ssoSessionOpt.isEmpty() || principal == null) {
                return redirectWithError(resolvedRedirectUri, state, "login_required",
                    "User is not authenticated and prompt=none was requested");
            }
        }

        // Handle prompt=login: force re-authentication even if SSO session exists
        if ("login".equals(prompt)) {
            if (ssoSessionOpt.isPresent()) {
                // Invalidate current SSO session to force re-login
                ssoSessionService.revokeSession(ssoSessionId);
                ssoSessionService.clearSsoCookie(response);
            }
            // Store request params so we can resume after re-authentication
            AuthorizationRequest authRequest = new AuthorizationRequest(
                responseType, clientId, resolvedRedirectUri, resolvedScope,
                state, codeChallenge, codeChallengeMethod, nonce, null, maxAge);
            session.setAttribute(AUTH_REQUEST_SESSION_KEY, authRequest);
            // Redirect to login page — Spring Security will handle authentication
            return "redirect:/oauth2/login";
        }

        // Handle max_age: if SSO session auth_time + max_age < now, force re-auth
        if (maxAge != null && ssoSessionOpt.isPresent()) {
            SsoSession ssoSession = ssoSessionOpt.get();
            Instant maxAgeDeadline = ssoSession.getAuthTime().plusSeconds(maxAge);
            if (Instant.now().isAfter(maxAgeDeadline)) {
                log.debug("max_age exceeded, forcing re-authentication");
                ssoSessionService.revokeSession(ssoSessionId);
                ssoSessionService.clearSsoCookie(response);
                AuthorizationRequest authRequest = new AuthorizationRequest(
                    responseType, clientId, resolvedRedirectUri, resolvedScope,
                    state, codeChallenge, codeChallengeMethod, nonce, null, maxAge);
                session.setAttribute(AUTH_REQUEST_SESSION_KEY, authRequest);
                return "redirect:/oauth2/login";
            }
        }

        // Touch SSO session and add client
        if (ssoSessionOpt.isPresent()) {
            SsoSession ssoSession = ssoSessionOpt.get();
            ssoSessionService.touchSession(ssoSession);
            ssoSessionService.addClientToSession(ssoSession, clientId);
        }

        // Store authorization request in session
        AuthorizationRequest authRequest = new AuthorizationRequest(
            responseType, clientId, resolvedRedirectUri, resolvedScope,
            state, codeChallenge, codeChallengeMethod, nonce, prompt, maxAge);
        session.setAttribute(AUTH_REQUEST_SESSION_KEY, authRequest);

        // Skip consent for 1st-party clients or if existing valid consent (unless prompt=consent)
        boolean skipConsent = false;
        if (!"consent".equals(prompt) && principal != null) {
            if (client.isFirstParty()) {
                skipConsent = true;
            } else if (consentService.hasValidConsent(principal.getUserId(), clientId, resolvedScope)) {
                skipConsent = true;
            }
        }

        if (skipConsent) {
            // Auto-approve: generate authorization code directly
            return autoApproveConsent(principal, authRequest, session);
        }

        // Show consent screen
        model.addAttribute("client", client);
        model.addAttribute("scopes", resolvedScope.split("\\s+"));
        model.addAttribute("authRequest", authRequest);
        model.addAttribute("principal", principal);
        return "oauth2-consent";
    }

    @PostMapping("/oauth2/authorize/consent")
    public String handleConsent(@RequestParam("consent") String consent,
                                @AuthenticationPrincipal SsoUserPrincipal principal,
                                HttpSession session) {

        AuthorizationRequest authRequest = (AuthorizationRequest) session.getAttribute(AUTH_REQUEST_SESSION_KEY);
        session.removeAttribute(AUTH_REQUEST_SESSION_KEY);

        if (authRequest == null) {
            return "redirect:/oauth2/login?error";
        }

        // User denied
        if (!"approve".equals(consent)) {
            return redirectWithError(authRequest.redirectUri(), authRequest.state(),
                "access_denied", "User denied the request");
        }

        // Store consent
        consentService.grantConsent(principal.getUserId(), authRequest.clientId(), authRequest.scope());

        // Generate authorization code
        AuthorizationCode code = authorizationCodeService.createCode(
            authRequest.clientId(),
            principal.getUserId(),
            authRequest.redirectUri(),
            authRequest.scope(),
            authRequest.codeChallenge(),
            authRequest.codeChallengeMethod(),
            authRequest.state(),
            authRequest.nonce());

        // Redirect with code
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(authRequest.redirectUri())
            .queryParam("code", code.getCode());
        if (StringUtils.hasText(authRequest.state())) {
            builder.queryParam("state", authRequest.state());
        }

        return "redirect:" + builder.toUriString();
    }

    private String autoApproveConsent(SsoUserPrincipal principal, AuthorizationRequest authRequest, HttpSession session) {
        session.removeAttribute(AUTH_REQUEST_SESSION_KEY);

        AuthorizationCode code = authorizationCodeService.createCode(
            authRequest.clientId(),
            principal.getUserId(),
            authRequest.redirectUri(),
            authRequest.scope(),
            authRequest.codeChallenge(),
            authRequest.codeChallengeMethod(),
            authRequest.state(),
            authRequest.nonce());

        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(authRequest.redirectUri())
            .queryParam("code", code.getCode());
        if (StringUtils.hasText(authRequest.state())) {
            builder.queryParam("state", authRequest.state());
        }
        return "redirect:" + builder.toUriString();
    }

    private String redirectWithError(String redirectUri, String state, String error, String description) {
        if (!StringUtils.hasText(redirectUri)) {
            return "redirect:/oauth2/login?error=" + error;
        }

        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(redirectUri)
            .queryParam("error", error)
            .queryParam("error_description", description);
        if (StringUtils.hasText(state)) {
            builder.queryParam("state", state);
        }
        return "redirect:" + builder.toUriString();
    }
}
