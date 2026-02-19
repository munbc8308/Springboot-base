package com.spring.lica.oauth2.controller;

import com.spring.lica.domain.entity.OAuthClient;
import com.spring.lica.oauth2.dto.OAuth2ErrorResponse;
import com.spring.lica.oauth2.dto.TokenRequest;
import com.spring.lica.oauth2.dto.TokenResponse;
import com.spring.lica.oauth2.service.OAuthClientService;
import com.spring.lica.oauth2.service.OAuth2TokenService;
import com.spring.lica.oauth2.service.TokenRevocationService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@Slf4j
@RestController
@RequiredArgsConstructor
public class TokenController {

    private final OAuth2TokenService oAuth2TokenService;
    private final OAuthClientService oAuthClientService;
    private final TokenRevocationService tokenRevocationService;

    @PostMapping(value = "/oauth2/token", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<?> token(
            @RequestParam("grant_type") String grantType,
            @RequestParam(value = "code", required = false) String code,
            @RequestParam(value = "redirect_uri", required = false) String redirectUri,
            @RequestParam(value = "client_id", required = false) String clientId,
            @RequestParam(value = "client_secret", required = false) String clientSecret,
            @RequestParam(value = "code_verifier", required = false) String codeVerifier,
            @RequestParam(value = "refresh_token", required = false) String refreshToken,
            @RequestParam(value = "scope", required = false) String scope,
            HttpServletRequest request) {

        try {
            TokenRequest tokenRequest = new TokenRequest(
                grantType, code, redirectUri, clientId, clientSecret,
                codeVerifier, refreshToken, scope);

            TokenResponse response = oAuth2TokenService.handleToken(request, tokenRequest);
            return ResponseEntity.ok(response);
        } catch (OAuthClientService.OAuth2Exception e) {
            log.debug("Token request failed: {} - {}", e.getError(), e.getErrorDescription());
            return ResponseEntity.badRequest()
                .body(new OAuth2ErrorResponse(e.getError(), e.getErrorDescription()));
        }
    }

    @PostMapping(value = "/oauth2/revoke", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<Void> revoke(
            @RequestParam("token") String token,
            @RequestParam(value = "token_type_hint", required = false) String tokenTypeHint,
            @RequestParam(value = "client_id", required = false) String clientId,
            @RequestParam(value = "client_secret", required = false) String clientSecret,
            HttpServletRequest request) {

        try {
            OAuthClient client = oAuthClientService.authenticateClient(request, clientId, clientSecret);
            tokenRevocationService.revokeToken(token, tokenTypeHint, client);
            return ResponseEntity.ok().build();
        } catch (OAuthClientService.OAuth2Exception e) {
            // Per RFC 7009: return 200 even for invalid tokens to not leak info
            log.debug("Revocation auth failed: {}", e.getErrorDescription());
            return ResponseEntity.ok().build();
        }
    }

    @PostMapping(value = "/oauth2/introspect", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<?> introspect(
            @RequestParam("token") String token,
            @RequestParam(value = "token_type_hint", required = false) String tokenTypeHint,
            @RequestParam(value = "client_id", required = false) String clientId,
            @RequestParam(value = "client_secret", required = false) String clientSecret,
            HttpServletRequest request) {

        try {
            OAuthClient client = oAuthClientService.authenticateClient(request, clientId, clientSecret);
            Map<String, Object> result = tokenRevocationService.introspectToken(token, tokenTypeHint, client);
            return ResponseEntity.ok(result);
        } catch (OAuthClientService.OAuth2Exception e) {
            return ResponseEntity.status(401)
                .body(new OAuth2ErrorResponse("invalid_client", e.getErrorDescription()));
        }
    }
}
