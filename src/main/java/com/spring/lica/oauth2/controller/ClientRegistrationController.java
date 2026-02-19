package com.spring.lica.oauth2.controller;

import com.spring.lica.oauth2.service.ClientRegistrationService;
import com.spring.lica.oauth2.service.OAuthClientService;
import com.spring.lica.sso.SsoProperties;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequiredArgsConstructor
public class ClientRegistrationController {

    private final ClientRegistrationService clientRegistrationService;
    private final SsoProperties ssoProperties;

    @PostMapping("/oauth2/register")
    public ResponseEntity<Map<String, Object>> registerClient(@RequestBody Map<String, Object> metadata) {
        metadata.put("_issuer", ssoProperties.issuer());
        Map<String, Object> response = clientRegistrationService.registerClient(metadata);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @GetMapping("/oauth2/register/{clientId}")
    public Map<String, Object> getClient(@PathVariable String clientId, HttpServletRequest request) {
        String token = resolveRegistrationToken(request);
        return clientRegistrationService.getClient(clientId, token);
    }

    @PutMapping("/oauth2/register/{clientId}")
    public Map<String, Object> updateClient(@PathVariable String clientId,
                                             @RequestBody Map<String, Object> metadata,
                                             HttpServletRequest request) {
        String token = resolveRegistrationToken(request);
        return clientRegistrationService.updateClient(clientId, token, metadata);
    }

    @DeleteMapping("/oauth2/register/{clientId}")
    public ResponseEntity<Void> deleteClient(@PathVariable String clientId, HttpServletRequest request) {
        String token = resolveRegistrationToken(request);
        clientRegistrationService.deleteClient(clientId, token);
        return ResponseEntity.noContent().build();
    }

    private String resolveRegistrationToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        throw new OAuthClientService.OAuth2Exception("invalid_token", "Missing registration access token");
    }
}
