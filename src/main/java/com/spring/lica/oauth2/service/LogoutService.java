package com.spring.lica.oauth2.service;

import com.spring.lica.domain.entity.OAuthClient;
import com.spring.lica.domain.entity.SsoSession;
import com.spring.lica.domain.entity.SsoSessionClient;
import com.spring.lica.domain.repository.OAuthClientRepository;
import com.spring.lica.security.jwt.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;

import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class LogoutService {

    private final SsoSessionService ssoSessionService;
    private final OAuthClientRepository oAuthClientRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final RestTemplate restTemplate = new RestTemplate();

    public void performLogout(String sessionId, String sub) {
        ssoSessionService.validateSession(sessionId).ifPresent(session -> {
            // Get participating clients before revoking
            List<SsoSessionClient> sessionClients = ssoSessionService.getSessionClients(session);

            // Send back-channel logout to each participating client
            for (SsoSessionClient sc : sessionClients) {
                oAuthClientRepository.findByClientId(sc.getClientId()).ifPresent(client -> {
                    if (StringUtils.hasText(client.getBackchannelLogoutUri())) {
                        sendBackChannelLogout(client, session, sub);
                    }
                });
            }

            // Revoke the SSO session
            ssoSessionService.revokeSession(sessionId);
        });
    }

    private void sendBackChannelLogout(OAuthClient client, SsoSession session, String sub) {
        try {
            String logoutToken = jwtTokenProvider.generateLogoutToken(
                sub, client.getClientId(), session.getSessionId());

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("logout_token", logoutToken);

            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);
            restTemplate.postForEntity(client.getBackchannelLogoutUri(), request, String.class);

            log.info("Back-channel logout sent to client {} at {}", client.getClientId(), client.getBackchannelLogoutUri());
        } catch (Exception e) {
            log.warn("Failed to send back-channel logout to client {}: {}", client.getClientId(), e.getMessage());
        }
    }
}
