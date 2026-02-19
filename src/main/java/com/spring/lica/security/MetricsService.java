package com.spring.lica.security;

import com.spring.lica.domain.repository.SsoSessionRepository;
import com.spring.lica.domain.repository.TotpCredentialRepository;
import com.spring.lica.domain.repository.UserRepository;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@ConditionalOnProperty(name = "app.module.actuator.enabled", havingValue = "true")
public class MetricsService {

    private final Counter tokenIssuedCounter;
    private final Counter loginSuccessCounter;
    private final Counter loginFailureCounter;

    public MetricsService(MeterRegistry meterRegistry,
                          SsoSessionRepository ssoSessionRepository,
                          TotpCredentialRepository totpCredentialRepository,
                          UserRepository userRepository) {

        // Gauge: active sessions
        Gauge.builder("sso_active_sessions", ssoSessionRepository,
                repo -> repo.findAll().stream().filter(s -> !s.isRevoked()).count())
            .description("Number of active SSO sessions")
            .register(meterRegistry);

        // Counter: tokens issued
        this.tokenIssuedCounter = Counter.builder("sso_token_issued_total")
            .description("Total number of tokens issued")
            .register(meterRegistry);

        // Counter: login success/failure
        this.loginSuccessCounter = Counter.builder("sso_login_success_total")
            .description("Total number of successful logins")
            .register(meterRegistry);

        this.loginFailureCounter = Counter.builder("sso_login_failure_total")
            .description("Total number of failed logins")
            .register(meterRegistry);

        // Gauge: MFA adoption rate
        Gauge.builder("sso_mfa_adoption_rate", () -> {
                long total = userRepository.count();
                if (total == 0) return 0.0;
                long mfaEnabled = totpCredentialRepository.count();
                return (double) mfaEnabled / total;
            })
            .description("MFA adoption rate among users")
            .register(meterRegistry);

        log.info("SSO custom metrics registered");
    }

    public void recordTokenIssued() {
        tokenIssuedCounter.increment();
    }

    public void recordLoginSuccess() {
        loginSuccessCounter.increment();
    }

    public void recordLoginFailure() {
        loginFailureCounter.increment();
    }
}
