package com.spring.lica.oauth2.config;

import com.spring.lica.security.RateLimitFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@RequiredArgsConstructor
public class OAuth2SecurityConfig {

	private final SsoAuthenticationSuccessHandler ssoAuthenticationSuccessHandler;
	private final SsoAuthenticationFailureHandler ssoAuthenticationFailureHandler;
	private final RateLimitFilter rateLimitFilter;

	@Bean
	@Order(2)
	public SecurityFilterChain oauth2FilterChain(HttpSecurity http) throws Exception {
		http
			.securityMatcher("/oauth2/**", "/.well-known/**")
			.cors(cors -> {})
			.addFilterBefore(rateLimitFilter, UsernamePasswordAuthenticationFilter.class)
			.authorizeHttpRequests(auth -> auth
				.requestMatchers("/oauth2/token").permitAll()
				.requestMatchers("/oauth2/revoke").permitAll()
				.requestMatchers("/oauth2/introspect").permitAll()
				.requestMatchers("/oauth2/jwks").permitAll()
				.requestMatchers("/.well-known/**").permitAll()
				.requestMatchers("/oauth2/login").permitAll()
				.requestMatchers("/oauth2/register").permitAll()
				.requestMatchers("/oauth2/logout").permitAll()
				.requestMatchers("/oauth2/mfa").permitAll()
				.requestMatchers("/oauth2/federation/**").permitAll()
				.requestMatchers("/oauth2/authorize").authenticated()
				.requestMatchers("/oauth2/authorize/consent").authenticated()
				.anyRequest().authenticated()
			)
			.formLogin(form -> form
				.loginPage("/oauth2/login")
				.loginProcessingUrl("/oauth2/login")
				.successHandler(ssoAuthenticationSuccessHandler)
				.failureHandler(ssoAuthenticationFailureHandler)
				.permitAll()
			)
			.logout(logout -> logout
				.logoutUrl("/oauth2/logout/session")
				.logoutSuccessUrl("/oauth2/login?logout")
			)
			.sessionManagement(session -> session
				.sessionFixation().newSession()
			);

		return http.build();
	}
}
