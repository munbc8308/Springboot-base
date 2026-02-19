package com.spring.lica.admin;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableConfigurationProperties(AdminProperties.class)
public class AdminSecurityConfig {

	@Bean
	@Order(1)
	public SecurityFilterChain adminFilterChain(HttpSecurity http, AdminProperties props,
	                                             PasswordEncoder passwordEncoder) throws Exception {
		InMemoryUserDetailsManager adminUds = adminUserDetailsService(props, passwordEncoder);

		DaoAuthenticationProvider adminAuthProvider = new DaoAuthenticationProvider();
		adminAuthProvider.setUserDetailsService(adminUds);
		adminAuthProvider.setPasswordEncoder(passwordEncoder);
		AuthenticationManager adminAuthManager = new ProviderManager(adminAuthProvider);

		http
			.securityMatcher("/admin/**", "/login", "/css/**", "/js/**", "/actuator/**")
			.authenticationManager(adminAuthManager)
			.authorizeHttpRequests(auth -> auth
				.requestMatchers("/login", "/css/**", "/js/**").permitAll()
				.requestMatchers("/actuator/health").permitAll()
				.requestMatchers("/actuator/**").hasRole("ADMIN")
				.requestMatchers("/admin/api/**").hasRole("ADMIN")
				.requestMatchers("/admin/**").hasRole("ADMIN")
			)
			.headers(headers -> headers
				.frameOptions(frame -> frame.sameOrigin())
			)
			.formLogin(form -> form
				.loginPage("/login")
				.defaultSuccessUrl("/admin/console", true)
				.permitAll()
			)
			.logout(logout -> logout
				.logoutUrl("/admin/logout")
				.logoutSuccessUrl("/login?logout")
			);
		return http.build();
	}

	@Bean
	public InMemoryUserDetailsManager adminUserDetailsService(AdminProperties props, PasswordEncoder passwordEncoder) {
		UserDetails admin = User.builder()
			.username(props.getUsername())
			.password(passwordEncoder.encode(props.getPassword()))
			.roles("ADMIN")
			.build();
		return new InMemoryUserDetailsManager(admin);
	}

}
