package com.spring.lica.security.jwt;

import com.spring.lica.security.jwk.RsaKeyProvider;
import com.spring.lica.sso.SsoProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.List;
import java.util.UUID;

@Component
public class JwtTokenProvider {

	private final RSAPrivateKey privateKey;
	private final RSAPublicKey publicKey;
	private final String kid;
	private final String issuer;
	private final long accessTokenExpiration;

	public JwtTokenProvider(RsaKeyProvider rsaKeyProvider, SsoProperties ssoProperties) {
		this.privateKey = rsaKeyProvider.getPrivateKey();
		this.publicKey = rsaKeyProvider.getPublicKey();
		this.kid = rsaKeyProvider.getKid();
		this.issuer = ssoProperties.issuer();
		this.accessTokenExpiration = ssoProperties.token().accessTokenExpiration();
	}

	public String generateToken(String subject, List<String> roles) {
		Date now = new Date();
		Date expiryDate = new Date(now.getTime() + accessTokenExpiration);

		return Jwts.builder()
			.header().keyId(kid).and()
			.issuer(issuer)
			.subject(subject)
			.claim("roles", roles)
			.id(UUID.randomUUID().toString())
			.issuedAt(now)
			.expiration(expiryDate)
			.signWith(privateKey)
			.compact();
	}

	public Authentication getAuthentication(String token) {
		Claims claims = Jwts.parser()
			.verifyWith(publicKey)
			.build()
			.parseSignedClaims(token)
			.getPayload();

		String subject = claims.getSubject();

		@SuppressWarnings("unchecked")
		List<String> roles = claims.get("roles", List.class);

		List<SimpleGrantedAuthority> authorities = roles.stream()
			.map(SimpleGrantedAuthority::new)
			.toList();

		return new UsernamePasswordAuthenticationToken(subject, null, authorities);
	}

	public boolean validateToken(String token) {
		try {
			Jwts.parser()
				.verifyWith(publicKey)
				.build()
				.parseSignedClaims(token);
			return true;
		} catch (JwtException | IllegalArgumentException e) {
			return false;
		}
	}
}
