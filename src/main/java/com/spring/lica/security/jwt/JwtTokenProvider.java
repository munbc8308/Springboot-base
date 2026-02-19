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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

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

	/**
	 * Generate an OAuth 2.0 Access Token per RFC 9068.
	 */
	public String generateOAuth2AccessToken(String subject, String clientId, String scope, List<String> roles) {
		Date now = new Date();
		Date expiryDate = new Date(now.getTime() + accessTokenExpiration);

		return Jwts.builder()
			.header().keyId(kid).and()
			.issuer(issuer)
			.subject(subject)
			.claim("client_id", clientId)
			.claim("scope", scope)
			.claim("roles", roles)
			.id(UUID.randomUUID().toString())
			.issuedAt(now)
			.expiration(expiryDate)
			.signWith(privateKey)
			.compact();
	}

	/**
	 * Generate an OIDC ID Token.
	 */
	public String generateIdToken(String subject, String clientId, String nonce,
								  String accessToken, Map<String, Object> userClaims) {
		Date now = new Date();
		Date expiryDate = new Date(now.getTime() + accessTokenExpiration);

		var builder = Jwts.builder()
			.header().keyId(kid).and()
			.issuer(issuer)
			.subject(subject)
			.audience().add(clientId).and()
			.id(UUID.randomUUID().toString())
			.issuedAt(now)
			.expiration(expiryDate)
			.claim("auth_time", now.getTime() / 1000);

		if (nonce != null) {
			builder.claim("nonce", nonce);
		}

		if (accessToken != null) {
			builder.claim("at_hash", computeAtHash(accessToken));
		}

		for (Map.Entry<String, Object> entry : userClaims.entrySet()) {
			if (!"sub".equals(entry.getKey())) {
				builder.claim(entry.getKey(), entry.getValue());
			}
		}

		return builder.signWith(privateKey).compact();
	}

	private String computeAtHash(String accessToken) {
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] hash = digest.digest(accessToken.getBytes(StandardCharsets.US_ASCII));
			byte[] leftHalf = Arrays.copyOf(hash, hash.length / 2);
			return Base64.getUrlEncoder().withoutPadding().encodeToString(leftHalf);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("SHA-256 algorithm not available", e);
		}
	}

	/**
	 * Generate a Back-Channel Logout Token per OIDC Back-Channel Logout spec.
	 */
	public String generateLogoutToken(String sub, String aud, String sid) {
		Date now = new Date();

		Map<String, Object> events = Map.of(
			"http://schemas.openid.net/event/backchannel-logout", Map.of());

		return Jwts.builder()
			.header().keyId(kid).and()
			.issuer(issuer)
			.subject(sub)
			.audience().add(aud).and()
			.id(UUID.randomUUID().toString())
			.issuedAt(now)
			.claim("events", events)
			.claim("sid", sid)
			.signWith(privateKey)
			.compact();
	}

	public Authentication getAuthentication(String token) {
		Claims claims = extractClaims(token);

		String subject = claims.getSubject();

		@SuppressWarnings("unchecked")
		List<String> roles = claims.get("roles", List.class);

		List<SimpleGrantedAuthority> authorities = roles != null
			? roles.stream().map(SimpleGrantedAuthority::new).toList()
			: List.of();

		return new UsernamePasswordAuthenticationToken(subject, null, authorities);
	}

	public Claims extractClaims(String token) {
		return Jwts.parser()
			.verifyWith(publicKey)
			.build()
			.parseSignedClaims(token)
			.getPayload();
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
