package com.spring.lica.domain.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.Instant;

@Entity
@Table(name = "identity_providers", uniqueConstraints = {
    @UniqueConstraint(columnNames = "alias")
})
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class IdentityProvider {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 50)
    private String alias;

    @Column(name = "provider_type", nullable = false, length = 20)
    private String providerType; // OIDC, SOCIAL

    @Column(name = "client_id", nullable = false, length = 255)
    private String clientId;

    @Column(name = "client_secret", length = 500)
    private String clientSecret;

    @Column(name = "authorization_url", length = 500)
    private String authorizationUrl;

    @Column(name = "token_url", length = 500)
    private String tokenUrl;

    @Column(name = "userinfo_url", length = 500)
    private String userinfoUrl;

    @Column(name = "jwks_url", length = 500)
    private String jwksUrl;

    @Column(length = 500)
    private String scopes;

    @Column(name = "claim_mappings", length = 2000)
    private String claimMappings; // JSON

    @Column(nullable = false)
    @Builder.Default
    private boolean enabled = true;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;
}
