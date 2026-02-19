package com.spring.lica.domain.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "oauth_clients", uniqueConstraints = {
    @UniqueConstraint(columnNames = "client_id")
})
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OAuthClient {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "client_id", nullable = false, unique = true, length = 100)
    private String clientId;

    @Column(name = "client_secret_hash", length = 255)
    private String clientSecretHash;

    @Column(name = "client_name", nullable = false, length = 200)
    private String clientName;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "oauth_client_redirect_uris",
        joinColumns = @JoinColumn(name = "oauth_client_id"))
    @Column(name = "redirect_uri", nullable = false, length = 2000)
    @Builder.Default
    private Set<String> redirectUris = new HashSet<>();

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "oauth_client_grant_types",
        joinColumns = @JoinColumn(name = "oauth_client_id"))
    @Column(name = "grant_type", nullable = false, length = 50)
    @Builder.Default
    private Set<String> grantTypes = new HashSet<>();

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "oauth_client_response_types",
        joinColumns = @JoinColumn(name = "oauth_client_id"))
    @Column(name = "response_type", nullable = false, length = 50)
    @Builder.Default
    private Set<String> responseTypes = new HashSet<>();

    @Column(nullable = false, length = 1000)
    @Builder.Default
    private String scopes = "";

    @Column(name = "token_endpoint_auth_method", nullable = false, length = 50)
    @Builder.Default
    private String tokenEndpointAuthMethod = "client_secret_basic";

    @Enumerated(EnumType.STRING)
    @Column(name = "client_type", nullable = false, length = 20)
    @Builder.Default
    private ClientType clientType = ClientType.CONFIDENTIAL;

    @Column(name = "logo_uri", length = 2000)
    private String logoUri;

    @Column(name = "policy_uri", length = 2000)
    private String policyUri;

    @Column(name = "tos_uri", length = 2000)
    private String tosUri;

    @Column(name = "jwks_uri", length = 2000)
    private String jwksUri;

    @Column(name = "registration_access_token", length = 2000)
    private String registrationAccessToken;

    @Column(name = "backchannel_logout_uri", length = 2000)
    private String backchannelLogoutUri;

    @Column(name = "frontchannel_logout_uri", length = 2000)
    private String frontchannelLogoutUri;

    @Column(name = "post_logout_redirect_uri", length = 2000)
    private String postLogoutRedirectUri;

    @Column(name = "first_party", nullable = false)
    @Builder.Default
    private boolean firstParty = false;

    @Column(nullable = false)
    @Builder.Default
    private boolean enabled = true;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;
}
