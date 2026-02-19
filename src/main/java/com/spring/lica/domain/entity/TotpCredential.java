package com.spring.lica.domain.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.Instant;

@Entity
@Table(name = "totp_credentials")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TotpCredential {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(nullable = false, length = 500)
    private String secret;

    @Column(nullable = false, length = 20)
    @Builder.Default
    private String algorithm = "HmacSHA1";

    @Column(nullable = false)
    @Builder.Default
    private int digits = 6;

    @Column(name = "time_period", nullable = false)
    @Builder.Default
    private int period = 30;

    @Column(nullable = false)
    @Builder.Default
    private boolean verified = false;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;
}
