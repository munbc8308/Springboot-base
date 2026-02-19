package com.spring.lica.domain.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Entity
@Table(name = "sso_session_clients", uniqueConstraints = {
    @UniqueConstraint(columnNames = {"session_id", "client_id"})
})
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SsoSessionClient {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "session_id", nullable = false)
    private SsoSession session;

    @Column(name = "client_id", nullable = false, length = 100)
    private String clientId;

    @Column(name = "joined_at", nullable = false)
    private Instant joinedAt;
}
