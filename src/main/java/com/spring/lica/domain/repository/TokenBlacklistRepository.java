package com.spring.lica.domain.repository;

import com.spring.lica.domain.entity.TokenBlacklist;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;

public interface TokenBlacklistRepository extends JpaRepository<TokenBlacklist, Long> {

    boolean existsByJti(String jti);

    void deleteByExpiresAtBefore(Instant now);
}
