package com.spring.lica.domain.repository;

import com.spring.lica.domain.entity.AuthorizationCode;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.Optional;

public interface AuthorizationCodeRepository extends JpaRepository<AuthorizationCode, Long> {

    Optional<AuthorizationCode> findByCode(String code);

    void deleteByExpiresAtBefore(Instant now);
}
