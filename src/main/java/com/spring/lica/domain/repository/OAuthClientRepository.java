package com.spring.lica.domain.repository;

import com.spring.lica.domain.entity.OAuthClient;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface OAuthClientRepository extends JpaRepository<OAuthClient, Long> {

    Optional<OAuthClient> findByClientId(String clientId);

    boolean existsByClientId(String clientId);
}
