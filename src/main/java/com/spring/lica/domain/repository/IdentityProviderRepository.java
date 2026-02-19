package com.spring.lica.domain.repository;

import com.spring.lica.domain.entity.IdentityProvider;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface IdentityProviderRepository extends JpaRepository<IdentityProvider, Long> {

    Optional<IdentityProvider> findByAlias(String alias);

    List<IdentityProvider> findByEnabledTrue();
}
