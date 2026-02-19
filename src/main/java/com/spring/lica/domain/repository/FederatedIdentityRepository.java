package com.spring.lica.domain.repository;

import com.spring.lica.domain.entity.FederatedIdentity;
import com.spring.lica.domain.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface FederatedIdentityRepository extends JpaRepository<FederatedIdentity, Long> {

    Optional<FederatedIdentity> findByIdpAliasAndExternalUserId(String idpAlias, String externalUserId);

    List<FederatedIdentity> findByUser(User user);
}
