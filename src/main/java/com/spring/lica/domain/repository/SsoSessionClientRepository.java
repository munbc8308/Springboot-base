package com.spring.lica.domain.repository;

import com.spring.lica.domain.entity.SsoSession;
import com.spring.lica.domain.entity.SsoSessionClient;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface SsoSessionClientRepository extends JpaRepository<SsoSessionClient, Long> {

    List<SsoSessionClient> findBySession(SsoSession session);

    boolean existsBySessionAndClientId(SsoSession session, String clientId);
}
