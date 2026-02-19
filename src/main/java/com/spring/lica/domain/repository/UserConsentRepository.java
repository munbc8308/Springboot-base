package com.spring.lica.domain.repository;

import com.spring.lica.domain.entity.UserConsent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserConsentRepository extends JpaRepository<UserConsent, Long> {

    Optional<UserConsent> findByUserIdAndClientId(Long userId, String clientId);

    List<UserConsent> findByUserId(Long userId);
}
