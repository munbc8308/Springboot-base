package com.spring.lica.domain.repository;

import com.spring.lica.domain.entity.TotpCredential;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface TotpCredentialRepository extends JpaRepository<TotpCredential, Long> {

    Optional<TotpCredential> findByUserIdAndVerifiedTrue(Long userId);

    List<TotpCredential> findAllByUserId(Long userId);

    void deleteAllByUserId(Long userId);
}
