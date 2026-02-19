package com.spring.lica.domain.repository;

import com.spring.lica.domain.entity.LoginAttempt;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface LoginAttemptRepository extends JpaRepository<LoginAttempt, Long> {

    Optional<LoginAttempt> findByUsername(String username);

    Optional<LoginAttempt> findByIpAddress(String ipAddress);

    void deleteByUsername(String username);
}
