package com.spring.lica.domain.repository;

import com.spring.lica.domain.entity.SsoSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface SsoSessionRepository extends JpaRepository<SsoSession, Long> {

    Optional<SsoSession> findBySessionId(String sessionId);

    List<SsoSession> findByUserIdAndRevokedFalseOrderByCreatedAtAsc(Long userId);

    @Modifying
    @Query("UPDATE SsoSession s SET s.revoked = true WHERE s.userId = :userId AND s.revoked = false")
    void revokeByUserId(@Param("userId") Long userId);
}
