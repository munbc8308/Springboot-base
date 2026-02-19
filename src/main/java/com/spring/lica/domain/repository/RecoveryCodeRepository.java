package com.spring.lica.domain.repository;

import com.spring.lica.domain.entity.RecoveryCode;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface RecoveryCodeRepository extends JpaRepository<RecoveryCode, Long> {

    List<RecoveryCode> findByUserIdAndUsedFalse(Long userId);

    void deleteAllByUserId(Long userId);
}
