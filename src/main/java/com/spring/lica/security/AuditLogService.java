package com.spring.lica.security;

import com.spring.lica.domain.entity.AuditLog;
import com.spring.lica.domain.repository.AuditLogRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuditLogService {

    private final AuditLogRepository auditLogRepository;

    @Transactional
    public void log(String eventType, Long userId, String username, String clientId,
                    String ipAddress, String userAgent, String outcome, String details, String sessionId) {
        AuditLog entry = AuditLog.builder()
            .eventType(eventType)
            .userId(userId)
            .username(username)
            .clientId(clientId)
            .ipAddress(ipAddress)
            .userAgent(userAgent)
            .outcome(outcome)
            .details(details)
            .sessionId(sessionId)
            .build();
        auditLogRepository.save(entry);
        log.debug("Audit: {} user={} outcome={} details={}", eventType, username, outcome, details);
    }

    @Transactional
    public void logAuth(String eventType, String username, String ipAddress, String userAgent, String outcome, String details) {
        log(eventType, null, username, null, ipAddress, userAgent, outcome, details, null);
    }

    @Transactional(readOnly = true)
    public Page<AuditLog> findAll(Pageable pageable) {
        return auditLogRepository.findAllByOrderByTimestampDesc(pageable);
    }

    @Transactional(readOnly = true)
    public Page<AuditLog> findByEventType(String eventType, Pageable pageable) {
        return auditLogRepository.findByEventType(eventType, pageable);
    }

    @Transactional(readOnly = true)
    public Page<AuditLog> findByUsername(String username, Pageable pageable) {
        return auditLogRepository.findByUsername(username, pageable);
    }
}
