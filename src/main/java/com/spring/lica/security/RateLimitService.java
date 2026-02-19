package com.spring.lica.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Service
public class RateLimitService {

    private final Map<String, RateBucket> buckets = new ConcurrentHashMap<>();

    public RateLimitResult checkLimit(String key, int maxRequests, long windowSeconds) {
        Instant now = Instant.now();
        RateBucket bucket = buckets.compute(key, (k, existing) -> {
            if (existing == null || existing.windowStart.plusSeconds(windowSeconds).isBefore(now)) {
                return new RateBucket(now, 1);
            }
            existing.count++;
            return existing;
        });

        int remaining = Math.max(0, maxRequests - bucket.count);
        long resetEpoch = bucket.windowStart.plusSeconds(windowSeconds).getEpochSecond();

        if (bucket.count > maxRequests) {
            return new RateLimitResult(false, maxRequests, 0, resetEpoch);
        }

        return new RateLimitResult(true, maxRequests, remaining, resetEpoch);
    }

    public void cleanup() {
        Instant cutoff = Instant.now().minusSeconds(3600);
        buckets.entrySet().removeIf(e -> e.getValue().windowStart.isBefore(cutoff));
    }

    private static class RateBucket {
        Instant windowStart;
        int count;

        RateBucket(Instant windowStart, int count) {
            this.windowStart = windowStart;
            this.count = count;
        }
    }

    public record RateLimitResult(boolean allowed, int limit, int remaining, long resetEpoch) {}
}
