package com.prasiddha.gateway.service;

import com.prasiddha.gateway.model.entity.SecurityAlert;
import com.prasiddha.gateway.repository.SecurityAlertRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@DisplayName("ThreatDetectionService — Redis-backed lockout logic")
class ThreatDetectionServiceTest {

    private StringRedisTemplate redis;
    private ValueOperations<String, String> valueOps;
    private SecurityAlertRepository securityAlertRepository;
    private RealtimeEventPublisher eventPublisher;
    private ThreatDetectionService service;

    @BeforeEach
    void setUp() {
        redis = mock(StringRedisTemplate.class);
        valueOps = mock(ValueOperations.class);
        when(redis.opsForValue()).thenReturn(valueOps);
        securityAlertRepository = mock(SecurityAlertRepository.class);
        eventPublisher = mock(RealtimeEventPublisher.class);

        service = new ThreatDetectionService(redis, securityAlertRepository, eventPublisher);
        ReflectionTestUtils.setField(service, "windowSeconds", 300L);
        ReflectionTestUtils.setField(service, "lockoutSeconds", 900L);
        ReflectionTestUtils.setField(service, "injectionThreshold", 3L);
        ReflectionTestUtils.setField(service, "outputBlockThreshold", 5L);
        ReflectionTestUtils.setField(service, "rateLimitAbuseThreshold", 5L);
        ReflectionTestUtils.setField(service, "failedLoginThreshold", 5L);
        ReflectionTestUtils.setField(service, "distinctIpThreshold", 3L);
        ReflectionTestUtils.setField(service, "coordinatedAttackUserThreshold", 3L);

        when(securityAlertRepository.save(any(SecurityAlert.class)))
            .thenAnswer(inv -> inv.getArgument(0));
    }

    @Test
    @DisplayName("crossing the threshold acquires the lockout and raises exactly one alert")
    void lockoutFiresOnceOnFirstThresholdCross() {
        when(valueOps.increment(anyString())).thenReturn(3L); // == injectionThreshold
        when(valueOps.setIfAbsent(anyString(), anyString(), anyLong(), any())).thenReturn(true);

        service.recordEvent("alice", SecurityAlert.Type.REPEATED_INJECTION);

        verify(securityAlertRepository, times(1)).save(any(SecurityAlert.class));
        verify(eventPublisher, times(1)).publishAlert(any(SecurityAlert.class));
    }

    @Test
    @DisplayName("repeated offenses while already locked do not spam alerts")
    void noDuplicateAlertWhileLockoutActive() {
        when(valueOps.increment(anyString())).thenReturn(4L); // already past threshold
        when(valueOps.setIfAbsent(anyString(), anyString(), anyLong(), any())).thenReturn(false); // lock already held

        service.recordEvent("alice", SecurityAlert.Type.REPEATED_INJECTION);

        verify(securityAlertRepository, never()).save(any());
        verify(eventPublisher, never()).publishAlert(any());
    }

    @Test
    @DisplayName("re-offending right after a manual unlock re-arms the lockout (SETNX, not a count compare)")
    void reoffendingAfterManualUnlockReTriggersLockout() {
        when(valueOps.increment(anyString())).thenReturn(7L); // well past threshold already
        when(valueOps.setIfAbsent(anyString(), anyString(), anyLong(), any())).thenReturn(true); // key was cleared -> succeeds again

        service.recordEvent("alice", SecurityAlert.Type.REPEATED_INJECTION);

        verify(securityAlertRepository, times(1)).save(any(SecurityAlert.class));
    }

    @Test
    @DisplayName("Redis failures fail open and never propagate")
    void recordEventFailsOpenOnRedisError() {
        when(valueOps.increment(anyString())).thenThrow(new RuntimeException("connection refused"));

        assertThatCode(() -> service.recordEvent("alice", SecurityAlert.Type.REPEATED_INJECTION))
            .doesNotThrowAnyException();
        verify(securityAlertRepository, never()).save(any());
    }

    @Test
    @DisplayName("isLocked fails open (returns false) when Redis is unreachable")
    void isLockedFailsOpenOnRedisError() {
        when(redis.hasKey(anyString())).thenThrow(new RuntimeException("connection refused"));

        assertThat(service.isLocked("alice")).isFalse();
    }

    @Test
    @DisplayName("below-threshold occurrences do not lock or alert")
    void belowThresholdDoesNothing() {
        when(valueOps.increment(anyString())).thenReturn(1L);

        service.recordEvent("alice", SecurityAlert.Type.REPEATED_INJECTION);

        verify(securityAlertRepository, never()).save(any());
        verify(valueOps, never()).setIfAbsent(anyString(), anyString(), anyLong(), any());
    }
}
