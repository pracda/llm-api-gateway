package com.prasiddha.gateway.exception;

import com.prasiddha.gateway.exception.GatewayException.ErrorClass;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * F6 — provider HTTP errors must be classified into the right fallback-ladder error class:
 * 5xx/timeout retry the same provider, 429/402 advance to a free rung, everything else throws.
 */
@DisplayName("GatewayException — provider error classification")
class GatewayExceptionTest {

    @Test
    void serverErrorsAreRetryableTransient() {
        GatewayException e = GatewayException.fromProviderStatus("openai", HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(e.getErrorClass()).isEqualTo(ErrorClass.RETRYABLE_TRANSIENT);
        assertThat(e.isRetryable()).isTrue();
        assertThat(e.isUsageBlocked()).isFalse();
    }

    @Test
    void tooManyRequestsIsUsageBlocked() {
        GatewayException e = GatewayException.fromProviderStatus("openai", HttpStatus.TOO_MANY_REQUESTS);
        assertThat(e.getErrorClass()).isEqualTo(ErrorClass.USAGE_BLOCKED);
        assertThat(e.isUsageBlocked()).isTrue();
        assertThat(e.isRetryable()).isFalse();
    }

    @Test
    void paymentRequiredIsUsageBlocked() {
        GatewayException e = GatewayException.fromProviderStatus("openai", HttpStatus.PAYMENT_REQUIRED);
        assertThat(e.getErrorClass()).isEqualTo(ErrorClass.USAGE_BLOCKED);
    }

    @Test
    void badRequestIsNonRetryable() {
        GatewayException e = GatewayException.fromProviderStatus("openai", HttpStatus.BAD_REQUEST);
        assertThat(e.getErrorClass()).isEqualTo(ErrorClass.NON_RETRYABLE);
        assertThat(e.isRetryable()).isFalse();
        assertThat(e.isUsageBlocked()).isFalse();
    }

    @Test
    void legacyRetryableBooleanStillMapsToTransient() {
        assertThat(GatewayException.providerError("x", true).getErrorClass()).isEqualTo(ErrorClass.RETRYABLE_TRANSIENT);
        assertThat(GatewayException.providerError("x", false).getErrorClass()).isEqualTo(ErrorClass.NON_RETRYABLE);
    }
}
