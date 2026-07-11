package com.prasiddha.gateway.service;

import org.junit.jupiter.api.*;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("OutputScanService — response sanitisation")
class OutputScanServiceTest {

    private OutputScanService service;

    @BeforeEach
    void setUp() {
        service = new OutputScanService(new CanaryTokenProvider(""));
        ReflectionTestUtils.setField(service, "enabled", true);
        ReflectionTestUtils.setField(service, "blockOnUnsafe", true);
        ReflectionTestUtils.setField(service, "maxResponseLength", 10000);
    }

    @Nested
    @DisplayName("Safe responses — should pass unchanged")
    class SafeResponses {

        @Test void normalText() {
            var result = service.scan("The capital of France is Paris.");
            assertThat(result.isSafe()).isTrue();
            assertThat(result.content()).isEqualTo("The capital of France is Paris.");
        }

        @Test void codeSnippet() {
            var result = service.scan("Here is a Java example:\n```java\npublic class Hello {}\n```");
            assertThat(result.isSafe()).isTrue();
        }
    }

    @Nested
    @DisplayName("PII — should redact")
    class PiiRedaction {

        @Test void emailAddress() {
            var result = service.scan("Contact us at user@example.com for help.");
            assertThat(result.isSanitised()).isTrue();
            assertThat(result.content()).contains("[EMAIL REDACTED]");
            assertThat(result.content()).doesNotContain("user@example.com");
        }

        @Test void phoneNumber() {
            var result = service.scan("Call us at 555-123-4567 anytime.");
            assertThat(result.isSanitised()).isTrue();
            assertThat(result.content()).contains("[PHONE REDACTED]");
        }

        @Test void creditCard() {
            var result = service.scan("Card number: 4111 1111 1111 1111");
            assertThat(result.isSanitised()).isTrue();
            assertThat(result.content()).contains("[CARD REDACTED]");
        }

        @Test void ssn() {
            var result = service.scan("SSN: 123-45-6789");
            assertThat(result.isSanitised()).isTrue();
            assertThat(result.content()).contains("[SSN REDACTED]");
        }

        @Test void internalIp() {
            var result = service.scan("Server is at 192.168.1.100");
            assertThat(result.isSanitised()).isTrue();
            assertThat(result.content()).contains("[INTERNAL-IP REDACTED]");
        }
    }

    @Nested
    @DisplayName("Dangerous content — should block")
    class DangerousContent {

        @Test void xssScript() {
            var result = service.scan("Click here: <script>alert('xss')</script>");
            assertThat(result.isBlocked()).isTrue();
        }

        @Test void apiKeyLeakage() {
            var result = service.scan("Your key is sk-abcdefghijklmnopqrstuvwxyz1234567890ABCDEF12");
            assertThat(result.isBlocked()).isTrue();
        }

        @Test void sqlInjectionEcho() {
            var result = service.scan("Try: ' UNION SELECT * FROM users; -- ");
            assertThat(result.isBlocked()).isTrue();
        }

        @Test void shellCommand() {
            var result = service.scan("Run this to clean up: rm -rf /var/data");
            assertThat(result.isBlocked()).isTrue();
        }
    }

    @Test
    @DisplayName("Oversized response — should truncate")
    void truncatesLongResponse() {
        ReflectionTestUtils.setField(service, "maxResponseLength", 100);
        String longText = "A".repeat(200);
        var result = service.scan(longText);
        assertThat(result.isSanitised()).isTrue();
        assertThat(result.content()).contains("[Response truncated");
        assertThat(result.content().length()).isLessThan(200);
    }
}
