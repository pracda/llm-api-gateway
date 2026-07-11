package com.prasiddha.gateway.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("ReportPdfService — PDF generation sanity checks")
class ReportPdfServiceTest {

    private final ReportPdfService service = new ReportPdfService();

    @Test
    @DisplayName("generates a valid PDF byte stream for a populated member list")
    void generatesValidPdfWithMembers() {
        List<ReportPdfService.MemberRow> rows = List.of(
            new ReportPdfService.MemberRow("alice", 100, 5, 15000, 3, 1, 2, 22.5),
            new ReportPdfService.MemberRow("bob", 50, 0, 8000, 0, 0, 0, 4.0)
        );

        byte[] pdf = service.generateOrganizationReport("Acme Corp", "Weekly report",
            Instant.now().minusSeconds(7 * 86400L), Instant.now(), rows);

        assertThat(pdf).isNotEmpty();
        assertThat(new String(pdf, 0, 5, StandardCharsets.US_ASCII)).isEqualTo("%PDF-");
    }

    @Test
    @DisplayName("generates a valid PDF even with zero members")
    void generatesValidPdfWithNoMembers() {
        byte[] pdf = service.generateOrganizationReport("Empty Org", "Monthly report",
            Instant.now().minusSeconds(30 * 86400L), Instant.now(), List.of());

        assertThat(pdf).isNotEmpty();
        assertThat(new String(pdf, 0, 5, StandardCharsets.US_ASCII)).isEqualTo("%PDF-");
    }

    @Test
    @DisplayName("handles a large member list across multiple pages without error")
    void handlesManyMembersAcrossPages() {
        List<ReportPdfService.MemberRow> rows = java.util.stream.IntStream.range(0, 200)
            .mapToObj(i -> new ReportPdfService.MemberRow("user" + i, i, 0, i * 10L, 0, 0, 0, 0.0))
            .toList();

        byte[] pdf = service.generateOrganizationReport("Big Org", "Weekly report",
            Instant.now().minusSeconds(7 * 86400L), Instant.now(), rows);

        assertThat(pdf).isNotEmpty();
        assertThat(new String(pdf, 0, 5, StandardCharsets.US_ASCII)).isEqualTo("%PDF-");
    }
}
