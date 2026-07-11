package com.prasiddha.gateway.service;

import lombok.extern.slf4j.Slf4j;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * Renders the per-organization member activity report as a downloadable PDF —
 * the artifact an org admin takes to a compliance/security review. Only
 * aggregated counts go in (request/token/alert counts, intent-classification
 * tallies) — raw prompt/response content is never stored anywhere in this
 * gateway, so there is none to include here either (OWASP LLM #06).
 */
@Slf4j
@Service
public class ReportPdfService {

    private static final float MARGIN = 50f;
    private static final float LINE_HEIGHT = 16f;
    private static final DateTimeFormatter DATE_FMT = DateTimeFormatter.ISO_LOCAL_DATE.withZone(ZoneOffset.UTC);

    public record MemberRow(
        String username, long totalRequests, long blocked, long totalTokens,
        long suspicious, long malicious, long alertCount, double avgJailbreakScore
    ) {}

    public byte[] generateOrganizationReport(
        String organizationName, String periodLabel, Instant periodStart, Instant periodEnd, List<MemberRow> rows
    ) {
        try (PDDocument doc = new PDDocument()) {
            PageCursor cursor = new PageCursor(doc);

            cursor.writeLine("Gateway Activity Report", PDType1Font.HELVETICA_BOLD, 18);
            cursor.writeLine(organizationName, PDType1Font.HELVETICA_BOLD, 14);
            cursor.writeLine(periodLabel + ":  " + DATE_FMT.format(periodStart) + "  to  " + DATE_FMT.format(periodEnd),
                PDType1Font.HELVETICA, 11);
            cursor.writeLine("Generated " + Instant.now(), PDType1Font.HELVETICA, 9);
            cursor.blankLine();

            long totalRequests = rows.stream().mapToLong(MemberRow::totalRequests).sum();
            long totalBlocked  = rows.stream().mapToLong(MemberRow::blocked).sum();
            long totalTokens   = rows.stream().mapToLong(MemberRow::totalTokens).sum();
            long totalFlagged  = rows.stream().mapToLong(r -> r.suspicious() + r.malicious()).sum();

            cursor.writeLine("Summary - " + rows.size() + " member(s)", PDType1Font.HELVETICA_BOLD, 12);
            cursor.writeLine("Total requests: " + totalRequests + "   Blocked: " + totalBlocked +
                "   Tokens: " + totalTokens + "   Flagged suspicious/malicious: " + totalFlagged,
                PDType1Font.HELVETICA, 10);
            cursor.blankLine();

            cursor.writeLine("Note: figures are derived from request metadata and heuristic signals only -",
                PDType1Font.HELVETICA_OBLIQUE, 8);
            cursor.writeLine("raw prompt/response content is never stored or included in this report.",
                PDType1Font.HELVETICA_OBLIQUE, 8);
            cursor.blankLine();

            float[] colX     = {0, 150, 220, 280, 345, 415, 480, 520};
            String[] headers = {"Username", "Requests", "Blocked", "Tokens", "Suspicious", "Malicious", "Alerts", "AvgScore"};
            cursor.writeRow(colX, headers, PDType1Font.HELVETICA_BOLD, 9);

            for (MemberRow r : rows) {
                cursor.writeRow(colX, new String[]{
                    r.username(),
                    String.valueOf(r.totalRequests()),
                    String.valueOf(r.blocked()),
                    String.valueOf(r.totalTokens()),
                    String.valueOf(r.suspicious()),
                    String.valueOf(r.malicious()),
                    String.valueOf(r.alertCount()),
                    String.format("%.0f", r.avgJailbreakScore())
                }, PDType1Font.HELVETICA, 9);
            }

            if (rows.isEmpty()) {
                cursor.writeLine("No members in this organization yet.", PDType1Font.HELVETICA_OBLIQUE, 9);
            }

            cursor.close();

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            doc.save(out);
            return out.toByteArray();
        } catch (IOException e) {
            log.error("PDF report generation failed: {}", e.getMessage());
            throw new IllegalStateException("Failed to generate PDF report", e);
        }
    }

    /** Tracks the current Y position across one or more pages, rolling to a new page when space runs out. */
    private static class PageCursor {
        private final PDDocument doc;
        private PDPage page;
        private PDPageContentStream cs;
        private float y;

        PageCursor(PDDocument doc) throws IOException {
            this.doc = doc;
            newPage();
        }

        private void newPage() throws IOException {
            page = new PDPage(PDRectangle.A4);
            doc.addPage(page);
            cs = new PDPageContentStream(doc, page);
            y = page.getMediaBox().getHeight() - MARGIN;
        }

        private void ensureSpace() throws IOException {
            if (y < MARGIN + LINE_HEIGHT) {
                cs.close();
                newPage();
            }
        }

        void writeLine(String text, PDType1Font font, float size) throws IOException {
            ensureSpace();
            cs.beginText();
            cs.setFont(font, size);
            cs.newLineAtOffset(MARGIN, y);
            cs.showText(sanitize(text));
            cs.endText();
            y -= LINE_HEIGHT;
        }

        void writeRow(float[] colOffsets, String[] cells, PDType1Font font, float size) throws IOException {
            ensureSpace();
            cs.beginText();
            cs.setFont(font, size);
            cs.newLineAtOffset(MARGIN + colOffsets[0], y);
            cs.showText(sanitize(cells[0]));
            for (int i = 1; i < cells.length; i++) {
                cs.newLineAtOffset(colOffsets[i] - colOffsets[i - 1], 0);
                cs.showText(sanitize(cells[i]));
            }
            cs.endText();
            y -= LINE_HEIGHT;
        }

        void blankLine() {
            y -= LINE_HEIGHT / 2;
        }

        void close() throws IOException {
            cs.close();
        }

        /** PDFBox's WinAnsiEncoding (the standard-14 fonts) can't encode arbitrary Unicode. */
        private String sanitize(String text) {
            return text == null ? "" : text.replaceAll("[^\\x20-\\x7E]", "?");
        }
    }
}
