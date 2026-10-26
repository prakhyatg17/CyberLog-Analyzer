package reports;

import com.lowagie.text.Document;
import com.lowagie.text.DocumentException;
import com.lowagie.text.Font;
import com.lowagie.text.FontFactory;
import com.lowagie.text.PageSize;
import com.lowagie.text.Paragraph;
import com.lowagie.text.Phrase;
import com.lowagie.text.pdf.PdfPCell;
import com.lowagie.text.pdf.PdfPTable;
import com.lowagie.text.pdf.PdfWriter;
import java.awt.Color;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import model.SecurityAlert;
import model.Severity;

public final class PDFReportGenerator {
    private PDFReportGenerator() { }

    private static final Color NAVY = new Color(15, 23, 42);
    private static final Font TITLE = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 20, Font.BOLD, NAVY);
    private static final Font H2 = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 14, Font.BOLD, NAVY);
    private static final Font BODY = FontFactory.getFont(FontFactory.HELVETICA, 10, Font.NORMAL, Color.BLACK);
    private static final Font BOLD = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 10, Font.BOLD, Color.BLACK);
    private static final Font MONO = FontFactory.getFont(FontFactory.COURIER, 8, Font.NORMAL, Color.DARK_GRAY);
    private static final int MAX_EVIDENCE = 20;

    public static void write(Path out, ReportData d) throws IOException {
        Document doc = new Document(PageSize.A4, 40, 40, 40, 40);
        try (OutputStream os = Files.newOutputStream(out)) {
            PdfWriter.getInstance(doc, os);
            doc.open();

            doc.add(new Paragraph("Cyber Log Analyzer", TITLE));
            Paragraph sub = new Paragraph("Security investigation report - generated "
                + Instant.now() + " (UTC)", BODY);
            sub.setSpacingAfter(12);
            doc.add(sub);

            doc.add(new Paragraph("1. Investigation summary", H2));
            long crit = d.countBySeverity(Severity.CRITICAL), high = d.countBySeverity(Severity.HIGH);
            Paragraph sum = new Paragraph("The log file " + d.fileName() + " contained " + d.totalEvents()
                + " valid events. The rule-based engine raised " + d.alerts().size() + " alerts ("
                + crit + " critical, " + high + " high). These are indicators that need human "
                + "investigation, not confirmed attacks.", BODY);
            sum.setSpacingAfter(8);
            doc.add(sum);

            doc.add(table(new String[][]{
                {"Log file", d.fileName()},
                {"Imported (UTC)", String.valueOf(d.importedAt())},
                {"Events analyzed", String.valueOf(d.totalEvents())},
                {"Lines skipped", String.valueOf(d.skippedLines())},
                {"Successful logins", String.valueOf(d.successLogins())},
                {"Failed logins", String.valueOf(d.failedLogins())},
                {"Alerts (Low / Medium / High / Critical)", d.countBySeverity(Severity.LOW) + " / "
                    + d.countBySeverity(Severity.MEDIUM) + " / " + high + " / " + crit},
                {"Detection rules used", d.rules()}}));

            doc.add(new Paragraph("2. Detected suspicious patterns", H2));
            if (d.alerts().isEmpty()) doc.add(new Paragraph("No alerts were generated.", BODY));
            for (SecurityAlert a : d.alerts()) {
                Paragraph head = new Paragraph(a.id() + "   " + a.severity() + "   " + a.rule(),
                    FontFactory.getFont(FontFactory.HELVETICA_BOLD, 11, Font.BOLD, color(a.severity())));
                head.setSpacingBefore(10);
                head.setSpacingAfter(3);
                doc.add(head);
                doc.add(table(new String[][]{
                    {"Username", nz(a.username())}, {"IP address", nz(a.ip())},
                    {"First event (UTC)", String.valueOf(a.first())},
                    {"Last event (UTC)", String.valueOf(a.last())},
                    {"Matching events", String.valueOf(a.count())},
                    {"Why flagged", a.explanation()},
                    {"Recommended action", a.action()}}));
                doc.add(new Paragraph("Evidence (original log lines):", BOLD));
                int shown = Math.min(MAX_EVIDENCE, a.evidence().size());
                for (int i = 0; i < shown; i++) doc.add(new Paragraph(a.evidence().get(i), MONO));
                if (a.evidence().size() > shown) {
                    doc.add(new Paragraph("... " + (a.evidence().size() - shown)
                        + " more lines (see the CSV report).", MONO));
                }
            }

            Paragraph lim = new Paragraph("3. False positives and limitations", H2);
            lim.setSpacingBefore(14);
            doc.add(lim);
            doc.add(new Paragraph(ReportData.LIMITATIONS, BODY));
            doc.close();
        } catch (DocumentException e) {
            throw new IOException("PDF error: " + e.getMessage(), e);
        }
    }

    private static PdfPTable table(String[][] rows) throws DocumentException {
        PdfPTable t = new PdfPTable(2);
        t.setWidthPercentage(100);
        t.setWidths(new float[]{28, 72});
        for (String[] r : rows) {
            t.addCell(cell(r[0], BOLD, new Color(241, 245, 249)));
            t.addCell(cell(r[1], BODY, Color.WHITE));
        }
        t.setSpacingAfter(6);
        return t;
    }

    private static PdfPCell cell(String text, Font f, Color bg) {
        PdfPCell c = new PdfPCell(new Phrase(nz(text), f));
        c.setBackgroundColor(bg);
        c.setPadding(4);
        return c;
    }

    private static String nz(String s) { return s == null ? "-" : s; }

    private static Color color(Severity s) {
        return switch (s) {
            case LOW -> new Color(22, 163, 74);
            case MEDIUM -> new Color(202, 138, 4);
            case HIGH -> new Color(234, 88, 12);
            case CRITICAL -> new Color(220, 38, 38);
        };
    }
}