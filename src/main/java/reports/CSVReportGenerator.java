package reports;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import model.SecurityAlert;
import model.Severity;

public final class CSVReportGenerator {
    private CSVReportGenerator() { }

    public static void write(Path out, ReportData d) throws IOException {
        List<String> lines = new ArrayList<>();
        lines.add(row("Cyber Log Analyzer - Security Report"));
        lines.add(row("Generated (UTC)", Instant.now()));
        lines.add(row("Log file", d.fileName()));
        lines.add(row("Imported (UTC)", d.importedAt()));
        lines.add(row("Events analyzed", d.totalEvents()));
        lines.add(row("Lines skipped (malformed)", d.skippedLines()));
        lines.add(row("Successful logins", d.successLogins()));
        lines.add(row("Failed logins", d.failedLogins()));
        lines.add(row("Alerts", d.alerts().size()));
        for (Severity s : Severity.values()) lines.add(row("Alerts - " + s, d.countBySeverity(s)));
        lines.add(row("Detection rules used", d.rules()));
        lines.add(row("False positives and limitations", ReportData.LIMITATIONS));
        lines.add("");
        lines.add(row("Alert ID", "Severity", "Rule", "Username", "IP", "First event (UTC)",
            "Last event (UTC)", "Matching events", "Why flagged", "Recommended action",
            "Evidence (original log lines)"));
        for (SecurityAlert a : d.alerts()) {
            lines.add(row(a.id(), a.severity(), a.rule(), a.username(), a.ip(), a.first(), a.last(),
                a.count(), a.explanation(), a.action(), String.join("\n", a.evidence())));
        }
        Files.write(out, lines, StandardCharsets.UTF_8);
    }

    static String row(Object... cells) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < cells.length; i++) {
            if (i > 0) sb.append(',');
            sb.append(cell(cells[i]));
        }
        return sb.toString();
    }

    /** Quotes the cell if needed. A leading = + - @ gets a ' so Excel never runs log text as a formula. */
    static String cell(Object o) {
        String s = o == null ? "" : String.valueOf(o);
        if (!s.isEmpty() && "=+-@\t\r".indexOf(s.charAt(0)) >= 0) s = "'" + s;
        if (s.contains(",") || s.contains("\"") || s.contains("\n") || s.contains("\r")) {
            s = "\"" + s.replace("\"", "\"\"") + "\"";
        }
        return s;
    }
}