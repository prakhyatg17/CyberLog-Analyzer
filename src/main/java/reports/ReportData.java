package reports;

import java.time.Instant;
import java.util.List;
import model.SecurityAlert;
import model.Severity;

/** Everything a report needs, so the generators don't depend on the UI. */
public record ReportData(String fileName, Instant importedAt, int totalEvents,
                         int skippedLines, long successLogins, long failedLogins,
                         String rules, List<SecurityAlert> alerts) {

    public static final String LIMITATIONS =
        "Alerts are rule-based indicators, not proof of an attack. Each one may be a false positive "
        + "(for example a user mistyping a password, a shared office IP, or a legitimate late-night login) "
        + "and must be reviewed by a person. Detection only covers the imported file and the configured "
        + "thresholds, so attacks that stay below the thresholds or are missing from the log are not "
        + "detected. All times are UTC.";

    public long countBySeverity(Severity s) {
        return alerts.stream().filter(a -> a.severity() == s).count();
    }
}