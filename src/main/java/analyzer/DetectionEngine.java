package analyzer;

import java.time.Duration;
import java.time.ZoneOffset;
import java.util.*;
import java.util.stream.Collectors;
import model.LogEvent;
import model.LogEvent.Result;
import model.SecurityAlert;
import model.Severity;

public class DetectionEngine {
    public static final String BRUTE_FORCE = "Possible brute-force activity";
    public static final String SUCCESS_AFTER = "Successful login after repeated failures";
    public static final String ADMIN = "Repeated administrator login failures";
    public static final String OFF_HOURS = "Unusual login time";
    public static final String PATTERN = "Suspicious event pattern";

    private static final String CAVEAT =
        " This is an indicator, not proof of an attack; it may be a false positive and needs investigation.";

    private final RuleManager rules;

    public DetectionEngine(RuleManager rules) { this.rules = rules; }

    public List<SecurityAlert> analyze(List<LogEvent> events) {
        List<LogEvent> sorted = events.stream()
            .sorted(Comparator.comparing(LogEvent::timestamp).thenComparingInt(LogEvent::lineNumber))
            .toList();
        List<LogEvent> failures = sorted.stream().filter(e -> isLogin(e, Result.FAILURE)).toList();

        List<SecurityAlert> found = new ArrayList<>();
        bruteForce(failures, found);
        successAfterFailures(sorted, found);
        adminFailures(failures, found);
        unusualTimes(sorted, found);
        distinctUsers(failures, found);

        found.sort(Comparator.comparing(SecurityAlert::first));
        List<SecurityAlert> numbered = new ArrayList<>();
        for (int i = 0; i < found.size(); i++) {
            numbered.add(found.get(i).withId(String.format("A-%03d", i + 1)));
        }
        return numbered;
    }

    // Rule 1: N failures from the same IP inside the time window
    private void bruteForce(List<LogEvent> failures, List<SecurityAlert> out) {
        for (var en : EventCorrelator.groupBy(failures, LogEvent::ip).entrySet()) {
            for (List<LogEvent> c : EventCorrelator.clusters(
                    en.getValue(), rules.bruteForceThreshold, rules.bruteForceWindowSec)) {
                Severity s = c.size() >= 2 * rules.bruteForceThreshold ? Severity.HIGH : Severity.MEDIUM;
                out.add(make(BRUTE_FORCE, s, en.getKey(), null, c,
                    c.size() + " failed logins from " + en.getKey() + " (rule: " + rules.bruteForceThreshold
                        + " failures within " + rules.bruteForceWindowSec + " seconds).",
                    "Consider rate-limiting or blocking this IP and reviewing the accounts it targeted."));
            }
        }
    }

    // Rule 2: a success from an IP that recently had several failures
    private void successAfterFailures(List<LogEvent> sorted, List<SecurityAlert> out) {
        Map<String, List<LogEvent>> pending = new HashMap<>();
        for (LogEvent e : sorted) {
            if (e.ip() == null || !"LOGIN".equals(e.eventType())) continue;
            List<LogEvent> list = pending.computeIfAbsent(e.ip(), k -> new ArrayList<>());
            if (e.result() == Result.FAILURE) {
                list.add(e);
            } else if (e.result() == Result.SUCCESS) {
                list.removeIf(f -> secs(f, e) > rules.successLookbackSec);
                if (list.size() >= rules.failuresBeforeSuccess) {
                    List<LogEvent> ev = new ArrayList<>(list);
                    ev.add(e);
                    Severity s = list.size() >= rules.bruteForceThreshold ? Severity.CRITICAL : Severity.HIGH;
                    out.add(make(SUCCESS_AFTER, s, e.ip(), e.username(), ev,
                        "A login succeeded from " + e.ip() + " after " + list.size()
                            + " recent failures, so the account may have been guessed or compromised.",
                        "Verify the login with the account owner, reset the password and review the session."));
                }
                list.clear();
            }
        }
    }

    // Rule 3: repeated failures against privileged accounts
    private void adminFailures(List<LogEvent> failures, List<SecurityAlert> out) {
        List<LogEvent> admin = failures.stream()
            .filter(e -> e.username() != null && rules.adminNames.contains(e.username().toLowerCase()))
            .toList();
        for (var en : EventCorrelator.groupBy(admin, e -> e.username().toLowerCase()).entrySet()) {
            for (List<LogEvent> c : EventCorrelator.clusters(
                    en.getValue(), rules.adminThreshold, rules.adminWindowSec)) {
                String ips = c.stream().map(LogEvent::ip).filter(Objects::nonNull)
                              .distinct().collect(Collectors.joining(", "));
                Severity s = c.size() >= 2 * rules.adminThreshold ? Severity.CRITICAL : Severity.HIGH;
                out.add(make(ADMIN, s, ips.isEmpty() ? null : ips, en.getKey(), c,
                    c.size() + " failed logins against privileged account '" + en.getKey() + "' (rule: "
                        + rules.adminThreshold + " within " + rules.adminWindowSec + " seconds).",
                    "Enforce MFA and strong passwords on this account and restrict where it can log in from."));
            }
        }
    }

    // Rule 4: successful logins outside working hours (UTC)
    private void unusualTimes(List<LogEvent> sorted, List<SecurityAlert> out) {
        for (LogEvent e : sorted) {
            if (!isLogin(e, Result.SUCCESS)) continue;
            int h = e.timestamp().atZone(ZoneOffset.UTC).getHour();
            if (h < rules.workStartHour || h >= rules.workEndHour) {
                out.add(make(OFF_HOURS, Severity.LOW, e.ip(), e.username(), List.of(e),
                    "Login at " + String.format("%02d:00", h) + " UTC is outside working hours ("
                        + rules.workStartHour + ":00-" + rules.workEndHour + ":00).",
                    "Confirm with the user that this login was expected."));
            }
        }
    }

    // Rule 5: many different usernames tried from one IP in a short time
    private void distinctUsers(List<LogEvent> failures, List<SecurityAlert> out) {
        List<LogEvent> named = failures.stream()
            .filter(e -> e.username() != null && e.ip() != null).toList();
        for (var en : EventCorrelator.groupBy(named, LogEvent::ip).entrySet()) {
            List<LogEvent> list = en.getValue();
            List<LogEvent> best = null;
            long bestN = 0;
            int left = 0;
            for (int r = 0; r < list.size(); r++) {
                while (secs(list.get(left), list.get(r)) > rules.distinctUsersWindowSec) left++;
                List<LogEvent> win = list.subList(left, r + 1);
                long n = win.stream().map(e -> e.username().toLowerCase()).distinct().count();
                if (n >= rules.distinctUsersThreshold && n > bestN) {
                    best = new ArrayList<>(win);
                    bestN = n;
                }
            }
            if (best != null) {
                Severity s = bestN >= 2L * rules.distinctUsersThreshold ? Severity.HIGH : Severity.MEDIUM;
                out.add(make(PATTERN, s, en.getKey(), null, best,
                    en.getKey() + " tried " + bestN + " different usernames within "
                        + rules.distinctUsersWindowSec + " seconds, a pattern seen in account guessing.",
                    "Review the usernames targeted and consider blocking the IP."));
            }
        }
    }

    private boolean isLogin(LogEvent e, Result result) {
        return "LOGIN".equals(e.eventType()) && e.result() == result;
    }

    private static long secs(LogEvent a, LogEvent b) {
        return Duration.between(a.timestamp(), b.timestamp()).getSeconds();
    }

    private SecurityAlert make(String rule, Severity sev, String ip, String user,
                               List<LogEvent> ev, String why, String action) {
        List<String> evidence = ev.stream()
            .map(e -> "Line " + e.lineNumber() + ": " + e.rawLine().trim()).toList();
        return new SecurityAlert(null, rule, sev, ip, user, ev.get(0).timestamp(),
            ev.get(ev.size() - 1).timestamp(), ev.size(), evidence, why + CAVEAT, action);
    }
}