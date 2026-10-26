package model;

import java.time.Instant;
import java.util.List;

public record SecurityAlert(String id, String rule, Severity severity, String ip, String username,
                            Instant first, Instant last, int count, List<String> evidence,
                            String explanation, String action) {

    public SecurityAlert withId(String newId) {
        return new SecurityAlert(newId, rule, severity, ip, username, first, last, count,
                                 evidence, explanation, action);
    }
}