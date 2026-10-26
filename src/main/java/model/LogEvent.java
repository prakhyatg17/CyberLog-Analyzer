package model;

import java.time.Instant;

/** One parsed log entry. A record is an immutable data holder: getters are timestamp(), ip(), etc. */
public record LogEvent(int lineNumber, Instant timestamp, String eventType,
                       String username, String ip, Result result,
                       String description, String rawLine) {

    public enum Result { SUCCESS, FAILURE, UNKNOWN }
}