package parser;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.format.ResolverStyle;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import model.LogEvent;
import model.LogEvent.Result;

public class SampleLogParser implements LogParser {

    private static final Pattern LINE = Pattern.compile(
        "^(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2})\\s*\\|\\s*([A-Z_]+)\\s*\\|\\s*([^|]*?)\\s*\\|"
        + "\\s*([^|]*?)\\s*\\|\\s*(SUCCESS|FAILURE|N/A)\\s*\\|\\s*(.*)$");

    private static final Pattern IPV4 = Pattern.compile(
        "^((25[0-5]|2[0-4]\\d|1?\\d?\\d)\\.){3}(25[0-5]|2[0-4]\\d|1?\\d?\\d)$");

    private static final DateTimeFormatter TS =
        DateTimeFormatter.ofPattern("uuuu-MM-dd HH:mm:ss").withResolverStyle(ResolverStyle.STRICT);

    @Override
    public LogEvent parseLine(String line, int lineNumber) {
        Matcher m = LINE.matcher(line.trim());
        if (!m.matches()) {
            throw new IllegalArgumentException("does not match expected format");
        }
        Instant ts;
        try {
            ts = LocalDateTime.parse(m.group(1), TS).toInstant(ZoneOffset.UTC);
        } catch (DateTimeParseException e) {
            throw new IllegalArgumentException("invalid timestamp '" + m.group(1) + "'");
        }
        String user = blankToNull(m.group(3));
        String ip = blankToNull(m.group(4));
        if (ip != null && !IPV4.matcher(ip).matches()) {
            throw new IllegalArgumentException("invalid IP '" + ip + "'");
        }
        Result result = switch (m.group(5)) {
            case "SUCCESS" -> Result.SUCCESS;
            case "FAILURE" -> Result.FAILURE;
            default -> Result.UNKNOWN;
        };
        return new LogEvent(lineNumber, ts, m.group(2), user, ip, result, m.group(6), line);
    }

    private static String blankToNull(String s) {
        return (s.isEmpty() || s.equals("-")) ? null : s;
    }
}