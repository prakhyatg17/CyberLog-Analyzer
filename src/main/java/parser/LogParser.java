package parser;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import model.LogEvent;

public interface LogParser {

    /** Parses one line. Throws IllegalArgumentException with a reason if the line is invalid. */
    LogEvent parseLine(String line, int lineNumber);

    default ParseResult parseLines(List<String> lines) {
        List<LogEvent> events = new ArrayList<>();
        List<String> errors = new ArrayList<>();
        int n = 0;
        for (String line : lines) {
            n++;
            String t = line.trim();
            if (t.isEmpty() || t.startsWith("#")) continue;
            try {
                events.add(parseLine(line, n));
            } catch (IllegalArgumentException e) {
                errors.add("Line " + n + ": " + e.getMessage());
            }
        }
        return new ParseResult(events, errors);
    }

    /** Reads the file as plain text only. Nothing in the file is ever executed. */
    default ParseResult parseFile(Path path) throws IOException {
        String text = new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
        return parseLines(text.lines().toList());
    }
}