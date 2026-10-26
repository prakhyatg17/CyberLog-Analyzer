package parser;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import model.LogEvent;
import org.junit.jupiter.api.Test;

class SampleLogParserTest {
    private final SampleLogParser parser = new SampleLogParser();

    @Test
    void parsesValidLine() {
        LogEvent e = parser.parseLine(
            "2026-03-10 09:20:03 | LOGIN | carol | 192.168.1.12 | FAILURE | Wrong password", 1);
        assertEquals("carol", e.username());
        assertEquals("192.168.1.12", e.ip());
        assertEquals(LogEvent.Result.FAILURE, e.result());
        assertEquals(Instant.parse("2026-03-10T09:20:03Z"), e.timestamp());
    }

    @Test
    void dashMeansMissingField() {
        LogEvent e = parser.parseLine("2026-03-10 09:00:00 | LOGOUT | - | - | N/A | Closed", 1);
        assertNull(e.username());
        assertNull(e.ip());
        assertEquals(LogEvent.Result.UNKNOWN, e.result());
    }

    @Test
    void rejectsGarbage() {
        assertThrows(IllegalArgumentException.class, () -> parser.parseLine("hello", 1));
    }

    @Test
    void rejectsBadTimestamp() {
        assertThrows(IllegalArgumentException.class, () -> parser.parseLine(
            "2026-13-45 99:99:99 | LOGIN | bob | 1.2.3.4 | SUCCESS | x", 1));
    }

    @Test
    void rejectsBadIp() {
        assertThrows(IllegalArgumentException.class, () -> parser.parseLine(
            "2026-03-10 09:00:00 | LOGIN | bob | 999.1.1.1 | SUCCESS | x", 1));
    }

    @Test
    void skipsBlankAndCommentLines() {
        ParseResult r = parser.parseLines(List.of("", "# comment"));
        assertTrue(r.events().isEmpty());
        assertTrue(r.errors().isEmpty());
    }

    @Test
    void sampleFileCounts() throws Exception {
        ParseResult r = parser.parseFile(Path.of("src/test/resources/small.log"));
        assertEquals(20, r.events().size());
        assertEquals(4, r.errors().size());
    }
}