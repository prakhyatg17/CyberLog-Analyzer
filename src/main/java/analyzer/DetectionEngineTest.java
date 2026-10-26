package analyzer;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import model.LogEvent;
import model.SecurityAlert;
import model.Severity;
import org.junit.jupiter.api.Test;
import parser.SampleLogParser;

class DetectionEngineTest {
    private final DetectionEngine engine = new DetectionEngine(new RuleManager());
    private final SampleLogParser parser = new SampleLogParser();
    private int line;

    private LogEvent ev(String time, String user, String ip, String result) {
        return parser.parseLine("2026-03-10 " + time + " | LOGIN | " + user + " | " + ip
            + " | " + result + " | x", ++line);
    }

    /** 'count' failures starting at 10:00:00, 'gap' seconds apart. */
    private List<LogEvent> burst(int count, int gap, String user, String ip) {
        List<LogEvent> list = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            int t = i * gap;
            list.add(ev(String.format("10:%02d:%02d", t / 60, t % 60), user, ip, "FAILURE"));
        }
        return list;
    }

    @Test
    void fiveFailuresInWindowTriggers() {
        List<SecurityAlert> a = engine.analyze(burst(5, 10, "bob", "1.1.1.1"));
        assertEquals(1, a.size());
        assertEquals(DetectionEngine.BRUTE_FORCE, a.get(0).rule());
        assertEquals(Severity.MEDIUM, a.get(0).severity());
        assertEquals(5, a.get(0).count());
        assertEquals(5, a.get(0).evidence().size());
        assertTrue(a.get(0).evidence().get(0).contains("10:00:00"));
    }

    @Test
    void fourFailuresNoAlert() {
        assertTrue(engine.analyze(burst(4, 10, "bob", "1.1.1.1")).isEmpty());
    }

    @Test
    void slowFailuresNoAlert() {
        assertTrue(engine.analyze(burst(5, 70, "bob", "1.1.1.1")).isEmpty());
    }

    @Test
    void tenFailuresIsHigh() {
        List<SecurityAlert> a = engine.analyze(burst(10, 5, "bob", "1.1.1.1"));
        assertEquals(1, a.size());
        assertEquals(Severity.HIGH, a.get(0).severity());
        assertEquals(10, a.get(0).count());
    }

    @Test
    void successAfterRepeatedFailures() {
        List<LogEvent> events = burst(3, 10, "bob", "5.5.5.5");
        events.add(ev("10:01:00", "bob", "5.5.5.5", "SUCCESS"));
        List<SecurityAlert> a = engine.analyze(events);
        assertEquals(1, a.size());
        assertEquals(DetectionEngine.SUCCESS_AFTER, a.get(0).rule());
        assertEquals(Severity.HIGH, a.get(0).severity());
        assertEquals(4, a.get(0).count());
    }

    @Test
    void twoFailuresThenSuccessNoAlert() {
        List<LogEvent> events = burst(2, 10, "bob", "5.5.5.5");
        events.add(ev("10:01:00", "bob", "5.5.5.5", "SUCCESS"));
        assertTrue(engine.analyze(events).isEmpty());
    }

    @Test
    void adminFailures() {
        List<SecurityAlert> a = engine.analyze(burst(3, 30, "admin", "6.6.6.6"));
        assertEquals(1, a.size());
        assertEquals(DetectionEngine.ADMIN, a.get(0).rule());
        assertEquals(Severity.HIGH, a.get(0).severity());
    }

    @Test
    void offHoursLogin() {
        List<SecurityAlert> a = engine.analyze(List.of(ev("02:00:00", "carol", "7.7.7.7", "SUCCESS")));
        assertEquals(1, a.size());
        assertEquals(DetectionEngine.OFF_HOURS, a.get(0).rule());
        assertEquals(Severity.LOW, a.get(0).severity());
    }

    @Test
    void workingHoursNoAlert() {
        assertTrue(engine.analyze(List.of(ev("10:00:00", "carol", "7.7.7.7", "SUCCESS"))).isEmpty());
    }

    @Test
    void sampleLogProducesSixAlerts() throws Exception {
        List<LogEvent> events = parser.parseFile(Path.of("src/test/resources/small.log")).events();
        List<SecurityAlert> a = engine.analyze(events);
        assertEquals(6, a.size());
        assertEquals(DetectionEngine.OFF_HOURS, a.get(0).rule());
        assertTrue(a.stream().anyMatch(x -> x.severity() == Severity.CRITICAL));
    }
}