package analyzer;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import model.LogEvent;

public class EventCorrelator {

    /** Groups events by a key (for example IP). Events with a null key are skipped. */
    public static <K> Map<K, List<LogEvent>> groupBy(List<LogEvent> events, Function<LogEvent, K> key) {
        Map<K, List<LogEvent>> map = new LinkedHashMap<>();
        for (LogEvent e : events) {
            K k = key.apply(e);
            if (k != null) map.computeIfAbsent(k, x -> new ArrayList<>()).add(e);
        }
        return map;
    }

    /**
     * Rolling window: finds bursts where at least 'threshold' events fall within 'windowSec' seconds.
     * Overlapping windows are merged into one burst. Input must be sorted by time.
     */
    public static List<List<LogEvent>> clusters(List<LogEvent> sorted, int threshold, long windowSec) {
        List<List<LogEvent>> out = new ArrayList<>();
        int left = 0, start = -1, end = -1;
        for (int r = 0; r < sorted.size(); r++) {
            while (Duration.between(sorted.get(left).timestamp(), sorted.get(r).timestamp())
                           .getSeconds() > windowSec) {
                left++;
            }
            if (r - left + 1 >= threshold) {
                if (start == -1) start = left;
                end = r;
            } else if (start != -1) {
                out.add(new ArrayList<>(sorted.subList(start, end + 1)));
                start = -1;
            }
        }
        if (start != -1) out.add(new ArrayList<>(sorted.subList(start, end + 1)));
        return out;
    }
}