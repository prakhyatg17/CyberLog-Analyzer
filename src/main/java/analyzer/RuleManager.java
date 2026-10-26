package analyzer;

import java.util.Set;

/** All detection thresholds in one place. Change a value here to tune a rule. */
public class RuleManager {
    public int bruteForceThreshold = 5;          // failures from one IP...
    public long bruteForceWindowSec = 60;        // ...within this many seconds
    public int failuresBeforeSuccess = 3;        // failures before a success looks suspicious
    public long successLookbackSec = 300;
    public Set<String> adminNames = Set.of("admin", "administrator", "root");
    public int adminThreshold = 3;
    public long adminWindowSec = 300;
    public int workStartHour = 9;                // inclusive, UTC
    public int workEndHour = 18;                 // exclusive, UTC
    public int distinctUsersThreshold = 4;       // different usernames tried from one IP...
    public long distinctUsersWindowSec = 60;     // ...within this many seconds
}