package parser;

import java.util.List;
import model.LogEvent;

/** Valid events plus a readable error for every line that could not be parsed. */
public record ParseResult(List<LogEvent> events, List<String> errors) { }