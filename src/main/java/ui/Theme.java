package ui;

import java.awt.Color;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import javax.swing.table.DefaultTableModel;
import model.Severity;

/** Shared colours, time format and small helpers. */
public final class Theme {
    private Theme() { }

    public static final Color NAVY = new Color(15, 23, 42);
    public static final Color CARD = new Color(30, 41, 59);
    public static final Color ACCENT = new Color(56, 189, 248);
    public static final DateTimeFormatter TIME =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneOffset.UTC);

    public static Color severity(Severity s) {
        return switch (s) {
            case LOW -> new Color(34, 197, 94);
            case MEDIUM -> new Color(202, 138, 4);
            case HIGH -> new Color(249, 115, 22);
            case CRITICAL -> new Color(220, 38, 38);
        };
    }

    public static String nz(String s) { return s == null ? "-" : s; }

    /** Read-only table model whose columns sort by their real type (numbers sort as numbers). */
    public static DefaultTableModel readOnlyModel(String... cols) {
        return new DefaultTableModel(cols, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
            @Override public Class<?> getColumnClass(int c) {
                return getRowCount() > 0 && getValueAt(0, c) != null
                    ? getValueAt(0, c).getClass() : Object.class;
            }
        };
    }
}