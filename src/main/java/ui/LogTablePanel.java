package ui;

import java.awt.*;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.TreeSet;
import java.util.stream.Collectors;
import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableModel;
import model.LogEvent;

/** Searchable, filterable table of all parsed log events. */
public class LogTablePanel extends JPanel {
    private final DefaultTableModel model = Theme.readOnlyModel(
        "Line", "Time (UTC)", "Event", "User", "IP", "Result", "Description");
    private final JTextField search = new JTextField(14);
    private final JTextField user = new JTextField(8);
    private final JTextField ip = new JTextField(9);
    private final JTextField from = new JTextField(8);
    private final JTextField to = new JTextField(8);
    private final JComboBox<String> type = new JComboBox<>(new String[]{"All"});
    private final JLabel count = new JLabel(" ");
    private List<LogEvent> all = List.of();

    public LogTablePanel() {
        super(new BorderLayout(0, 6));
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        from.setToolTipText("yyyy-MM-dd");
        to.setToolTipText("yyyy-MM-dd");

        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        bar.add(new JLabel("Search")); bar.add(search);
        bar.add(new JLabel("User")); bar.add(user);
        bar.add(new JLabel("IP")); bar.add(ip);
        bar.add(new JLabel("Event")); bar.add(type);
        bar.add(new JLabel("From")); bar.add(from);
        bar.add(new JLabel("To")); bar.add(to);
        JButton reset = new JButton("Reset filters");
        reset.addActionListener(e -> {
            search.setText(""); user.setText(""); ip.setText("");
            from.setText(""); to.setText(""); type.setSelectedIndex(0);
        });
        bar.add(reset);

        for (JTextField f : new JTextField[]{search, user, ip, from, to}) {
            f.getDocument().addDocumentListener(new DocumentListener() {
                public void insertUpdate(DocumentEvent e) { apply(); }
                public void removeUpdate(DocumentEvent e) { apply(); }
                public void changedUpdate(DocumentEvent e) { apply(); }
            });
        }
        type.addActionListener(e -> apply());

        JTable table = new JTable(model);
        table.setAutoCreateRowSorter(true);
        table.setRowHeight(22);
        add(bar, BorderLayout.NORTH);
        add(new JScrollPane(table), BorderLayout.CENTER);
        add(count, BorderLayout.SOUTH);
    }

    public void setEvents(List<LogEvent> events) {
        all = events;
        DefaultComboBoxModel<String> m = new DefaultComboBoxModel<>();
        m.addElement("All");
        events.stream().map(LogEvent::eventType)
              .collect(Collectors.toCollection(TreeSet::new)).forEach(m::addElement);
        type.setModel(m);
        apply();
    }

    private void apply() {
        String q = search.getText().trim().toLowerCase();
        String u = user.getText().trim().toLowerCase();
        String ipText = ip.getText().trim();
        String t = (String) type.getSelectedItem();
        LocalDate d1 = parseDate(from), d2 = parseDate(to);

        List<LogEvent> shown = all.stream()
            .filter(e -> q.isEmpty() || e.rawLine().toLowerCase().contains(q))
            .filter(e -> u.isEmpty() || (e.username() != null && e.username().toLowerCase().contains(u)))
            .filter(e -> ipText.isEmpty() || (e.ip() != null && e.ip().contains(ipText)))
            .filter(e -> t == null || "All".equals(t) || e.eventType().equals(t))
            .filter(e -> {
                LocalDate d = e.timestamp().atZone(ZoneOffset.UTC).toLocalDate();
                return (d1 == null || !d.isBefore(d1)) && (d2 == null || !d.isAfter(d2));
            }).toList();

        model.setRowCount(0);
        for (LogEvent e : shown) {
            model.addRow(new Object[]{e.lineNumber(), Theme.TIME.format(e.timestamp()), e.eventType(),
                Theme.nz(e.username()), Theme.nz(e.ip()), e.result(), e.description()});
        }
        count.setText("Showing " + shown.size() + " of " + all.size() + " events");
    }

    /** Empty means "no limit". An invalid date turns the box red and is ignored. */
    private LocalDate parseDate(JTextField f) {
        f.setBackground(Color.WHITE);
        String s = f.getText().trim();
        if (s.isEmpty()) return null;
        try {
            return LocalDate.parse(s);
        } catch (DateTimeParseException ex) {
            f.setBackground(new Color(255, 200, 200));
            return null;
        }
    }
}