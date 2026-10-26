package ui;

import java.awt.*;
import java.util.List;
import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import model.SecurityAlert;
import model.Severity;

/** Alerts table with severity/text filters and a detail view showing the evidence. */
public class AlertPanel extends JPanel {
    private final DefaultTableModel model = Theme.readOnlyModel(
        "ID", "Severity", "Rule", "User", "IP", "First (UTC)", "Last (UTC)", "Events");
    private final JTable table = new JTable(model);
    private final JTextArea detail = new JTextArea(9, 60);
    private final JComboBox<String> severity =
        new JComboBox<>(new String[]{"All", "LOW", "MEDIUM", "HIGH", "CRITICAL"});
    private final JTextField search = new JTextField(16);
    private final JLabel count = new JLabel(" ");
    private List<SecurityAlert> all = List.of();
    private List<SecurityAlert> shown = List.of();

    public AlertPanel() {
        super(new BorderLayout(0, 6));
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        bar.add(new JLabel("Severity")); bar.add(severity);
        bar.add(new JLabel("Search (ID, rule, user, IP)")); bar.add(search);
        bar.add(count);
        severity.addActionListener(e -> apply());
        search.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { apply(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { apply(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { apply(); }
        });

        table.setAutoCreateRowSorter(true);
        table.setRowHeight(22);
        table.getColumnModel().getColumn(1).setCellRenderer(new DefaultTableCellRenderer() {
            @Override public Component getTableCellRendererComponent(
                    JTable t, Object v, boolean sel, boolean foc, int r, int c) {
                Component comp = super.getTableCellRendererComponent(t, v, sel, foc, r, c);
                if (!sel && v instanceof Severity s) {
                    comp.setBackground(Theme.severity(s));
                    comp.setForeground(Color.WHITE);
                } else if (!sel) {
                    comp.setBackground(Color.WHITE);
                    comp.setForeground(Color.BLACK);
                }
                return comp;
            }
        });
        table.getSelectionModel().addListSelectionListener(ev -> {
            int row = table.getSelectedRow();
            if (ev.getValueIsAdjusting() || row < 0) return;
            SecurityAlert a = shown.get(table.convertRowIndexToModel(row));
            detail.setText("Why flagged: " + a.explanation()
                + "\n\nRecommended action: " + a.action()
                + "\n\nEvidence (original log lines):\n" + String.join("\n", a.evidence()));
            detail.setCaretPosition(0);
        });

        detail.setEditable(false);
        detail.setLineWrap(true);
        detail.setWrapStyleWord(true);
        JScrollPane detailScroll = new JScrollPane(detail);
        detailScroll.setBorder(BorderFactory.createTitledBorder("Alert details"));
        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(table), detailScroll);
        split.setResizeWeight(0.55);

        add(bar, BorderLayout.NORTH);
        add(split, BorderLayout.CENTER);
    }

    public void setAlerts(List<SecurityAlert> alerts) {
        all = alerts;
        apply();
    }

    private void apply() {
        String q = search.getText().trim().toLowerCase();
        String sev = (String) severity.getSelectedItem();
        shown = all.stream()
            .filter(a -> sev == null || "All".equals(sev) || a.severity().name().equals(sev))
            .filter(a -> q.isEmpty() || (a.id() + " " + a.rule() + " " + Theme.nz(a.username())
                + " " + Theme.nz(a.ip())).toLowerCase().contains(q))
            .toList();
        model.setRowCount(0);
        detail.setText("");
        for (SecurityAlert a : shown) {
            model.addRow(new Object[]{a.id(), a.severity(), a.rule(), Theme.nz(a.username()),
                Theme.nz(a.ip()), Theme.TIME.format(a.first()), Theme.TIME.format(a.last()), a.count()});
        }
        count.setText("   " + shown.size() + " of " + all.size() + " alerts");
    }
}