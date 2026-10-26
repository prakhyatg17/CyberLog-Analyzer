package ui;

import analyzer.DetectionEngine;
import analyzer.RuleManager;
import java.awt.*;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableModel;
import model.LogEvent;
import model.LogEvent.Result;
import model.SecurityAlert;
import model.Severity;
import parser.ParseResult;
import parser.SampleLogParser;
import java.time.Instant;
import reports.CSVReportGenerator;
import reports.PDFReportGenerator;
import reports.ReportData;

public class Dashboard extends JFrame {
    private List<LogEvent> events = new ArrayList<>();
    private List<SecurityAlert> alerts = new ArrayList<>();
    private List<String> errors = new ArrayList<>();
    private String fileName = "none";
    private boolean analyzed = false;
        private Instant importedAt;

    private final LogTablePanel logPanel = new LogTablePanel();
    private final AlertPanel alertPanel = new AlertPanel();
    private final JTabbedPane tabs = new JTabbedPane();
    private final JLabel status = new JLabel(" ");
    private final JLabel lblTotal = valueLabel(), lblSuccess = valueLabel(), lblFailed = valueLabel(),
                         lblIps = valueLabel(), lblAlerts = valueLabel();
    private final BarChartPanel severityChart = new BarChartPanel("Alerts by severity");
    private final BarChartPanel ipChart = new BarChartPanel("Top IPs by failed logins");
    private final DefaultTableModel recentModel = Theme.readOnlyModel(
        "Time (UTC)", "Event", "User", "IP", "Result", "Description");
    private final JTextArea skipped = new JTextArea();

    public Dashboard() {
        super("Cyber Log Analyzer");
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setLayout(new BorderLayout());
        skipped.setEditable(false);

        tabs.addTab("Overview", buildOverview());
        tabs.addTab("Events", logPanel);
        tabs.addTab("Alerts", alertPanel);
        tabs.addTab("Skipped Lines", new JScrollPane(skipped));
        status.setBorder(BorderFactory.createEmptyBorder(6, 12, 6, 12));
        add(buildHeader(), BorderLayout.NORTH);
        add(tabs, BorderLayout.CENTER);
        add(status, BorderLayout.SOUTH);

        setSize(1200, 780);
        setLocationRelativeTo(null);
        Path sample = Path.of("src/main/resources/sample.log");
        if (Files.exists(sample)) loadFile(sample); else refresh();
    }

    // ---------- layout ----------
    private JPanel buildHeader() {
        JPanel p = new JPanel(new BorderLayout());
        p.setBackground(Theme.NAVY);
        p.setBorder(BorderFactory.createEmptyBorder(10, 14, 10, 14));
        JLabel title = new JLabel("Cyber Log Analyzer");
        title.setForeground(Theme.ACCENT);
        title.setFont(new Font("SansSerif", Font.BOLD, 22));
        JPanel btns = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        btns.setOpaque(false);
        btns.add(button("Import Log...", e -> importLog()));
        btns.add(button("Analyze", e -> analyze()));
        btns.add(button("View Alerts", e -> tabs.setSelectedIndex(2)));
                btns.add(button("Export Report", e -> exportReport()));
        btns.add(button("Clear", e -> clearAll()));
        p.add(title, BorderLayout.WEST);
        p.add(btns, BorderLayout.EAST);
        return p;
    }

    private JPanel buildOverview() {
        JPanel cards = new JPanel(new GridLayout(1, 5, 10, 0));
        cards.add(card("Events analyzed", lblTotal, Theme.ACCENT));
        cards.add(card("Successful logins", lblSuccess, new Color(34, 197, 94)));
        cards.add(card("Failed logins", lblFailed, new Color(239, 68, 68)));
        cards.add(card("Suspicious IPs", lblIps, new Color(245, 158, 11)));
        cards.add(card("Alerts", lblAlerts, new Color(168, 85, 247)));

        JPanel charts = new JPanel(new GridLayout(1, 2, 10, 0));
        charts.add(severityChart);
        charts.add(ipChart);

        JScrollPane recent = new JScrollPane(new JTable(recentModel));
        recent.setBorder(BorderFactory.createTitledBorder("Recent security events"));
        recent.setPreferredSize(new Dimension(100, 200));

        JPanel p = new JPanel(new BorderLayout(0, 10));
        p.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
        p.add(cards, BorderLayout.NORTH);
        p.add(charts, BorderLayout.CENTER);
        p.add(recent, BorderLayout.SOUTH);
        return p;
    }

    private static JLabel valueLabel() {
        JLabel l = new JLabel("0");
        l.setFont(new Font("SansSerif", Font.BOLD, 28));
        return l;
    }

    private JPanel card(String title, JLabel value, Color accent) {
        JPanel c = new JPanel(new BorderLayout());
        c.setBackground(Theme.CARD);
        c.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(0, 4, 0, 0, accent),
            BorderFactory.createEmptyBorder(10, 14, 10, 14)));
        JLabel t = new JLabel(title);
        t.setForeground(new Color(148, 163, 184));
        value.setForeground(Color.WHITE);
        c.add(t, BorderLayout.NORTH);
        c.add(value, BorderLayout.CENTER);
        return c;
    }

    private JButton button(String text, ActionListener l) {
        JButton b = new JButton(text);
        b.addActionListener(l);
        return b;
    }

    // ---------- actions ----------
    private void importLog() {
        JFileChooser fc = new JFileChooser(".");
        fc.setFileFilter(new FileNameExtensionFilter("Log files (*.log, *.txt, *.csv)", "log", "txt", "csv"));
        if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) loadFile(fc.getSelectedFile().toPath());
    }

    private void loadFile(Path path) {
        String name = path.getFileName().toString().toLowerCase();
        if (!(name.endsWith(".log") || name.endsWith(".txt") || name.endsWith(".csv"))) {
            problem("Unsupported file type. Use .log, .txt or .csv.");
            return;
        }
        try {
            if (!Files.isReadable(path) || Files.isDirectory(path)) { problem("File is not readable."); return; }
            if (Files.size(path) == 0) { problem("File is empty."); return; }
            ParseResult r = new SampleLogParser().parseFile(path);
            events = new ArrayList<>(r.events());
            errors = new ArrayList<>(r.errors());
            alerts = new ArrayList<>();
            analyzed = false;
            fileName = path.getFileName().toString();
            importedAt = Instant.now();
            refresh();
            if (events.isEmpty()) problem("No valid log entries found. See the 'Skipped Lines' tab.");
        } catch (IOException ex) {
            problem("Could not read file: " + ex.getMessage());
        }
    }

    private void analyze() {
        if (events.isEmpty()) { problem("Import a log file first."); return; }
        alerts = new DetectionEngine(new RuleManager()).analyze(events);
        analyzed = true;
        refresh();
    }

    private void clearAll() {
        events = new ArrayList<>();
        alerts = new ArrayList<>();
        errors = new ArrayList<>();
        fileName = "none";
        analyzed = false;
        importedAt = null;
        refresh();
    }
    private ReportData reportData() {
        long ok = events.stream().filter(e -> isLogin(e, Result.SUCCESS)).count();
        long bad = events.stream().filter(e -> isLogin(e, Result.FAILURE)).count();
        RuleManager r = new RuleManager();
        String rules = "Brute force: " + r.bruteForceThreshold + " failures from one IP within "
            + r.bruteForceWindowSec + "s. Success after failures: " + r.failuresBeforeSuccess
            + "+ failures within " + r.successLookbackSec + "s. Admin failures: " + r.adminThreshold
            + " within " + r.adminWindowSec + "s on " + new java.util.TreeSet<>(r.adminNames)
            + ". Working hours (UTC): " + r.workStartHour + ":00-" + r.workEndHour
            + ":00. Username guessing: " + r.distinctUsersThreshold + " different usernames within "
            + r.distinctUsersWindowSec + "s.";
        return new ReportData(fileName, importedAt, events.size(), errors.size(),
            ok, bad, rules, alerts);
    }

    private void exportReport() {
        if (!analyzed) { problem("Import a log and click Analyze first."); return; }
        String[] options = {"PDF", "CSV", "Cancel"};
        int choice = JOptionPane.showOptionDialog(this, "Choose report format", "Export Report",
            JOptionPane.DEFAULT_OPTION, JOptionPane.QUESTION_MESSAGE, null, options, options[0]);
        if (choice != 0 && choice != 1) return;
        boolean pdf = choice == 0;
        String ext = pdf ? ".pdf" : ".csv";
        JFileChooser fc = new JFileChooser(".");
        fc.setSelectedFile(new java.io.File("security-report" + ext));
        if (fc.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;
        Path out = fc.getSelectedFile().toPath();
        if (!out.getFileName().toString().toLowerCase().endsWith(ext)) {
            out = out.resolveSibling(out.getFileName() + ext);
        }
        if (Files.exists(out) && JOptionPane.showConfirmDialog(this,
                "Overwrite " + out.getFileName() + "?", "File exists",
                JOptionPane.YES_NO_OPTION) != JOptionPane.YES_OPTION) return;
        try {
            if (pdf) PDFReportGenerator.write(out, reportData());
            else CSVReportGenerator.write(out, reportData());
            JOptionPane.showMessageDialog(this, "Report saved to:\n" + out.toAbsolutePath(),
                "Export complete", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) {
            problem("Could not create report: " + ex.getMessage());
        }
    }
    
    private void problem(String msg) {
        JOptionPane.showMessageDialog(this, msg, "Import problem", JOptionPane.ERROR_MESSAGE);
    }

    // ---------- update every widget from the current data ----------
    private void refresh() {
        lblTotal.setText(String.valueOf(events.size()));
        lblSuccess.setText(String.valueOf(events.stream().filter(e -> isLogin(e, Result.SUCCESS)).count()));
        lblFailed.setText(String.valueOf(events.stream().filter(e -> isLogin(e, Result.FAILURE)).count()));
        Set<String> ips = alerts.stream().map(SecurityAlert::ip).filter(Objects::nonNull)
            .flatMap(s -> Arrays.stream(s.split(",\\s*"))).collect(Collectors.toSet());
        lblIps.setText(analyzed ? String.valueOf(ips.size()) : "-");
        lblAlerts.setText(analyzed ? String.valueOf(alerts.size()) : "-");

        List<String> names = new ArrayList<>();
        List<Integer> vals = new ArrayList<>();
        List<Color> cols = new ArrayList<>();
        for (Severity s : Severity.values()) {
            names.add(s.name());
            vals.add((int) alerts.stream().filter(a -> a.severity() == s).count());
            cols.add(Theme.severity(s));
        }
        severityChart.setData(names, vals, cols);

        Map<String, Long> byIp = events.stream().filter(e -> isLogin(e, Result.FAILURE) && e.ip() != null)
            .collect(Collectors.groupingBy(LogEvent::ip, Collectors.counting()));
        List<Map.Entry<String, Long>> top = byIp.entrySet().stream()
            .sorted(Map.Entry.<String, Long>comparingByValue().reversed()).limit(5).toList();
        ipChart.setData(top.stream().map(Map.Entry::getKey).toList(),
            top.stream().map(en -> en.getValue().intValue()).toList(),
            top.stream().map(en -> new Color(59, 130, 246)).toList());

        recentModel.setRowCount(0);
        events.stream().sorted(Comparator.comparing(LogEvent::timestamp).reversed()).limit(8)
            .forEach(e -> recentModel.addRow(new Object[]{Theme.TIME.format(e.timestamp()), e.eventType(),
                Theme.nz(e.username()), Theme.nz(e.ip()), e.result(), e.description()}));

        logPanel.setEvents(events);
        alertPanel.setAlerts(alerts);
        skipped.setText(String.join("\n", errors));
        status.setText("File: " + fileName + "  |  " + events.size() + " events  |  "
            + errors.size() + " lines skipped  |  "
            + (analyzed ? alerts.size() + " alerts" : "not analyzed yet"));
    }

    private static boolean isLogin(LogEvent e, Result r) {
        return "LOGIN".equals(e.eventType()) && e.result() == r;
    }
}