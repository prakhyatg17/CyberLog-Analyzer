package ui;

import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import javax.swing.BorderFactory;
import javax.swing.JPanel;

/** A simple bar chart drawn with Java2D. */
public class BarChartPanel extends JPanel {
    private final String title;
    private List<String> labels = new ArrayList<>();
    private List<Integer> values = new ArrayList<>();
    private List<Color> colors = new ArrayList<>();

    public BarChartPanel(String title) {
        this.title = title;
        setBackground(Color.WHITE);
        setBorder(BorderFactory.createLineBorder(new Color(210, 214, 220)));
        setPreferredSize(new Dimension(380, 220));
    }

    public void setData(List<String> labels, List<Integer> values, List<Color> colors) {
        this.labels = new ArrayList<>(labels);
        this.values = new ArrayList<>(values);
        this.colors = new ArrayList<>(colors);
        repaint();
    }

    @Override
    protected void paintComponent(Graphics g0) {
        super.paintComponent(g0);
        Graphics2D g = (Graphics2D) g0.create();
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g.setColor(Theme.NAVY);
        g.setFont(new Font("SansSerif", Font.BOLD, 14));
        g.drawString(title, 12, 22);

        int max = values.stream().mapToInt(Integer::intValue).max().orElse(0);
        if (max == 0) {
            g.setColor(Color.GRAY);
            g.setFont(new Font("SansSerif", Font.PLAIN, 12));
            g.drawString("No data yet", 12, 50);
            g.dispose();
            return;
        }
        int top = 45, bottom = 28, side = 12;
        int chartH = getHeight() - top - bottom;
        int slot = (getWidth() - 2 * side) / values.size();
        int barW = Math.min(60, slot - 14);
        g.setFont(new Font("SansSerif", Font.PLAIN, 12));
        FontMetrics fm = g.getFontMetrics();
        g.setColor(Color.LIGHT_GRAY);
        g.drawLine(side, top + chartH, getWidth() - side, top + chartH);

        for (int i = 0; i < values.size(); i++) {
            int bh = (int) ((double) values.get(i) / max * chartH);
            int x = side + i * slot + (slot - barW) / 2;
            int y = top + chartH - bh;
            g.setColor(colors.get(i));
            g.fillRoundRect(x, y, barW, bh, 6, 6);
            g.setColor(Color.DARK_GRAY);
            String v = String.valueOf(values.get(i));
            g.drawString(v, x + (barW - fm.stringWidth(v)) / 2, y - 4);
            String l = labels.get(i);
            if (fm.stringWidth(l) > slot - 4) l = l.substring(0, Math.min(l.length(), 8)) + "..";
            g.drawString(l, side + i * slot + (slot - fm.stringWidth(l)) / 2, top + chartH + 18);
        }
        g.dispose();
    }
}