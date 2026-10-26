package app;

import javax.swing.SwingUtilities;
import ui.Dashboard;

public class Main {
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new Dashboard().setVisible(true));
    }
}