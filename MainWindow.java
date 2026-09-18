package securepass.gui;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.filechooser.FileNameExtensionFilter;

import securepass.analyzer.PasswordAnalyzer;
import securepass.model.SecurityReport;
import securepass.util.ReportExporter;

/**
 * The main application window: a tabbed frame holding the Password Analyzer, the
 * Password Generator, the Security Report and the About page.
 *
 * <p>The window owns the most recent {@link SecurityReport}. Both the analyzer and the
 * generator hand their results here through a callback, and the report tab displays
 * whichever one arrived last.</p>
 */
public class MainWindow extends JFrame {

    private static final long serialVersionUID = 1L;

    private static final String APP_TITLE = "SecurePass - Password Security Analyzer & Generator";

    private final PasswordAnalyzer analyzer = new PasswordAnalyzer();

    private final JTabbedPane tabs = new JTabbedPane();
    private final JTextArea reportArea = new JTextArea();
    private final JButton exportButton = new JButton("Export Report...");
    private final JLabel reportStatus = new JLabel("No report yet - analyze or generate a password first.");

    private AnalyzerPanel analyzerPanel;
    private GeneratorPanel generatorPanel;

    /** The latest report; null until a password has been analyzed. */
    private SecurityReport currentReport;

    /** Builds and lays out the window. Call {@link #showWindow()} to display it. */
    public MainWindow() {
        super(APP_TITLE);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setMinimumSize(new Dimension(760, 620));

        analyzerPanel = new AnalyzerPanel(analyzer, this::setCurrentReport);
        generatorPanel = new GeneratorPanel(analyzer, this::setCurrentReport);

        tabs.addTab("Password Analyzer", analyzerPanel);
        tabs.addTab("Password Generator", generatorPanel);
        tabs.addTab("Security Report", buildReportPanel());
        tabs.addTab("About", buildAboutPanel());

        setLayout(new BorderLayout());
        add(buildHeader(), BorderLayout.NORTH);
        add(tabs, BorderLayout.CENTER);
        add(buildFooter(), BorderLayout.SOUTH);

        pack();
        setLocationRelativeTo(null);
    }

    private JPanel buildHeader() {
        JPanel header = new JPanel(new BorderLayout());
        header.setBorder(BorderFactory.createEmptyBorder(12, 16, 8, 16));

        JLabel title = new JLabel("SecurePass");
        title.setFont(title.getFont().deriveFont(Font.BOLD, 22f));
        header.add(title, BorderLayout.NORTH);

        JLabel subtitle = new JLabel("Offline password analysis and generation - nothing leaves this computer.");
        subtitle.setFont(subtitle.getFont().deriveFont(Font.PLAIN, 12f));
        header.add(subtitle, BorderLayout.SOUTH);

        return header;
    }

    private JPanel buildFooter() {
        JPanel footer = new JPanel(new FlowLayout(FlowLayout.LEFT, 16, 6));
        JLabel credit = new JLabel("Praveen P B (24BCY10026) - Programming in Java, Evaluated Project");
        credit.setFont(credit.getFont().deriveFont(Font.PLAIN, 11f));
        footer.add(credit);
        return footer;
    }

    private JPanel buildReportPanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));

        reportArea.setEditable(false);
        reportArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        reportArea.setText("No report yet.\n\n"
                + "Analyze a password on the Password Analyzer tab, or generate one on the\n"
                + "Password Generator tab, and the report will appear here.\n\n"
                + "The report contains analysis data only - never the password itself.");
        reportArea.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        JScrollPane scroll = new JScrollPane(reportArea);
        scroll.setPreferredSize(new Dimension(700, 420));
        panel.add(scroll, BorderLayout.CENTER);

        JPanel controls = new JPanel(new BorderLayout(8, 8));
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        buttons.add(exportButton);
        controls.add(buttons, BorderLayout.WEST);

        reportStatus.setFont(reportStatus.getFont().deriveFont(Font.ITALIC, 11f));
        controls.add(reportStatus, BorderLayout.SOUTH);
        panel.add(controls, BorderLayout.SOUTH);

        exportButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent event) {
                exportReport();
            }
        });

        return panel;
    }

    private JPanel buildAboutPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));

        JTextArea about = new JTextArea();
        about.setEditable(false);
        about.setLineWrap(true);
        about.setWrapStyleWord(true);
        about.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        about.setFont(about.getFont().deriveFont(Font.PLAIN, 13f));
        about.setText(aboutText());
        about.setCaretPosition(0);

        panel.add(new JScrollPane(about), BorderLayout.CENTER);
        return panel;
    }

    private static String aboutText() {
        StringBuilder text = new StringBuilder();
        String nl = System.lineSeparator();

        text.append("SecurePass - Password Security Analyzer & Generator").append(nl).append(nl);
        text.append("Praveen P B  |  Registration Number 24BCY10026").append(nl);
        text.append("Programming in Java - Evaluated Project").append(nl).append(nl);

        text.append("WHAT IT DOES").append(nl);
        text.append("SecurePass rates the strength of a password and explains the rating, rule ")
            .append("by rule, instead of showing a coloured bar with no reasoning behind it. ")
            .append("It also generates strong passwords using java.security.SecureRandom.").append(nl).append(nl);

        text.append("PRIVACY").append(nl);
        text.append("- The application makes no network calls of any kind.").append(nl);
        text.append("- Passwords are read as char[] and overwritten after use, never stored as String.").append(nl);
        text.append("- Exported reports contain derived analysis data only. ReportExporter has no ")
            .append("parameter through which a password could be passed in.").append(nl).append(nl);

        text.append("HOW THE SCORE WORKS").append(nl);
        text.append("Base 20 points, up to 40 for length, up to 40 for character variety, minus a ")
            .append("penalty for each failed check, clamped to 0-100. These weights are a ")
            .append("documented convention chosen for clarity, not an empirically validated ")
            .append("security model.").append(nl).append(nl);

        text.append("LIMITATIONS").append(nl);
        text.append("- Entropy uses L x log2(R), which assumes uniformly random characters and ")
            .append("therefore overstates human-chosen passwords.").append(nl);
        text.append("- The bundled common-password list is a small educational sample, not a full ")
            .append("breached-password corpus.").append(nl);
        text.append("- SecurePass never claims a password is unbreakable. It reports only which ")
            .append("specific checks passed and which failed.").append(nl);

        return text.toString();
    }

    /**
     * Stores a new report and refreshes the report tab.
     *
     * @param report the report to display; ignored if null
     */
    public void setCurrentReport(SecurityReport report) {
        if (report == null) {
            return;
        }
        this.currentReport = report;
        reportArea.setText(report.toPlainText());
        reportArea.setCaretPosition(0);
        reportStatus.setText("Report generated at " + report.getFormattedTimestamp()
                + " - contains analysis data only.");
    }

    /** @return the most recent report, or null if none has been produced */
    public SecurityReport getCurrentReport() {
        return currentReport;
    }

    private void exportReport() {
        if (currentReport == null) {
            JOptionPane.showMessageDialog(this,
                    "Analyze or generate a password first - there is nothing to export yet.",
                    "No report", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export security report");
        chooser.setSelectedFile(new File(ReportExporter.DEFAULT_FILE_NAME));
        chooser.setFileFilter(new FileNameExtensionFilter("Text files (*.txt)", "txt"));

        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }

        File destination = ReportExporter.withTextExtension(chooser.getSelectedFile());
        if (destination.exists()) {
            int overwrite = JOptionPane.showConfirmDialog(this,
                    destination.getName() + " already exists. Replace it?",
                    "Confirm overwrite", JOptionPane.YES_NO_OPTION);
            if (overwrite != JOptionPane.YES_OPTION) {
                return;
            }
        }

        try {
            ReportExporter.export(currentReport, destination);
            reportStatus.setText("Exported to " + destination.getAbsolutePath());
            JOptionPane.showMessageDialog(this,
                    "Report saved to:\n" + destination.getAbsolutePath()
                            + "\n\nThe file contains analysis data only - not the password.",
                    "Export complete", JOptionPane.INFORMATION_MESSAGE);
        } catch (IOException e) {
            JOptionPane.showMessageDialog(this,
                    "The report could not be saved.\n\nReason: " + e.getMessage(),
                    "Export failed", JOptionPane.ERROR_MESSAGE);
        } catch (IllegalArgumentException e) {
            JOptionPane.showMessageDialog(this, e.getMessage(),
                    "Export failed", JOptionPane.WARNING_MESSAGE);
        }
    }

    /** Makes the window visible and puts the cursor in the password field. */
    public void showWindow() {
        setVisible(true);
        analyzerPanel.focusInput();
    }
}
