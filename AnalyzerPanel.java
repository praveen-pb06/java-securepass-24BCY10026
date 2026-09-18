package securepass.gui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Arrays;
import java.util.List;
import java.util.function.Consumer;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingConstants;

import securepass.analyzer.EntropyCalculator;
import securepass.analyzer.PasswordAnalyzer;
import securepass.analyzer.SecurityCheck;
import securepass.model.PasswordResult;
import securepass.model.SecurityReport;
import securepass.util.InputValidator;

/**
 * The Password Analyzer tab.
 *
 * <p>The password is read from a {@link JPasswordField} as a {@code char[]}, passed
 * straight to the analyzer, and then overwritten with zeros in a {@code finally} block.
 * It is never converted into a String and never held in a field of this class.</p>
 */
public class AnalyzerPanel extends JPanel {

    private static final long serialVersionUID = 1L;

    private final PasswordAnalyzer analyzer;
    private final Consumer<SecurityReport> reportListener;

    private final JPasswordField passwordField = new JPasswordField(24);
    private final JCheckBox showPasswordBox = new JCheckBox("Show password");
    private final JButton analyzeButton = new JButton("Analyze");
    private final JButton clearButton = new JButton("Clear");

    private final JLabel strengthLabel = new JLabel("Not analyzed yet", SwingConstants.LEFT);
    private final JProgressBar scoreBar = new JProgressBar(0, 100);
    private final JLabel entropyLabel = new JLabel(" ");
    private final JTextArea detailArea = new JTextArea();

    private char defaultEchoChar;

    /**
     * @param analyzer       the analyzer to use; must not be null
     * @param reportListener notified whenever a new report is produced; may be null
     */
    public AnalyzerPanel(PasswordAnalyzer analyzer, Consumer<SecurityReport> reportListener) {
        if (analyzer == null) {
            throw new IllegalArgumentException("Analyzer must not be null.");
        }
        this.analyzer = analyzer;
        this.reportListener = reportListener;
        this.defaultEchoChar = passwordField.getEchoChar();

        setLayout(new BorderLayout(10, 10));
        setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));

        add(buildInputPanel(), BorderLayout.NORTH);
        add(buildResultPanel(), BorderLayout.CENTER);

        wireActions();
    }

    private JPanel buildInputPanel() {
        JPanel input = new JPanel(new BorderLayout(8, 8));
        input.setBorder(BorderFactory.createTitledBorder("Enter a password to analyze"));

        JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 8));
        row.add(new JLabel("Password:"));
        row.add(passwordField);
        row.add(showPasswordBox);
        row.add(analyzeButton);
        row.add(clearButton);
        input.add(row, BorderLayout.CENTER);

        JLabel privacy = new JLabel(
                "The password is analyzed on this computer only. It is never saved, logged or sent anywhere.");
        privacy.setFont(privacy.getFont().deriveFont(Font.ITALIC, 11f));
        privacy.setBorder(BorderFactory.createEmptyBorder(0, 10, 6, 10));
        input.add(privacy, BorderLayout.SOUTH);

        return input;
    }

    private JPanel buildResultPanel() {
        JPanel results = new JPanel(new BorderLayout(8, 8));
        results.setBorder(BorderFactory.createTitledBorder("Results"));

        JPanel summary = new JPanel(new GridLayout(3, 1, 4, 4));
        summary.setBorder(BorderFactory.createEmptyBorder(8, 10, 8, 10));

        strengthLabel.setFont(strengthLabel.getFont().deriveFont(Font.BOLD, 16f));
        summary.add(strengthLabel);

        scoreBar.setStringPainted(true);
        scoreBar.setString("Score: -");
        scoreBar.setPreferredSize(new Dimension(300, 20));
        summary.add(scoreBar);

        summary.add(entropyLabel);
        results.add(summary, BorderLayout.NORTH);

        detailArea.setEditable(false);
        detailArea.setLineWrap(true);
        detailArea.setWrapStyleWord(true);
        detailArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        detailArea.setText("Type a password above and click Analyze.\n\n"
                + "SecurePass will show which individual checks passed or failed, and why.");
        detailArea.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        JScrollPane scroll = new JScrollPane(detailArea);
        scroll.setPreferredSize(new Dimension(640, 300));
        results.add(scroll, BorderLayout.CENTER);

        return results;
    }

    private void wireActions() {
        analyzeButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent event) {
                runAnalysis();
            }
        });

        // Pressing Enter in the password field analyzes too.
        passwordField.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent event) {
                runAnalysis();
            }
        });

        clearButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent event) {
                clearAll();
            }
        });

        showPasswordBox.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent event) {
                passwordField.setEchoChar(showPasswordBox.isSelected() ? (char) 0 : defaultEchoChar);
            }
        });
    }

    /** Reads the field, analyzes it, displays the outcome, then wipes the characters. */
    private void runAnalysis() {
        char[] password = passwordField.getPassword();
        try {
            InputValidator.validatePasswordInput(password);
            PasswordResult result = analyzer.analyze(password);
            display(result);

            SecurityReport report = new SecurityReport(result);
            if (reportListener != null) {
                reportListener.accept(report);
            }
        } catch (IllegalArgumentException e) {
            JOptionPane.showMessageDialog(this, e.getMessage(),
                    "Cannot analyze", JOptionPane.WARNING_MESSAGE);
        } finally {
            // The password leaves memory here, whatever happened above.
            Arrays.fill(password, '\0');
        }
    }

    /**
     * Analyzes a password supplied by another panel, such as a freshly generated one.
     *
     * @param password the characters to analyze; the caller still owns and clears them
     */
    public void analyzeExternal(char[] password) {
        if (!InputValidator.isUsablePassword(password)) {
            return;
        }
        PasswordResult result = analyzer.analyze(password);
        display(result);
        if (reportListener != null) {
            reportListener.accept(new SecurityReport(result));
        }
    }

    private void display(PasswordResult result) {
        strengthLabel.setText("Strength: " + result.getStrength().getLabel());
        strengthLabel.setForeground(colourFor(result.getStrength()));

        scoreBar.setValue(result.getScore());
        scoreBar.setString("Score: " + result.getScore() + " / 100");
        scoreBar.setForeground(colourFor(result.getStrength()));

        entropyLabel.setText(String.format("Estimated entropy: %.1f bits  (%s)",
                result.getEntropyBits(), EntropyCalculator.describeEntropy(result.getEntropyBits())));

        StringBuilder text = new StringBuilder();
        text.append("SECURITY CHECKS (")
            .append(result.getPassedCount()).append(" of ")
            .append(result.getTotalCheckCount()).append(" passed)")
            .append(System.lineSeparator())
            .append("------------------------------------------------------------")
            .append(System.lineSeparator());

        for (SecurityCheck.CheckResult check : result.getCheckResults()) {
            text.append(check.isPassed() ? "[PASS] " : "[FAIL] ")
                .append(check.getCheckName()).append(System.lineSeparator())
                .append("        ").append(check.getDetail()).append(System.lineSeparator());
        }

        text.append(System.lineSeparator())
            .append("RECOMMENDATIONS").append(System.lineSeparator())
            .append("------------------------------------------------------------")
            .append(System.lineSeparator());

        List<String> advice = result.getRecommendations();
        if (advice.isEmpty()) {
            text.append("No issues were found by the checks above. Remember that this is not a")
                .append(System.lineSeparator())
                .append("guarantee - it only means every check listed here passed.")
                .append(System.lineSeparator());
        } else {
            int index = 1;
            for (String item : advice) {
                text.append(index).append(". ").append(item).append(System.lineSeparator());
                index++;
            }
        }

        text.append(System.lineSeparator())
            .append("Length: ").append(result.getLength()).append(" characters   |   ")
            .append("Character types used: ").append(result.getCharacterClassCount()).append(" of 4")
            .append("   |   Pool size: ").append(result.getCharacterPoolSize())
            .append(System.lineSeparator());

        detailArea.setText(text.toString());
        detailArea.setCaretPosition(0);
    }

    private static Color colourFor(PasswordResult.Strength strength) {
        switch (strength) {
            case VERY_WEAK:
                return new Color(178, 34, 34);
            case WEAK:
                return new Color(205, 92, 0);
            case MODERATE:
                return new Color(184, 134, 11);
            case STRONG:
                return new Color(46, 125, 50);
            case VERY_STRONG:
                return new Color(27, 94, 32);
            default:
                return Color.DARK_GRAY;
        }
    }

    /** Clears the field and resets the display. */
    public void clearAll() {
        passwordField.setText("");
        strengthLabel.setText("Not analyzed yet");
        strengthLabel.setForeground(Color.DARK_GRAY);
        scoreBar.setValue(0);
        scoreBar.setString("Score: -");
        entropyLabel.setText(" ");
        detailArea.setText("Type a password above and click Analyze.");
        passwordField.requestFocusInWindow();
    }

    /** Gives the password field keyboard focus when the tab is opened. */
    public void focusInput() {
        passwordField.requestFocusInWindow();
    }
}
