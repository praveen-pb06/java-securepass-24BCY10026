package securepass.gui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridLayout;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Arrays;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SpinnerNumberModel;

import securepass.analyzer.EntropyCalculator;
import securepass.analyzer.PasswordAnalyzer;
import securepass.analyzer.SecurityCheck;
import securepass.generator.PasswordGenerator;
import securepass.model.PasswordResult;
import securepass.model.SecurityReport;
import securepass.util.InputValidator;

/**
 * The Password Generator tab.
 *
 * <p>Generates a password with {@link PasswordGenerator}, immediately analyzes it with
 * {@link PasswordAnalyzer} so the user can see why it is strong, and shows the result.
 * The generated characters are cleared as soon as the display has been updated.</p>
 */
public class GeneratorPanel extends JPanel {

    private static final long serialVersionUID = 1L;

    private final PasswordGenerator generator = new PasswordGenerator();
    private final PasswordAnalyzer analyzer;
    private final java.util.function.Consumer<SecurityReport> reportListener;

    private final JSpinner lengthSpinner = new JSpinner(new SpinnerNumberModel(
            PasswordGenerator.DEFAULT_LENGTH,
            InputValidator.MIN_GENERATED_LENGTH,
            InputValidator.MAX_GENERATED_LENGTH,
            1));

    private final JCheckBox lowercaseBox = new JCheckBox("Lowercase (a-z)", true);
    private final JCheckBox uppercaseBox = new JCheckBox("Uppercase (A-Z)", true);
    private final JCheckBox digitsBox = new JCheckBox("Digits (0-9)", true);
    private final JCheckBox symbolsBox = new JCheckBox("Symbols (!@#...)", true);

    private final JButton generateButton = new JButton("Generate");
    private final JButton copyButton = new JButton("Copy");
    private final JButton clearButton = new JButton("Clear");

    private final JTextField outputField = new JTextField(28);
    private final JLabel strengthLabel = new JLabel("No password generated yet");
    private final JTextArea analysisArea = new JTextArea();

    /**
     * @param analyzer       used to analyze each generated password; must not be null
     * @param reportListener notified with the analysis of each generated password; may be null
     */
    public GeneratorPanel(PasswordAnalyzer analyzer,
                          java.util.function.Consumer<SecurityReport> reportListener) {
        if (analyzer == null) {
            throw new IllegalArgumentException("Analyzer must not be null.");
        }
        this.analyzer = analyzer;
        this.reportListener = reportListener;

        setLayout(new BorderLayout(10, 10));
        setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));

        add(buildOptionsPanel(), BorderLayout.NORTH);
        add(buildOutputPanel(), BorderLayout.CENTER);

        wireActions();
    }

    private JPanel buildOptionsPanel() {
        JPanel options = new JPanel(new BorderLayout(8, 8));
        options.setBorder(BorderFactory.createTitledBorder("Generator settings"));

        JPanel lengthRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 8));
        lengthRow.add(new JLabel("Length:"));
        ((JSpinner.DefaultEditor) lengthSpinner.getEditor()).getTextField().setColumns(4);
        lengthRow.add(lengthSpinner);
        lengthRow.add(new JLabel("(" + InputValidator.MIN_GENERATED_LENGTH + " - "
                + InputValidator.MAX_GENERATED_LENGTH + " characters)"));
        options.add(lengthRow, BorderLayout.NORTH);

        JPanel typeRow = new JPanel(new GridLayout(1, 4, 8, 8));
        typeRow.setBorder(BorderFactory.createEmptyBorder(0, 10, 8, 10));
        typeRow.add(lowercaseBox);
        typeRow.add(uppercaseBox);
        typeRow.add(digitsBox);
        typeRow.add(symbolsBox);
        options.add(typeRow, BorderLayout.CENTER);

        JPanel buttonRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 8));
        buttonRow.add(generateButton);
        buttonRow.add(copyButton);
        buttonRow.add(clearButton);
        options.add(buttonRow, BorderLayout.SOUTH);

        return options;
    }

    private JPanel buildOutputPanel() {
        JPanel output = new JPanel(new BorderLayout(8, 8));
        output.setBorder(BorderFactory.createTitledBorder("Generated password"));

        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 8));
        outputField.setEditable(false);
        outputField.setFont(new Font(Font.MONOSPACED, Font.BOLD, 14));
        top.add(outputField);
        output.add(top, BorderLayout.NORTH);

        strengthLabel.setFont(strengthLabel.getFont().deriveFont(Font.BOLD, 14f));
        strengthLabel.setBorder(BorderFactory.createEmptyBorder(0, 12, 6, 12));

        JPanel middle = new JPanel(new BorderLayout());
        middle.add(strengthLabel, BorderLayout.NORTH);

        analysisArea.setEditable(false);
        analysisArea.setLineWrap(true);
        analysisArea.setWrapStyleWord(true);
        analysisArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        analysisArea.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        analysisArea.setText("Choose a length and character types, then click Generate.\n\n"
                + "Every generated password is analyzed straight away so you can see why it "
                + "scores the way it does.");

        JScrollPane scroll = new JScrollPane(analysisArea);
        scroll.setPreferredSize(new Dimension(640, 260));
        middle.add(scroll, BorderLayout.CENTER);
        output.add(middle, BorderLayout.CENTER);

        return output;
    }

    private void wireActions() {
        generateButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent event) {
                generatePassword();
            }
        });

        copyButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent event) {
                copyToClipboard();
            }
        });

        clearButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent event) {
                clearAll();
            }
        });
    }

    private void generatePassword() {
        char[] password = null;
        try {
            int length = ((Integer) lengthSpinner.getValue()).intValue();
            password = generator.generate(length,
                    lowercaseBox.isSelected(),
                    uppercaseBox.isSelected(),
                    digitsBox.isSelected(),
                    symbolsBox.isSelected());

            // The generated password has to be visible for the user to copy it; that is
            // the whole point of the tab. Nothing is written to disk or sent anywhere.
            outputField.setText(new String(password));

            PasswordResult result = analyzer.analyze(password);
            showAnalysis(result);

            if (reportListener != null) {
                reportListener.accept(new SecurityReport(result));
            }
        } catch (IllegalArgumentException e) {
            JOptionPane.showMessageDialog(this, e.getMessage(),
                    "Invalid generator settings", JOptionPane.WARNING_MESSAGE);
        } finally {
            if (password != null) {
                Arrays.fill(password, '\0');
            }
        }
    }

    private void showAnalysis(PasswordResult result) {
        strengthLabel.setText("Strength: " + result.getStrength().getLabel()
                + "   |   Score: " + result.getScore() + " / 100");

        StringBuilder text = new StringBuilder();
        text.append(String.format("Estimated entropy: %.1f bits (%s)",
                result.getEntropyBits(), EntropyCalculator.describeEntropy(result.getEntropyBits())))
            .append(System.lineSeparator())
            .append("Character pool: ").append(result.getCharacterPoolSize())
            .append(" possible characters").append(System.lineSeparator())
            .append(System.lineSeparator())
            .append("SECURITY CHECKS (").append(result.getPassedCount()).append(" of ")
            .append(result.getTotalCheckCount()).append(" passed)").append(System.lineSeparator())
            .append("------------------------------------------------------------")
            .append(System.lineSeparator());

        for (SecurityCheck.CheckResult check : result.getCheckResults()) {
            text.append(check.isPassed() ? "[PASS] " : "[FAIL] ")
                .append(check.getCheckName()).append(System.lineSeparator())
                .append("        ").append(check.getDetail()).append(System.lineSeparator());
        }

        analysisArea.setText(text.toString());
        analysisArea.setCaretPosition(0);
    }

    private void copyToClipboard() {
        String generated = outputField.getText();
        if (generated == null || generated.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Generate a password first.",
                    "Nothing to copy", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        Toolkit.getDefaultToolkit().getSystemClipboard()
                .setContents(new StringSelection(generated), null);
        JOptionPane.showMessageDialog(this,
                "Copied to the clipboard.\nPaste it into your password manager, then clear the clipboard.",
                "Copied", JOptionPane.INFORMATION_MESSAGE);
    }

    /** Clears the generated password and the analysis shown beside it. */
    public void clearAll() {
        outputField.setText("");
        strengthLabel.setText("No password generated yet");
        strengthLabel.setForeground(Color.DARK_GRAY);
        analysisArea.setText("Choose a length and character types, then click Generate.");
    }
}
