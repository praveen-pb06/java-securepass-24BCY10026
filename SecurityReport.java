package securepass.model;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

import securepass.analyzer.EntropyCalculator;
import securepass.analyzer.SecurityCheck;

/**
 * A printable, exportable summary built from a {@link PasswordResult}.
 *
 * <p>The report is assembled entirely from derived values. Because a
 * {@code SecurityReport} can only be constructed from a {@code PasswordResult}, and a
 * {@code PasswordResult} never holds the password, an exported report cannot contain a
 * password even by mistake.</p>
 */
public class SecurityReport {

    private static final DateTimeFormatter TIMESTAMP_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private static final String LINE =
            "------------------------------------------------------------";

    private final PasswordResult result;
    private final LocalDateTime generatedAt;

    /**
     * @param result the analysis this report describes; must not be null
     * @throws IllegalArgumentException if result is null
     */
    public SecurityReport(PasswordResult result) {
        if (result == null) {
            throw new IllegalArgumentException("Cannot build a report without an analysis result.");
        }
        this.result = result;
        this.generatedAt = LocalDateTime.now();
    }

    public PasswordResult getResult() {
        return result;
    }

    public LocalDateTime getGeneratedAt() {
        return generatedAt;
    }

    public String getFormattedTimestamp() {
        return generatedAt.format(TIMESTAMP_FORMAT);
    }

    /**
     * Renders the full report as plain text, suitable for on-screen display or export.
     *
     * @return the report body; contains analysis data only
     */
    public String toPlainText() {
        StringBuilder out = new StringBuilder();

        out.append(LINE).append(System.lineSeparator());
        out.append("            SecurePass - Security Report").append(System.lineSeparator());
        out.append(LINE).append(System.lineSeparator());
        out.append("Generated        : ").append(getFormattedTimestamp()).append(System.lineSeparator());
        out.append("Analysis mode    : Offline (no network access)").append(System.lineSeparator());
        out.append(System.lineSeparator());

        out.append("SUMMARY").append(System.lineSeparator());
        out.append(LINE).append(System.lineSeparator());
        out.append("Strength rating  : ").append(result.getStrength().getLabel()).append(System.lineSeparator());
        out.append("Score            : ").append(result.getScore()).append(" / 100").append(System.lineSeparator());
        out.append("Password length  : ").append(result.getLength()).append(" characters").append(System.lineSeparator());
        out.append("Character classes: ").append(result.getCharacterClassCount()).append(" of 4 (lower, upper, digit, symbol)")
                .append(System.lineSeparator());
        out.append("Character pool   : ").append(result.getCharacterPoolSize()).append(" possible characters")
                .append(System.lineSeparator());
        out.append("Estimated entropy: ").append(String.format("%.1f", result.getEntropyBits())).append(" bits")
                .append(System.lineSeparator());
        out.append("Entropy reading  : ").append(EntropyCalculator.describeEntropy(result.getEntropyBits()))
                .append(System.lineSeparator());
        out.append("Checks passed    : ").append(result.getPassedCount()).append(" of ")
                .append(result.getTotalCheckCount()).append(System.lineSeparator());
        out.append(System.lineSeparator());

        out.append("SECURITY CHECKS").append(System.lineSeparator());
        out.append(LINE).append(System.lineSeparator());
        for (SecurityCheck.CheckResult check : result.getCheckResults()) {
            out.append(check.isPassed() ? "[PASS] " : "[FAIL] ")
               .append(check.getCheckName()).append(System.lineSeparator());
            out.append("        ").append(check.getDetail()).append(System.lineSeparator());
        }
        out.append(System.lineSeparator());

        out.append("RECOMMENDATIONS").append(System.lineSeparator());
        out.append(LINE).append(System.lineSeparator());
        List<String> advice = result.getRecommendations();
        if (advice.isEmpty()) {
            out.append("No issues were found by the checks listed above.").append(System.lineSeparator());
        } else {
            int index = 1;
            for (String item : advice) {
                out.append(index).append(". ").append(item).append(System.lineSeparator());
                index++;
            }
        }
        out.append(System.lineSeparator());

        out.append("NOTES AND LIMITATIONS").append(System.lineSeparator());
        out.append(LINE).append(System.lineSeparator());
        out.append("- This report contains derived analysis data only. The password itself is")
                .append(System.lineSeparator());
        out.append("  never stored, logged, transmitted or written to this file.").append(System.lineSeparator());
        out.append("- Entropy uses the L x log2(R) model, which assumes uniformly random")
                .append(System.lineSeparator());
        out.append("  characters and therefore overstates human-chosen passwords.").append(System.lineSeparator());
        out.append("- The bundled common-password list is a small educational sample, not a")
                .append(System.lineSeparator());
        out.append("  full breached-password corpus.").append(System.lineSeparator());
        out.append("- Passing every check does not guarantee a password is unbreakable.")
                .append(System.lineSeparator());
        out.append(LINE).append(System.lineSeparator());
        out.append("SecurePass - Praveen P B (24BCY10026)").append(System.lineSeparator());

        return out.toString();
    }

    @Override
    public String toString() {
        return "SecurityReport{generatedAt=" + getFormattedTimestamp()
                + ", strength=" + result.getStrength() + "}";
    }
}
