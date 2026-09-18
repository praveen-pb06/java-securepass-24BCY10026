package securepass.analyzer;

/**
 * A single, self-contained password security rule.
 *
 * <p>Every rule in SecurePass (length, repetition, sequences, keyboard patterns,
 * common passwords, ...) implements this interface. {@link PasswordAnalyzer} keeps a
 * collection of {@code SecurityCheck} objects and runs them polymorphically, so adding
 * a new rule means writing one class and registering it - the analyzer itself never
 * changes.</p>
 *
 * <p>Implementations must never store, copy or log the password they are given.</p>
 */
public interface SecurityCheck {

    /** Short human-readable name shown in the report, e.g. "Minimum length". */
    String getName();

    /** One-line explanation of what this rule looks for. */
    String getDescription();

    /** Score penalty applied when this check fails. Must be zero or positive. */
    int getPenalty();

    /**
     * Runs the rule against the supplied password.
     *
     * @param password the password characters; must not be null
     * @return the outcome of the rule, never null
     */
    CheckResult check(char[] password);

    /**
     * The outcome of one {@link SecurityCheck}. Immutable, and derived only -
     * it never contains the password itself.
     */
    final class CheckResult {

        private final String checkName;
        private final boolean passed;
        private final String detail;
        private final String recommendation;

        /**
         * @param checkName      name of the rule that produced this result
         * @param passed         true if the password satisfied the rule
         * @param detail         what the rule found, in plain language
         * @param recommendation advice shown when the rule failed; may be null when passed
         */
        public CheckResult(String checkName, boolean passed, String detail, String recommendation) {
            this.checkName = checkName;
            this.passed = passed;
            this.detail = detail;
            this.recommendation = (recommendation == null) ? "" : recommendation;
        }

        public String getCheckName() {
            return checkName;
        }

        public boolean isPassed() {
            return passed;
        }

        public String getDetail() {
            return detail;
        }

        public String getRecommendation() {
            return recommendation;
        }

        @Override
        public String toString() {
            return (passed ? "[PASS] " : "[FAIL] ") + checkName + " - " + detail;
        }
    }
}
