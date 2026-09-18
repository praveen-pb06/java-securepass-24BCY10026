package securepass.analyzer;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import securepass.model.PasswordResult;
import securepass.security.CommonPasswordChecker;

/**
 * Runs every registered {@link SecurityCheck} against a password and turns the results
 * into a {@link PasswordResult}.
 *
 * <p>The analyzer knows nothing about any individual rule. It holds a
 * {@code List<SecurityCheck>} and calls {@code check()} on each one in turn, so new
 * rules can be added without touching this class:</p>
 *
 * <pre>
 *     PasswordAnalyzer analyzer = new PasswordAnalyzer();
 *     analyzer.addCheck(new MyOwnRule());
 * </pre>
 *
 * <h2>Scoring</h2>
 * <ul>
 *   <li>Length contributes up to 40 points.</li>
 *   <li>Character diversity contributes up to 40 points (10 per class used).</li>
 *   <li>A base of 20 points is awarded for any non-empty password.</li>
 *   <li>Each failed check subtracts its own penalty.</li>
 *   <li>The total is clamped to the range 0-100.</li>
 * </ul>
 * These weights are a documented, defensible convention chosen for clarity - they are
 * not an empirically validated security model.
 */
public class PasswordAnalyzer {

    private static final int BASE_SCORE = 20;
    private static final int MAX_LENGTH_POINTS = 40;
    private static final int POINTS_PER_CHARACTER_CLASS = 10;

    private final List<SecurityCheck> checks;

    /** Builds an analyzer with the standard SecurePass rule set. */
    public PasswordAnalyzer() {
        this.checks = new ArrayList<SecurityCheck>();
        this.checks.add(new LengthCheck());
        this.checks.add(new CharacterDiversityCheck());
        this.checks.add(new PatternChecker(PatternChecker.PatternType.REPEATED_CHARACTERS));
        this.checks.add(new PatternChecker(PatternChecker.PatternType.SEQUENTIAL_CHARACTERS));
        this.checks.add(new PatternChecker(PatternChecker.PatternType.KEYBOARD_PATTERN));
        this.checks.add(new CommonPasswordChecker());
    }

    /**
     * Builds an analyzer with a caller-supplied rule set. Used by the unit tests to
     * isolate individual rules.
     *
     * @param checks the rules to run; must not be null
     * @throws IllegalArgumentException if checks is null
     */
    public PasswordAnalyzer(List<SecurityCheck> checks) {
        if (checks == null) {
            throw new IllegalArgumentException("The list of checks must not be null.");
        }
        this.checks = new ArrayList<SecurityCheck>(checks);
    }

    /**
     * Registers an additional rule.
     *
     * @param check the rule to add; ignored if null
     */
    public void addCheck(SecurityCheck check) {
        if (check != null) {
            checks.add(check);
        }
    }

    /** @return an unmodifiable view of the registered rules */
    public List<SecurityCheck> getChecks() {
        return Collections.unmodifiableList(checks);
    }

    /**
     * Analyzes a password.
     *
     * <p>The array is only read - it is never copied, stored or logged. The caller stays
     * responsible for clearing it afterwards.</p>
     *
     * @param password the password characters
     * @return the derived analysis result
     * @throws IllegalArgumentException if the password is null or empty
     */
    public PasswordResult analyze(char[] password) {
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("Please enter a password before analyzing.");
        }

        List<SecurityCheck.CheckResult> results = new ArrayList<SecurityCheck.CheckResult>();
        int penaltyTotal = 0;

        for (SecurityCheck check : checks) {
            SecurityCheck.CheckResult result = check.check(password);
            results.add(result);
            if (!result.isPassed()) {
                penaltyTotal += check.getPenalty();
            }
        }

        int classCount = EntropyCalculator.countCharacterClasses(password);
        int poolSize = EntropyCalculator.calculatePoolSize(password);
        double entropy = EntropyCalculator.calculateEntropyBits(password);

        int score = BASE_SCORE
                + lengthPoints(password.length)
                + (classCount * POINTS_PER_CHARACTER_CLASS)
                - penaltyTotal;
        score = clamp(score);

        return new PasswordResult(password.length, score, toStrength(score),
                entropy, poolSize, classCount, results);
    }

    /** Length contributes up to {@value #MAX_LENGTH_POINTS} points. */
    private static int lengthPoints(int length) {
        if (length >= 16) {
            return MAX_LENGTH_POINTS;
        } else if (length >= 12) {
            return 32;
        } else if (length >= 10) {
            return 26;
        } else if (length >= 8) {
            return 20;
        } else if (length >= 6) {
            return 10;
        }
        return 0;
    }

    private static int clamp(int score) {
        if (score < 0) {
            return 0;
        }
        if (score > 100) {
            return 100;
        }
        return score;
    }

    /**
     * Maps a numeric score to a strength band.
     *
     * @param score a value from 0 to 100
     * @return the matching strength band
     */
    public static PasswordResult.Strength toStrength(int score) {
        if (score < 20) {
            return PasswordResult.Strength.VERY_WEAK;
        } else if (score < 40) {
            return PasswordResult.Strength.WEAK;
        } else if (score < 60) {
            return PasswordResult.Strength.MODERATE;
        } else if (score < 80) {
            return PasswordResult.Strength.STRONG;
        }
        return PasswordResult.Strength.VERY_STRONG;
    }

    // ---------------------------------------------------------------------
    // Built-in rules that need no state of their own
    // ---------------------------------------------------------------------

    /** Requires a password of at least 8 characters, and notes when it is under 12. */
    public static class LengthCheck implements SecurityCheck {

        /** Minimum acceptable length. */
        public static final int MINIMUM_LENGTH = 8;

        @Override
        public String getName() {
            return "Minimum length";
        }

        @Override
        public String getDescription() {
            return "Requires at least " + MINIMUM_LENGTH + " characters; 12 or more is recommended.";
        }

        @Override
        public int getPenalty() {
            return 25;
        }

        @Override
        public CheckResult check(char[] password) {
            if (password == null || password.length == 0) {
                return new CheckResult(getName(), false, "No password was supplied.",
                        "Enter a password to analyze.");
            }
            if (password.length < MINIMUM_LENGTH) {
                return new CheckResult(getName(), false,
                        "Only " + password.length + " characters - shorter than the "
                                + MINIMUM_LENGTH + "-character minimum.",
                        "Use at least 12 characters. Length helps more than any other single change.");
            }
            if (password.length < 12) {
                return new CheckResult(getName(), true,
                        password.length + " characters - acceptable, though 12 or more is safer.",
                        "");
            }
            return new CheckResult(getName(), true,
                    password.length + " characters - a good length.", "");
        }
    }

    /** Requires at least three of the four character classes. */
    public static class CharacterDiversityCheck implements SecurityCheck {

        /** Minimum number of character classes required to pass. */
        public static final int MINIMUM_CLASSES = 3;

        @Override
        public String getName() {
            return "Character variety";
        }

        @Override
        public String getDescription() {
            return "Requires at least " + MINIMUM_CLASSES
                    + " of: lowercase, uppercase, digits, symbols.";
        }

        @Override
        public int getPenalty() {
            return 20;
        }

        @Override
        public CheckResult check(char[] password) {
            if (password == null || password.length == 0) {
                return new CheckResult(getName(), false, "No password was supplied.",
                        "Enter a password to analyze.");
            }
            int classes = EntropyCalculator.countCharacterClasses(password);
            if (classes < MINIMUM_CLASSES) {
                return new CheckResult(getName(), false,
                        "Uses only " + classes + " of the 4 character types.",
                        "Mix lowercase, uppercase, digits and symbols to widen the search space.");
            }
            return new CheckResult(getName(), true,
                    "Uses " + classes + " of the 4 character types.", "");
        }
    }
}
