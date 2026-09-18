package securepass.analyzer;

/**
 * Detects human-predictable patterns that raw entropy arithmetic cannot see.
 *
 * <p>One class implements three related rules, selected by {@link PatternType} at
 * construction time. {@link PasswordAnalyzer} holds them as {@link SecurityCheck}
 * references and never needs to know which kind it is running - the polymorphism
 * demonstration at the heart of the project.</p>
 *
 * <pre>
 *     SecurityCheck repeats   = new PatternChecker(PatternType.REPEATED_CHARACTERS);
 *     SecurityCheck sequences = new PatternChecker(PatternType.SEQUENTIAL_CHARACTERS);
 * </pre>
 */
public class PatternChecker implements SecurityCheck {

    /** The kinds of pattern this checker can look for. */
    public enum PatternType {
        /** Three or more identical characters in a row, e.g. {@code aaa}. */
        REPEATED_CHARACTERS,
        /** Three or more consecutive characters, e.g. {@code abc}, {@code 123}, {@code cba}. */
        SEQUENTIAL_CHARACTERS,
        /** Four or more adjacent keyboard keys, e.g. {@code qwerty}, {@code asdf}. */
        KEYBOARD_PATTERN
    }

    /** Rows of a standard QWERTY keyboard, used for adjacency detection. */
    private static final String[] KEYBOARD_ROWS = {
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm",
        "1234567890"
    };

    private static final int MIN_REPEAT_RUN = 3;
    private static final int MIN_SEQUENCE_RUN = 3;
    private static final int MIN_KEYBOARD_RUN = 4;

    private final PatternType patternType;

    /**
     * @param patternType which pattern this instance should look for; must not be null
     * @throws IllegalArgumentException if patternType is null
     */
    public PatternChecker(PatternType patternType) {
        if (patternType == null) {
            throw new IllegalArgumentException("Pattern type must not be null.");
        }
        this.patternType = patternType;
    }

    public PatternType getPatternType() {
        return patternType;
    }

    @Override
    public String getName() {
        switch (patternType) {
            case REPEATED_CHARACTERS:
                return "No repeated characters";
            case SEQUENTIAL_CHARACTERS:
                return "No character sequences";
            case KEYBOARD_PATTERN:
                return "No keyboard patterns";
            default:
                return "Pattern check";
        }
    }

    @Override
    public String getDescription() {
        switch (patternType) {
            case REPEATED_CHARACTERS:
                return "Looks for three or more identical characters in a row, such as \"aaa\".";
            case SEQUENTIAL_CHARACTERS:
                return "Looks for runs of consecutive characters, such as \"abc\" or \"123\".";
            case KEYBOARD_PATTERN:
                return "Looks for adjacent keyboard keys, such as \"qwerty\" or \"asdf\".";
            default:
                return "Looks for predictable character patterns.";
        }
    }

    @Override
    public int getPenalty() {
        switch (patternType) {
            case REPEATED_CHARACTERS:
                return 10;
            case SEQUENTIAL_CHARACTERS:
                return 10;
            case KEYBOARD_PATTERN:
                return 15;
            default:
                return 10;
        }
    }

    @Override
    public CheckResult check(char[] password) {
        if (password == null || password.length == 0) {
            return new CheckResult(getName(), false, "No password was supplied.",
                    "Enter a password to analyze.");
        }

        boolean found;
        switch (patternType) {
            case REPEATED_CHARACTERS:
                found = hasRepeatedRun(password);
                break;
            case SEQUENTIAL_CHARACTERS:
                found = hasSequentialRun(password);
                break;
            case KEYBOARD_PATTERN:
                found = hasKeyboardRun(password);
                break;
            default:
                found = false;
                break;
        }

        if (found) {
            return new CheckResult(getName(), false, failureDetail(), failureAdvice());
        }
        return new CheckResult(getName(), true, passDetail(), "");
    }

    /**
     * @return true if the password contains {@value #MIN_REPEAT_RUN} or more identical
     *         characters in a row
     */
    public static boolean hasRepeatedRun(char[] password) {
        if (password == null || password.length < MIN_REPEAT_RUN) {
            return false;
        }
        int run = 1;
        for (int i = 1; i < password.length; i++) {
            if (password[i] == password[i - 1]) {
                run++;
                if (run >= MIN_REPEAT_RUN) {
                    return true;
                }
            } else {
                run = 1;
            }
        }
        return false;
    }

    /**
     * @return true if the password contains a run of consecutive characters, ascending
     *         or descending, such as {@code abc}, {@code 123} or {@code cba}
     */
    public static boolean hasSequentialRun(char[] password) {
        if (password == null || password.length < MIN_SEQUENCE_RUN) {
            return false;
        }
        int ascending = 1;
        int descending = 1;
        for (int i = 1; i < password.length; i++) {
            char previous = Character.toLowerCase(password[i - 1]);
            char current = Character.toLowerCase(password[i]);

            if (current - previous == 1) {
                ascending++;
                descending = 1;
            } else if (previous - current == 1) {
                descending++;
                ascending = 1;
            } else {
                ascending = 1;
                descending = 1;
            }

            if (ascending >= MIN_SEQUENCE_RUN || descending >= MIN_SEQUENCE_RUN) {
                return true;
            }
        }
        return false;
    }

    /**
     * @return true if the password contains {@value #MIN_KEYBOARD_RUN} or more adjacent
     *         keys from one keyboard row, in either direction
     */
    public static boolean hasKeyboardRun(char[] password) {
        if (password == null || password.length < MIN_KEYBOARD_RUN) {
            return false;
        }
        for (String row : KEYBOARD_ROWS) {
            for (int start = 0; start + MIN_KEYBOARD_RUN <= row.length(); start++) {
                String forward = row.substring(start, start + MIN_KEYBOARD_RUN);
                String backward = new StringBuilder(forward).reverse().toString();
                if (containsIgnoreCase(password, forward) || containsIgnoreCase(password, backward)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Case-insensitive substring search performed directly on the character array, so
     * the password is never converted into an immutable String.
     */
    private static boolean containsIgnoreCase(char[] password, String fragment) {
        int limit = password.length - fragment.length();
        for (int i = 0; i <= limit; i++) {
            boolean matches = true;
            for (int j = 0; j < fragment.length(); j++) {
                if (Character.toLowerCase(password[i + j]) != fragment.charAt(j)) {
                    matches = false;
                    break;
                }
            }
            if (matches) {
                return true;
            }
        }
        return false;
    }

    private String failureDetail() {
        switch (patternType) {
            case REPEATED_CHARACTERS:
                return "Contains three or more identical characters in a row.";
            case SEQUENTIAL_CHARACTERS:
                return "Contains a run of consecutive characters such as \"abc\" or \"123\".";
            case KEYBOARD_PATTERN:
                return "Contains a run of adjacent keyboard keys such as \"qwerty\".";
            default:
                return "Contains a predictable pattern.";
        }
    }

    private String passDetail() {
        switch (patternType) {
            case REPEATED_CHARACTERS:
                return "No long runs of identical characters were found.";
            case SEQUENTIAL_CHARACTERS:
                return "No consecutive character runs were found.";
            case KEYBOARD_PATTERN:
                return "No keyboard-adjacency patterns were found.";
            default:
                return "No predictable pattern was found.";
        }
    }

    private String failureAdvice() {
        switch (patternType) {
            case REPEATED_CHARACTERS:
                return "Break up repeated characters - cracking tools expand runs like \"aaa\" cheaply.";
            case SEQUENTIAL_CHARACTERS:
                return "Avoid counting up or down; replace the run with unrelated characters.";
            case KEYBOARD_PATTERN:
                return "Keyboard walks are in every cracking dictionary - choose unrelated keys.";
            default:
                return "Replace the predictable section with unrelated characters.";
        }
    }
}
