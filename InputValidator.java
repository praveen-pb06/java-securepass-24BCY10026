package securepass.util;

/**
 * Central place for input rules, so the GUI panels can fail early with a clear message
 * instead of letting an exception surface from deeper in the application.
 *
 * <p>Every method either returns quietly or throws {@link IllegalArgumentException} with
 * a message written for a user rather than a developer.</p>
 */
public final class InputValidator {

    /** Shortest password the generator will produce. */
    public static final int MIN_GENERATED_LENGTH = 8;

    /** Longest password the generator will produce. */
    public static final int MAX_GENERATED_LENGTH = 64;

    /** Longest password the analyzer will accept. */
    public static final int MAX_ANALYZED_LENGTH = 256;

    private InputValidator() {
        // utility class - no instances
    }

    /**
     * Checks that a password was actually typed.
     *
     * @param password the characters from the password field
     * @throws IllegalArgumentException if the password is null, empty, or only whitespace
     */
    public static void validatePasswordInput(char[] password) {
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("Please enter a password before analyzing.");
        }
        if (isAllWhitespace(password)) {
            throw new IllegalArgumentException("A password of only spaces cannot be analyzed.");
        }
        if (password.length > MAX_ANALYZED_LENGTH) {
            throw new IllegalArgumentException(
                    "Passwords longer than " + MAX_ANALYZED_LENGTH + " characters are not supported.");
        }
    }

    /**
     * Convenience test used by the GUI to decide whether the Analyze button should act.
     *
     * @param password the characters from the password field
     * @return true if the password would pass {@link #validatePasswordInput(char[])}
     */
    public static boolean isUsablePassword(char[] password) {
        try {
            validatePasswordInput(password);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * Checks the settings chosen on the generator panel.
     *
     * @param length         requested password length
     * @param useLowercase   include a-z
     * @param useUppercase   include A-Z
     * @param useDigits      include 0-9
     * @param useSymbols     include punctuation
     * @throws IllegalArgumentException if the length is out of range, no character type
     *                                  was selected, or the length is too short to fit
     *                                  one character of each selected type
     */
    public static void validateGeneratorSettings(int length,
                                                 boolean useLowercase,
                                                 boolean useUppercase,
                                                 boolean useDigits,
                                                 boolean useSymbols) {
        if (length < MIN_GENERATED_LENGTH || length > MAX_GENERATED_LENGTH) {
            throw new IllegalArgumentException("Choose a length between "
                    + MIN_GENERATED_LENGTH + " and " + MAX_GENERATED_LENGTH + " characters.");
        }

        int selectedTypes = 0;
        if (useLowercase) {
            selectedTypes++;
        }
        if (useUppercase) {
            selectedTypes++;
        }
        if (useDigits) {
            selectedTypes++;
        }
        if (useSymbols) {
            selectedTypes++;
        }

        if (selectedTypes == 0) {
            throw new IllegalArgumentException("Select at least one character type to generate from.");
        }
        if (selectedTypes > length) {
            throw new IllegalArgumentException("A password of " + length
                    + " characters cannot contain all " + selectedTypes + " selected types.");
        }
    }

    /**
     * Checks that an export destination was chosen and looks writable.
     *
     * @param fileName the file name or path selected by the user
     * @throws IllegalArgumentException if the name is null or blank
     */
    public static void validateExportFileName(String fileName) {
        if (fileName == null || fileName.trim().isEmpty()) {
            throw new IllegalArgumentException("Choose a file name for the exported report.");
        }
    }

    private static boolean isAllWhitespace(char[] password) {
        for (char c : password) {
            if (!Character.isWhitespace(c)) {
                return false;
            }
        }
        return true;
    }
}
