package securepass.analyzer;

/**
 * Estimates password entropy using the transparent {@code L x log2(R)} model,
 * where {@code L} is the password length and {@code R} is the size of the character
 * pool the password appears to be drawn from.
 *
 * <p><b>Limitation (stated deliberately):</b> this model assumes every character was
 * chosen uniformly at random, so it <i>overestimates</i> the strength of human-chosen
 * passwords such as {@code Password123!}, which use a large pool but a highly
 * predictable structure. The rules in {@link PatternChecker} and
 * {@link securepass.security.CommonPasswordChecker} exist precisely because this
 * number on its own is not a verdict.</p>
 *
 * <p>Stateless utility class - it cannot be instantiated.</p>
 */
public final class EntropyCalculator {

    private static final int LOWERCASE_POOL = 26;
    private static final int UPPERCASE_POOL = 26;
    private static final int DIGIT_POOL = 10;
    private static final int SYMBOL_POOL = 33;

    private EntropyCalculator() {
        // utility class - no instances
    }

    /**
     * Calculates the character pool size implied by the classes actually used.
     *
     * @param password the password characters
     * @return the pool size R, or 0 for a null or empty password
     */
    public static int calculatePoolSize(char[] password) {
        if (password == null || password.length == 0) {
            return 0;
        }
        boolean lower = false;
        boolean upper = false;
        boolean digit = false;
        boolean symbol = false;

        for (char c : password) {
            if (c >= 'a' && c <= 'z') {
                lower = true;
            } else if (c >= 'A' && c <= 'Z') {
                upper = true;
            } else if (c >= '0' && c <= '9') {
                digit = true;
            } else {
                symbol = true;
            }
        }

        int pool = 0;
        if (lower) {
            pool += LOWERCASE_POOL;
        }
        if (upper) {
            pool += UPPERCASE_POOL;
        }
        if (digit) {
            pool += DIGIT_POOL;
        }
        if (symbol) {
            pool += SYMBOL_POOL;
        }
        return pool;
    }

    /**
     * Counts how many distinct character classes (lower, upper, digit, symbol) are used.
     *
     * @param password the password characters
     * @return a value from 0 to 4
     */
    public static int countCharacterClasses(char[] password) {
        if (password == null || password.length == 0) {
            return 0;
        }
        boolean lower = false;
        boolean upper = false;
        boolean digit = false;
        boolean symbol = false;

        for (char c : password) {
            if (c >= 'a' && c <= 'z') {
                lower = true;
            } else if (c >= 'A' && c <= 'Z') {
                upper = true;
            } else if (c >= '0' && c <= '9') {
                digit = true;
            } else {
                symbol = true;
            }
        }

        int classes = 0;
        if (lower) {
            classes++;
        }
        if (upper) {
            classes++;
        }
        if (digit) {
            classes++;
        }
        if (symbol) {
            classes++;
        }
        return classes;
    }

    /**
     * Estimates entropy in bits as {@code length x log2(poolSize)}.
     *
     * @param password the password characters
     * @return estimated bits of entropy, or 0.0 for a null or empty password
     */
    public static double calculateEntropyBits(char[] password) {
        if (password == null || password.length == 0) {
            return 0.0;
        }
        int pool = calculatePoolSize(password);
        if (pool <= 1) {
            return 0.0;
        }
        double bitsPerCharacter = Math.log(pool) / Math.log(2.0);
        return password.length * bitsPerCharacter;
    }

    /**
     * Describes an entropy value in words, for display next to the number.
     *
     * @param bits estimated entropy in bits
     * @return a short descriptive label
     */
    public static String describeEntropy(double bits) {
        if (bits < 28) {
            return "Very weak - guessable almost instantly by an offline attacker";
        } else if (bits < 36) {
            return "Weak - resists only casual guessing";
        } else if (bits < 60) {
            return "Moderate - acceptable for low-value accounts";
        } else if (bits < 80) {
            return "Strong - suitable for most accounts";
        } else {
            return "Very strong - suitable for high-value accounts";
        }
    }
}
