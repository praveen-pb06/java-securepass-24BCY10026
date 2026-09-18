package securepass.generator;

import java.security.SecureRandom;

import securepass.util.InputValidator;

/**
 * Builds strong random passwords.
 *
 * <p>Generation uses {@link SecureRandom}, never {@code Math.random()}: the latter is a
 * predictable linear congruential generator and is unsuitable for anything
 * security-related.</p>
 *
 * <p>The generated password is returned as a {@code char[]} so the caller can clear it
 * when finished. The generator keeps no copy of anything it produces.</p>
 */
public class PasswordGenerator {

    /** Lowercase letters. */
    public static final String LOWERCASE = "abcdefghijklmnopqrstuvwxyz";

    /** Uppercase letters. */
    public static final String UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    /** Digits. */
    public static final String DIGITS = "0123456789";

    /** Punctuation and symbols that are safe to type on a standard keyboard. */
    public static final String SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/";

    /** Default length offered by the generator panel. */
    public static final int DEFAULT_LENGTH = 16;

    private final SecureRandom random = new SecureRandom();

    /**
     * Generates a password using all four character types.
     *
     * @param length requested length
     * @return the generated characters
     * @throws IllegalArgumentException if the length is outside the supported range
     */
    public char[] generate(int length) {
        return generate(length, true, true, true, true);
    }

    /**
     * Generates a password from the selected character types.
     *
     * <p>The result is guaranteed to contain at least one character from every selected
     * type, and the guaranteed characters are shuffled into random positions so their
     * placement leaks nothing.</p>
     *
     * @param length       requested length
     * @param useLowercase include a-z
     * @param useUppercase include A-Z
     * @param useDigits    include 0-9
     * @param useSymbols   include punctuation
     * @return the generated characters
     * @throws IllegalArgumentException if the settings are invalid, with a message that
     *                                  can be shown directly to the user
     */
    public char[] generate(int length,
                           boolean useLowercase,
                           boolean useUppercase,
                           boolean useDigits,
                           boolean useSymbols) {

        InputValidator.validateGeneratorSettings(length, useLowercase, useUppercase, useDigits, useSymbols);

        StringBuilder pool = new StringBuilder();
        if (useLowercase) {
            pool.append(LOWERCASE);
        }
        if (useUppercase) {
            pool.append(UPPERCASE);
        }
        if (useDigits) {
            pool.append(DIGITS);
        }
        if (useSymbols) {
            pool.append(SYMBOLS);
        }

        char[] password = new char[length];
        int position = 0;

        // One guaranteed character from each selected type.
        if (useLowercase) {
            password[position++] = randomCharacterFrom(LOWERCASE);
        }
        if (useUppercase) {
            password[position++] = randomCharacterFrom(UPPERCASE);
        }
        if (useDigits) {
            password[position++] = randomCharacterFrom(DIGITS);
        }
        if (useSymbols) {
            password[position++] = randomCharacterFrom(SYMBOLS);
        }

        // Fill the rest from the combined pool.
        String combined = pool.toString();
        while (position < length) {
            password[position++] = randomCharacterFrom(combined);
        }

        shuffle(password);
        return password;
    }

    /**
     * Picks one character uniformly at random from the given set.
     *
     * @param characters the set to choose from
     * @return a single character
     */
    private char randomCharacterFrom(String characters) {
        return characters.charAt(random.nextInt(characters.length()));
    }

    /**
     * Fisher-Yates shuffle driven by {@link SecureRandom}.
     *
     * @param characters the array to shuffle in place
     */
    private void shuffle(char[] characters) {
        for (int i = characters.length - 1; i > 0; i--) {
            int j = random.nextInt(i + 1);
            char temp = characters[i];
            characters[i] = characters[j];
            characters[j] = temp;
        }
    }

    /**
     * Size of the pool implied by the selected character types, for display on the
     * generator panel.
     *
     * @param useLowercase include a-z
     * @param useUppercase include A-Z
     * @param useDigits    include 0-9
     * @param useSymbols   include punctuation
     * @return the number of distinct characters available
     */
    public static int poolSize(boolean useLowercase, boolean useUppercase,
                               boolean useDigits, boolean useSymbols) {
        int size = 0;
        if (useLowercase) {
            size += LOWERCASE.length();
        }
        if (useUppercase) {
            size += UPPERCASE.length();
        }
        if (useDigits) {
            size += DIGITS.length();
        }
        if (useSymbols) {
            size += SYMBOLS.length();
        }
        return size;
    }
}
