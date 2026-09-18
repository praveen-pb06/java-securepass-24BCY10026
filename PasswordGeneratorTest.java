package securepass;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import securepass.analyzer.EntropyCalculator;
import securepass.generator.PasswordGenerator;

/** Unit tests for {@link PasswordGenerator}. */
class PasswordGeneratorTest {

    private PasswordGenerator generator;

    @BeforeEach
    void setUp() {
        generator = new PasswordGenerator();
    }

    @Test
    @DisplayName("The generated password has exactly the requested length")
    void respectsRequestedLength() {
        for (int length = 8; length <= 32; length += 4) {
            assertEquals(length, generator.generate(length).length);
        }
    }

    @Test
    @DisplayName("All four character types appear when all four are selected")
    void includesEverySelectedType() {
        for (int attempt = 0; attempt < 50; attempt++) {
            char[] password = generator.generate(12, true, true, true, true);
            assertEquals(4, EntropyCalculator.countCharacterClasses(password),
                    "Every selected character type should be present");
        }
    }

    @Test
    @DisplayName("Unselected character types never appear")
    void excludesUnselectedTypes() {
        char[] password = generator.generate(20, true, false, false, false);
        for (char c : password) {
            assertTrue(c >= 'a' && c <= 'z', "Only lowercase letters were selected");
        }
    }

    @Test
    @DisplayName("Two consecutive calls do not produce the same password")
    void producesDifferentPasswordsEachTime() {
        char[] first = generator.generate(20);
        char[] second = generator.generate(20);
        assertFalse(java.util.Arrays.equals(first, second));
    }

    @Test
    @DisplayName("Invalid settings raise a message fit to show the user")
    void rejectsInvalidSettings() {
        assertThrows(IllegalArgumentException.class, () -> generator.generate(3));
        assertThrows(IllegalArgumentException.class,
                () -> generator.generate(16, false, false, false, false));
    }

    @Test
    @DisplayName("Pool size matches the selected character types")
    void reportsPoolSize() {
        assertEquals(26, PasswordGenerator.poolSize(true, false, false, false));
        assertEquals(62, PasswordGenerator.poolSize(true, true, true, false));
    }
}
