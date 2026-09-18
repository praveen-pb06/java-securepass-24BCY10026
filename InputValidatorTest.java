package securepass;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import securepass.util.InputValidator;

/** Unit tests for {@link InputValidator}. */
class InputValidatorTest {

    @Test
    @DisplayName("An empty password is rejected with a readable message")
    void rejectsEmptyPassword() {
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> InputValidator.validatePasswordInput(new char[0]));
        assertFalse(error.getMessage().isEmpty());
    }

    @Test
    @DisplayName("A null password is rejected")
    void rejectsNullPassword() {
        assertThrows(IllegalArgumentException.class,
                () -> InputValidator.validatePasswordInput(null));
    }

    @Test
    @DisplayName("A password of only spaces is rejected")
    void rejectsWhitespaceOnlyPassword() {
        assertThrows(IllegalArgumentException.class,
                () -> InputValidator.validatePasswordInput("     ".toCharArray()));
    }

    @Test
    @DisplayName("A normal password is accepted")
    void acceptsNormalPassword() {
        assertDoesNotThrow(() -> InputValidator.validatePasswordInput("Kx7#mQ2v".toCharArray()));
        assertTrue(InputValidator.isUsablePassword("Kx7#mQ2v".toCharArray()));
        assertFalse(InputValidator.isUsablePassword(new char[0]));
    }

    @Test
    @DisplayName("Generator length must stay inside the supported range")
    void rejectsOutOfRangeLength() {
        assertThrows(IllegalArgumentException.class,
                () -> InputValidator.validateGeneratorSettings(4, true, true, true, true));
        assertThrows(IllegalArgumentException.class,
                () -> InputValidator.validateGeneratorSettings(500, true, true, true, true));
    }

    @Test
    @DisplayName("At least one character type must be selected")
    void rejectsNoCharacterTypes() {
        assertThrows(IllegalArgumentException.class,
                () -> InputValidator.validateGeneratorSettings(16, false, false, false, false));
    }

    @Test
    @DisplayName("Valid generator settings are accepted")
    void acceptsValidGeneratorSettings() {
        assertDoesNotThrow(() -> InputValidator.validateGeneratorSettings(16, true, true, true, true));
        assertDoesNotThrow(() -> InputValidator.validateGeneratorSettings(8, true, false, false, false));
    }

    @Test
    @DisplayName("An empty export file name is rejected")
    void rejectsBlankExportName() {
        assertThrows(IllegalArgumentException.class,
                () -> InputValidator.validateExportFileName("   "));
    }
}
