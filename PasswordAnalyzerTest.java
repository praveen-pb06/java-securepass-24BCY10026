package securepass;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import securepass.analyzer.PasswordAnalyzer;
import securepass.analyzer.PatternChecker;
import securepass.analyzer.SecurityCheck;
import securepass.model.PasswordResult;
import securepass.model.SecurityReport;

/** Unit tests for {@link PasswordAnalyzer} and the objects it produces. */
class PasswordAnalyzerTest {

    private PasswordAnalyzer analyzer;

    @BeforeEach
    void setUp() {
        analyzer = new PasswordAnalyzer();
    }

    @Test
    @DisplayName("An empty password is refused with a readable message")
    void refusesEmptyPassword() {
        assertThrows(IllegalArgumentException.class, () -> analyzer.analyze(new char[0]));
        assertThrows(IllegalArgumentException.class, () -> analyzer.analyze(null));
    }

    @Test
    @DisplayName("A short, single-class password scores poorly")
    void weakPasswordScoresLow() {
        PasswordResult result = analyzer.analyze("abc".toCharArray());
        assertTrue(result.getScore() < 40, "Expected a low score, got " + result.getScore());
        assertTrue(result.getStrength().ordinal() <= PasswordResult.Strength.WEAK.ordinal());
        assertFalse(result.getRecommendations().isEmpty());
    }

    @Test
    @DisplayName("A long, mixed, pattern-free password scores highly")
    void strongPasswordScoresHigh() {
        PasswordResult result = analyzer.analyze("Kx7#mQ2vTr9$Lz".toCharArray());
        assertTrue(result.getScore() >= 80, "Expected a high score, got " + result.getScore());
        assertEquals(PasswordResult.Strength.VERY_STRONG, result.getStrength());
        assertEquals(4, result.getCharacterClassCount());
    }

    @Test
    @DisplayName("The score always stays within 0 to 100")
    void scoreStaysInRange() {
        String[] samples = {"a", "aaa", "password", "qwerty123", "Kx7#mQ2vTr9$Lz", "correcthorsebattery"};
        for (String sample : samples) {
            int score = analyzer.analyze(sample.toCharArray()).getScore();
            assertTrue(score >= 0 && score <= 100, sample + " produced an out-of-range score: " + score);
        }
    }

    @Test
    @DisplayName("Every registered check produces exactly one result")
    void runsEveryRegisteredCheck() {
        PasswordResult result = analyzer.analyze("Kx7#mQ2vTr9$Lz".toCharArray());
        assertEquals(analyzer.getChecks().size(), result.getTotalCheckCount());
    }

    @Test
    @DisplayName("A new rule can be added without changing the analyzer")
    void supportsCustomChecks() {
        List<SecurityCheck> checks = new ArrayList<SecurityCheck>();
        checks.add(new PatternChecker(PatternChecker.PatternType.REPEATED_CHARACTERS));
        PasswordAnalyzer custom = new PasswordAnalyzer(checks);

        assertEquals(1, custom.analyze("aaabbb".toCharArray()).getTotalCheckCount());

        custom.addCheck(new PatternChecker(PatternChecker.PatternType.KEYBOARD_PATTERN));
        assertEquals(2, custom.analyze("aaabbb".toCharArray()).getTotalCheckCount());
    }

    @Test
    @DisplayName("Failed checks are the ones that carry recommendations")
    void recommendationsComeFromFailedChecks() {
        PasswordResult result = analyzer.analyze("aaaaaaaa".toCharArray());
        assertFalse(result.getFailedChecks().isEmpty());
        assertTrue(result.getFailedChecks().size() <= result.getTotalCheckCount());
    }

    @Test
    @DisplayName("The check result list cannot be modified from outside")
    void resultListIsUnmodifiable() {
        PasswordResult result = analyzer.analyze("Kx7#mQ2vTr9$Lz".toCharArray());
        assertThrows(UnsupportedOperationException.class, () -> result.getCheckResults().clear());
    }

    @Test
    @DisplayName("The exported report text never contains the password")
    void reportDoesNotContainThePassword() {
        char[] password = "Kx7#mQ2vTr9$Lz".toCharArray();
        SecurityReport report = new SecurityReport(analyzer.analyze(password));
        String text = report.toPlainText();

        assertFalse(text.contains(new String(password)));
        assertTrue(text.contains("SecurePass"));
        Arrays.fill(password, '\0');
    }

    @Test
    @DisplayName("Score bands map to the documented strength labels")
    void scoreMapsToStrengthBand() {
        assertEquals(PasswordResult.Strength.VERY_WEAK, PasswordAnalyzer.toStrength(0));
        assertEquals(PasswordResult.Strength.WEAK, PasswordAnalyzer.toStrength(30));
        assertEquals(PasswordResult.Strength.MODERATE, PasswordAnalyzer.toStrength(50));
        assertEquals(PasswordResult.Strength.STRONG, PasswordAnalyzer.toStrength(70));
        assertEquals(PasswordResult.Strength.VERY_STRONG, PasswordAnalyzer.toStrength(95));
    }
}
