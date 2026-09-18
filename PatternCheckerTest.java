package securepass;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import securepass.analyzer.PatternChecker;
import securepass.analyzer.SecurityCheck;

/** Unit tests for {@link PatternChecker}. */
class PatternCheckerTest {

    @Test
    @DisplayName("Three identical characters in a row are detected")
    void detectsRepeatedCharacters() {
        assertTrue(PatternChecker.hasRepeatedRun("helloooo".toCharArray()));
        assertTrue(PatternChecker.hasRepeatedRun("aaa".toCharArray()));
        assertFalse(PatternChecker.hasRepeatedRun("hello".toCharArray()));
        assertFalse(PatternChecker.hasRepeatedRun("abab".toCharArray()));
    }

    @Test
    @DisplayName("Ascending and descending runs are detected")
    void detectsSequences() {
        assertTrue(PatternChecker.hasSequentialRun("abc".toCharArray()));
        assertTrue(PatternChecker.hasSequentialRun("x123y".toCharArray()));
        assertTrue(PatternChecker.hasSequentialRun("cba".toCharArray()));
        assertFalse(PatternChecker.hasSequentialRun("acbd".toCharArray()));
    }

    @Test
    @DisplayName("Keyboard walks are detected in either direction")
    void detectsKeyboardPatterns() {
        assertTrue(PatternChecker.hasKeyboardRun("qwerty".toCharArray()));
        assertTrue(PatternChecker.hasKeyboardRun("myasdfpass".toCharArray()));
        assertTrue(PatternChecker.hasKeyboardRun("REWQ".toCharArray()));
        assertFalse(PatternChecker.hasKeyboardRun("Kx7#mQ2v".toCharArray()));
    }

    @Test
    @DisplayName("A failing check returns a recommendation, a passing one does not")
    void failedCheckCarriesAdvice() {
        SecurityCheck checker = new PatternChecker(PatternChecker.PatternType.REPEATED_CHARACTERS);

        SecurityCheck.CheckResult failed = checker.check("aaabbb".toCharArray());
        assertFalse(failed.isPassed());
        assertFalse(failed.getRecommendation().isEmpty());

        SecurityCheck.CheckResult passed = checker.check("Kx7#mQ2v".toCharArray());
        assertTrue(passed.isPassed());
        assertTrue(passed.getRecommendation().isEmpty());
    }

    @Test
    @DisplayName("Each pattern type reports its own name")
    void eachTypeHasItsOwnName() {
        SecurityCheck repeated = new PatternChecker(PatternChecker.PatternType.REPEATED_CHARACTERS);
        SecurityCheck keyboard = new PatternChecker(PatternChecker.PatternType.KEYBOARD_PATTERN);
        assertFalse(repeated.getName().equals(keyboard.getName()));
    }
}
