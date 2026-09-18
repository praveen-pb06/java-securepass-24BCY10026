package securepass;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import securepass.analyzer.EntropyCalculator;

/** Unit tests for {@link EntropyCalculator}. */
class EntropyCalculatorTest {

    @Test
    @DisplayName("Pool size reflects only the character classes actually used")
    void poolSizeMatchesClassesUsed() {
        assertEquals(26, EntropyCalculator.calculatePoolSize("abcdef".toCharArray()));
        assertEquals(10, EntropyCalculator.calculatePoolSize("123456".toCharArray()));
        assertEquals(52, EntropyCalculator.calculatePoolSize("abcDEF".toCharArray()));
        assertEquals(62, EntropyCalculator.calculatePoolSize("abcDEF123".toCharArray()));
    }

    @Test
    @DisplayName("Empty and null passwords have a pool size of zero")
    void emptyPasswordHasNoPool() {
        assertEquals(0, EntropyCalculator.calculatePoolSize(new char[0]));
        assertEquals(0, EntropyCalculator.calculatePoolSize(null));
    }

    @Test
    @DisplayName("Character classes are counted from 0 to 4")
    void countsCharacterClasses() {
        assertEquals(1, EntropyCalculator.countCharacterClasses("abcdef".toCharArray()));
        assertEquals(2, EntropyCalculator.countCharacterClasses("abc123".toCharArray()));
        assertEquals(3, EntropyCalculator.countCharacterClasses("Abc123".toCharArray()));
        assertEquals(4, EntropyCalculator.countCharacterClasses("Abc123!".toCharArray()));
        assertEquals(0, EntropyCalculator.countCharacterClasses(new char[0]));
    }

    @Test
    @DisplayName("Entropy follows L x log2(R)")
    void entropyUsesTheDocumentedFormula() {
        // 8 lowercase characters: 8 x log2(26) = 37.6 bits
        double bits = EntropyCalculator.calculateEntropyBits("abcdefgh".toCharArray());
        assertEquals(37.6, bits, 0.1);
    }

    @Test
    @DisplayName("A longer password of the same pool has more entropy")
    void longerPasswordHasMoreEntropy() {
        double shorter = EntropyCalculator.calculateEntropyBits("abcdefgh".toCharArray());
        double longer = EntropyCalculator.calculateEntropyBits("abcdefghijkl".toCharArray());
        assertTrue(longer > shorter);
    }

    @Test
    @DisplayName("Empty password has zero entropy")
    void emptyPasswordHasZeroEntropy() {
        assertEquals(0.0, EntropyCalculator.calculateEntropyBits(new char[0]), 0.0001);
        assertEquals(0.0, EntropyCalculator.calculateEntropyBits(null), 0.0001);
    }
}
