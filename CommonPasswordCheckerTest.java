package securepass;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import securepass.analyzer.SecurityCheck;
import securepass.security.CommonPasswordChecker;

/** Unit tests for {@link CommonPasswordChecker}. */
class CommonPasswordCheckerTest {

    /** Writes a small word list so the tests do not depend on the bundled file. */
    private File writeSampleList(File folder) throws IOException {
        File list = new File(folder, "sample_passwords.txt");
        try (PrintWriter writer = new PrintWriter(list, StandardCharsets.UTF_8)) {
            writer.println("# a comment line that must be ignored");
            writer.println("");
            writer.println("password");
            writer.println("qwerty");
            writer.println("letmein");
        }
        return list;
    }

    @Test
    @DisplayName("Listed passwords are recognised, case-insensitively")
    void recognisesListedPasswords(@TempDir File folder) throws IOException {
        CommonPasswordChecker checker = new CommonPasswordChecker(writeSampleList(folder));

        assertTrue(checker.isListAvailable());
        assertTrue(checker.isCommon("password".toCharArray()));
        assertTrue(checker.isCommon("PASSWORD".toCharArray()));
        assertTrue(checker.isCommon("QwErTy".toCharArray()));
    }

    @Test
    @DisplayName("Comments and blank lines are not loaded as entries")
    void ignoresCommentsAndBlankLines(@TempDir File folder) throws IOException {
        CommonPasswordChecker checker = new CommonPasswordChecker(writeSampleList(folder));
        org.junit.jupiter.api.Assertions.assertEquals(3, checker.getEntryCount());
    }

    @Test
    @DisplayName("An unlisted password is not flagged")
    void doesNotFlagUnlistedPasswords(@TempDir File folder) throws IOException {
        CommonPasswordChecker checker = new CommonPasswordChecker(writeSampleList(folder));
        assertFalse(checker.isCommon("Kx7#mQ2vTr9$Lz".toCharArray()));
    }

    @Test
    @DisplayName("A listed password fails the check and gets a recommendation")
    void listedPasswordFailsTheCheck(@TempDir File folder) throws IOException {
        CommonPasswordChecker checker = new CommonPasswordChecker(writeSampleList(folder));
        SecurityCheck.CheckResult result = checker.check("letmein".toCharArray());

        assertFalse(result.isPassed());
        assertFalse(result.getRecommendation().isEmpty());
    }

    @Test
    @DisplayName("A missing word list degrades gracefully instead of crashing")
    void missingFileDoesNotCrash(@TempDir File folder) {
        CommonPasswordChecker checker =
                new CommonPasswordChecker(new File(folder, "does_not_exist.txt"));

        assertFalse(checker.isListAvailable());
        assertFalse(checker.isCommon("password".toCharArray()));

        // The check is reported as skipped, so an analysis can still run.
        SecurityCheck.CheckResult result = checker.check("password".toCharArray());
        assertTrue(result.isPassed());
        assertTrue(result.getDetail().toLowerCase().contains("skipped"));
    }
}
