package securepass.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import securepass.analyzer.SecurityCheck;

/**
 * The immutable outcome of analyzing one password.
 *
 * <p>Everything stored here is <b>derived</b> data - a score, a rating, an entropy
 * estimate, and the pass/fail result of each rule. The password itself is deliberately
 * absent, and there is no setter or constructor parameter through which it could be
 * introduced.</p>
 */
public class PasswordResult {

    /** Overall strength band, derived from the numeric score. */
    public enum Strength {
        VERY_WEAK("Very Weak"),
        WEAK("Weak"),
        MODERATE("Moderate"),
        STRONG("Strong"),
        VERY_STRONG("Very Strong");

        private final String label;

        Strength(String label) {
            this.label = label;
        }

        public String getLabel() {
            return label;
        }

        @Override
        public String toString() {
            return label;
        }
    }

    private final int length;
    private final int score;
    private final Strength strength;
    private final double entropyBits;
    private final int characterPoolSize;
    private final int characterClassCount;
    private final List<SecurityCheck.CheckResult> checkResults;

    /**
     * @param length              number of characters in the analyzed password
     * @param score               overall score from 0 to 100
     * @param strength            strength band matching the score
     * @param entropyBits         estimated entropy in bits
     * @param characterPoolSize   character pool size used for the entropy estimate
     * @param characterClassCount how many character classes were present (0-4)
     * @param checkResults        the result of every security check that was run
     */
    public PasswordResult(int length,
                          int score,
                          Strength strength,
                          double entropyBits,
                          int characterPoolSize,
                          int characterClassCount,
                          List<SecurityCheck.CheckResult> checkResults) {
        this.length = length;
        this.score = score;
        this.strength = strength;
        this.entropyBits = entropyBits;
        this.characterPoolSize = characterPoolSize;
        this.characterClassCount = characterClassCount;
        this.checkResults = (checkResults == null)
                ? new ArrayList<SecurityCheck.CheckResult>()
                : new ArrayList<SecurityCheck.CheckResult>(checkResults);
    }

    public int getLength() {
        return length;
    }

    public int getScore() {
        return score;
    }

    public Strength getStrength() {
        return strength;
    }

    public double getEntropyBits() {
        return entropyBits;
    }

    public int getCharacterPoolSize() {
        return characterPoolSize;
    }

    public int getCharacterClassCount() {
        return characterClassCount;
    }

    /** @return an unmodifiable view of every check result, in the order they were run */
    public List<SecurityCheck.CheckResult> getCheckResults() {
        return Collections.unmodifiableList(checkResults);
    }

    /** @return only the checks that failed */
    public List<SecurityCheck.CheckResult> getFailedChecks() {
        List<SecurityCheck.CheckResult> failed = new ArrayList<SecurityCheck.CheckResult>();
        for (SecurityCheck.CheckResult result : checkResults) {
            if (!result.isPassed()) {
                failed.add(result);
            }
        }
        return failed;
    }

    /** @return the recommendation text of every failed check, with duplicates removed */
    public List<String> getRecommendations() {
        List<String> advice = new ArrayList<String>();
        for (SecurityCheck.CheckResult result : getFailedChecks()) {
            String recommendation = result.getRecommendation();
            if (recommendation != null && !recommendation.isEmpty() && !advice.contains(recommendation)) {
                advice.add(recommendation);
            }
        }
        return advice;
    }

    public int getPassedCount() {
        return checkResults.size() - getFailedChecks().size();
    }

    public int getTotalCheckCount() {
        return checkResults.size();
    }

    @Override
    public String toString() {
        return "PasswordResult{score=" + score
                + ", strength=" + strength
                + ", entropyBits=" + String.format("%.1f", entropyBits)
                + ", checksPassed=" + getPassedCount() + "/" + getTotalCheckCount() + "}";
    }
}
