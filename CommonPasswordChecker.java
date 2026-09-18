package securepass.security;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import securepass.analyzer.SecurityCheck;

/**
 * Checks a password against a bundled sample list of very common passwords.
 *
 * <p>The list is loaded once, at construction, from {@code common_passwords.txt}. The
 * loader tries the classpath first and then the working directory, so the application
 * runs whether the resources folder was copied into {@code out/} or left in the project
 * root.</p>
 *
 * <p>If the file cannot be found or read the application does <b>not</b> crash: the
 * checker reports itself as unavailable and every analysis simply shows this one check
 * as skipped. That behaviour is the file-I/O error handling demonstration for the
 * project.</p>
 *
 * <p>Entries are held as {@code char[]} and compared character by character, so neither
 * the list nor the password under test is ever turned into an immutable String.</p>
 */
public class CommonPasswordChecker implements SecurityCheck {

    /** Locations tried, in order, when loading the word list. */
    private static final String[] CLASSPATH_LOCATIONS = {
        "/resources/common_passwords.txt",
        "/common_passwords.txt"
    };

    private static final String[] FILE_LOCATIONS = {
        "resources/common_passwords.txt",
        "out/resources/common_passwords.txt",
        "../resources/common_passwords.txt"
    };

    private final List<char[]> commonPasswords = new ArrayList<char[]>();
    private boolean listAvailable;
    private String loadStatus;

    /** Loads the bundled list, degrading gracefully if it is missing. */
    public CommonPasswordChecker() {
        loadList();
    }

    /**
     * Loads the list from an explicit file instead of the bundled locations.
     * Used mainly by the unit tests.
     *
     * @param file the word list to load; may be null, which leaves the checker unavailable
     */
    public CommonPasswordChecker(File file) {
        if (file != null && file.isFile()) {
            try (InputStream in = new FileInputStream(file)) {
                readEntries(in);
                listAvailable = !commonPasswords.isEmpty();
                loadStatus = listAvailable
                        ? "Loaded " + commonPasswords.size() + " entries from " + file.getPath()
                        : "The supplied word list was empty.";
                return;
            } catch (IOException e) {
                loadStatus = "Could not read " + file.getPath() + ": " + e.getMessage();
            }
        } else {
            loadStatus = "The supplied word list does not exist.";
        }
        listAvailable = false;
    }

    private void loadList() {
        for (String location : CLASSPATH_LOCATIONS) {
            InputStream in = CommonPasswordChecker.class.getResourceAsStream(location);
            if (in != null) {
                try {
                    readEntries(in);
                    listAvailable = !commonPasswords.isEmpty();
                    loadStatus = listAvailable
                            ? "Loaded " + commonPasswords.size() + " entries from the classpath."
                            : "The bundled word list was empty.";
                    return;
                } catch (IOException e) {
                    loadStatus = "Could not read the bundled word list: " + e.getMessage();
                } finally {
                    closeQuietly(in);
                }
            }
        }

        for (String path : FILE_LOCATIONS) {
            File candidate = new File(path);
            if (candidate.isFile()) {
                try (InputStream in = new FileInputStream(candidate)) {
                    readEntries(in);
                    listAvailable = !commonPasswords.isEmpty();
                    loadStatus = listAvailable
                            ? "Loaded " + commonPasswords.size() + " entries from " + candidate.getPath()
                            : "The word list at " + candidate.getPath() + " was empty.";
                    return;
                } catch (IOException e) {
                    loadStatus = "Could not read " + candidate.getPath() + ": " + e.getMessage();
                }
            }
        }

        listAvailable = false;
        if (loadStatus == null) {
            loadStatus = "common_passwords.txt was not found - this check will be skipped.";
        }
    }

    /** Reads one entry per line, skipping blank lines and '#' comments. */
    private void readEntries(InputStream in) throws IOException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
        String line = reader.readLine();
        while (line != null) {
            String trimmed = line.trim();
            if (!trimmed.isEmpty() && !trimmed.startsWith("#")) {
                commonPasswords.add(trimmed.toLowerCase().toCharArray());
            }
            line = reader.readLine();
        }
    }

    private static void closeQuietly(InputStream in) {
        try {
            in.close();
        } catch (IOException ignored) {
            // nothing useful can be done here
        }
    }

    /** @return true if the word list loaded successfully */
    public boolean isListAvailable() {
        return listAvailable;
    }

    /** @return how many entries were loaded */
    public int getEntryCount() {
        return commonPasswords.size();
    }

    /** @return a human-readable description of how loading went */
    public String getLoadStatus() {
        return loadStatus;
    }

    /**
     * Case-insensitive membership test performed on character arrays.
     *
     * @param password the password characters
     * @return true if the password appears in the loaded list
     */
    public boolean isCommon(char[] password) {
        if (password == null || password.length == 0 || !listAvailable) {
            return false;
        }
        for (char[] entry : commonPasswords) {
            if (equalsIgnoreCase(password, entry)) {
                return true;
            }
        }
        return false;
    }

    private static boolean equalsIgnoreCase(char[] password, char[] lowercaseEntry) {
        if (password.length != lowercaseEntry.length) {
            return false;
        }
        for (int i = 0; i < password.length; i++) {
            if (Character.toLowerCase(password[i]) != lowercaseEntry[i]) {
                return false;
            }
        }
        return true;
    }

    @Override
    public String getName() {
        return "Not a common password";
    }

    @Override
    public String getDescription() {
        return "Compares the password against a bundled sample list of very common passwords.";
    }

    @Override
    public int getPenalty() {
        return 40;
    }

    @Override
    public CheckResult check(char[] password) {
        if (!listAvailable) {
            return new CheckResult(getName(), true,
                    "Skipped - the common-password list could not be loaded (" + loadStatus + ").",
                    "Restore resources/common_passwords.txt to enable this check.");
        }
        if (password == null || password.length == 0) {
            return new CheckResult(getName(), false, "No password was supplied.",
                    "Enter a password to analyze.");
        }
        if (isCommon(password)) {
            return new CheckResult(getName(), false,
                    "This password appears in the bundled list of commonly used passwords.",
                    "Choose something unrelated to common words - a password on any public list "
                            + "is tried first in an attack.");
        }
        return new CheckResult(getName(), true,
                "Not found in the bundled sample list of " + commonPasswords.size() + " common passwords.",
                "");
    }
}
