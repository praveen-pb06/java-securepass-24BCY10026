package securepass.util;

import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.FileOutputStream;
import java.io.Writer;
import java.nio.charset.StandardCharsets;

import securepass.model.SecurityReport;

/**
 * Writes a {@link SecurityReport} to a text file.
 *
 * <p>This class is the reason an exported report cannot leak a password: there is no
 * method here that accepts a password, a {@code char[]} or a raw String of user input.
 * The only thing that can be exported is a {@code SecurityReport}, which is built from
 * derived analysis data alone. The guarantee is enforced by the method signatures, not
 * by a promise in the documentation.</p>
 */
public final class ReportExporter {

    /** Default file name offered in the save dialog. */
    public static final String DEFAULT_FILE_NAME = "securepass_report.txt";

    private ReportExporter() {
        // utility class - no instances
    }

    /**
     * Writes the report to the given file, replacing it if it already exists.
     *
     * @param report      the report to export; must not be null
     * @param destination the file to write; must not be null
     * @throws IllegalArgumentException if either argument is null
     * @throws IOException              if the file cannot be written
     */
    public static void export(SecurityReport report, File destination) throws IOException {
        if (report == null) {
            throw new IllegalArgumentException("There is no report to export - analyze a password first.");
        }
        if (destination == null) {
            throw new IllegalArgumentException("Choose a file to export the report to.");
        }

        File parent = destination.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            throw new IOException("Could not create the folder " + parent.getPath());
        }

        try (Writer writer = new BufferedWriter(
                new OutputStreamWriter(new FileOutputStream(destination), StandardCharsets.UTF_8))) {
            writer.write(report.toPlainText());
        }
    }

    /**
     * Ensures the chosen file name ends with {@code .txt}.
     *
     * @param destination the file chosen by the user
     * @return the same file, or a new one with the extension appended
     */
    public static File withTextExtension(File destination) {
        if (destination == null) {
            return null;
        }
        String name = destination.getName().toLowerCase();
        if (name.endsWith(".txt")) {
            return destination;
        }
        return new File(destination.getParentFile(), destination.getName() + ".txt");
    }
}
