package securepass;

import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;

import securepass.gui.MainWindow;

/**
 * Application entry point for SecurePass.
 *
 * <p>Builds the Swing user interface on the Event Dispatch Thread, as Swing requires,
 * and reports any unexpected start-up failure in a dialog rather than a stack trace.</p>
 *
 * <pre>
 *     javac -d out $(find src/main/java -name "*.java")
 *     cp -r resources out/
 *     java -cp out securepass.Main
 * </pre>
 *
 * @author Praveen P B (24BCY10026)
 */
public final class Main {

    private Main() {
        // entry point only - no instances
    }

    /**
     * Starts the application.
     *
     * @param args not used
     */
    public static void main(String[] args) {
        applySystemLookAndFeel();

        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                try {
                    new MainWindow().showWindow();
                } catch (RuntimeException e) {
                    JOptionPane.showMessageDialog(null,
                            "SecurePass could not start.\n\nReason: " + e.getMessage(),
                            "Startup error", JOptionPane.ERROR_MESSAGE);
                }
            }
        });
    }

    /** Uses the native look and feel where available, falling back silently otherwise. */
    private static void applySystemLookAndFeel() {
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception e) {
            // The default cross-platform look and feel is perfectly usable.
        }
    }
}
