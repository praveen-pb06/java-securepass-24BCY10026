# SecurePass — Java Password Security Analyzer & Generator
### Programming in Java — Evaluated Project

| Field | Details |
|---|---|
| **Student Name** | Praveen P B |
| **Registration Number** | 24BCY10026 |
| **Course** | Programming in Java – Evaluated Project |
| **Project Type** | Java Desktop Application (Swing) |
| **Submission** | VITyarthi Portal |

---

## About This Project

**SecurePass** is a Java desktop application that analyzes the security strength of a password and generates strong new passwords — entirely **offline**. It never stores, logs, or transmits the actual password a user types in; every result shown is *derived* from the password, not the password itself.

The project demonstrates core object-oriented and Java programming concepts (interfaces, polymorphism, encapsulation, collections, exception handling, file I/O, and GUI programming) through a single coherent, real-world security-awareness tool.

---

## Features

- **Password Analyzer** — scores length, character diversity, repetition, sequential patterns, and common-password matches, and explains *why* a password received its strength rating.
- **Security / Vulnerability Checks** — a pluggable set of checks (short length, repeated characters, sequences like `abc`/`123`, common passwords, keyboard patterns) with concrete improvement recommendations.
- **Secure Password Generator** — builds strong passwords with configurable length and character classes using `java.security.SecureRandom`.
- **Security Report** — a consolidated, exportable report containing only derived analysis data (strength, entropy, check results) — **never** the password itself.
- **Entropy Estimation** — a transparent `L × log₂(R)` bits-of-entropy calculation with clearly stated limitations.
- **Friendly error handling** — empty input, invalid generator settings, and missing resource files are all handled gracefully with clear messages instead of crashes.

---

## Repository Structure

```
SecurePass/
│
├── README.md                             ← This file
├── statement.md                          ← Problem statement, scope, target users
│
├── src/
│   └── main/
│       └── java/
│           └── securepass/
│               ├── Main.java             ← Application entry point
│               │
│               ├── model/
│               │   ├── PasswordResult.java
│               │   └── SecurityReport.java
│               │
│               ├── analyzer/
│               │   ├── SecurityCheck.java        ← interface
│               │   ├── PasswordAnalyzer.java
│               │   ├── PatternChecker.java
│               │   └── EntropyCalculator.java
│               │
│               ├── security/
│               │   └── CommonPasswordChecker.java
│               │
│               ├── generator/
│               │   └── PasswordGenerator.java
│               │
│               ├── gui/
│               │   ├── MainWindow.java
│               │   ├── AnalyzerPanel.java
│               │   └── GeneratorPanel.java
│               │
│               └── util/
│                   ├── InputValidator.java
│                   └── ReportExporter.java
│
├── resources/
│   └── common_passwords.txt              ← small educational sample list
│
└── test/
    └── java/securepass/                  ← JUnit test classes
```

---

## Technologies / Tools Used

| Tool | Purpose |
|---|---|
| **Java (JDK 17+)** | Core language |
| **Java Swing** | Desktop GUI |
| **java.security.SecureRandom** | Cryptographically strong password generation |
| **JUnit** | Unit testing of analyzer/generator logic |
| **Git** | Version control |

No external/third-party libraries or database are used — see `statement.md` and the project report's *Design Decisions* section for why.

---

## Requirements

- **JDK 17 or later** installed and on your `PATH`
- A normal Windows, macOS, or Linux laptop — no special hardware or GPU required
- (Optional) An IDE such as IntelliJ IDEA, Eclipse, or VS Code with the Java extension pack

Check your Java version:
```bash
java -version
javac -version
```

---

## Installation

```bash
# Clone the repository
git clone https://github.com/<your-username>/SecurePass-24BCY10026.git
cd SecurePass-24BCY10026
```

No build tool (Maven/Gradle) is required — the project compiles directly with `javac`.

---

## How to Compile

From the project root:

```bash
javac -d out $(find src/main/java -name "*.java")
```

This compiles all source files into an `out/` directory, preserving the `securepass` package structure.

---

## How to Run

```bash
# Copy resources so the running app can find the common-password list
cp -r resources out/

java -cp out securepass.Main
```

The **SecurePass** main window should open with navigation for **Password Analyzer**, **Password Generator**, **Security Report**, and **About**.

---

## How to Use

1. Open the **Password Analyzer** tab, type a password into the masked field, and click **Analyze**.
2. Review the strength rating, entropy estimate, individual security checks, and recommendations.
3. Switch to the **Password Generator** tab, choose a length and character types, and click **Generate**.
4. The generated password is automatically analyzed so you can see its strength immediately.
5. Optionally, export the **Security Report** — the exported file contains analysis data only, never the password.

---

## Testing

Unit tests (JUnit) cover the non-GUI logic: `PasswordAnalyzer`, `EntropyCalculator`, `PatternChecker`, `CommonPasswordChecker`, `PasswordGenerator`, and `InputValidator`.

```bash
# Example if using an IDE: right-click the test/ folder → Run All Tests
# Example from the command line with JUnit console launcher:
java -jar junit-platform-console-standalone.jar -cp out:test-out --scan-classpath
```

The GUI itself is verified through manual exploratory testing (empty input, weak/strong/common passwords, invalid generator settings). See the full test case table (TC-01 to TC-12) in the project report.

---

## Security Considerations

- Passwords are captured as `char[]` via `JPasswordField`, never as an immutable `String`, and are explicitly cleared after use.
- **No network calls** are made anywhere in the application — all processing is local.
- Exported reports cannot contain a password even by mistake — `ReportExporter` has no parameter through which one could be passed in.
- `SecureRandom`, not `Math.random()`, is used for all password generation.
- SecurePass does **not** claim any password is guaranteed unbreakable — it only reports which specific checks passed or failed. See `statement.md` and the report's *Limitations* section for details.

---

## Limitations

- The entropy formula assumes uniform random character selection and does not capture human-predictable patterns.
- The bundled `common_passwords.txt` is a small educational sample, not a full breached-password corpus.
- Scoring weights are a documented, defensible convention — not an empirically validated security model.

---

## Future Enhancements

- Optional privacy-preserving k-anonymity lookup against a breached-password API.
- Configurable/advanced scoring weights.
- Passphrase (word-based) generation mode.

---

## Author

**Praveen P B** — Registration Number **24BCY10026**
Submitted for *Programming in Java – Evaluated Project*, VITyarthi Portal.

---

*"A password strength meter is only useful if it explains itself — a strong password shouldn't be a black-box verdict."*
