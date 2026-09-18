# SecurePass — Problem Statement

### Programming in Java — Evaluated Project

| Field | Details |
|---|---|
| **Student Name** | Praveen P B |
| **Registration Number** | 24BCY10026 |
| **Course** | Programming in Java – Evaluated Project |
| **Project Title** | SecurePass — Password Security Analyzer & Generator |
| **Project Type** | Java Desktop Application (Swing) |
| **Submission** | VITyarthi Portal |

---

## 1. Problem Statement

Weak and reused passwords remain one of the most common causes of account compromise. Most people are never told *why* a password is weak — they are shown a coloured bar that says "Weak" or "Strong" and are left to guess what to change. Worse, many online "password strength checkers" require the user to type a real password into a web page, sending it over the network to an unknown server.

This creates two distinct problems:

1. **An explanation problem.** Existing strength meters behave as black boxes. A user who is told their password is weak learns nothing transferable about choosing a better one.
2. **A trust problem.** A tool that asks for a password and then transmits it is asking the user to take a security risk in order to improve their security.

**SecurePass** addresses both. It is a fully offline Java desktop application that analyzes a password, explains each individual finding in plain language, suggests concrete improvements, and can generate a cryptographically strong replacement — without ever storing, logging, or transmitting the password itself.

---

## 2. Objectives

1. Analyze a user-supplied password and produce a strength rating derived from length, character diversity, repetition, sequential patterns, keyboard patterns, and common-password matches.
2. Explain the rating by reporting which specific checks passed or failed, and pair each failed check with an actionable recommendation.
3. Estimate password entropy using a transparent, documented formula, and state its limitations honestly.
4. Generate strong passwords with user-configurable length and character classes using `java.security.SecureRandom`.
5. Produce an exportable security report containing only *derived* analysis data — never the password.
6. Guarantee that no password data leaves the machine: no network calls, no persistence of input, no logging.
7. Demonstrate core Java concepts — interfaces, polymorphism, encapsulation, collections, exception handling, file I/O, and GUI programming — within a single coherent application rather than as disconnected exercises.

---

## 3. Scope

### In Scope

- A Swing desktop GUI with four sections: **Password Analyzer**, **Password Generator**, **Security Report**, and **About**.
- Rule-based password analysis with a pluggable set of security checks implemented against a common `SecurityCheck` interface.
- Entropy estimation using the `L × log₂(R)` model (length × log₂ of character-pool size).
- Password generation backed by `SecureRandom`, with validation of generator settings.
- Matching against a small, bundled, educational sample list of common passwords loaded from `resources/common_passwords.txt`.
- Exporting a plain-text security report containing strength rating, entropy estimate, and per-check results.
- Graceful handling of empty input, invalid generator configuration, and a missing or unreadable resource file.
- JUnit unit tests for all non-GUI logic, plus documented manual test cases for the GUI.

### Out of Scope

- Any network communication, including breached-password API lookups (noted as a future enhancement).
- Storing, caching, or persisting the user's password in any form.
- A database, password manager, or credential vault.
- Authentication, encryption, or key-derivation services for other applications.
- Machine-learning or corpus-trained strength models.
- Mobile or web front-ends.

---

## 4. Target Users

| User | Need served by SecurePass |
|---|---|
| **Students and beginners in cybersecurity** | A visible, readable implementation of how password strength is actually evaluated. |
| **General computer users** | A safe way to test a password without sending it anywhere, plus plain-language reasons for the verdict. |
| **Instructors and lab demonstrators** | A self-contained offline tool for classroom demonstrations of password hygiene and entropy. |
| **Anyone creating a new password** | A generator that produces strong candidates and immediately shows why they are strong. |

---

## 5. Proposed Solution

SecurePass is organised into layered packages, each with a single responsibility:

| Package | Responsibility |
|---|---|
| `model` | Plain data holders — `PasswordResult`, `SecurityReport`. |
| `analyzer` | The `SecurityCheck` interface, `PasswordAnalyzer` (orchestration and scoring), `PatternChecker`, `EntropyCalculator`. |
| `security` | `CommonPasswordChecker` — file-backed lookup against the bundled sample list. |
| `generator` | `PasswordGenerator` — `SecureRandom`-based construction with configurable character classes. |
| `gui` | `MainWindow`, `AnalyzerPanel`, `GeneratorPanel` — Swing presentation only. |
| `util` | `InputValidator` (input rules), `ReportExporter` (file output). |

Each individual security rule implements the `SecurityCheck` interface, so `PasswordAnalyzer` holds a collection of checks and runs them polymorphically. Adding a new rule requires writing one class and registering it — no change to the analyzer's logic. This is the project's main demonstration of interfaces and polymorphism serving a practical design goal rather than an academic one.

---

## 6. Key Design Decisions

- **Offline by construction, not by policy.** There is no networking code anywhere in the project, so the privacy guarantee cannot be broken by a configuration mistake.
- **`char[]` instead of `String`.** Passwords are read from `JPasswordField` as a mutable character array and cleared after use, rather than becoming immutable `String` objects that linger in memory until garbage collection.
- **The exporter cannot leak.** `ReportExporter` accepts a `SecurityReport` only. There is no method parameter through which a password could be passed in, accidentally or otherwise.
- **`SecureRandom`, never `Math.random()`.** Generation uses a cryptographically strong source.
- **No external libraries or database.** The project is compiled with `javac` alone and runs on a stock JDK 17+ installation. This keeps the submission reproducible on any evaluator's machine, keeps every line of security-relevant logic visible and reviewable, and avoids hiding the graded concepts behind a framework.
- **Explain, don't just score.** Every rating is accompanied by the list of checks that produced it.

---

## 7. Assumptions

- The user has JDK 17 or later installed and available on `PATH`.
- The application runs on a single-user personal machine that is not already compromised.
- The bundled `common_passwords.txt` is present in the runtime classpath directory; if it is missing, the application degrades gracefully and reports the check as unavailable instead of failing.
- The user is entering a password for evaluation purposes and understands that SecurePass gives advice, not guarantees.

---

## 8. Limitations

- The `L × log₂(R)` entropy formula assumes uniformly random character selection. It systematically overestimates the strength of human-chosen passwords that happen to contain varied character classes but follow predictable structures.
- The bundled common-password list is a small educational sample, not a full breached-credential corpus. A password absent from the list is not thereby proven safe.
- Scoring weights are a documented, defensible convention chosen for clarity — they are not an empirically validated security model.
- SecurePass makes no claim that any password is unbreakable. It reports only which specific checks passed and which failed.

---

## 9. Expected Outcome

A working, self-contained Java desktop application that a user can compile and run in two commands, which analyzes a password and explains its verdict, generates strong alternatives, exports a password-free security report, and does all of this without a single byte leaving the machine — while serving as a readable demonstration of object-oriented design in Java.

---

**Praveen P B** — Registration Number **24BCY10026**
*Programming in Java – Evaluated Project*, VITyarthi Portal.
