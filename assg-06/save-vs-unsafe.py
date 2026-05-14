"""
command_injection_safe_vs_unsafe.py
=====================================
Educational demonstration: Command Injection – Safe vs. Unsafe Patterns
Assignment context: Web Application Security – Remediation Deliverable

This file does NOT perform any attacks. It demonstrates, using only the
Python standard library, why certain coding patterns are dangerous and
what the secure alternatives look like. No network requests are made.
"""

import subprocess
import shlex


# =============================================================================
# SECTION 1 — THE UNSAFE PATTERN (do not use in production)
# =============================================================================

def unsafe_ping_shell_true(user_input: str) -> str:
    """
    UNSAFE: passes user input directly into a shell command string.

    When shell=True, the OS shell (e.g. /bin/sh) interprets the entire
    string, including any metacharacters the user may have included.

    Common shell metacharacters that allow injection:
        ;   – command separator      e.g.  127.0.0.1; id
        &&  – AND chaining           e.g.  127.0.0.1 && cat /etc/passwd
        ||  – OR chaining            e.g.  127.0.0.1 || whoami
        |   – pipe                   e.g.  127.0.0.1 | ls -la
        $() – command substitution   e.g.  127.0.0.1$(id)
        ``  – backtick substitution  e.g.  127.0.0.1`id`

    Root cause in DVWA (Low level) – the PHP source does exactly this:
        $cmd = shell_exec('ping -c 4 ' . $_GET['ip']);
    The Python equivalent below mirrors that antipattern.
    """
    # !! NEVER DO THIS !!
    command_string = f"ping -c 1 {user_input}"
    print(f"[UNSAFE] Would execute shell string: {command_string!r}")

    # To illustrate the danger without running anything, we just show what
    # the shell would see for various malicious inputs:
    examples = [
        "127.0.0.1",               # legitimate
        "127.0.0.1; id",           # command separator
        "127.0.0.1 && whoami",     # AND chain
        "127.0.0.1 | cat /etc/passwd",  # pipe
        "$(id)",                   # command substitution
    ]
    print("\n  What the shell would receive for various inputs:")
    for ex in examples:
        print(f"    Input {ex!r:40s}  →  shell sees: {f'ping -c 1 {ex}'!r}")
    return "[unsafe – not executed]"


# =============================================================================
# SECTION 2 — THE SAFE PATTERN
# =============================================================================

def safe_ping_no_shell(user_input: str) -> str:
    """
    SAFE: passes arguments as a list, bypassing the shell entirely.

    When shell=False (the default), subprocess.run() calls execvp()
    directly. The OS never invokes a shell, so metacharacters have no
    special meaning — they are passed as literal data to the program.

    Even if the user supplies '127.0.0.1; id', ping receives that as
    its first argument and fails cleanly (invalid host), rather than
    running a second command.
    """
    print(f"\n[SAFE] Preparing to call ping with input: {user_input!r}")

    # Input validation layer — check before we even call subprocess
    validated = _validate_ip(user_input)
    if validated is None:
        return f"[SAFE] Input rejected by validation: {user_input!r}"

    # Arguments as a list — no shell involved
    args = ["ping", "-c", "1", validated]
    print(f"[SAFE] Argument list passed to execvp: {args}")

    # In a real application you would capture output; here we just show
    # the pattern. We use check=False so demo doesn't raise on failure.
    result = subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=5,
        shell=False,   # explicit for clarity; False is already the default
    )
    return result.stdout or result.stderr


def _validate_ip(value: str) -> str | None:
    """
    Allowlist validation: only accept strings that look like an IPv4
    address (four 0-255 octets). Anything else is rejected outright.

    Allowlist (permit known-good) is always preferred over denylist
    (block known-bad), because attackers can always find metacharacters
    you forgot to block.
    """
    import re
    pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    if not re.match(pattern, value):
        return None
    octets = value.split(".")
    if all(0 <= int(o) <= 255 for o in octets):
        return value
    return None


# =============================================================================
# SECTION 3 — ADDITIONAL SAFE ALTERNATIVE: shlex quoting
# =============================================================================

def demonstrate_shlex_quoting():
    """
    If you genuinely must use shell=True (e.g. you need shell globbing),
    shlex.quote() escapes the input so it is treated as a single literal
    token by the shell.  This is a secondary defence; avoiding shell=True
    is always preferable.
    """
    dangerous_input = "127.0.0.1; id"
    quoted = shlex.quote(dangerous_input)
    shell_string = f"ping -c 1 {quoted}"
    print(f"\n[shlex] Raw input   : {dangerous_input!r}")
    print(f"[shlex] After quote : {quoted!r}")
    print(f"[shlex] Shell sees  : {shell_string!r}")
    print("  → shell treats the entire quoted string as one argument to ping")
    print("  → ping fails (bad hostname) but no second command executes")


# =============================================================================
# SECTION 4 — DVWA LEVEL COMPARISON SUMMARY
# =============================================================================

DVWA_LEVELS = {
    "Low": {
        "php_snippet": "shell_exec('ping -c 4 ' . $_REQUEST['ip']);",
        "defence": "None – raw concatenation into shell command.",
        "bypass": "Any shell metacharacter works: ; | && || $() ``",
    },
    "Medium": {
        "php_snippet": (
            "$substitutions = array('&&' => '', ';' => '');\n"
            "$target = str_replace(array_keys($substitutions), "
            "$substitutions, $target);"
        ),
        "defence": "Denylist stripping of && and ;",
        "bypass": "Use | or || which are not stripped.",
    },
    "High": {
        "php_snippet": (
            "$substitutions = array('&' => '', ';' => '', '|' => ' ', "
            "'-' => '', '$' => '', '(' => '', ')' => '', '`' => '', "
            "'||' => '');\n"
            "$target = str_replace(...);"
        ),
        "defence": "Broader denylist – strips most metacharacters.",
        "bypass": (
            "| (pipe with space before it) may survive depending on "
            "implementation; denylist approach is inherently fragile."
        ),
    },
    "Impossible": {
        "php_snippet": (
            "// Validate IP with stripos/intval on each octet\n"
            "// Only four numeric octets allowed; else die()"
        ),
        "defence": (
            "Strict allowlist – only a valid IPv4 address passes. "
            "No metacharacter can survive because non-numeric input "
            "is rejected before the shell call."
        ),
        "bypass": "None – allowlist validation is the correct approach.",
    },
}


def print_level_comparison():
    print("\n" + "=" * 70)
    print("DVWA Command Injection – Defence Level Comparison")
    print("=" * 70)
    for level, info in DVWA_LEVELS.items():
        print(f"\n  Level: {level}")
        print(f"  PHP:   {info['php_snippet']}")
        print(f"  Defence: {info['defence']}")
        print(f"  Residual risk: {info['bypass']}")
    print()


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("Command Injection – Safe vs. Unsafe Pattern Demonstration")
    print("Educational use only | No network attacks performed")
    print("=" * 70)

    print("\n--- Section 1: Unsafe pattern (illustrated only, not executed) ---")
    unsafe_ping_shell_true("127.0.0.1")

    print("\n--- Section 2: Safe pattern (shell=False + allowlist validation) ---")
    test_inputs = [
        "127.0.0.1",          # valid
        "192.168.1.1",        # valid
        "127.0.0.1; id",      # injection attempt
        "$(whoami)",          # command substitution attempt
        "999.999.999.999",    # invalid IP
    ]
    for inp in test_inputs:
        result = safe_ping_no_shell(inp)
        print(f"  Result: {result[:80]}")

    print("\n--- Section 3: shlex.quote() as a secondary control ---")
    demonstrate_shlex_quoting()

    print_level_comparison()

    print("KEY TAKEAWAY")
    print("-" * 70)
    print("Denylist approaches (Low/Medium/High) are fragile by design —")
    print("they try to enumerate bad input, which attackers can always")
    print("work around. Allowlist validation (Impossible level) is the")
    print("correct fix: define exactly what is permitted and reject everything")
    print("else before it reaches a shell call.")