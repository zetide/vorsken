# Test fixture: intentionally vulnerable subprocess shell=True calls.
#
# Exercised by tests/test_rule_subprocess_shell_true.py to verify the
# `subprocess-shell-true` Semgrep rule fires on every shell=True subprocess
# call and does NOT fire on safe (list-argument / shell=False) calls.
import subprocess


def vulnerable_run(user_input):
    # VULN-RUN: shell=True command injection
    subprocess.run(user_input, shell=True)


def vulnerable_popen(user_input):
    # VULN-POPEN: shell=True command injection
    subprocess.Popen(user_input, shell=True)


def vulnerable_call(user_input):
    # VULN-CALL: shell=True command injection
    subprocess.call(user_input, shell=True)


def vulnerable_check_call(user_input):
    # VULN-CHECK-CALL: shell=True command injection
    subprocess.check_call(user_input, shell=True)


def vulnerable_check_output(user_input):
    # VULN-CHECK-OUTPUT: shell=True command injection
    subprocess.check_output(user_input, shell=True)


def safe_list_args():
    # SAFE-LIST: list arguments, no shell
    subprocess.run(["ls", "-la"])


def safe_shell_false(user_input):
    # SAFE-SHELL-FALSE: explicit shell=False with list args
    subprocess.run([user_input], shell=False)
