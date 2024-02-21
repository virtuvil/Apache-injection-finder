import sys
import re

def detect_attacks(log_file_path):
    # Regular expression patterns for SQL injection, XSS, and SSTI attacks
    sql_injection_pattern = r"(?i)\b(union.*select|select.*from.*information_schema|drop.*table|\bexec(\s|\+)+(s|x)p\w+|exec(\s|\+)+xp_cmdshell|convert(\s|\+)+\(\w+|\bdeclare(\s|\+)+\w+)"
    xss_pattern = r"<(script|img|body|iframe|svg|input|div|a|button)[\s>]"
    ssti_pattern = r"\{\{.*?\}\}"

    # Read the log file
    with open(log_file_path, 'r') as file:
        log_data = file.read()

    # Check for SQL injection attacks
    sql_injection_matches = re.findall(sql_injection_pattern, log_data)
    if sql_injection_matches:
        print("SQL Injection Attacks Detected:")
        for match in sql_injection_matches:
            print(f" - {match}")

    # Check for XSS attacks
    xss_matches = re.findall(xss_pattern, log_data)
    if xss_matches:
        print("\nXSS Attacks Detected:")
        for match in xss_matches:
            print(f" - {match}")

    # Check for SSTI attacks
    ssti_matches = re.findall(ssti_pattern, log_data)
    if ssti_matches:
        print("\nSSTI Attacks Detected:")
        for match in ssti_matches:
            print(f" - {match}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python detect_attacks.py <apache_access_log>")
        sys.exit(1)

    log_file_path = sys.argv[1]
    detect_attacks(log_file_path)

