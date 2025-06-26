import requests
import time
from datetime import datetime
import pyfiglet
from termcolor import colored

# Function to display the header
def display_header():
    figlet = pyfiglet.Figlet(font='big')  # Larger font
    ascii_art = figlet.renderText('SQLyzer')
    lines = ascii_art.split('\n')
    for line in lines:
        print(colored(line, 'cyan', attrs=['bold']))  # Cyan color with bold effect
        time.sleep(0.5)  # Slight delay for dramatic effect
    print(colored(' ' * 25 + "Written by Jesimiel", 'yellow', attrs=['bold', 'underline']))
    print(colored('-' * 70, 'green'))

# Function to log scan details
def log_scan(log_message, log_file="logs.txt"):
    with open(log_file, "a") as log:
        log.write(log_message + "\n")

# Function to save a report
def save_report(report_message, report_file="reports.txt"):
    with open(report_file, "a") as report:
        report.write(report_message + "\n")

# Function to test for Error-Based SQL Injection
def test_error_based_sqli(url, payloads):
    print("[INFO] Testing for Error-Based SQL Injection...")
    found_payloads = []
    db_error_keywords = [
        "you have an error in your sql syntax", 
        "warning: mysql_", 
        "unknown column",
        "malformed gtid set specification",
        "warning: mysqli_fetch_",
        "boolean given in",
        "unclosed quotation mark after the character string",  # SQL Server
        "syntax error at or near",  # PostgreSQL
        "unexpected end of SQL command",  # General
        "division by zero",  # MySQL
        "database error", 
        "native client", 
        "odbc",  # SQL Server/ODBC
        "ORA-00933: SQL command not properly ended",  # Oracle
        "ORA-00942: table or view does not exist",
        "ORA-01756: quoted string not properly terminated",
        "ORA-00984: column not allowed here",
        "ORA-06512: at line",
        "PLS-00306: wrong number or types of arguments",
        "ORA-01400: cannot insert NULL into",
        "ERROR: unterminated quoted string",  # PostgreSQL
        "ERROR: column \"x\" does not exist",
        "SQLite3::SQLException",
        "SQL logic error or missing database",
        "unrecognized token",
        "no such column",
    ]
    try:
        baseline_response = requests.get(url, timeout=10)
        baseline_text = baseline_response.text.lower()
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Failed to connect to the URL: {e}")
        return []

    for payload in payloads:
        target = f"{url}?{payload}"
        try:
            response = requests.get(target, timeout=10)
            response_text = response.text.lower()
            if any(keyword in response_text for keyword in db_error_keywords):
                if response_text != baseline_text:
                    print(f"[FOUND] Error-Based SQL Injection with payload: {payload}")
                    found_payloads.append(payload)
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Request failed: {e}")
    
    return found_payloads

# Function to test for Boolean-Based SQL Injection
def test_boolean_based_sqli(url, payloads):
    print("[INFO] Testing for Boolean-Based SQL Injection...")
    found_payloads = []
    for payload in payloads:
        payload_true = f"{payload} AND 1=1"
        payload_false = f"{payload} AND 1=2"
        try:
            response_true = requests.get(f"{url}?{payload_true}", timeout=10)
            response_false = requests.get(f"{url}?{payload_false}", timeout=10)
            if response_true.text != response_false.text:
                print(f"[FOUND] Boolean-Based SQL Injection with payload: {payload_true}")
                found_payloads.append(payload_true)
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Request failed: {e}")
    return found_payloads

# Function to test for Time-Based SQL Injection
def test_time_based_sqli(url, payloads):
    print("[INFO] Testing for Time-Based SQL Injection...")
    found_payloads = []
    for payload in payloads:
        target = f"{url}?{payload}"
        try:
            start_time = time.time()
            response = requests.get(target, timeout=15)
            elapsed_time = time.time() - start_time
            if elapsed_time > 5:  # Assuming a 5-second delay indicates vulnerability
                print(f"[FOUND] Time-Based SQL Injection with payload: {payload}")
                found_payloads.append(payload)
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Request failed: {e}")
    return found_payloads

# Main function
def main():
    display_header()  # Show header
    url = input("Enter the target URL (e.g., http://example.com/page): ").strip()
    payload_file = "sq1.txt"  # Fixed payload file name

    try:
        with open(payload_file, "r") as file:
            payloads = [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print(f"[ERROR] Payload file not found: {payload_file}")
        return

    # Get current time for logs and reports
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"[SCAN] Date/Time: {scan_time}, Target URL: {url}"

    # Conduct SQLi tests
    error_based_payloads = test_error_based_sqli(url, payloads)
    boolean_based_payloads = test_boolean_based_sqli(url, payloads)
    time_based_payloads = test_time_based_sqli(url, payloads)

    # Log scan results
    log_scan(log_message)
    
    # Create a combined report
    report_message = f"[REPORT] Date/Time: {scan_time}\nTarget URL: {url}\n"
    if error_based_payloads:
        report_message += "Error-Based SQLi Payloads Found:\n" + "\n".join(error_based_payloads) + "\n"
    if boolean_based_payloads:
        report_message += "Boolean-Based SQLi Payloads Found:\n" + "\n".join(boolean_based_payloads) + "\n"
    if time_based_payloads:
        report_message += "Time-Based SQLi Payloads Found:\n" + "\n".join(time_based_payloads) + "\n"
    if not (error_based_payloads or boolean_based_payloads or time_based_payloads):
        report_message += "No SQL Injection vulnerabilities found."

    save_report(report_message)
    print("[INFO] Scan completed. Results logged and report generated.")

if __name__ == "__main__":
    main()
