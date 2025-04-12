# Cloud XSS - Advanced XSS Exploitation Framework

![Banner](https://img.shields.io/badge/CloudXSS-Pro%203.0-brightgreen)
![Python](https://img.shields.io/badge/Python-3.7%2B-blue)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Platform](https://img.shields.io/badge/Platform-Linux-red)

A powerful Python tool for detecting Cross-Site Scripting (XSS) vulnerabilities in web applications.

## Features

- **Robust XSS Detection**: Detects a wide range of XSS vulnerabilities using an extensive payload library
- **Automatic Parameter Discovery**: Identifies potential input vectors automatically
- **Multi-threaded Scanning**: Faster scanning with parallel testing
- **Multiple Output Formats**: Export results as TXT, JSON, or HTML reports
- **Browser Automation**: Uses real browsers (Firefox/Chrome) to verify XSS vulnerabilities
- **Detailed Logging**: Comprehensive logs for analysis and debugging
- **Proxy Support**: Test through proxies for anonymity or testing internal applications
- **Customizable**: Fine-tune your scans with numerous configuration options

## Requirements

- Python 3.6+
- Firefox or Chrome browser
- Geckodriver (for Firefox, included in the repository)
- Required Python packages (see requirements.txt)

## Installation

1. Clone this repository or download the files
2. Install required packages:

```bash
pip install -r requirements.txt
```

3. The program will use the included geckodriver.exe, or you can specify a different path with the `--geckodriver` option

## Usage

### Basic Usage:

```bash
python cloudxss.py -u "http://example.com/page.php?param=test" -p param
```

### Auto-detect Parameters:

```bash
python cloudxss.py -u "http://example.com/page.php" -a
```

### Using Custom Headers and Cookies:

```bash
python cloudxss.py -u "http://example.com/page.php" -p param -H "Authorization: Bearer token" -c "session=abc123"
```

### Saving Results to HTML:

```bash
python cloudxss.py -u "http://example.com/page.php" -p param -o results.html -f html
```

### Multi-threaded Scanning:

```bash
python cloudxss.py -u "http://example.com/page.php" -p param -t 10
```

### Using a Proxy:

```bash
python cloudxss.py -u "http://example.com/page.php" -p param --proxy "http://127.0.0.1:8080"
```

## Command Line Options

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
                        Path to geckodriver (default: geckodriver.exe on Windows)
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

## Example Screenshots

### Command Line Interface
![CLI Example](https://via.placeholder.com/800x400/222222/FFFFFF?text=CLI+Example)

### HTML Report
![HTML Report](https://via.placeholder.com/800x400/222222/FFFFFF?text=HTML+Report+Example)

## File Structure

- `cloudxss.py` - Main program file
- `xss.txt` - Default XSS payload list
- `requirements.txt` - Python dependencies
- `geckodriver.exe` - Firefox WebDriver (for Windows)
- `logs/` - Directory containing scan logs

## Extending the Tool

### Adding Custom Payloads

Create a text file with one payload per line and use it with the `-x` option:

```bash
python cloudxss.py -u "http://example.com/page.php" -p param -x custom_payloads.txt
```

### Custom Detection Logic

Use the `--custom-alert` option to provide JavaScript that returns true when an XSS vulnerability is detected:

```bash
python cloudxss.py -u "http://example.com/page.php" -p param --custom-alert "document.querySelector('.injected') !== null"
```

## License

MIT License

## Disclaimer

This tool is for educational and security testing purposes only. Always obtain proper authorization before testing websites for vulnerabilities.
