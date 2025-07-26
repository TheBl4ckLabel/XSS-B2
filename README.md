# XSS-B2 
XSS-B2 Dropper Evasion Stealth Mode Tool 🚀

XSS-B2 is an enhanced XSS automation tool designed to streamline the process of identifying and exploiting Cross-Site Scripting (XSS) vulnerabilities. With a focus on real JavaScript execution detection, XSS-B2 offers advanced features such as:

* **<font color="green">Proxy Support</font>**: Rotate through a list of proxies for improved anonymity and evasion
* **<font color="green">User Agent Rotation</font>**: Switch between multiple user agents to avoid detection
* **<font color="green">reCAPTCHA Bypass</font>**: Utilize audio recognition to bypass reCAPTCHA challenges
* **<font color="green">Terminal Progress Bar</font>**: Visualize scan progress with a rich terminal interface
* **<font color="green">JSON Reporting</font>**: Generate detailed reports for comprehensive vulnerability analysis

## <font color="blue">Features</font>

* **<font color="red">Real XSS Detection</font>**: Focus on actual JavaScript execution, minimizing false positives
* **<font color="red">GET and POST Method Support</font>**: Test both HTTP methods for comprehensive vulnerability scanning
* **<font color="red">Arjun Integration</font>**: Leverage Arjun for parameter discovery to enhance scan effectiveness
* **<font color="red">Custom Payloads</font>**: Load your own XSS payloads for tailored testing
* **<font color="red">Verbose Output</font>**: Enable detailed logging for debugging and analysis

## <font color="blue">Installation</font>

1. Clone the repository: `git clone https://github.com/username/xss-b2.git`
2. Install dependencies: `python3 xss-b2.py --install-deps`
3. Run the tool: `python3 xss-b2.py -h`

## <font color="blue">Usage</font>

```bash
python3 xss-b2.py -u <target_url> -o <output_dir> [-p <proxy_file>] [-m <method>] [--bypassrecaptcha]
```

## <font color="blue">Command-Line Arguments</font>

* `-u, --url <URL>`: <font color="green">Single target URL</font>
* `-l, --list <FILE>`: <font color="green">File with list of URLs</font>
* `-o, --output-dir <DIR>`: <font color="green">Output directory for results</font>
* `-p, --proxy <FILE>`: <font color="green">File containing proxy list (HTTP, HTTPS, SOCKS5)</font>
* `--proxy-only`: <font color="red">Force proxy-only mode (no direct connection fallback)</font>
* `--test-proxies`: <font color="red">Test all proxies and exit</font>
* `--show-browser`: <font color="red">Show browser (run in visible mode)</font>
* `--timeout <SEC>`: <font color="green">Page load timeout in seconds (default:10)</font>
* `--delay <SEC>`: <font color="green">Delay between requests in seconds (default:1)</font>
* `--threads <NUM>`: <font color="green">Number of threads for Arjun (default:5)</font>
* `--payloads <FILE>`: <font color="green">Custom XSS payloads file (one per line)</font>
* `-m, --method <method>`: <font color="green">HTTP method for testing payloads (default: GET)</font>
* `--bypassrecaptcha`: <font color="red">Enable reCAPTCHA bypass using audio challenge</font>
* `--tbar`: <font color="red">Enable terminal progress bar (requires rich)</font>
* `-v, --verbose`: <font color="red">Enable verbose/debug output</font>
* `--log-file <FILE>`: <font color="green">Save logs to file</font>

## <font color="blue">Requirements</font>

* Python3.7+
* Selenium
* Requests
* BeautifulSoup4
* Pydub
* SpeechRecognition
* Rich

## <font color="blue">Disclaimer</font>

Use XSS-B2 only on authorized targets. The authors and contributors are not responsible for any misuse or damage caused.

## <font color="blue">Contributing</font>

Contributions are welcome! Please submit pull requests or issues on GitHub.

## <font color="blue">License</font>

XSS-B2 is licensed under the MIT License. See LICENSE for details.
