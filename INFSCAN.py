#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
================================================================================
██╗███╗   ██╗███████╗███████╗ ██████╗ █████╗ ███╗   ██╗
██║████╗  ██║██╔════╝██╔════╝██╔════╝██╔══██╗████╗  ██║
██║██╔██╗ ██║█████╗  ███████╗██║     ███████║██╔██╗ ██║
██║██║╚██╗██║██╔══╝  ╚════██║██║     ██╔══██║██║╚██╗██║
██║██║ ╚████║██║     ███████║╚██████╗██║  ██║██║ ╚████║
╚═╝╚═╝  ╚═══╝╚═╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
================================================================================
📌 Ultimate Domain Scanner v6.1 - Enterprise Edition (مُطوَّر بالكامل - الإصدار النهائي)
📌 Features: DNS, Subdomains (10+ sources), WAF, Tech Detection, Dir Busting,
             JS Extraction, Secrets, Subdomain Takeover, Cloud Detection,
             API Endpoints, Proxy Support, CSV Output, Progress Bar, and more!
📌 Author: Security Professional
================================================================================
"""

import socket
import sys
import argparse
import json
import time
import subprocess
import os
import re
import ssl
import logging
import asyncio
import aiohttp
from datetime import datetime
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import concurrent.futures
from typing import Dict, List, Set, Tuple, Optional, Any, Union
from collections import defaultdict
import pickle
from pathlib import Path
import warnings
warnings.filterwarnings('ignore')

# ========== محاولة استيراد المكتبات الاختيارية ==========
try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    import OpenSSL
    SSL_AVAILABLE = True
except ImportError:
    SSL_AVAILABLE = False

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False

# ========== التكوين والإعدادات ==========
class Config:
    TIMEOUT = 15
    MAX_RETRIES = 3
    THREADS = 50
    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    CACHE_DIR = ".cache"
    LOGS_DIR = "logs"
    REPORTS_DIR = "reports"
    PLUGINS_DIR = "plugins"
    PROXY = None
    NO_COLOR = False
    VERSION = "6.1"
    
    @classmethod
    def init_dirs(cls):
        for d in [cls.CACHE_DIR, cls.LOGS_DIR, cls.REPORTS_DIR, cls.PLUGINS_DIR]:
            Path(d).mkdir(exist_ok=True)

# ========== شعار الأداة ==========
def print_banner():
    banner = r"""
    ██╗███╗   ██╗███████╗███████╗ ██████╗ █████╗ ███╗   ██╗
    ██║████╗  ██║██╔════╝██╔════╝██╔════╝██╔══██╗████╗  ██║
    ██║██╔██╗ ██║█████╗  ███████╗██║     ███████║██╔██╗ ██║
    ██║██║╚██╗██║██╔══╝  ╚════██║██║     ██╔══██║██║╚██╗██║
    ██║██║ ╚████║██║     ███████║╚██████╗██║  ██║██║ ╚████║
    ╚═╝╚═╝  ╚═══╝╚═╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
    """
    print_color(banner, Colors.CYAN, bold=True)
    print_color("  🔍 Ultimate Domain Scanner v" + Config.VERSION + " - Enterprise Edition", Colors.MAGENTA, bold=True)
    print_color("  ⚡ Developed by Security Professional  |  🚀 All-in-One Recon Tool", Colors.GREEN)
    print_color("  " + "=" * 60, Colors.CYAN)

# ========== نظام الألوان ==========
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_color(msg: str, color: str = Colors.RESET, bold: bool = False):
    if Config.NO_COLOR:
        print(msg)
        return
    if bold:
        print(f"{Colors.BOLD}{color}{msg}{Colors.RESET}")
    else:
        print(f"{color}{msg}{Colors.RESET}")

# ========== نظام التسجيل ==========
class Logger:
    def __init__(self, name: str):
        self.name = name
        Config.init_dirs()
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        
        error_handler = logging.FileHandler(f"{Config.LOGS_DIR}/errors.log")
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(formatter)
        
        scan_handler = logging.FileHandler(f"{Config.LOGS_DIR}/scan.log")
        scan_handler.setLevel(logging.INFO)
        scan_handler.setFormatter(formatter)
        
        console = logging.StreamHandler()
        console.setLevel(logging.WARNING)
        console.setFormatter(formatter)
        
        self.logger.addHandler(error_handler)
        self.logger.addHandler(scan_handler)
        self.logger.addHandler(console)
    
    def info(self, msg): self.logger.info(msg)
    def error(self, msg): self.logger.error(msg)
    def warning(self, msg): self.logger.warning(msg)
    def debug(self, msg): self.logger.debug(msg)

# ========== نظام الكاش ==========
class Cache:
    def __init__(self):
        Config.init_dirs()
        self.cache_file = f"{Config.CACHE_DIR}/scan_cache.pkl"
        self.cache = self.load()
    
    def load(self) -> Dict:
        try:
            with open(self.cache_file, 'rb') as f:
                return pickle.load(f)
        except:
            return {}
    
    def save(self):
        with open(self.cache_file, 'wb') as f:
            pickle.dump(self.cache, f)
    
    def get(self, key: str) -> Optional[Any]:
        if key in self.cache:
            data = self.cache[key]
            if data['expires'] > time.time():
                return data['value']
        return None
    
    def set(self, key: str, value: Any, ttl: int = 7200):
        self.cache[key] = {'value': value, 'expires': time.time() + ttl}
        self.save()
    
    def clear_expired(self):
        now = time.time()
        self.cache = {k: v for k, v in self.cache.items() if v['expires'] > now}
        self.save()

# ========== دالة مساعدة لتحويل headers إلى dict بشكل آمن (محسّنة 100%) ==========
def safe_headers_to_dict(headers: Any) -> Dict[str, str]:
    """تحويل أي نوع من headers إلى dict بشكل آمن - معالجة جميع الحالات"""
    if headers is None:
        return {}
    
    # إذا كان headers بالفعل dict
    if isinstance(headers, dict):
        return {str(k): str(v) for k, v in headers.items() if k is not None and v is not None}
    
    # إذا كان headers من نوع CIMultiDict أو MultiDict (aiohttp) أو أي كائن له items()
    if hasattr(headers, 'items') and callable(headers.items):
        try:
            return {str(k): str(v) for k, v in headers.items() if k is not None and v is not None}
        except:
            pass
    
    # إذا كان headers list من tuples
    if isinstance(headers, (list, tuple)):
        result = {}
        for item in headers:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                key = str(item[0]) if item[0] is not None else ''
                val = str(item[1]) if item[1] is not None else ''
                if key and val:
                    result[key] = val
            elif hasattr(item, 'items') and callable(item.items):
                try:
                    for k, v in item.items():
                        if k is not None and v is not None:
                            result[str(k)] = str(v)
                except:
                    pass
        return result
    
    # محاولة تحويل headers باستخدام dict() مباشرة
    try:
        return dict(headers)
    except:
        pass
    
    # إذا كان headers له keys() و get()
    if hasattr(headers, 'keys') and hasattr(headers, 'get'):
        result = {}
        try:
            for key in headers.keys():
                val = headers.get(key)
                if key is not None and val is not None:
                    result[str(key)] = str(val)
            return result
        except:
            pass
    
    # إذا كان headers له getall() (aiohttp)
    if hasattr(headers, 'getall'):
        result = {}
        try:
            for key in headers.keys():
                vals = headers.getall(key)
                if vals and len(vals) > 0:
                    result[str(key)] = str(vals[0])
            return result
        except:
            pass
    
    # الحل الأخير: محاولة تحويله إلى str ثم تحليل (نادراً ما يستخدم)
    try:
        s = str(headers)
        # محاولة استخراج أزواج key:value إذا كان بالصيغة 'key: value'
        pairs = re.findall(r'([\w-]+):\s*([^\n\r]+)', s)
        if pairs:
            return {k.strip(): v.strip() for k, v in pairs}
    except:
        pass
    
    # إذا وصلنا إلى هنا، نعيد قاموساً فارغاً
    return {}

# ========== 1️⃣ DNS Scan ==========
class DNSScanner:
    def __init__(self, logger: Logger, cache: Cache):
        self.logger = logger
        self.cache = cache
        
    async def scan(self, domain: str) -> Dict:
        if not DNS_AVAILABLE:
            self.logger.warning("dnspython غير مثبت، تخطي فحص DNS")
            return {}
        records = {}
        print_color("\n[1️⃣] فحص سجلات DNS...", Colors.CYAN, bold=True)
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'PTR', 'SRV', 'CAA', 'NAPTR', 'LOC']
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, rtype, raise_on_no_answer=False)
                if answers:
                    records[rtype] = []
                    for rdata in answers:
                        if rtype == 'MX':
                            records[rtype].append(f"{rdata.preference} {rdata.exchange}")
                        elif rtype == 'SOA':
                            records[rtype].append(f"{rdata.mname} {rdata.rname}")
                        elif rtype == 'TXT':
                            txt = str(rdata).strip('"')
                            records[rtype].append(txt)
                            if txt.startswith('v=spf1'):
                                records['SPF'] = txt
                            if 'dmarc' in domain.lower():
                                records['DMARC'] = txt
                        else:
                            records[rtype].append(str(rdata))
                    print_color(f"  ✓ {rtype}: {len(records[rtype])} سجل", Colors.GREEN)
                    for rec in records[rtype][:3]:
                        print_color(f"    - {rec}", Colors.BLUE)
            except Exception as e:
                self.logger.debug(f"DNS {rtype} error: {e}")
        return records

# ========== 2️⃣ Subdomain Enumeration (محسّن) ==========
class SubdomainScanner:
    def __init__(self, logger: Logger, cache: Cache):
        self.logger = logger
        self.cache = cache

    async def scan_crtsh(self, domain: str) -> Set[str]:
        subs = set()
        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=Config.TIMEOUT) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for entry in data:
                            name = entry.get('name_value', '')
                            if name:
                                for sub in name.split('\n'):
                                    sub = sub.lower().strip()
                                    if sub.endswith(f".{domain}") and sub != domain and '*' not in sub:
                                        subs.add(sub)
        except Exception as e:
            self.logger.debug(f"crt.sh error: {e}")
        return subs

    async def scan_securitytrails(self, domain: str) -> Set[str]:
        subs = set()
        try:
            url = f"https://securitytrails.com/domain/{domain}/subdomains"
            headers = {'User-Agent': Config.USER_AGENT}
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=Config.TIMEOUT) as resp:
                    if resp.status == 200:
                        html = await resp.text()
                        pattern = r'<a[^>]*>([a-zA-Z0-9.-]+\.' + re.escape(domain) + r')</a>'
                        matches = re.findall(pattern, html)
                        for match in matches:
                            sub = match.lower().strip()
                            if sub != domain and '*' not in sub:
                                subs.add(sub)
        except Exception as e:
            self.logger.debug(f"SecurityTrails error: {e}")
        return subs

    async def scan_rapiddns(self, domain: str) -> Set[str]:
        subs = set()
        try:
            url = f"https://rapiddns.io/subdomain/{domain}"
            headers = {'User-Agent': Config.USER_AGENT}
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=Config.TIMEOUT) as resp:
                    if resp.status == 200:
                        html = await resp.text()
                        soup = BeautifulSoup(html, 'html.parser')
                        for td in soup.find_all('td'):
                            text = td.text.strip().lower()
                            if text.endswith(domain) and text != domain and '.' in text and '*' not in text:
                                subs.add(text)
        except Exception as e:
            self.logger.debug(f"RapidDNS error: {e}")
        return subs

    async def scan_bufferover(self, domain: str) -> Set[str]:
        subs = set()
        try:
            url = f"https://dns.bufferover.run/dns?q=.{domain}"
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=Config.TIMEOUT) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for fdns in data.get('FDNS_A', []):
                            parts = fdns.split(',')
                            if len(parts) > 1:
                                host = parts[1].strip().lower()
                                if host.endswith(domain) and host != domain and '*' not in host:
                                    subs.add(host)
                        for rdns in data.get('RDNS', []):
                            parts = rdns.split(',')
                            if len(parts) > 1:
                                host = parts[1].strip().lower()
                                if host.endswith(domain) and host != domain and '*' not in host:
                                    subs.add(host)
        except Exception as e:
            self.logger.debug(f"BufferOver error: {e}")
        return subs

    async def scan_hackertarget(self, domain: str) -> Set[str]:
        subs = set()
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=Config.TIMEOUT) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        for line in text.split('\n'):
                            if line and ',' in line:
                                host = line.split(',')[0].strip().lower()
                                if host.endswith(domain) and host != domain and '*' not in host:
                                    subs.add(host)
        except Exception as e:
            self.logger.debug(f"HackerTarget error: {e}")
        return subs

    async def scan_alienvault(self, domain: str) -> Set[str]:
        subs = set()
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=Config.TIMEOUT) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for entry in data.get('passive_dns', []):
                            host = entry.get('hostname', '').lower()
                            if host.endswith(domain) and host != domain and '*' not in host:
                                subs.add(host)
        except Exception as e:
            self.logger.debug(f"AlienVault error: {e}")
        return subs

    async def scan_certspotter(self, domain: str) -> Set[str]:
        subs = set()
        try:
            url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=Config.TIMEOUT) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for cert in data:
                            for name in cert.get('dns_names', []):
                                name = name.lower()
                                if name.endswith(domain) and name != domain and '*' not in name:
                                    subs.add(name)
        except Exception as e:
            self.logger.debug(f"CertSpotter error: {e}")
        return subs

    async def scan_threatcrowd(self, domain: str) -> Set[str]:
        subs = set()
        try:
            url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=Config.TIMEOUT) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for sub in data.get('subdomains', []):
                            sub = sub.lower()
                            if sub.endswith(domain) and sub != domain and '*' not in sub:
                                subs.add(sub)
        except Exception as e:
            self.logger.debug(f"ThreatCrowd error: {e}")
        return subs

    async def scan_anubis(self, domain: str) -> Set[str]:
        subs = set()
        try:
            url = f"https://jldc.me/anubis/subdomains/{domain}"
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=Config.TIMEOUT) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if isinstance(data, list):
                            for sub in data:
                                sub = sub.lower()
                                if sub.endswith(domain) and sub != domain and '*' not in sub:
                                    subs.add(sub)
        except Exception as e:
            self.logger.debug(f"Anubis error: {e}")
        return subs

    async def scan_urlscan(self, domain: str) -> Set[str]:
        subs = set()
        try:
            url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=Config.TIMEOUT) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for result in data.get('results', []):
                            page = result.get('page', {})
                            sub = page.get('domain', '').lower()
                            if sub.endswith(domain) and sub != domain and '*' not in sub:
                                subs.add(sub)
        except Exception as e:
            self.logger.debug(f"urlscan error: {e}")
        return subs

    async def scan_dnsdumpster(self, domain: str) -> Set[str]:
        subs = set()
        try:
            url = f"https://dnsdumpster.com/domain/{domain}"
            headers = {'User-Agent': Config.USER_AGENT}
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=Config.TIMEOUT) as resp:
                    if resp.status == 200:
                        html = await resp.text()
                        soup = BeautifulSoup(html, 'html.parser')
                        for td in soup.find_all('td'):
                            text = td.text.strip().lower()
                            if text.endswith(domain) and text != domain and '*' not in text:
                                subs.add(text)
        except Exception as e:
            self.logger.debug(f"DNSDumpster error: {e}")
        return subs

    async def scan_common(self, domain: str) -> Set[str]:
        subs = set()
        common = [
            'www', 'mail', 'ftp', 'smtp', 'pop', 'imap', 'ns1', 'ns2', 'ns3', 'ns4',
            'webmail', 'admin', 'blog', 'shop', 'api', 'docs', 'support', 'status',
            'test', 'dev', 'staging', 'prod', 'git', 'jenkins', 'jira', 'confluence',
            'slack', 'teams', 'zoom', 'meet', 'login', 'auth', 'sso', 'secure',
            'vpn', 'remote', 'cloud', 'cdn', 'static', 'media', 'assets',
            'download', 'uploads', 'images', 'css', 'js', 'app', 'mobile',
            'backup', 'backups', 'db', 'database', 'mysql', 'redis',
            'gitlab', 'bitbucket', 'phpmyadmin', 'pma', 'cpanel', 'whm',
            'mail2', 'mail3', 'mx', 'mx1', 'mx2', 'relay', 'pop3', 'imaps',
            'calendar', 'contacts', 'exchange', 'outlook', 'owa', 'autodiscover',
            'skype', 'teams', 'yammer', 'sharepoint', 'onedrive',
            'portal', 'my', 'account', 'profile', 'user', 'member',
            'partner', 'vendor', 'customer', 'client', 'help', 'faq', 'kb', 'wiki',
            'forum', 'community', 'chat', 'live', 'supportcenter',
            'payment', 'billing', 'invoice', 'checkout'
        ]
        def check(sub):
            try:
                full = f"{sub}.{domain}"
                ip = socket.gethostbyname(full)
                return full
            except:
                return None
        with concurrent.futures.ThreadPoolExecutor(max_workers=Config.THREADS) as executor:
            futures = [executor.submit(check, sub) for sub in common]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    subs.add(result)
        return subs

    async def scan(self, domain: str) -> List[str]:
        all_subs = set()
        print_color("\n[🔍] فحص النطاقات الفرعية المتقدم...", Colors.CYAN, bold=True)
        sources = [
            ("crt.sh", self.scan_crtsh),
            ("SecurityTrails", self.scan_securitytrails),
            ("RapidDNS", self.scan_rapiddns),
            ("BufferOver", self.scan_bufferover),
            ("HackerTarget", self.scan_hackertarget),
            ("AlienVault", self.scan_alienvault),
            ("CertSpotter", self.scan_certspotter),
            ("ThreatCrowd", self.scan_threatcrowd),
            ("Anubis", self.scan_anubis),
            ("urlscan", self.scan_urlscan),
            ("DNSDumpster", self.scan_dnsdumpster)
        ]
        tasks = [source(domain) for _, source in sources]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        source_stats = {}
        for i, result in enumerate(results):
            source_name = sources[i][0]
            if isinstance(result, set):
                count = len(result)
                source_stats[source_name] = count
                all_subs.update(result)
                if count > 0:
                    print_color(f"  ✓ {source_name}: {count} نطاق", Colors.GREEN)
            else:
                print_color(f"  ✗ {source_name}: فشل", Colors.RED)
        print_color(f"\n  🔍 فحص النطاقات الشائعة...", Colors.BLUE)
        common_subs = await self.scan_common(domain)
        all_subs.update(common_subs)
        print_color(f"  ✓ النطاقات الشائعة: {len(common_subs)} نطاق", Colors.GREEN)
        total = len(all_subs)
        print_color(f"\n  📊 إجمالي النطاقات الفرعية: {total}", Colors.MAGENTA, bold=True)
        if source_stats:
            best_source = max(source_stats, key=source_stats.get)
            print_color(f"  🏆 أفضل مصدر: {best_source} ({source_stats[best_source]} نطاق)", Colors.YELLOW)
        return sorted(list(all_subs))

# ========== 3️⃣ WAF Detection (محسّن) ==========
class WAFDetector:
    def __init__(self, logger: Logger):
        self.logger = logger
        self.waf_signatures = {
            'Cloudflare': {'headers': ['cf-ray', 'cf-cache-status', '_cfduid'], 'cookies': ['_cfduid'], 'response': ['cloudflare', 'ray id']},
            'AWS WAF': {'headers': ['x-amz-cf-id', 'x-amz-cf-pop', 'x-amzn-RequestId'], 'response': ['x-amz-cf-id']},
            'Akamai': {'headers': ['x-akamai-', 'x-akamai-transformed'], 'response': ['akamai', 'akamaighost']},
            'Imperva': {'headers': ['x-request-id', 'incap_s', 'x-iinfo'], 'cookies': ['incap_ses', 'visid_incap'], 'response': ['incapsula', 'imperva']},
            'Sucuri': {'headers': ['x-sucuri-', 'x-sucuri-cache'], 'response': ['sucuri', 'cloudproxy']},
            'F5 BIG-IP': {'headers': ['x-f5', 'x-wa-info'], 'response': ['bigip']},
            'ModSecurity': {'headers': ['mod_security'], 'response': ['mod_security', 'modsecurity']},
            'Wordfence': {'headers': ['wordfence'], 'cookies': ['wfvt', 'wordfence_verified']},
            'Fastly': {'headers': ['x-fastly-', 'x-served-by'], 'response': ['fastly']},
            'Varnish': {'headers': ['x-varnish'], 'response': ['varnish']},
            'Barracuda': {'headers': ['barracuda'], 'response': ['barracuda']},
            'Fortinet': {'headers': ['fortigate'], 'response': ['fortinet']},
            'Radware': {'headers': ['radware'], 'response': ['radware']},
        }
    def detect(self, headers: Union[Dict, Any], response_text: str) -> List[str]:
        detected = set()
        print_color("\n[🛡️] فحص جدار الحماية (WAF)...", Colors.CYAN, bold=True)
        headers_dict = safe_headers_to_dict(headers)
        for waf, sig in self.waf_signatures.items():
            for header in sig.get('headers', []):
                if any(header.lower() in h.lower() for h in headers_dict.keys()):
                    detected.add(waf)
            set_cookie = headers_dict.get('Set-Cookie', '')
            for cookie in sig.get('cookies', []):
                if cookie in set_cookie:
                    detected.add(waf)
            if response_text:
                for pattern in sig.get('response', []):
                    if pattern.lower() in response_text.lower():
                        detected.add(waf)
        if detected:
            print_color(f"  🛡️ WAF: {', '.join(detected)}", Colors.GREEN)
        else:
            print_color("  ❌ لم يتم الكشف عن WAF", Colors.YELLOW)
        return list(detected)

# ========== 4️⃣ Technology Detection (محسّن بالكامل) ==========
class TechnologyDetector:
    def __init__(self, logger: Logger):
        self.logger = logger
        self.tech_signatures = {
            'Nginx': {'headers': {'Server': 'nginx'}, 'category': 'Web Server'},
            'Apache': {'headers': {'Server': 'apache'}, 'category': 'Web Server'},
            'IIS': {'headers': {'Server': 'iis'}, 'category': 'Web Server'},
            'Tomcat': {'headers': {'Server': 'tomcat'}, 'category': 'App Server'},
            'GitHub': {'headers': {'Server': 'github.com', 'X-GitHub-Request-Id': ''}, 'category': 'Platform'},
            'GitLab': {'headers': {'Server': 'gitlab'}, 'category': 'Platform'},
            'WordPress': {'html': ['wp-content', 'wp-includes', 'wp-json'], 'cookies': ['wordpress_'], 'category': 'CMS'},
            'Drupal': {'html': ['drupal'], 'cookies': ['Drupal'], 'category': 'CMS'},
            'Joomla': {'html': ['joomla'], 'cookies': ['joomla'], 'category': 'CMS'},
            'React': {'html': ['react', 'reactjs', 'data-reactroot', '_NEXT_DATA_'], 'category': 'Frontend'},
            'Angular': {'html': ['ng-version', 'angular', 'ng-app'], 'category': 'Frontend'},
            'Vue.js': {'html': ['vuejs', 'data-v-', 'vue-app'], 'category': 'Frontend'},
            'Next.js': {'html': ['_NEXT_DATA_', '_next/static'], 'category': 'Framework'},
            'Nuxt.js': {'html': ['_NUXT_'], 'category': 'Framework'},
            'Gatsby': {'html': ['___gatsby'], 'category': 'Framework'},
            'jQuery': {'html': ['jquery'], 'category': 'Library'},
            'Bootstrap': {'html': ['bootstrap'], 'category': 'CSS Framework'},
            'Tailwind': {'html': ['tailwind'], 'category': 'CSS Framework'},
            'PHP': {'headers': {'X-Powered-By': 'php', 'Server': 'php'}, 'cookies': {'PHPSESSID': ''}, 'category': 'Backend'},
            'ASP.NET': {'headers': {'X-Powered-By': 'asp.net', 'X-AspNet-Version': ''}, 'cookies': {'ASP.NET_SessionId': ''}, 'category': 'Backend'},
            'Node.js': {'headers': {'X-Powered-By': 'express', 'Server': 'node'}, 'category': 'Backend'},
            'Python': {'headers': {'X-Powered-By': 'python', 'Server': 'python'}, 'category': 'Backend'},
            'Ruby': {'headers': {'X-Powered-By': 'ruby', 'Server': 'ruby'}, 'category': 'Backend'},
            'Java': {'headers': {'X-Powered-By': 'java', 'Server': 'java'}, 'cookies': {'JSESSIONID': ''}, 'category': 'Backend'},
            'Laravel': {'cookies': {'laravel_session': ''}, 'category': 'Framework'},
            'Django': {'cookies': {'csrftoken': '', 'sessionid': ''}, 'category': 'Framework'},
            'AWS': {'headers': {'x-amz-': ''}, 'category': 'Cloud'},
            'Google Cloud': {'headers': {'x-google-': ''}, 'category': 'Cloud'},
            'Azure': {'headers': {'x-azure-': ''}, 'category': 'Cloud'},
            'Google Analytics': {'html': ['google-analytics', 'gtag'], 'category': 'Analytics'},
            'Facebook Pixel': {'html': ['fbq', 'facebook-pixel'], 'category': 'Analytics'},
            'Cloudflare': {'headers': {'CF-Ray': '', 'cf-cache-status': ''}, 'category': 'CDN'},
            'Akamai': {'headers': {'X-Akamai-': ''}, 'category': 'CDN'},
            'Fastly': {'headers': {'X-Fastly-': ''}, 'category': 'CDN'},
            'HSTS': {'headers': {'Strict-Transport-Security': ''}, 'category': 'Security'},
            'CSP': {'headers': {'Content-Security-Policy': ''}, 'category': 'Security'},
            'Kubernetes': {'headers': {'Kubernetes': ''}, 'category': 'Orchestration'},
            'Docker': {'headers': {'Docker': ''}, 'category': 'Container'},
            'Elasticsearch': {'headers': {'X-Elastic-Product': ''}, 'category': 'Search'},
            'Grafana': {'headers': {'X-Grafana-': ''}, 'category': 'Monitoring'},
            'Prometheus': {'headers': {'X-Prometheus': ''}, 'category': 'Monitoring'},
        }
    
    def detect(self, headers: Any, html: str, url: str) -> Dict:
        found = defaultdict(set)
        print_color("\n[💻] كشف التقنيات...", Colors.CYAN, bold=True)
        try:
            # تحويل headers إلى dict بشكل آمن
            headers_dict = safe_headers_to_dict(headers)
            # تأكد من أنها قاموس (في حالة عادت شيئاً آخر)
            if not isinstance(headers_dict, dict):
                headers_dict = {}
            
            if headers_dict:
                for tech, sig in self.tech_signatures.items():
                    for h, pattern in sig.get('headers', {}).items():
                        for header, value in headers_dict.items():
                            if isinstance(header, str) and isinstance(value, str):
                                if h.lower() in header.lower():
                                    if not pattern or pattern.lower() in value.lower():
                                        found[sig['category']].add(tech)
                                        self.logger.debug(f"Found {tech} via header {header}={value}")
                    set_cookie = headers_dict.get('Set-Cookie', '')
                    if set_cookie and isinstance(set_cookie, str):
                        for cookie, pattern in sig.get('cookies', {}).items():
                            if cookie.lower() in set_cookie.lower():
                                found[sig['category']].add(tech)
                                self.logger.debug(f"Found {tech} via cookie {cookie}")
            if html and isinstance(html, str) and len(html) > 0:
                html_lower = html.lower()
                for tech, sig in self.tech_signatures.items():
                    for pattern in sig.get('html', []):
                        if pattern.lower() in html_lower:
                            found[sig['category']].add(tech)
                            self.logger.debug(f"Found {tech} via HTML pattern {pattern}")
        except Exception as e:
            self.logger.error(f"Technology detection error: {e}")
            print_color(f"  ⚠️ خطأ في كشف التقنيات: {e}", Colors.YELLOW)
        
        result = {k: list(v) for k, v in found.items()}
        if result:
            for cat, techs in result.items():
                print_color(f"  📌 {cat}: {', '.join(techs)}", Colors.GREEN)
        else:
            print_color("  ❌ لم يتم كشف تقنيات", Colors.YELLOW)
        return result

# ========== 5️⃣ Security Headers ==========
def analyze_security_headers(headers: Any) -> Tuple[Dict, int]:
    checks = {
        'Strict-Transport-Security': 'HSTS',
        'Content-Security-Policy': 'CSP',
        'X-Frame-Options': 'XFO',
        'X-Content-Type-Options': 'XCTO',
        'X-XSS-Protection': 'XSS',
        'Referrer-Policy': 'Referrer',
        'Permissions-Policy': 'Permissions'
    }
    result = {}
    found = 0
    print_color("\n[🛡️] رؤوس الأمان:", Colors.CYAN, bold=True)
    headers_dict = safe_headers_to_dict(headers)
    for h, name in checks.items():
        if h in headers_dict:
            val = headers_dict[h]
            result[name] = val[:40] + '...' if len(val) > 40 else val
            print_color(f"  ✓ {name}: موجود", Colors.GREEN)
            found += 1
        else:
            result[name] = '❌'
            print_color(f"  ✗ {name}: مفقود", Colors.RED)
    return result, found

# ========== 6️⃣ SSL Info ==========
def get_ssl_info(domain: str, port: int = 443) -> Dict:
    if not SSL_AVAILABLE:
        return {'error': 'pyOpenSSL غير مثبت'}
    try:
        cert = ssl.get_server_certificate((domain, port))
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        issuer = x509.get_issuer().get_components()
        not_after = datetime.strptime(x509.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
        days = (not_after - datetime.now()).days
        issuer_name = '?'
        for key, val in dict(issuer).items():
            if key == b'O':
                issuer_name = val.decode() if isinstance(val, bytes) else str(val)
                break
        status = '✅' if days > 30 else '⚠️' if days > 0 else '❌'
        print_color(f"\n[🔐] SSL:", Colors.GREEN, bold=True)
        print_color(f"  {status} {days} يوم متبقي", Colors.GREEN if days > 30 else Colors.YELLOW)
        print_color(f"  المُصدر: {issuer_name}", Colors.CYAN)
        return {'issuer': issuer_name, 'days_left': days, 'status': status}
    except Exception as e:
        print_color(f"  ✗ خطأ SSL: {e}", Colors.RED)
        return {'error': str(e)}

# ========== 7️⃣ SSL Protocols ==========
def scan_ssl_protocols(domain: str, port: int = 443) -> List[str]:
    protocols = []
    print_color("\n[📡] فحص بروتوكولات SSL/TLS...", Colors.CYAN, bold=True)
    try:
        for ver, min_ver, max_ver in [
            ('TLSv1.0', ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1),
            ('TLSv1.1', ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_1),
            ('TLSv1.2', ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2),
            ('TLSv1.3', ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3),
        ]:
            try:
                context = ssl.create_default_context()
                context.minimum_version = min_ver
                context.maximum_version = max_ver
                with socket.create_connection((domain, port), timeout=3) as sock:
                    with context.wrap_socket(sock, server_hostname=domain):
                        protocols.append(ver)
                        if '1.2' in ver or '1.3' in ver:
                            print_color(f"  ✅ {ver}: مدعوم", Colors.GREEN)
                        else:
                            print_color(f"  ⚠️ {ver}: مدعوم (قديم)", Colors.YELLOW)
            except:
                print_color(f"  ❌ {ver}: غير مدعوم", Colors.RED)
    except AttributeError:
        print_color("  ⚠️ إصدار Python لا يدعم ssl.TLSVersion، تخطي", Colors.YELLOW)
    return protocols

# ========== 8️⃣ Port Scanner ==========
def scan_ports(domain: str) -> List[Tuple[int, str]]:
    ports = [21,22,23,25,53,80,110,111,135,139,143,443,445,465,587,993,995,
             1723,3306,3389,5432,5900,6379,8080,8443,8888,9200,27017]
    open_ports = []
    print_color("\n[🔌] فحص المنافذ...", Colors.CYAN, bold=True)
    def check(p):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((domain, p))
        sock.close()
        if result == 0:
            try:
                service = socket.getservbyport(p)
            except:
                service = "unknown"
            return (p, service)
        return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=Config.THREADS) as executor:
        futures = [executor.submit(check, p) for p in ports]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
                p, s = result
                if p in [21,23,3389]:
                    print_color(f"  ⚠️ {p}/{s}", Colors.YELLOW)
                elif p in [22,3306,5432,27017]:
                    print_color(f"  🔐 {p}/{s}", Colors.CYAN)
                else:
                    print_color(f"  ✅ {p}/{s}", Colors.GREEN)
    return open_ports

# ========== 9️⃣ GeoIP ==========
async def get_geoip(ip: str) -> Optional[Dict]:
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f'http://ip-api.com/json/{ip}', timeout=5) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get('status') == 'success':
                        info = {'country': data.get('country', '?'), 'city': data.get('city', '?'), 'isp': data.get('isp', '?')}
                        print_color(f"  📍 الموقع: {info['city']}, {info['country']}", Colors.GREEN)
                        print_color(f"  🏢 المزود: {info['isp']}", Colors.GREEN)
                        return info
    except:
        pass
    return None

# ========== 🔟 WHOIS ==========
async def get_whois_info(domain: str) -> Dict:
    if not WHOIS_AVAILABLE:
        print_color("  ⚠️ python-whois غير مثبت، تخطي WHOIS", Colors.YELLOW)
        return {}
    try:
        import whois
        print_color("\n[📄] معلومات WHOIS...", Colors.CYAN, bold=True)
        w = whois.whois(domain)
        info = {}
        fields = [('domain_name', 'اسم النطاق'), ('registrar', 'المسجل'), ('creation_date', 'تاريخ الإنشاء'), ('expiration_date', 'تاريخ الانتهاء'), ('name_servers', 'خوادم الأسماء')]
        for field, label in fields:
            if hasattr(w, field) and getattr(w, field):
                val = getattr(w, field)
                if isinstance(val, list):
                    val = val[0] if val else ''
                if val:
                    info[label] = str(val)[:50]
                    print_color(f"  📌 {label}: {str(val)[:50]}", Colors.GREEN)
        return info
    except Exception as e:
        print_color(f"  ✗ خطأ WHOIS: {e}", Colors.RED)
        return {}

# ========== Nmap Integration ==========
async def run_nmap_scan(domain: str) -> Optional[Dict]:
    print_color("\n[🔍] تشغيل Nmap...", Colors.CYAN, bold=True)
    try:
        subprocess.run(['nmap', '--version'], capture_output=True, check=True)
    except:
        print_color("  ⚠️ Nmap غير مثبت. قم بتثبيته: sudo apt install nmap", Colors.YELLOW)
        return None
    results = {}
    try:
        print_color("  🔍 فحص المنافذ الشائعة...", Colors.BLUE)
        result = subprocess.run(['nmap', '-F', '-sV', domain], capture_output=True, text=True, timeout=60)
        for line in result.stdout.split('\n'):
            if '/tcp' in line and 'open' in line:
                print_color(f"    📌 {line.strip()}", Colors.GREEN)
        results['quick'] = result.stdout
    except Exception as e:
        print_color(f"  ✗ خطأ Nmap: {e}", Colors.RED)
    return results

# ========== AI Risk Analyzer (محسّن) ==========
class AIRiskAnalyzer:
    def __init__(self, logger: Logger):
        self.logger = logger
    def analyze(self, results: Dict) -> Dict:
        risk_score = 0
        findings = []
        # DNS
        if results.get('dns_records'):
            if 'SPF' not in results['dns_records']:
                risk_score += 5; findings.append('SPF Missing')
            if 'DMARC' not in results['dns_records']:
                risk_score += 5; findings.append('DMARC Missing')
        # Security Headers
        headers_count = results.get('headers_count', 0)
        if headers_count < 4:
            risk_score += 20; findings.append('Security Headers Missing')
        # Ports
        if results.get('ports'):
            dangerous_ports = [p for p,_ in results['ports'] if p in [21,23,3389]]
            if dangerous_ports:
                risk_score += len(dangerous_ports)*5; findings.append(f'Dangerous Ports: {dangerous_ports}')
        # SSL
        ssl = results.get('ssl', {})
        if ssl.get('days_left',0) < 30:
            risk_score += 10; findings.append('SSL Expiring Soon')
        # Secrets
        if results.get('secrets') and len(results['secrets']) > 0:
            risk_score += min(len(results['secrets'])*2, 30)
            findings.append(f"Secrets Found: {len(results['secrets'])}")
        # Directories
        if results.get('directories'):
            sensitive = [d for d in results['directories'] if d[1] == 200 and any(x in d[0] for x in ['admin','login','api','backup','.git','.env'])]
            if sensitive:
                risk_score += len(sensitive)*3
                findings.append(f"Sensitive directories: {len(sensitive)}")
        # Subdomain takeover
        if results.get('takeover_vulnerable'):
            risk_score += 20; findings.append('Subdomain takeover possible')
        # Risk level
        if risk_score >= 70:
            risk_level = "HIGH"; risk_color = Colors.RED
        elif risk_score >= 40:
            risk_level = "MEDIUM"; risk_color = Colors.YELLOW
        else:
            risk_level = "LOW"; risk_color = Colors.GREEN
        return {'score': risk_score, 'level': risk_level, 'color': risk_color, 'findings': findings}

# ========== 1️⃣1️⃣ Directory Bruteforce (مع دعم قائمة مخصصة) ==========
class DirectoryScanner:
    def __init__(self, logger: Logger, wordlist: List[str] = None):
        self.logger = logger
        self.wordlist = wordlist or [
            'admin', 'login', 'wp-admin', 'wp-content', 'wp-includes',
            'api', 'v1', 'v2', 'graphql', 'rest', '.git', '.env', 'config',
            'backup', 'backups', 'phpmyadmin', 'pma', 'mysql', 'database',
            'uploads', 'images', 'css', 'js', 'assets', 'vendor',
            'node_modules', 'src', 'dist', 'build', 'public',
            'robots.txt', 'sitemap.xml', 'crossdomain.xml',
            '.htaccess', '.htpasswd', 'web.config',
            'package.json', 'composer.json', 'Gemfile',
            'Dockerfile', 'docker-compose.yml',
            'README.md', 'CHANGELOG.md', 'LICENSE',
            '.env.local', '.env.production', '.env.development',
            'credentials', '.aws', '.gcp', '.azure',
            'test', 'tests', 'dev', 'development', 'stage', 'staging',
            'prod', 'production', 'qa', 'uat', 'preprod', 'demo',
            'sandbox', 'playground', 'lab',
            'private', 'secure', 'hidden', 'secret', 'confidential',
            'internal', 'restricted', 'protected',
            'db', 'database', 'mysql', 'postgres', 'mongodb', 'redis',
            'dump.sql', 'backup.sql', 'database.sql',
            'server-status', 'server-info', 'info.php', 'phpinfo.php',
            'status', 'health', 'healthz', 'metrics', 'stats',
            'actuator', 'actuator/health', 'actuator/info',
            'swagger', 'swagger-ui', 'api-docs', 'docs', 'graphiql',
            'jenkins', 'jira', 'confluence', 'bitbucket', 'gitlab',
            'circleci', '.circleci', 'travis.yml', '.travis.yml',
            '.github', '.gitlab', 'azure-pipelines.yml',
            'aws', 'gcp', 'azure', 's3', 'bucket', 'storage',
            'cloud', 'cdn', 'static', 'media', 'files',
            'mail', 'email', 'webmail', 'roundcube',
            'vault', 'keycloak', 'oauth2', 'sso', 'saml',
            'firebase', 'auth0', 'okta', 'cognito',
            'stripe', 'paypal', 'braintree', 'square',
            'slack', 'discord', 'telegram', 'whatsapp',
            'twilio', 'sendgrid', 'mailgun',
            'analytics', 'tracking', 'pixel', 'gtm',
            'grafana', 'prometheus', 'kibana', 'elastic',
            'kubernetes', 'k8s', 'helm', 'charts', 'rancher',
            'docker', 'swarm', 'mesos',
            'service', 'services', 'api-gateway', 'gateway', 'proxy'
        ]
    
    async def scan(self, base_url: str, baseline_len: int = 0) -> List[Tuple[str, int, str]]:
        found = []
        print_color(f"\n[📁] فحص {len(self.wordlist)} مجلد/ملف...", Colors.CYAN, bold=True)
        semaphore = asyncio.Semaphore(Config.THREADS)
        
        async def check(path):
            async with semaphore:
                url = urljoin(base_url, path)
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(url, timeout=Config.TIMEOUT, allow_redirects=False) as resp:
                            if resp.status == 200:
                                content = await resp.text()
                                if abs(len(content) - baseline_len) > 500:
                                    return (path, resp.status, 'محتوى')
                            elif resp.status in [301, 302, 307, 308]:
                                location = resp.headers.get('Location', '')
                                return (path, resp.status, f'تحويل ← {location[:30]}')
                            elif resp.status in [401, 403]:
                                return (path, resp.status, 'ممنوع الوصول')
                            elif resp.status == 500:
                                return (path, resp.status, 'خطأ داخلي')
                except:
                    pass
                return None
        
        tasks = [check(p) for p in self.wordlist]
        if TQDM_AVAILABLE:
            for future in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc="فحص المجلدات", unit="مسار"):
                result = await future
                if result:
                    found.append(result)
                    path, status, desc = result
                    if status == 200:
                        print_color(f"  ✓ {path} → [{status}] {desc}", Colors.GREEN)
                    elif status in [301, 302]:
                        print_color(f"  ➡️ {path} → [{status}] {desc}", Colors.YELLOW)
                    elif status in [401, 403]:
                        print_color(f"  🔒 {path} → [{status}] {desc}", Colors.RED)
                    else:
                        print_color(f"  • {path} → [{status}] {desc}", Colors.BLUE)
        else:
            for future in asyncio.as_completed(tasks):
                result = await future
                if result:
                    found.append(result)
        return found

# ========== 1️⃣2️⃣ JS File Extractor ==========
class JSExtractor:
    def __init__(self, logger: Logger):
        self.logger = logger
    
    async def extract(self, html: str, base_url: str) -> List[Dict]:
        js_files = []
        soup = BeautifulSoup(html, 'html.parser')
        script_tags = soup.find_all('script', src=True)
        for tag in script_tags:
            src = tag['src']
            full_url = urljoin(base_url, src)
            js_files.append({'url': full_url, 'content': None})
        
        if not js_files:
            return []
        
        print_color(f"\n[📦] استخراج ملفات JS...", Colors.CYAN, bold=True)
        print_color(f"  تم العثور على {len(js_files)} ملف JS", Colors.BLUE)
        
        async with aiohttp.ClientSession() as session:
            for js in js_files:
                try:
                    async with session.get(js['url'], timeout=Config.TIMEOUT) as resp:
                        if resp.status == 200:
                            js['content'] = await resp.text()
                            print_color(f"  ✓ {os.path.basename(js['url'])}", Colors.GREEN)
                        else:
                            print_color(f"  ✗ {os.path.basename(js['url'])} (HTTP {resp.status})", Colors.RED)
                except Exception as e:
                    self.logger.debug(f"Error fetching JS {js['url']}: {e}")
                    print_color(f"  ✗ {os.path.basename(js['url'])} (خطأ)", Colors.RED)
        
        return js_files

# ========== 1️⃣3️⃣ Secrets Finder (محسّن) ==========
class SecretsFinder:
    def __init__(self, logger: Logger):
        self.logger = logger
        self.patterns = [
            (r'api[-]?key[\s][:=][\s]["\']([a-zA-Z0-9\-]{20,})["\']', 'API Key'),
            (r'AIza[0-9A-Za-z\-_]{35}', 'Google API Key'),
            (r'sk_live_[0-9a-zA-Z]{24}', 'Stripe Live Key'),
            (r'pk_live_[0-9a-zA-Z]{24}', 'Stripe Publishable Key'),
            (r'sk_test_[0-9a-zA-Z]{24}', 'Stripe Test Key'),
            (r'[0-9a-fA-F]{32,40}', 'Hash (possible secret)'),
            (r'AKIA[0-9A-Z]{16}', 'AWS Access Key'),
            (r'eyJ[a-zA-Z0-9_\-]{20,}\.[a-zA-Z0-9_\-]{20,}\.[a-zA-Z0-9_\-]{20,}', 'JWT Token'),
            (r'gh[pousr][a-zA-Z0-9\-]{20,}', 'GitHub Token'),
            (r'ya29\.[0-9A-Za-z_\-]{100,}', 'Google OAuth Token'),
            (r'xox[baprs]-[0-9a-zA-Z]{10,}', 'Slack Token'),
            (r'SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}', 'SendGrid API Key'),
            (r'password[\s][:=][\s]["\'][^"\']+["\']', 'Password'),
            (r'secret[\s][:=][\s]["\'][^"\']+["\']', 'Secret'),
            (r'token[\s][:=][\s]["\'][^"\']+["\']', 'Token'),
            (r'mongodb://[^/\s]+', 'MongoDB URI'),
            (r'mysql://[^/\s]+', 'MySQL URI'),
            (r'postgresql://[^/\s]+', 'PostgreSQL URI'),
            (r'redis://[^/\s]+', 'Redis URI'),
            (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', 'Email'),
            (r'-----BEGIN (?:RSA )?PRIVATE KEY-----', 'Private Key'),
            (r'-----BEGIN OPENSSH PRIVATE KEY-----', 'OpenSSH Private Key'),
            (r'sk-[\w\-]{48}', 'OpenAI API Key'),
            (r'Bearer [a-zA-Z0-9_\-]{20,}', 'Bearer Token'),
        ]
    
    def find(self, js_files: List[Dict]) -> List[Dict]:
        secrets = []
        print_color("\n[🔑] البحث عن أسرار في ملفات JS...", Colors.CYAN, bold=True)
        for js in js_files:
            if not js.get('content'):
                continue
            content = js['content']
            for pattern, desc in self.patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0]
                    if len(str(match)) > 8:
                        secrets.append({
                            'url': js['url'],
                            'type': desc,
                            'value': str(match)[:30] + ('...' if len(match) > 30 else '')
                        })
                        print_color(f"  🔑 {desc} in {os.path.basename(js['url'])}: {str(match)[:30]}...", Colors.RED)
        if not secrets:
            print_color("  ✅ لم يتم العثور على أسرار", Colors.GREEN)
        return secrets

# ========== 1️⃣4️⃣ Subdomain Takeover Detection ==========
class SubdomainTakeoverDetector:
    def __init__(self, logger: Logger):
        self.logger = logger
        self.services = {
            'github.io': ['github.io'],
            'herokuapp.com': ['herokuapp.com'],
            'netlify.app': ['netlify.app'],
            'aws.amazon.com': ['s3.amazonaws.com', 'amazonaws.com'],
            'azurewebsites.net': ['azurewebsites.net'],
            'cloudfront.net': ['cloudfront.net'],
            'elasticbeanstalk.com': ['elasticbeanstalk.com'],
            'firebaseio.com': ['firebaseio.com'],
            'pages.dev': ['pages.dev'],
            'vercel.app': ['vercel.app'],
        }
    
    async def check(self, subdomain: str) -> bool:
        if not DNS_AVAILABLE:
            return False
        try:
            answers = dns.resolver.resolve(subdomain, 'CNAME', raise_on_no_answer=False)
            if answers:
                for cname in answers:
                    cname_str = str(cname.target).lower()
                    for service, domains in self.services.items():
                        for d in domains:
                            if d in cname_str:
                                try:
                                    async with aiohttp.ClientSession() as session:
                                        async with session.get(f"http://{subdomain}", timeout=5) as resp:
                                            if resp.status in [404, 403, 500]:
                                                return True
                                except:
                                    return True
        except:
            pass
        return False
    
    async def scan(self, subdomains: List[str]) -> List[str]:
        vulnerable = []
        print_color("\n[⚠️] فحص النطاقات الفرعية القابلة للاستيلاء...", Colors.YELLOW, bold=True)
        for sub in subdomains:
            if await self.check(sub):
                vulnerable.append(sub)
                print_color(f"  🔓 {sub} → معرض للاستيلاء!", Colors.RED)
        if not vulnerable:
            print_color("  ✅ لا توجد نطاقات فرعية معرضة", Colors.GREEN)
        return vulnerable

# ========== Report Generator ==========
class ReportGenerator:
    def __init__(self, results: Dict):
        self.results = results
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        Config.init_dirs()
    
    def generate_html(self) -> str:
        domain = self.results.get('domain', 'unknown')
        subdomains = self.results.get('subdomains', [])
        subdomains_html = "".join(f'<span class="subdomain-item">{sub}</span>' for sub in subdomains[:50])
        tech_html = "".join(f"<tr><td>{cat}</td><td>{', '.join(techs)}</td></tr>" for cat,techs in self.results.get('technologies',{}).items())
        ports = self.results.get('ports', [])
        ports_html = "".join(f'<tr><td>{p}</td><td>{s}</td><td><span class="badge badge-{"danger" if p in [21,23,3389] else "warning" if p in [22,3306] else "success"}">{ "عالٍ" if p in [21,23,3389] else "متوسط" if p in [22,3306] else "منخفض" }</span></td></tr>' for p,s in ports)
        headers_dict = self.results.get('security_headers', {})
        headers_html = ""
        for proto, headers in headers_dict.items():
            for name, value in headers.items():
                status = '✅' if value != '❌' else '❌'
                headers_html += f"<tr><td>{name}</td><td>{value}</td><td>{status}</td></tr>"
        dirs = self.results.get('directories', [])
        dirs_html = "".join(f"<tr><td>{d[0]}</td><td>{d[1]}</td><td>{d[2]}</td></tr>" for d in dirs[:30])
        secrets = self.results.get('secrets', [])
        secrets_html = "".join(f"<tr><td>{s['type']}</td><td>{os.path.basename(s['url'])}</td><td>{s['value']}</td></tr>" for s in secrets[:20])
        risk = self.results.get('risk_analysis', {})
        risk_score = risk.get('score', 0)
        risk_level = risk.get('level', 'UNKNOWN')
        risk_color = "#ff4444" if risk_score >= 70 else "#ffaa00" if risk_score >= 40 else "#00ff9d"
        takeover = self.results.get('takeover_vulnerable', [])
        takeover_html = "".join(f'<span class="badge badge-danger">{t}</span> ' for t in takeover)
        return f"""<!DOCTYPE html><html dir="rtl"><head><meta charset="UTF-8"><title>📊 تقرير تحليل النطاق - {domain}</title>
        <style>*{{margin:0;padding:0;box-sizing:border-box;}}
        body{{font-family:'Segoe UI',sans-serif;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);color:#333;min-height:100vh;padding:20px;}}
        .container{{max-width:1400px;margin:0 auto;}}
        .header{{background:rgba(255,255,255,0.95);border-radius:20px;padding:30px;margin-bottom:30px;box-shadow:0 10px 40px rgba(0,0,0,0.2);text-align:center;}}
        .header h1{{color:#667eea;font-size:2.5em;margin-bottom:10px;}}
        .header .timestamp{{color:#666;font-size:1.1em;}}
        .stats-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:20px;margin-bottom:30px;}}
        .stat-card{{background:rgba(255,255,255,0.95);border-radius:15px;padding:25px;box-shadow:0 5px 20px rgba(0,0,0,0.1);transition:transform 0.3s;text-align:center;}}
        .stat-card:hover{{transform:translateY(-5px);}}
        .stat-icon{{font-size:2.5em;margin-bottom:10px;}}
        .stat-value{{font-size:2em;font-weight:bold;color:#667eea;}}
        .stat-label{{color:#666;margin-top:5px;}}
        .risk-meter{{background:white;border-radius:20px;padding:25px;margin-bottom:30px;}}
        .risk-title{{font-size:1.5em;margin-bottom:15px;color:#333;}}
        .progress{{height:30px;background:#f0f0f0;border-radius:15px;overflow:hidden;margin:15px 0;}}
        .progress-bar{{height:100%;background:linear-gradient(90deg,#00ff9d,#ffaa00,#ff4444);width:{risk_score}%;transition:width 0.5s;}}
        .risk-level{{display:inline-block;padding:8px 20px;border-radius:25px;font-weight:bold;font-size:1.2em;color:white;background:{risk_color};}}
        .section{{background:rgba(255,255,255,0.95);border-radius:20px;padding:25px;margin-bottom:30px;box-shadow:0 5px 20px rgba(0,0,0,0.1);}}
        .section-title{{font-size:1.8em;color:#667eea;margin-bottom:20px;border-bottom:2px solid #f0f0f0;padding-bottom:10px;}}
        table{{width:100%;border-collapse:collapse;}}
        th,td{{padding:12px;text-align:right;border-bottom:1px solid #f0f0f0;}}
        th{{background:#667eea;color:white;font-weight:600;}}
        tr:hover{{background:#f8f9fa;}}
        .badge{{display:inline-block;padding:5px 12px;border-radius:15px;font-size:0.9em;font-weight:600;}}
        .badge-danger{{background:#ff4444;color:white;}}
        .badge-warning{{background:#ffaa00;color:black;}}
        .badge-success{{background:#00ff9d;color:black;}}
        .subdomain-cloud{{display:flex;flex-wrap:wrap;gap:10px;justify-content:center;}}
        .subdomain-item{{background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);color:white;padding:8px 16px;border-radius:25px;font-size:0.9em;box-shadow:0 2px 10px rgba(102,126,234,0.3);}}
        .footer{{text-align:center;color:white;margin-top:30px;font-size:1.1em;}}
        @media print{{body{{background:white;}}.stat-card,.section{{box-shadow:none;border:1px solid #ddd;}}}}
        </style></head><body><div class="container"><div class="header"><h1>📊 تقرير تحليل النطاق الشامل</h1><div class="timestamp">{self.results.get('timestamp', '')}</div><div style="margin-top:15px;"><span class="badge" style="background:#667eea;color:white;font-size:1.2em;">{domain}</span></div></div>
        <div class="stats-grid"><div class="stat-card"><div class="stat-icon">🌐</div><div class="stat-value">{self.results.get('ip','N/A')}</div><div class="stat-label">IP Address</div></div><div class="stat-card"><div class="stat-icon">🔍</div><div class="stat-value">{len(subdomains)}</div><div class="stat-label">Subdomains</div></div><div class="stat-card"><div class="stat-icon">🔌</div><div class="stat-value">{len(ports)}</div><div class="stat-label">Open Ports</div></div><div class="stat-card"><div class="stat-icon">📋</div><div class="stat-value">{len(self.results.get('dns_records',{}))}</div><div class="stat-label">DNS Records</div></div></div>
        <div class="risk-meter"><div class="risk-title">📊 مؤشر المخاطر</div><div class="progress"><div class="progress-bar"></div></div><div style="display:flex;justify-content:space-between;align-items:center;"><span class="risk-level">{risk_level}</span><span style="font-size:1.5em;font-weight:bold;">{risk_score}%</span></div></div>
        <div class="section"><div class="section-title">🌐 معلومات أساسية</div><table><tr><th>المعلومة</th><th>القيمة</th></tr><tr><td>IP Address</td><td>{self.results.get('ip','N/A')}</td></tr><tr><td>الدولة</td><td>{self.results.get('geoip',{}).get('country','N/A')}</td></tr><tr><td>المدينة</td><td>{self.results.get('geoip',{}).get('city','N/A')}</td></tr><tr><td>المزود</td><td>{self.results.get('geoip',{}).get('isp','N/A')}</td></tr></table></div>
        <div class="section"><div class="section-title">🔍 النطاقات الفرعية ({len(subdomains)})</div><div class="subdomain-cloud">{subdomains_html}</div></div>
        <div class="section"><div class="section-title">💻 التقنيات المكتشفة</div><table><tr><th>الفئة</th><th>التقنيات</th></tr>{tech_html}</table></div>
        <div class="section"><div class="section-title">🔌 المنافذ المفتوحة</div><table><tr><th>المنفذ</th><th>الخدمة</th><th>مستوى الخطر</th></tr>{ports_html}</table></div>
        <div class="section"><div class="section-title">🛡️ رؤوس الأمان</div><table><tr><th>الرأس</th><th>القيمة</th><th>الحالة</th></tr>{headers_html}</table></div>
        <div class="section"><div class="section-title">📁 الملفات والمجلدات المكتشفة</div><table><tr><th>المسار</th><th>الحالة</th><th>ملاحظات</th></tr>{dirs_html}</table></div>
        <div class="section"><div class="section-title">🔑 الأسرار في JavaScript</div><table><tr><th>النوع</th><th>الملف</th><th>القيمة</th></tr>{secrets_html}</table></div>
        <div class="section"><div class="section-title">⚠️ النطاقات الفرعية المعرضة للاستيلاء</div><div>{takeover_html or "✅ لا توجد"}</div></div>
        <div class="footer">Generated by Ultimate Domain Scanner v6.1</div></div></body></html>"""
    
    def save(self) -> str:
        filename = f"{Config.REPORTS_DIR}/report_{self.timestamp}.html"
        with open(filename,'w',encoding='utf-8') as f:
            f.write(self.generate_html())
        return filename

# ========== الدالة الرئيسية ==========
async def scan_domain(domain: str, options: argparse.Namespace) -> Dict:
    logger = Logger("DomainScanner")
    cache = Cache()
    Config.init_dirs()
    
    Config.TIMEOUT = options.timeout or Config.TIMEOUT
    Config.THREADS = options.threads or Config.THREADS
    Config.PROXY = options.proxy
    Config.NO_COLOR = options.no_color
    
    results = {
        'domain': domain, 'timestamp': datetime.now().isoformat(), 'ip': None, 'geoip': None,
        'dns_records': {}, 'subdomains': [], 'waf': [], 'technologies': {}, 'nmap': None,
        'whois': {}, 'ssl': {}, 'ssl_protocols': [], 'ports': [], 'security_headers': {},
        'headers_count': 0, 'risk_analysis': {}, 'directories': [], 'js_files': [], 'secrets': [],
        'takeover_vulnerable': []
    }
    
    print_color(f"\n{'='*70}", Colors.CYAN, bold=True)
    print_color(f"🚀 بدء التحليل الشامل لـ {domain}", Colors.CYAN, bold=True)
    print_color(f"{'='*70}", Colors.CYAN, bold=True)

    # IP and GeoIP
    try:
        ip = socket.gethostbyname(domain)
        results['ip'] = ip
        print_color(f"\n[🌐] IP: {ip}", Colors.GREEN, bold=True)
        if options.geoip:
            geo = await get_geoip(ip)
            if geo: results['geoip'] = geo
    except Exception as e:
        logger.error(f"IP error: {e}")

    # DNS Scan
    if options.dns:
        dns_scanner = DNSScanner(logger, cache)
        results['dns_records'] = await dns_scanner.scan(domain)

    # Subdomain Enumeration
    subdomains = []
    if options.subdomains:
        sub_scanner = SubdomainScanner(logger, cache)
        subdomains = await sub_scanner.scan(domain)
        results['subdomains'] = subdomains
        
        if options.takeover and subdomains:
            takeover_detector = SubdomainTakeoverDetector(logger)
            results['takeover_vulnerable'] = await takeover_detector.scan(subdomains)

    # HTTP/HTTPS Scan
    base_url = None
    html_content = None
    headers = {}
    if options.http:
        for proto in ['https', 'http']:
            url = f"{proto}://{domain}"
            try:
                connector = None
                if Config.PROXY:
                    connector = aiohttp.TCPConnector(ssl=False)
                async with aiohttp.ClientSession(connector=connector) as session:
                    async with session.get(url, timeout=Config.TIMEOUT, ssl=False) as resp:
                        html_content = await resp.text()
                        headers = safe_headers_to_dict(resp.headers)
                        base_url = url
                        if options.waf:
                            waf_detector = WAFDetector(logger)
                            results['waf'] = waf_detector.detect(headers, html_content)
                        if options.technologies:
                            tech_detector = TechnologyDetector(logger)
                            results['technologies'] = tech_detector.detect(headers, html_content, url)
                        sec_headers, count = analyze_security_headers(headers)
                        results['security_headers'][proto] = sec_headers
                        results['headers_count'] = count
                        break
            except Exception as e:
                logger.warning(f"{proto} error: {e}")

    # Directory Bruteforce
    if not options.quick and options.dirb and base_url:
        baseline_len = 0
        try:
            async with aiohttp.ClientSession() as session:
                rand_path = f"this-page-does-not-exist-{int(time.time())}"
                url = urljoin(base_url, rand_path)
                async with session.get(url, timeout=5) as resp:
                    if resp.status == 404:
                        content = await resp.text()
                        baseline_len = len(content)
        except:
            pass
        wordlist = None
        if options.wordlist and os.path.isfile(options.wordlist):
            with open(options.wordlist, 'r') as f:
                wordlist = [line.strip() for line in f if line.strip()]
        dir_scanner = DirectoryScanner(logger, wordlist)
        results['directories'] = await dir_scanner.scan(base_url, baseline_len)

    # JS Extraction and Secrets
    if not options.quick and (options.js_extract or options.secrets) and html_content and base_url:
        js_extractor = JSExtractor(logger)
        js_files = await js_extractor.extract(html_content, base_url)
        results['js_files'] = js_files
        if options.secrets and js_files:
            secrets_finder = SecretsFinder(logger)
            results['secrets'] = secrets_finder.find(js_files)

    # Nmap
    if options.nmap:
        results['nmap'] = await run_nmap_scan(domain)

    # WHOIS
    if options.whois:
        results['whois'] = await get_whois_info(domain)

    # SSL
    if options.ssl:
        results['ssl'] = get_ssl_info(domain)
        if options.ssl_protocols:
            results['ssl_protocols'] = scan_ssl_protocols(domain)

    # Ports
    if options.ports:
        results['ports'] = scan_ports(domain)

    # Risk Analysis
    risk_analyzer = AIRiskAnalyzer(logger)
    results['risk_analysis'] = risk_analyzer.analyze(results)

    return results

def print_results(results: Dict, format: str = 'text'):
    if format == 'json':
        print(json.dumps(results, indent=2, default=str))
        return
    print_color("\n"+"="*80, Colors.CYAN, bold=True)
    print_color(f"📊 تحليل شامل: {results['domain']}", Colors.CYAN, bold=True)
    print_color(f"📅 {results['timestamp']}", Colors.CYAN)
    print_color("="*80, Colors.CYAN)
    
    if results['ip']:
        print_color("\n[🌐] IP:", Colors.GREEN, bold=True)
        print(f"  📍 {results['ip']}")
        if results['geoip']:
            g = results['geoip']
            print(f"  🇩🇪 {g.get('country')} - {g.get('city')}")
            print(f"  🏢 {g.get('isp')}")
    
    if results.get('risk_analysis'):
        r = results['risk_analysis']
        print_color(f"\n[🤖] Risk Score: {r['score']}/100", r['color'], bold=True)
        print_color(f"  Level: {r['level']}", r['color'], bold=True)
    
    if results['subdomains']:
        print_color("\n[🔍] النطاقات الفرعية:", Colors.GREEN, bold=True)
        for sub in results['subdomains'][:20]:
            print(f"  • {sub}")
        if len(results['subdomains']) > 20:
            print(f"  ... و {len(results['subdomains'])-20} نطاق آخر")
    
    if results.get('takeover_vulnerable'):
        print_color("\n[⚠️] نطاقات فرعية معرضة للاستيلاء:", Colors.RED, bold=True)
        for sub in results['takeover_vulnerable']:
            print(f"  🔓 {sub}")
    
    if results['technologies']:
        print_color("\n[💻] التقنيات:", Colors.GREEN, bold=True)
        for cat, techs in results['technologies'].items():
            print(f"  {cat}: {', '.join(techs)}")
    
    if results['ssl'] and 'error' not in results['ssl']:
        s = results['ssl']
        print_color("\n[🔐] SSL:", Colors.GREEN, bold=True)
        print(f"  {s.get('status')} {s.get('days_left')} يوم")
        print(f"  المُصدر: {s.get('issuer', '?')}")
    
    if results['ssl_protocols']:
        print_color("\n  📡 Protocols:", Colors.CYAN)
        for p in results['ssl_protocols']:
            if '1.2' in p or '1.3' in p:
                print_color(f"    ✅ {p}", Colors.GREEN)
            else:
                print_color(f"    ⚠️ {p}", Colors.YELLOW)
    
    if results['ports']:
        print_color("\n[🔌] المنافذ:", Colors.GREEN, bold=True)
        for p, s in results['ports']:
            if p in [21,23,3389]:
                print_color(f"  ⚠️ {p}/{s}", Colors.YELLOW)
            elif p in [22,3306]:
                print_color(f"  🔐 {p}/{s}", Colors.CYAN)
            else:
                print(f"  ✅ {p}/{s}")
    
    if results.get('directories'):
        print_color("\n[📁] الملفات والمجلدات المكتشفة:", Colors.GREEN, bold=True)
        for path, status, desc in results['directories'][:20]:
            color = Colors.GREEN if status == 200 else Colors.YELLOW if status in [301,302] else Colors.RED
            print_color(f"  {path} → [{status}] {desc}", color)
    
    if results.get('secrets'):
        print_color("\n[🔑] الأسرار المكتشفة:", Colors.RED, bold=True)
        for sec in results['secrets'][:10]:
            print(f"  • {sec['type']} in {os.path.basename(sec['url'])}: {sec['value']}")

# ========== Main ==========
async def main():
    parser = argparse.ArgumentParser(description='🚀 Ultimate Domain Scanner v6.1 (مُطوَّر بالكامل)')
    parser.add_argument('domain', help='النطاق (مثال: github.com)')
    parser.add_argument('--all', action='store_true', help='كل الفحوصات')
    parser.add_argument('--quick', action='store_true', help='فحص سريع (يتخطى dirb و js-extract و secrets)')
    parser.add_argument('--dns', action='store_true', help='فحص DNS')
    parser.add_argument('--subdomains', action='store_true', help='النطاقات الفرعية')
    parser.add_argument('--takeover', action='store_true', help='كشف النطاقات الفرعية القابلة للاستيلاء')
    parser.add_argument('--technologies', action='store_true', help='كشف التقنيات')
    parser.add_argument('--waf', action='store_true', help='كشف WAF')
    parser.add_argument('--http', action='store_true', help='فحص HTTP')
    parser.add_argument('--ssl', action='store_true', help='معلومات SSL')
    parser.add_argument('--ssl-protocols', action='store_true', help='بروتوكولات SSL')
    parser.add_argument('--ports', action='store_true', help='المنافذ')
    parser.add_argument('--geoip', action='store_true', help='الموقع الجغرافي')
    parser.add_argument('--whois', action='store_true', help='معلومات WHOIS')
    parser.add_argument('--nmap', action='store_true', help='دمج Nmap')
    parser.add_argument('--dirb', action='store_true', help='فحص المجلدات والملفات')
    parser.add_argument('--js-extract', action='store_true', help='استخراج ملفات JavaScript')
    parser.add_argument('--secrets', action='store_true', help='البحث عن أسرار في JS')
    parser.add_argument('--output', '-o', help='حفظ النتائج (يدعم .json, .html, .csv)')
    parser.add_argument('--format', choices=['text','json','html','csv'], default='text', help='صيغة العرض')
    parser.add_argument('--report', action='store_true', help='توليد تقرير HTML (مثل --output report.html)')
    parser.add_argument('--quiet', action='store_true', help='تقليل المخرجات')
    parser.add_argument('--proxy', help='استخدام بروكسي (مثال: http://127.0.0.1:8080)')
    parser.add_argument('--wordlist', help='ملف قائمة كلمات مخصصة لفحص المجلدات')
    parser.add_argument('--threads', type=int, default=50, help='عدد الخيوط المتزامنة')
    parser.add_argument('--timeout', type=int, default=15, help='مهلة الطلبات بالثواني')
    parser.add_argument('--no-color', action='store_true', help='تعطيل الألوان')
    parser.add_argument('--version', action='version', version=f'Ultimate Domain Scanner v{Config.VERSION}')
    
    args = parser.parse_args()
    
    if not args.quiet:
        print_banner()
    
    if args.all:
        args.dns = args.subdomains = args.technologies = args.waf = args.http = args.ssl = args.ssl_protocols = args.ports = args.geoip = args.whois = args.nmap = args.dirb = args.js_extract = args.secrets = args.takeover = True
    
    if args.report:
        args.format = 'html'
        if not args.output:
            args.output = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    
    results = await scan_domain(args.domain, args)
    
    if not args.quiet:
        print_results(results, args.format)
    
    if args.output:
        ext = os.path.splitext(args.output)[1].lower()
        if ext == '.json':
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, default=str)
            print_color(f"\n✅ النتائج محفوظة في {args.output}", Colors.GREEN)
        elif ext == '.html' or args.report:
            report = ReportGenerator(results)
            filename = report.save() if not args.output else args.output
            if args.output and ext == '.html':
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write(report.generate_html())
                filename = args.output
            print_color(f"\n✅ التقرير HTML محفوظ في {filename}", Colors.GREEN)
        elif ext == '.csv':
            import csv
            with open(args.output, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['المجال', 'IP', 'عدد النطاقات الفرعية', 'عدد المنافذ', 'عدد التقنيات', 'مؤشر المخاطر'])
                writer.writerow([
                    results['domain'],
                    results.get('ip', ''),
                    len(results.get('subdomains', [])),
                    len(results.get('ports', [])),
                    len(results.get('technologies', {})),
                    results.get('risk_analysis', {}).get('score', 0)
                ])
            print_color(f"\n✅ النتائج محفوظة في {args.output}", Colors.GREEN)
        else:
            print_color(f"⚠️ امتداد غير معروف: {ext}. حفظ كـ JSON.", Colors.YELLOW)
            with open(args.output + '.json', 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, default=str)
    
    print_color("\n✅ اكتمل التحليل.", Colors.GREEN, bold=True)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print_color("\n🛑 تم إيقاف التشغيل بواسطة المستخدم.", Colors.YELLOW, bold=True)
        sys.exit(0)
