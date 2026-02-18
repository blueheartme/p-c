"""
Collector module for gathering proxy configs from various sources
"""

import re
import requests
import logging
from typing import Set
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from .config import *

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ConfigCollector:
    """Main collector class for gathering configs from multiple sources"""
    
    def __init__(self):
        self.configs: Set[str] = set()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def collect_all(self) -> Set[str]:
        """Collect configs from all sources"""
        logger.info("Starting config collection from all sources...")
        
        try:
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = []
                
                futures.append(executor.submit(self.collect_from_github))
                futures.append(executor.submit(self.collect_from_telegram))
                futures.append(executor.submit(self.collect_from_apis))
                futures.append(executor.submit(self.collect_from_web))
                
                for future in as_completed(futures):
                    try:
                        configs = future.result()
                        self.configs.update(configs)
                    except Exception as e:
                        logger.error(f"Error in collection task: {e}")
                        continue
        
        except Exception as e:
            logger.error(f"Error in collect_all: {e}")
        
        logger.info(f"Total configs collected: {len(self.configs)}")
        return self.configs
    
    def collect_from_github(self) -> Set[str]:
        """Collect configs from GitHub repositories"""
        configs = set()
        logger.info("Collecting from GitHub repositories...")
        
        for repo in GITHUB_REPOS:
            try:
                paths = [
                    f"https://raw.githubusercontent.com/{repo}/main/sub/mix",
                    f"https://raw.githubusercontent.com/{repo}/main/sub/base64",
                    f"https://raw.githubusercontent.com/{repo}/master/sub/mix",
                    f"https://raw.githubusercontent.com/{repo}/main/configs.txt",
                    f"https://raw.githubusercontent.com/{repo}/master/v2ray",
                ]
                
                for url in paths:
                    try:
                        response = self.session.get(url, timeout=CONNECTION_TIMEOUT)
                        if response.status_code == 200:
                            # این منابع معمولاً متن خالص هستند
                            extracted = self._extract_configs_from_text(response.text)
                            configs.update(extracted)
                            logger.info(f"Found {len(extracted)} configs from {url}")
                            break
                    except Exception as e:
                        logger.debug(f"Failed to fetch {url}: {e}")
                        continue
                        
            except Exception as e:
                logger.error(f"Error collecting from GitHub repo {repo}: {e}")
                continue
        
        return configs
    
    def collect_from_telegram(self) -> Set[str]:
        """Collect configs from Telegram channels"""
        configs = set()
        logger.info("Collecting from Telegram channels...")
        
        for channel in TELEGRAM_CHANNELS:
            try:
                response = self.session.get(channel, timeout=CONNECTION_TIMEOUT)
                if response.status_code != 200:
                    continue

                # ۱. HTML را parse می‌کنیم
                soup = BeautifulSoup(response.text, 'html.parser')
                # ۲. متن خالصی که کاربر می‌بیند
                text_content = soup.get_text(separator=' ')
                # ۳. روی متن خالص regex می‌زنیم (نه روی HTML خام)
                extracted = self._extract_configs_from_text(text_content)
                configs.update(extracted)
                logger.info(f"Found {len(extracted)} configs from {channel}")
            except Exception as e:
                logger.error(f"Error collecting from Telegram {channel}: {e}")
                continue
        
        return configs
    
    def collect_from_apis(self) -> Set[str]:
        """Collect configs from public APIs"""
        configs = set()
        logger.info("Collecting from public APIs...")
        
        for api_url in PUBLIC_APIS:
            try:
                response = self.session.get(api_url, timeout=CONNECTION_TIMEOUT)
                if response.status_code == 200:
                    extracted = self._extract_configs_from_text(response.text)
                    configs.update(extracted)
                    logger.info(f"Found {len(extracted)} configs from {api_url}")
            except Exception as e:
                logger.error(f"Error collecting from API {api_url}: {e}")
                continue
        
        return configs
    
    def collect_from_web(self) -> Set[str]:
        """Collect configs from web scraping"""
        configs = set()
        
        if not WEB_SCRAPE_URLS:
            return configs
            
        logger.info("Collecting from web scraping...")
        
        for url in WEB_SCRAPE_URLS:
            try:
                response = self.session.get(url, timeout=CONNECTION_TIMEOUT)
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    text_content = soup.get_text(separator=' ')
                    extracted = self._extract_configs_from_text(text_content)
                    configs.update(extracted)
                    logger.info(f"Found {len(extracted)} configs from {url}")
            except Exception as e:
                logger.error(f"Error scraping web {url}: {e}")
                continue
        
        return configs
    
    def _extract_configs_from_text(self, text: str) -> Set[str]:
        """Extract proxy configs from plain text using regex patterns"""
        configs: Set[str] = set()
        
        try:
            # ترتیب مهم است: اول vmess/vless/trojan، بعد ss
            patterns = [
                # VMESS
                r'vmess://\S+',
                # VLESS
                r'vless://\S+',
                # TROJAN
                r'trojan://\S+',
                # SS: جلوگیری از match وسط vless/vmess
                r'(?<!vle)(?<!vme)ss://\S+',
                # SSR
                r'ssr://\S+',
                # سایر پروتکل‌ها
                r'hysteria://\S+',
                r'hysteria2://\S+',
                r'tuic://\S+',
            ]
            
            for pattern in patterns:
                matches = re.findall(pattern, text, re.IGNORECASE)
                configs.update(matches)
        
        except Exception as e:
            logger.error(f"Error extracting configs from text: {e}")
        
        return configs
