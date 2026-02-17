"""
Parser module for parsing different proxy config formats
"""

import base64
import json
import re
import logging
from typing import Dict, Optional
from urllib.parse import urlparse, parse_qs, unquote

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ConfigParser:
    """Parser for different proxy config formats"""
    
    @staticmethod
    def _safe_base64_decode(data: str) -> str:
        """Helper method to safely decode Base64 strings with various quirks"""
        if not data:
            return ""
        
        # ممکن است لینک URL-encoded باشد
        data = unquote(data)
        
        # حذف فاصله‌ها
        data = data.strip()
        
        # استانداردسازی کاراکترهای URL-safe
        data = data.replace('-', '+').replace('_', '/')
        
        # اصلاح Padding
        padding = 4 - len(data) % 4
        if padding < 4:
            data += '=' * padding
            
        try:
            decoded_bytes = base64.b64decode(data)
            # در اینجا فقط می‌خوانیم، جایی دوباره انکود نمی‌کنیم
            return decoded_bytes.decode('utf-8', errors='ignore')
        except Exception:
            # در صورت خطا، رشته خالی برمی‌گردانیم
            return ""

    @staticmethod
    def _clean_name(name: str) -> str:
        """Clean config name from control characters and weird symbols"""
        if not name:
            return ""
        # دیکد کردن URL encoded chars
        name = unquote(name)
        # حذف کاراکترهای کنترلی غیرچاپ
        name = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', name)
        # حذف فاصله‌های اضافی
        return name.strip()

    @staticmethod
    def parse_config(config: str) -> Optional[Dict]:
        """Parse a proxy config and extract information"""
        try:
            config = config.strip()
            if config.startswith('vmess://'):
                return ConfigParser._parse_vmess(config)
            elif config.startswith('vless://'):
                return ConfigParser._parse_vless(config)
            elif config.startswith('trojan://'):
                return ConfigParser._parse_trojan(config)
            elif config.startswith('ss://'):
                return ConfigParser._parse_shadowsocks(config)
            elif config.startswith('ssr://'):
                return ConfigParser._parse_ssr(config)
            elif config.startswith('hysteria://') or config.startswith('hysteria2://'):
                return ConfigParser._parse_hysteria(config)
            elif config.startswith('tuic://'):
                return ConfigParser._parse_tuic(config)
            else:
                return None
        except Exception as e:
            logger.debug(f"Error parsing config: {e}")
            return None
    
    @staticmethod
    def _parse_vmess(config: str) -> Optional[Dict]:
        """Parse VMess config"""
        try:
            config_data = config.replace('vmess://', '')
            decoded = ConfigParser._safe_base64_decode(config_data)
            
            if not decoded:
                return None
                
            data = json.loads(decoded)
            
            return {
                'type': 'vmess',
                'address': data.get('add', ''),
                'port': str(data.get('port', '')),
                'id': data.get('id', ''),
                'name': ConfigParser._clean_name(data.get('ps', '')),
                'network': data.get('net', ''),
                'host': data.get('host', ''),
                'sni': data.get('sni', ''),
                'original': config
            }
        except Exception as e:
            logger.debug(f"Error parsing VMess: {e}")
            return None
    
    @staticmethod
    def _parse_vless(config: str) -> Optional[Dict]:
        """Parse VLESS config"""
        try:
            pattern = r'vless://([^@]+)@([^:]+):(\d+)\?([^#]*)#?(.*)'
            match = re.match(pattern, config)
            
            if not match:
                return None
            
            uuid, address, port, params, name = match.groups()
            params_dict = parse_qs(params)
            
            return {
                'type': 'vless',
                'address': address,
                'port': port,
                'id': uuid,
                'name': ConfigParser._clean_name(name),
                'network': params_dict.get('type', [''])[0],
                'sni': params_dict.get('sni', [''])[0],
                'host': params_dict.get('host', [''])[0],
                'original': config
            }
        except Exception as e:
            logger.debug(f"Error parsing VLESS: {e}")
            return None
    
    @staticmethod
    def _parse_trojan(config: str) -> Optional[Dict]:
        """Parse Trojan config"""
        try:
            pattern = r'trojan://([^@]+)@([^:]+):(\d+)\??([^#]*)#?(.*)'
            match = re.match(pattern, config)
            
            if not match:
                return None
            
            password, address, port, params, name = match.groups()
            params_dict = parse_qs(params) if params else {}
            
            return {
                'type': 'trojan',
                'address': address,
                'port': port,
                'password': password,
                'name': ConfigParser._clean_name(name),
                'sni': params_dict.get('sni', [''])[0],
                'host': params_dict.get('host', [''])[0],
                'original': config
            }
        except Exception as e:
            logger.debug(f"Error parsing Trojan: {e}")
            return None
    
    @staticmethod
    def _parse_shadowsocks(config: str) -> Optional[Dict]:
        """
        Parse Shadowsocks (SS) config

        نکته مهم:
        - اصلاً userinfo (یعنی base64(method:password) یا method:password) را برای ساخت رشته جدید
          استفاده نمی‌کنیم؛ فقط می‌خوانیم تا در صورت امکان address/port را به‌دست بیاوریم.
        - خود لینک ss:// در فیلد original دقیقاً همان چیزی است که از collector آمده.
        """
        try:
            clean_config = config.replace('ss://', '', 1)
            
            # 1. جدا کردن نام (Remark)
            name = ''
            if '#' in clean_config:
                clean_config, name_raw = clean_config.split('#', 1)
                name = ConfigParser._clean_name(name_raw)

            address = ''
            port = ''
            method = ''
            password = ''
            plugin = ''

            # حالت ۱: فرمت SIP002 یا plain: userinfo@host:port[?query]
            if '@' in clean_config:
                userinfo_raw, server_and_params = clean_config.rsplit('@', 1)

                query = {}
                server_part = server_and_params
                if '?' in server_and_params:
                    server_part, query_part = server_and_params.split('?', 1)
                    query = parse_qs(query_part)

                if ':' in server_part:
                    address, port = server_part.rsplit(':', 1)
                    address = address.strip('[]')  # IPv6 براکت‌دار

                # استخراج plugin (فقط برای اطلاعات جانبی، روی لینک اصلی اثر ندارد)
                plugin_raw = ''
                if query:
                    plugin_raw = query.get('plugin', [''])[0]
                    if plugin_raw:
                        plugin_raw = unquote(plugin_raw)
                        if ';' in plugin_raw:
                            plugin_raw = plugin_raw.split(';', 1)[0]
                        plugin_raw = plugin_raw.strip()
                        if not re.fullmatch(r'[A-Za-z0-9._\-]+', plugin_raw):
                            plugin_raw = ''
                plugin = plugin_raw

                # اگر userinfo به صورت plain method:password باشد، فقط برای اطلاعات متادیتا می‌خوانیم
                m = re.match(r'^([A-Za-z0-9._\-]+):(.+)$', userinfo_raw)
                if m:
                    method, password = m.groups()

            else:
                # حالت ۲: فرمت Legacy: base64(method:password@host:port[?query])
                decoded_full = ConfigParser._safe_base64_decode(clean_config).strip()
                if decoded_full and '@' in decoded_full:
                    userinfo_part, server_and_params = decoded_full.rsplit('@', 1)

                    query = {}
                    server_part = server_and_params
                    if '?' in server_and_params:
                        server_part, query_part = server_and_params.split('?', 1)
                        query = parse_qs(query_part)

                    if ':' in server_part:
                        address, port = server_part.rsplit(':', 1)
                        address = address.strip('[]')

                    # plugin (در صورت وجود در query)
                    plugin_raw = ''
                    if query:
                        plugin_raw = query.get('plugin', [''])[0]
                        if plugin_raw:
                            plugin_raw = unquote(plugin_raw)
                            if ';' in plugin_raw:
                                plugin_raw = plugin_raw.split(';', 1)[0]
                            plugin_raw = plugin_raw.strip()
                            if not re.fullmatch(r'[A-Za-z0-9._\-]+', plugin_raw):
                                plugin_raw = ''
                    plugin = plugin_raw

                    # userinfo_part = method:password اما ما برای جلوگیری از خراب‌کاری روی لینک،
                    # آن را جایی استفاده نمی‌کنیم؛ فقط اگر خواستی در JSON ببینی.
                    if ':' in userinfo_part:
                        method, password = userinfo_part.split(':', 1)

            return {
                'type': 'ss',
                'address': address,
                'port': port,
                'method': method,
                'password': password,
                'plugin': plugin,
                'name': name,
                'original': config
            }
            
        except Exception as e:
            logger.debug(f"Error parsing Shadowsocks: {e}")
            return None
    
    @staticmethod
    def _parse_ssr(config: str) -> Optional[Dict]:
        """Parse ShadowsocksR config"""
        try:
            config_data = config.replace('ssr://', '')
            decoded = ConfigParser._safe_base64_decode(config_data)
            
            if not decoded:
                return None
                
            parts = decoded.split(':')
            if len(parts) >= 6:
                return {
                    'type': 'ssr',
                    'address': parts[0],
                    'port': parts[1],
                    'name': '',
                    'original': config
                }
            return None
        except Exception as e:
            logger.debug(f"Error parsing SSR: {e}")
            return None
    
    @staticmethod
    def _parse_hysteria(config: str) -> Optional[Dict]:
        """Parse Hysteria config"""
        try:
            parsed = urlparse(config)
            name = parsed.fragment if parsed.fragment else ''
            
            return {
                'type': 'hysteria' if config.startswith('hysteria://') else 'hysteria2',
                'address': parsed.hostname or '',
                'port': str(parsed.port) if parsed.port else '',
                'name': ConfigParser._clean_name(name),
                'original': config
            }
        except Exception as e:
            logger.debug(f"Error parsing Hysteria: {e}")
            return None
    
    @staticmethod
    def _parse_tuic(config: str) -> Optional[Dict]:
        """Parse TUIC config"""
        try:
            parsed = urlparse(config)
            name = parsed.fragment if parsed.fragment else ''
            
            return {
                'type': 'tuic',
                'address': parsed.hostname or '',
                'port': str(parsed.port) if parsed.port else '',
                'name': ConfigParser._clean_name(name),
                'original': config
            }
        except Exception as e:
            logger.debug(f"Error parsing TUIC: {e}")
            return None
