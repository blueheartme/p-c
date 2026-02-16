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

# Prefixes for known / common Shadowsocks cipher names
SS_KNOWN_METHOD_PREFIXES = (
    "aes-",
    "chacha20",
    "xchacha20",
    "2022-blake3-",
    "rc4-",
    "bf-",
    "camellia-",
    "idea-",
    "none",
    "gost",
    "salsa20",
)


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
    def _is_valid_ss_method(method: str) -> bool:
        """Check if a Shadowsocks cipher name looks valid/reasonable"""
        if not method:
            return False
        m = method.lower()

        # فقط حروف/اعداد/نقطه/خط تیره مجاز است
        if not re.fullmatch(r'[a-z0-9._\-]+', m):
            return False

        # با یکی از پیشوندهای شناخته‌شده شروع شود
        for prefix in SS_KNOWN_METHOD_PREFIXES:
            if m.startswith(prefix):
                return True

        return False

    @staticmethod
    def _parse_ss_userinfo(userinfo: str) -> (str, str):
        """
        Parse the 'userinfo' part of an ss URI.

        userinfo ممکن است یکی از دو حالت باشد:
        1) base64(method:password)
        2) plain method:password (بدون base64)

        خروجی: (method, password) – اگر معتبر نباشد، رشته خالی برمی‌گردد.
        """
        userinfo = userinfo.strip()
        method = ""
        password = ""

        # 1. ابتدا فرض می‌کنیم base64(method:password) است
        decoded = ConfigParser._safe_base64_decode(userinfo).strip()
        if decoded and ':' in decoded:
            m, p = decoded.split(':', 1)
            m = m.strip()
            if ConfigParser._is_valid_ss_method(m):
                method, password = m, p

        # 2. اگر دیکد base64 جواب نداد یا معتبر نبود، plain را امتحان می‌کنیم
        if not method:
            if ':' in userinfo:
                m, p = userinfo.split(':', 1)
            else:
                m, p = userinfo, ''
            m = m.strip()
            if ConfigParser._is_valid_ss_method(m):
                method, password = m, p

        return method, password

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
        """Parse Shadowsocks (SS) config"""
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

            # 2. تشخیص فرمتی که @ جداکننده‌ی userinfo و سرور است
            if '@' in clean_config:
                # حالت SIP002 یا plain: userinfo@host:port[?query]
                userinfo_raw, server_part = clean_config.rsplit('@', 1)

                query = {}
                if '?' in server_part:
                    server_part, query_part = server_part.split('?', 1)
                    query = parse_qs(query_part)

                if ':' in server_part:
                    address, port = server_part.rsplit(':', 1)
                    address = address.strip('[]')
                else:
                    return None

                # استخراج method و password از userinfo
                method, password = ConfigParser._parse_ss_userinfo(userinfo_raw)

                # استخراج plugin (در صورت وجود)
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

            else:
                # 3. فرمت Legacy: base64(method:password@host:port[?query])
                decoded_full = ConfigParser._safe_base64_decode(clean_config).strip()
                if not decoded_full or '@' not in decoded_full:
                    return None

                userinfo_part, server_part = decoded_full.rsplit('@', 1)

                query = {}
                if '?' in server_part:
                    server_part, query_part = server_part.split('?', 1)
                    query = parse_qs(query_part)

                if ':' in server_part:
                    address, port = server_part.rsplit(':', 1)
                    address = address.strip('[]')
                else:
                    return None

                # استخراج method و password
                method, password = ConfigParser._parse_ss_userinfo(userinfo_part)

                # plugin در Legacy هم می‌تواند باشد
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

            # اگر method معتبر پیدا نشد، همچنان کانفیگ را برمی‌گردانیم ولی method/password خالی است
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
