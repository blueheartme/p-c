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
        
        # 1. URL Unquote (ممکن است لینک انکود شده باشد)
        data = unquote(data)
        
        # 2. حذف Whitespace
        data = data.strip()
        
        # 3. استانداردسازی کاراکترهای URL-Safe
        data = data.replace('-', '+').replace('_', '/')
        
        # 4. اصلاح Padding
        padding = 4 - len(data) % 4
        if padding < 4:
            data += '=' * padding
            
        try:
            decoded_bytes = base64.b64decode(data)
            return decoded_bytes.decode('utf-8', errors='ignore')
        except Exception:
            # تلاش دوم: گاهی اوقات رشته دوبار انکود شده است یا فرمت خاصی دارد
            # اما معمولا همان تلاش اول کافی است. در صورت خطا رشته خالی برمی‌گردانیم
            return ""

    @staticmethod
    def _clean_name(name: str) -> str:
        """Clean config name from control characters and weird symbols"""
        if not name:
            return ""
        # دیکد کردن URL encoded chars
        name = unquote(name)
        # حذف کاراکترهای کنترلی غیرچاپ (مثل مربع، \x1d و غیره)
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
        """Parse Shadowsocks config"""
        try:
            clean_config = config.replace('ss://', '')
            
            # 1. جدا کردن نام (Remark)
            name = ''
            if '#' in clean_config:
                clean_config, name_raw = clean_config.split('#', 1)
                name = ConfigParser._clean_name(name_raw)

            address = ''
            port = ''
            decoded_info = ''

            # 2. تشخیص فرمت (SIP002 vs Legacy)
            if '@' in clean_config:
                # فرمت SIP002: base64(method:password)@host:port
                user_info_raw, server_part = clean_config.rsplit('@', 1)
                
                if ':' in server_part:
                    address, port = server_part.rsplit(':', 1)
                    # حذف براکت IPv6 اگر وجود داشته باشد
                    address = address.strip('[]')
                else:
                    return None

                # دیکد کردن بخش متد و پسورد
                decoded_info = ConfigParser._safe_base64_decode(user_info_raw)

            else:
                # فرمت Legacy: base64(method:password@host:port)
                full_decoded = ConfigParser._safe_base64_decode(clean_config)
                
                if '@' in full_decoded:
                    decoded_info, server_part = full_decoded.rsplit('@', 1)
                    if ':' in server_part:
                        address, port = server_part.rsplit(':', 1)
                    else:
                        return None
                else:
                    return None

            if not decoded_info:
                return None

            # 3. جدا کردن متد و پسورد
            if ':' in decoded_info:
                method, password = decoded_info.split(':', 1)
            else:
                method = decoded_info
                password = ''
            
            return {
                'type': 'ss',
                'address': address,
                'port': port,
                'method': method,
                'password': password,
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
