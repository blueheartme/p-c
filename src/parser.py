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
    def parse_config(config: str) -> Optional[Dict]:
        """Parse a proxy config and extract information"""
        try:
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
            padding = 4 - len(config_data) % 4
            if padding != 4:
                config_data += '=' * padding
            
            decoded = base64.b64decode(config_data).decode('utf-8')
            data = json.loads(decoded)
            
            return {
                'type': 'vmess',
                'address': data.get('add', ''),
                'port': str(data.get('port', '')),
                'id': data.get('id', ''),
                'name': data.get('ps', ''),
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
                'name': unquote(name) if name else '',
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
                'name': unquote(name) if name else '',
                'sni': params_dict.get('sni', [''])[0],
                'host': params_dict.get('host', [''])[0],
                'original': config
            }
        except Exception as e:
            logger.debug(f"Error parsing Trojan: {e}")
            return None
    
    @staticmethod
    def _parse_shadowsocks(config: str) -> Optional[Dict]:
        """Parse Shadowsocks config - Fixed Base64 decoding"""
        try:
            # حذف پروتکل
            clean_config = config.replace('ss://', '')
            
            # جدا کردن نام (Remark)
            name = ''
            if '#' in clean_config:
                clean_config, name_raw = clean_config.split('#', 1)
                name = unquote(name_raw)

            address = ''
            port = ''
            decoded_str = ''

            # بررسی نوع فرمت (SIP002 یا Legacy)
            if '@' in clean_config:
                # فرمت جدید: base64(method:password)@host:port
                user_info_raw, server_part = clean_config.rsplit('@', 1)
                
                # استخراج آدرس و پورت
                if ':' in server_part:
                    address, port = server_part.rsplit(':', 1)
                    address = address.strip('[]') # هندل کردن IPv6
                else:
                    return None

                # نرمال‌سازی Base64 (تبدیل URL-Safe به استاندارد و افزودن Padding)
                user_info_raw = user_info_raw.replace('-', '+').replace('_', '/')
                padding = 4 - len(user_info_raw) % 4
                if padding < 4:
                    user_info_raw += '=' * padding
                
                try:
                    decoded_bytes = base64.b64decode(user_info_raw)
                    decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
                except Exception:
                    # در صورت خطا در دیکد، بازگشت None
                    return None

            else:
                # فرمت قدیمی: base64(method:password@host:port)
                # نرمال‌سازی Base64
                clean_config = clean_config.replace('-', '+').replace('_', '/')
                padding = 4 - len(clean_config) % 4
                if padding < 4:
                    clean_config += '=' * padding
                
                try:
                    decoded_bytes = base64.b64decode(clean_config)
                    full_info = decoded_bytes.decode('utf-8', errors='ignore')
                    
                    if '@' in full_info:
                        decoded_str, server_part = full_info.rsplit('@', 1)
                        if ':' in server_part:
                            address, port = server_part.rsplit(':', 1)
                        else:
                            return None
                    else:
                        return None
                except Exception:
                    return None

            # جدا کردن متد و پسورد
            if ':' in decoded_str:
                method, password = decoded_str.split(':', 1)
            else:
                method = decoded_str
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
            padding = 4 - len(config_data) % 4
            if padding != 4:
                config_data += '=' * padding
            decoded = base64.b64decode(config_data).decode('utf-8')
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
            
            return {
                'type': 'hysteria' if config.startswith('hysteria://') else 'hysteria2',
                'address': parsed.hostname or '',
                'port': str(parsed.port) if parsed.port else '',
                'name': unquote(parsed.fragment) if parsed.fragment else '',
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
            
            return {
                'type': 'tuic',
                'address': parsed.hostname or '',
                'port': str(parsed.port) if parsed.port else '',
                'name': unquote(parsed.fragment) if parsed.fragment else '',
                'original': config
            }
        except Exception as e:
            logger.debug(f"Error parsing TUIC: {e}")
            return None
