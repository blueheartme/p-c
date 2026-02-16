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
        """Parse Shadowsocks config - فیکس کامل base64url + garbage در method/password/name"""
        try:
            if '@' not in config:
                return None
                
            parts = config.replace('ss://', '').split('@')
            cred_data = parts[0]
            
            # دیکد مستقیم base64url (بهترین روش برای ss مدرن)
            credentials_bytes = base64.urlsafe_b64decode(cred_data)
            credentials = credentials_bytes.decode('utf-8', errors='ignore')
            
            # جدا کردن method و password
            if ':' in credentials:
                method, password = credentials.split(':', 1)
            else:
                method = credentials
                password = ''
            
            # فیکس garbage در method (برای name تمیز)
            if not method or len(method) > 50 or not all(ord(c) < 128 and c.isprintable() for c in method):
                method = 'aes-256-gcm'  # fallback استاندارد و تمیز
            
            # بخش سرور و نام
            server_part = parts[1].split('#')
            server_info = server_part[0]
            name = unquote(server_part[1]) if len(server_part) > 1 else ''
            
            address, port = server_info.rsplit(':', 1)
            
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
