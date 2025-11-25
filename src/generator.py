"""
Generator module for creating output files with standard protocol-based naming
All transmission types supported: tcp, ws, grpc, h2, kcp, quic, httpupgrade, xhttp
"""

import os
import json
import base64
import logging
import re
from typing import Dict, List
from datetime import datetime
from urllib.parse import quote, parse_qs
from .config import *

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class OutputGenerator:
    """Generate output files in different formats"""
    
    def __init__(self):
        self._ensure_directories()
    
    def _ensure_directories(self):
        """Create output directories if they don't exist"""
        for directory in [OUTPUT_DIR, IRAN_DIR, GERMANY_DIR, OTHERS_DIR, TESTED_DIR]:
            os.makedirs(directory, exist_ok=True)
    
    def generate_all_outputs(self, categorized_configs: Dict[str, List[Dict]], 
                            tested_configs: Dict[str, List[Dict]]):
        """Generate all output formats"""
        logger.info("Generating output files...")
        
        try:
            for country, configs in categorized_configs.items():
                logger.info(f"Generating outputs for {country} with {len(configs)} configs")
                self._generate_country_outputs(country, configs, tested=False)
            
            for country, configs in tested_configs.items():
                logger.info(f"Generating tested outputs for {country} with {len(configs)} configs")
                self._generate_country_outputs(country, configs, tested=True)
            
            self._generate_readme(categorized_configs, tested_configs)
            
            logger.info("Output generation complete!")
            
        except Exception as e:
            logger.error(f"Error generating outputs: {e}", exc_info=True)
    
    def _generate_country_outputs(self, country: str, configs: List[Dict], tested: bool = False):
        """Generate outputs for a specific country"""
        try:
            if tested:
                base_dir = TESTED_DIR
                prefix = "tested_"
            elif country == "IR":
                base_dir = IRAN_DIR
                prefix = ""
            elif country == "DE":
                base_dir = GERMANY_DIR
                prefix = ""
            else:
                base_dir = OTHERS_DIR
                prefix = ""
            
            country_dir = os.path.join(base_dir, country.lower())
            os.makedirs(country_dir, exist_ok=True)
            
            # Rebuild configs with standard names
            rebuilt_configs = self._rebuild_configs_with_standard_names(configs, country)
            
            logger.info(f"Rebuilt {len(rebuilt_configs)} configs for {country}")
            
            if not rebuilt_configs:
                logger.warning(f"No configs to generate for {country}!")
                return
            
            self._generate_json(country_dir, prefix + "configs.json", rebuilt_configs)
            self._generate_txt(country_dir, prefix + "configs.txt", rebuilt_configs)
            self._generate_subscription(country_dir, prefix + "subscription.txt", rebuilt_configs)
            
            logger.info(f"✅ Generated outputs for {country} ({'tested' if tested else 'all'})")
            
        except Exception as e:
            logger.error(f"Error generating country outputs for {country}: {e}", exc_info=True)
    
    def _rebuild_configs_with_standard_names(self, configs: List[Dict], country: str) -> List[Dict]:
        """Rebuild configs with standard protocol-based naming"""
        rebuilt = []
        
        logger.info(f"Rebuilding {len(configs)} configs for {country}...")
        
        for idx, config in enumerate(configs, 1):
            try:
                # Build standard name based on protocol type
                new_name = self._build_standard_name(config, country, idx)
                
                logger.debug(f"Config {idx}: New name = {new_name}")
                
                # Rebuild config with new name
                new_config = self._rebuild_config_with_name(config, new_name)
                
                if new_config:
                    config['rebuilt'] = new_config
                    rebuilt.append(config)
                else:
                    # If rebuild failed, use original
                    logger.warning(f"Failed to rebuild config {idx}, using original")
                    config['rebuilt'] = config.get('original', '')
                    rebuilt.append(config)
                    
            except Exception as e:
                logger.error(f"Error rebuilding config {idx}: {e}")
                # IMPORTANT: Still add the config with original name
                config['rebuilt'] = config.get('original', '')
                rebuilt.append(config)
        
        logger.info(f"Successfully rebuilt {len(rebuilt)} configs")
        return rebuilt
    
    def _build_standard_name(self, config: Dict, country: str, idx: int) -> str:
        """
        Build standard name based on protocol specifications
        Only includes relevant fields for each protocol
        """
        
        protocol = config.get('type', 'unknown').lower()
        
        try:
            if protocol == 'vless':
                return self._build_vless_name(config, country, idx)
            elif protocol == 'vmess':
                return self._build_vmess_name(config, country, idx)
            elif protocol == 'trojan':
                return self._build_trojan_name(config, country, idx)
            elif protocol == 'ss':
                return self._build_shadowsocks_name(config, country, idx)
            elif protocol == 'ssr':
                return self._build_ssr_name(config, country, idx)
            elif protocol in ['hysteria', 'hysteria2']:
                return self._build_hysteria_name(config, country, idx)
            elif protocol == 'tuic':
                return self._build_tuic_name(config, country, idx)
            else:
                flag = COUNTRY_FLAGS.get(country, '🌐')
                return f"{protocol}-{country}{flag}-{idx}"
        except Exception as e:
            logger.error(f"Error in _build_standard_name: {e}")
            # Fallback to simple name
            flag = COUNTRY_FLAGS.get(country, '🌐')
            return f"{protocol}-{country}{flag}-{idx}"
    
    def _build_vless_name(self, config: Dict, country: str, idx: int) -> str:
        """
        VLESS format: vless-[flow]-[network]-[headerType]-[security]-[fingerprint]-[cdn]-COUNTRY-num
        
        Supported networks: tcp, ws, grpc, h2, kcp, quic, httpupgrade, xhttp
        Example: vless-xtls-rprx-vision-tcp-reality-chrome-IR🇮🇷-1
        """
        parts = ['vless']
        
        try:
            original = config.get('original', '')
            params = self._extract_vless_params(original)
            
            # UPDATED: Flow (xtls-rprx-vision, xtls-rprx-direct, xtls-rprx-origin)
            flow = params.get('flow', '').lower()
            if flow and flow not in ['none', '']:
                parts.append(flow)
            
            # Encryption (none is default, don't show)
            encryption = params.get('encryption', '')
            if encryption and encryption not in ['none', '']:
                parts.append(encryption)
            
            # UPDATED: Network - Support ALL types: tcp, ws, grpc, h2, kcp, quic, httpupgrade, xhttp
            # Always show network type
            network = params.get('type', config.get('network', '')).lower()
            if not network or network == '':
                network = 'tcp'  # default
            parts.append(network)
            
            # UPDATED: Header Type (http, none) - only show if not none/empty
            header_type = params.get('headerType', '')
            if header_type and header_type not in ['none', '']:
                parts.append(header_type)
            
            # UPDATED: Security (tls, reality, none) - Always show if exists
            security = params.get('security', '')
            if security and security not in ['none', '']:
                parts.append(security)
            
            # UPDATED: Fingerprint (chrome, firefox, safari, ios, android, edge, 360, qq, random)
            fingerprint = params.get('fp', params.get('fingerprint', ''))
            if fingerprint and fingerprint not in ['none', '']:
                parts.append(fingerprint)
            
            # CDN
            cdn = config.get('cdn', '')
            if cdn:
                cdn_name = CDN_NAMES.get(cdn, cdn).replace('☁️', '').strip()
                parts.append(cdn_name)
            
        except Exception as e:
            logger.debug(f"Error building VLESS name: {e}")
        
        # Country + Flag
        flag = COUNTRY_FLAGS.get(country, '🌐')
        parts.append(f"{country}{flag}")
        parts.append(str(idx))
        
        return '-'.join(parts)
    
    def _build_vmess_name(self, config: Dict, country: str, idx: int) -> str:
        """
        VMESS format: vmess-[encryption]-[network]-[headerType]-[security]-[cdn]-COUNTRY-num
        
        Supported networks: tcp, ws, h2, grpc, kcp, quic, httpupgrade
        Example: vmess-auto-ws-tls-Cloudflare-IR🇮🇷-1
        """
        parts = ['vmess']
        
        try:
            vmess_data = self._extract_vmess_data(config.get('original', ''))
            
            # UPDATED: Encryption/Security (auto, aes-128-gcm, chacha20-poly1305, none, zero)
            scy = vmess_data.get('scy', '')
            if scy and scy not in ['', 'none', 'auto']:
                parts.append(scy)
            elif scy == 'auto':
                parts.append('auto')
            
            # UPDATED: Network - Support ALL types: tcp, ws, h2, grpc, kcp, quic, httpupgrade
            # Always show network type
            network = vmess_data.get('net', config.get('network', '')).lower()
            if not network or network == '':
                network = 'tcp'  # default
            parts.append(network)
            
            # UPDATED: Header Type (none, http, srtp, utp, wechat-video, dtls, wireguard)
            # Only show if not none/http/empty
            header_type = vmess_data.get('type', '')
            if header_type and header_type not in ['none', '', 'http']:
                parts.append(header_type)
            
            # UPDATED: TLS - Always show if exists
            tls = vmess_data.get('tls', '')
            if tls and tls not in ['none', '']:
                parts.append(tls)
            
            # CDN
            cdn = config.get('cdn', '')
            if cdn:
                cdn_name = CDN_NAMES.get(cdn, cdn).replace('☁️', '').strip()
                parts.append(cdn_name)
        
        except Exception as e:
            logger.debug(f"Error building VMESS name: {e}")
        
        flag = COUNTRY_FLAGS.get(country, '🌐')
        parts.append(f"{country}{flag}")
        parts.append(str(idx))
        
        return '-'.join(parts)
    
    def _build_trojan_name(self, config: Dict, country: str, idx: int) -> str:
        """
        TROJAN format: trojan-[network]-[headerType]-[security]-[cdn]-COUNTRY-num
        
        Supported networks: tcp, ws, grpc, h2
        Example: trojan-tcp-tls-ArvanCloud-IR🇮🇷-1
        """
        parts = ['trojan']
        
        try:
            original = config.get('original', '')
            params = self._extract_trojan_params(original)
            
            # UPDATED: Network - Support: tcp, ws, grpc, h2
            # Always show network type
            network = params.get('type', config.get('network', '')).lower()
            if not network or network == '':
                network = 'tcp'  # default for trojan
            parts.append(network)
            
            # UPDATED: Header Type - only show if exists and not none
            header_type = params.get('headerType', '')
            if header_type and header_type not in ['none', '']:
                parts.append(header_type)
            
            # UPDATED: Security (usually always tls for trojan) - Always show
            security = params.get('security', '')
            if security and security not in ['none', '']:
                parts.append(security)
            elif not security:
                # Trojan default is tls
                parts.append('tls')
            
            # CDN
            cdn = config.get('cdn', '')
            if cdn:
                cdn_name = CDN_NAMES.get(cdn, cdn).replace('☁️', '').strip()
                parts.append(cdn_name)
        
        except Exception as e:
            logger.debug(f"Error building Trojan name: {e}")
        
        flag = COUNTRY_FLAGS.get(country, '🌐')
        parts.append(f"{country}{flag}")
        parts.append(str(idx))
        
        return '-'.join(parts)
    
    def _build_shadowsocks_name(self, config: Dict, country: str, idx: int) -> str:
        """
        SS format: ss-[method]-[plugin]-[cdn]-COUNTRY-num
        
        Supported methods: aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305, etc.
        Example: ss-aes-256-gcm-obfs-IR🇮🇷-1
        """
        parts = ['ss']
        
        # UPDATED: Encryption method - Always show
        method = config.get('method', '').lower()
        if method:
            method = method.replace('_', '-')
            parts.append(method)
        
        # UPDATED: Plugin (obfs, v2ray-plugin, etc.) - if exists in future
        plugin = config.get('plugin', '')
        if plugin and plugin not in ['none', '']:
            parts.append(plugin)
        
        # CDN
        cdn = config.get('cdn', '')
        if cdn:
            cdn_name = CDN_NAMES.get(cdn, cdn).replace('☁️', '').strip()
            parts.append(cdn_name)
        
        flag = COUNTRY_FLAGS.get(country, '🌐')
        parts.append(f"{country}{flag}")
        parts.append(str(idx))
        
        return '-'.join(parts)
    
    def _build_ssr_name(self, config: Dict, country: str, idx: int) -> str:
        """
        SSR format: ssr-[method]-[protocol]-[obfs]-COUNTRY-num
        
        Example: ssr-aes-256-cfb-origin-plain-IR🇮🇷-1
        """
        parts = ['ssr']
        
        # UPDATED: Add SSR specific fields if available in future parsing
        # For now, simple format
        
        flag = COUNTRY_FLAGS.get(country, '🌐')
        parts.append(f"{country}{flag}")
        parts.append(str(idx))
        
        return '-'.join(parts)
    
    def _build_hysteria_name(self, config: Dict, country: str, idx: int) -> str:
        """
        Hysteria format: hysteria-[version]-[protocol]-[cdn]-COUNTRY-num
        
        Example: hysteria2-udp-Cloudflare-DE🇩🇪-1
        """
        protocol_type = config.get('type', 'hysteria')
        parts = [protocol_type]
        
        # Protocol (udp always for hysteria)
        parts.append('udp')
        
        # CDN
        cdn = config.get('cdn', '')
        if cdn:
            cdn_name = CDN_NAMES.get(cdn, cdn).replace('☁️', '').strip()
            parts.append(cdn_name)
        
        flag = COUNTRY_FLAGS.get(country, '🌐')
        parts.append(f"{country}{flag}")
        parts.append(str(idx))
        
        return '-'.join(parts)
    
    def _build_tuic_name(self, config: Dict, country: str, idx: int) -> str:
        """
        TUIC format: tuic-[version]-udp-[cdn]-COUNTRY-num
        
        Example: tuic-v5-udp-Cloudflare-US🇺🇸-1
        """
        parts = ['tuic']
        
        # UPDATED: Add version if available
        # For now, simple format
        
        # Protocol (udp for TUIC)
        parts.append('udp')
        
        # CDN
        cdn = config.get('cdn', '')
        if cdn:
            cdn_name = CDN_NAMES.get(cdn, cdn).replace('☁️', '').strip()
            parts.append(cdn_name)
        
        flag = COUNTRY_FLAGS.get(country, '🌐')
        parts.append(f"{country}{flag}")
        parts.append(str(idx))
        
        return '-'.join(parts)
    
    def _extract_vless_params(self, config_str: str) -> dict:
        """
        Extract parameters from VLESS config
        
        UPDATED: Better parameter extraction for all network types
        """
        try:
            if '?' not in config_str:
                return {}
            
            params_part = config_str.split('?')[1].split('#')[0]
            params = parse_qs(params_part)
            
            # Flatten single values
            result = {}
            for key, value in params.items():
                result[key] = value[0] if len(value) == 1 else value
            
            return result
        except Exception as e:
            logger.debug(f"Error extracting VLESS params: {e}")
            return {}
    
    def _extract_trojan_params(self, config_str: str) -> dict:
        """
        Extract parameters from Trojan config
        
        UPDATED: Better parameter extraction
        """
        try:
            if '?' not in config_str:
                return {}
            
            params_part = config_str.split('?')[1].split('#')[0]
            params = parse_qs(params_part)
            
            result = {}
            for key, value in params.items():
                result[key] = value[0] if len(value) == 1 else value
            
            return result
        except Exception as e:
            logger.debug(f"Error extracting Trojan params: {e}")
            return {}
    
    def _extract_vmess_data(self, config_str: str) -> dict:
        """
        Extract data from VMess config
        
        UPDATED: Better error handling for malformed base64
        """
        try:
            config_data = config_str.replace('vmess://', '')
            padding = 4 - len(config_data) % 4
            if padding != 4:
                config_data += '=' * padding
            
            decoded = base64.b64decode(config_data).decode('utf-8')
            data = json.loads(decoded)
            
            return data
        except Exception as e:
            logger.debug(f"Error extracting VMess data: {e}")
            return {}
    
    def _rebuild_config_with_name(self, config: Dict, new_name: str) -> str:
        """
        Rebuild config string with new name
        
        UPDATED: Better error handling and fallback
        """
        
        config_type = config.get('type', '')
        original = config.get('original', '')
        
        if not original:
            logger.warning("Config has no original string!")
            return ''
        
        try:
            if config_type == 'vmess':
                return self._rebuild_vmess(original, new_name)
            elif config_type == 'vless':
                return self._rebuild_vless(original, new_name)
            elif config_type == 'trojan':
                return self._rebuild_trojan(original, new_name)
            elif config_type == 'ss':
                return self._rebuild_shadowsocks(original, new_name)
            elif config_type == 'ssr':
                return self._rebuild_ssr(original, new_name)
            elif config_type in ['hysteria', 'hysteria2']:
                return self._rebuild_hysteria(original, new_name)
            elif config_type == 'tuic':
                return self._rebuild_tuic(original, new_name)
            else:
                logger.warning(f"Unknown config type: {config_type}")
                return original
        except Exception as e:
            logger.error(f"Error rebuilding {config_type}: {e}")
            return original
    
    def _rebuild_vmess(self, original: str, new_name: str) -> str:
        """Rebuild VMess config with new name"""
        try:
            config_data = original.replace('vmess://', '')
            padding = 4 - len(config_data) % 4
            if padding != 4:
                config_data += '=' * padding
            
            decoded = base64.b64decode(config_data).decode('utf-8')
            data = json.loads(decoded)
            
            data['ps'] = new_name
            
            new_json = json.dumps(data, separators=(',', ':'), ensure_ascii=False)
            new_b64 = base64.b64encode(new_json.encode('utf-8')).decode('utf-8')
            
            return 'vmess://' + new_b64
        except Exception as e:
            logger.debug(f"Error rebuilding VMess: {e}")
            return original
    
    def _rebuild_vless(self, original: str, new_name: str) -> str:
        """Rebuild VLESS config with new name"""
        try:
            base = original.split('#')[0] if '#' in original else original
            # UPDATED: Keep emojis safe in URL encoding
            encoded_name = quote(new_name, safe='🇮🇷🇩🇪🇺🇸🇬🇧🇫🇷🇳🇱🇨🇦🇸🇬🇯🇵🇰🇷🇭🇰🇹🇼🇦🇺🇮🇳🇷🇺🇹🇷🇦🇪🇸🇪🇫🇮🇵🇱🇺🇦🇧🇷🇦🇷🇲🇽🇿🇦🇪🇬🇨🇭🇦🇹🌐-')
            return f"{base}#{encoded_name}"
        except Exception as e:
            logger.debug(f"Error rebuilding VLESS: {e}")
            return original
    
    def _rebuild_trojan(self, original: str, new_name: str) -> str:
        """Rebuild Trojan config with new name"""
        try:
            base = original.split('#')[0] if '#' in original else original
            encoded_name = quote(new_name, safe='🇮🇷🇩🇪🇺🇸🇬🇧🇫🇷🇳🇱🇨🇦🇸🇬🇯🇵🇰🇷🇭🇰🇹🇼🇦🇺🇮🇳🇷🇺🇹🇷🇦🇪🇸🇪🇫🇮🇵🇱🇺🇦🇧🇷🇦🇷🇲🇽🇿🇦🇪🇬🇨🇭🇦🇹🌐-')
            return f"{base}#{encoded_name}"
        except Exception as e:
            logger.debug(f"Error rebuilding Trojan: {e}")
            return original
    
    def _rebuild_shadowsocks(self, original: str, new_name: str) -> str:
        """Rebuild Shadowsocks config with new name"""
        try:
            base = original.split('#')[0] if '#' in original else original
            encoded_name = quote(new_name, safe='🇮🇷🇩🇪🇺🇸🇬🇧🇫🇷🇳🇱🇨🇦🇸🇬🇯🇵🇰🇷🇭🇰🇹🇼🇦🇺🇮🇳🇷🇺🇹🇷🇦🇪🇸🇪🇫🇮🇵🇱🇺🇦🇧🇷🇦🇷🇲🇽🇿🇦🇪🇬🇨🇭🇦🇹🌐-')
            return f"{base}#{encoded_name}"
        except Exception as e:
            logger.debug(f"Error rebuilding SS: {e}")
            return original
    
    def _rebuild_ssr(self, original: str, new_name: str) -> str:
        """
        Rebuild SSR config with new name
        
        UPDATED: SSR has complex encoding, keeping original for safety
        """
        return original
    
    def _rebuild_hysteria(self, original: str, new_name: str) -> str:
        """Rebuild Hysteria config with new name"""
        try:
            base = original.split('#')[0] if '#' in original else original
            encoded_name = quote(new_name, safe='🇮🇷🇩🇪🇺🇸🇬🇧🇫🇷🇳🇱🇨🇦🇸🇬🇯🇵🇰🇷🇭🇰🇹🇼🇦🇺🇮🇳🇷🇺🇹🇷🇦🇪🇸🇪🇫🇮🇵🇱🇺🇦🇧🇷🇦🇷🇲🇽🇿🇦🇪🇬🇨🇭🇦🇹🌐-')
            return f"{base}#{encoded_name}"
        except Exception as e:
            logger.debug(f"Error rebuilding Hysteria: {e}")
            return original
    
    def _rebuild_tuic(self, original: str, new_name: str) -> str:
        """Rebuild TUIC config with new name"""
        try:
            base = original.split('#')[0] if '#' in original else original
            encoded_name = quote(new_name, safe='🇮🇷🇩🇪🇺🇸🇬🇧🇫🇷🇳🇱🇨🇦🇸🇬🇯🇵🇰🇷🇭🇰🇹🇼🇦🇺🇮🇳🇷🇺🇹🇷🇦🇪🇸🇪🇫🇮🇵🇱🇺🇦🇧🇷🇦🇷🇲🇽🇿🇦🇪🇬🇨🇭🇦🇹🌐-')
            return f"{base}#{encoded_name}"
        except Exception as e:
            logger.debug(f"Error rebuilding TUIC: {e}")
            return original
    
    def _generate_json(self, directory: str, filename: str, configs: List[Dict]):
        """Generate JSON output"""
        try:
            filepath = os.path.join(directory, filename)
            
            output_data = {
                'updated': datetime.utcnow().isoformat(),
                'count': len(configs),
                'configs': []
            }
            
            for config in configs:
                output_config = config.copy()
                output_config['original'] = config.get('rebuilt', config.get('original', ''))
                output_data['configs'].append(output_config)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, ensure_ascii=False, indent=2)
            
            logger.info(f"✅ Generated JSON: {filepath}")
                
        except Exception as e:
            logger.error(f"Error generating JSON: {e}", exc_info=True)
    
    def _generate_txt(self, directory: str, filename: str, configs: List[Dict]):
        """Generate TXT output"""
        try:
            filepath = os.path.join(directory, filename)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                for config in configs:
                    config_str = config.get('rebuilt', config.get('original', ''))
                    if config_str:
                        f.write(config_str + '\n')
            
            logger.info(f"✅ Generated TXT: {filepath}")
                    
        except Exception as e:
            logger.error(f"Error generating TXT: {e}", exc_info=True)
    
    def _generate_subscription(self, directory: str, filename: str, configs: List[Dict]):
        """Generate subscription link (base64 encoded)"""
        try:
            filepath = os.path.join(directory, filename)
            
            config_lines = []
            for config in configs:
                config_str = config.get('rebuilt', config.get('original', ''))
                if config_str:
                    config_lines.append(config_str)
            
            if not config_lines:
                logger.warning(f"No config lines to encode for subscription!")
                return
            
            all_configs = '\n'.join(config_lines)
            encoded = base64.b64encode(all_configs.encode('utf-8')).decode('utf-8')
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(encoded)
            
            logger.info(f"✅ Generated Subscription: {filepath}")
                
        except Exception as e:
            logger.error(f"Error generating subscription: {e}", exc_info=True)
    
    def _generate_readme(self, all_configs: Dict, tested_configs: Dict):
        """Generate README.md with statistics and links"""
        try:
            readme_path = os.path.join(OUTPUT_DIR, 'README.md')
            
            with open(readme_path, 'w', encoding='utf-8') as f:
                f.write("# 🌐 Free Proxy Configs\n\n")
                f.write(f"**Last Updated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC\n\n")
                
                f.write("## 📊 Statistics\n\n")
                
                total_configs = sum(len(configs) for configs in all_configs.values())
                total_tested = sum(len(configs) for configs in tested_configs.values())
                
                f.write(f"- **Total Configs:** {total_configs}\n")
                f.write(f"- **Tested & Working:** {total_tested}\n")
                f.write(f"- **Countries:** {len(all_configs)}\n\n")
                
                if "IR" in all_configs:
                    ir_count = len(all_configs["IR"])
                    ir_tested = len(tested_configs.get("IR", []))
                    f.write("## 🇮🇷 Iran Configs (Priority)\n\n")
                    f.write(f"- **Total:** {ir_count}\n")
                    f.write(f"- **Tested:** {ir_tested}\n\n")
                    f.write("### 📥 Download Links:\n")
                    f.write("- [JSON](iran/ir/configs.json)\n")
                    f.write("- [TXT](iran/ir/configs.txt)\n")
                    f.write("- [Subscription](iran/ir/subscription.txt)\n")
                    if ir_tested > 0:
                        f.write("- [Tested Subscription](tested/ir/tested_subscription.txt) ✅\n")
                    f.write("\n")
                
                if "DE" in all_configs:
                    de_count = len(all_configs["DE"])
                    de_tested = len(tested_configs.get("DE", []))
                    f.write("## 🇩🇪 Germany Configs\n\n")
                    f.write(f"- **Total:** {de_count}\n")
                    f.write(f"- **Tested:** {de_tested}\n\n")
                    f.write("### 📥 Download Links:\n")
                    f.write("- [JSON](germany/de/configs.json)\n")
                    f.write("- [TXT](germany/de/configs.txt)\n")
                    f.write("- [Subscription](germany/de/subscription.txt)\n")
                    if de_tested > 0:
                        f.write("- [Tested Subscription](tested/de/tested_subscription.txt) ✅\n")
                    f.write("\n")
                
                other_countries = [c for c in all_configs.keys() if c not in ["IR", "DE"]]
                if other_countries:
                    f.write("## 🌍 Other Countries\n\n")
                    for country in sorted(other_countries):
                        flag = COUNTRY_FLAGS.get(country, "🌐")
                        count = len(all_configs[country])
                        f.write(f"### {flag} {country}\n")
                        f.write(f"- **Count:** {count}\n")
                        f.write(f"- [JSON](others/{country.lower()}/configs.json) | ")
                        f.write(f"[TXT](others/{country.lower()}/configs.txt) | ")
                        f.write(f"[Subscription](others/{country.lower()}/subscription.txt)\n\n")
                
                f.write("\n---\n")
                f.write("*🤖 Auto-updated every 8 hours via GitHub Actions*\n")
            
            logger.info(f"✅ Generated README: {readme_path}")
                
        except Exception as e:
            logger.error(f"Error generating README: {e}", exc_info=True)
