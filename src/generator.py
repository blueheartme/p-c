"""
Generator module for creating output files with proper config naming
"""

import os
import json
import base64
import logging
import re
from typing import Dict, List
from datetime import datetime
from urllib.parse import quote, urlparse, parse_qs, urlencode, urlunparse
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
                self._generate_country_outputs(country, configs, tested=False)
            
            for country, configs in tested_configs.items():
                self._generate_country_outputs(country, configs, tested=True)
            
            self._generate_readme(categorized_configs, tested_configs)
            
            logger.info("Output generation complete!")
            
        except Exception as e:
            logger.error(f"Error generating outputs: {e}")
    
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
            
            # Rebuild configs with new names
            rebuilt_configs = self._rebuild_configs_with_new_names(configs, country)
            
            self._generate_json(country_dir, prefix + "configs.json", rebuilt_configs)
            self._generate_txt(country_dir, prefix + "configs.txt", rebuilt_configs)
            self._generate_subscription(country_dir, prefix + "subscription.txt", rebuilt_configs)
            
            logger.info(f"Generated outputs for {country} ({'tested' if tested else 'all'})")
            
        except Exception as e:
            logger.error(f"Error generating country outputs: {e}")
    
    def _rebuild_configs_with_new_names(self, configs: List[Dict], country: str) -> List[Dict]:
        """Rebuild configs with completely new naming format"""
        rebuilt = []
        
        for idx, config in enumerate(configs, 1):
            try:
                # Build new name
                new_name = self._build_new_name(config, country, idx)
                
                # Rebuild config based on type
                new_config = self._rebuild_config_with_name(config, new_name)
                
                if new_config:
                    config['rebuilt'] = new_config
                    rebuilt.append(config)
                else:
                    # If rebuild failed, use original
                    rebuilt.append(config)
                    
            except Exception as e:
                logger.debug(f"Error rebuilding config: {e}")
                rebuilt.append(config)
        
        return rebuilt
    
    def _build_new_name(self, config: Dict, country: str, idx: int) -> str:
        """Build new name in format: protocol-network-tls-cdn-COUNTRY-flag"""
        
        parts = []
        
        # Protocol
        protocol = config.get('type', 'unknown')
        parts.append(protocol)
        
        # Network type
        network = config.get('network', 'tcp')
        if network:
            parts.append(network)
        
        # TLS
        sni = config.get('sni', '')
        if sni:
            parts.append('tls')
        
        # CDN
        cdn = config.get('cdn', '')
        if cdn:
            cdn_name = CDN_NAMES.get(cdn, cdn).replace('☁️', '').strip()
            parts.append(cdn_name)
        
        # Country code
        parts.append(country)
        
        # Flag
        flag = COUNTRY_FLAGS.get(country, '🌐')
        parts.append(flag)
        
        # Join with hyphen (safe for URLs)
        name = '-'.join(parts)
        
        # Add index
        name += f'-{idx}'
        
        return name
    
    def _rebuild_config_with_name(self, config: Dict, new_name: str) -> str:
        """Rebuild config string with new name based on protocol type"""
        
        config_type = config.get('type', '')
        original = config.get('original', '')
        
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
                return original
        except Exception as e:
            logger.debug(f"Error rebuilding {config_type}: {e}")
            return original
    
    def _rebuild_vmess(self, original: str, new_name: str) -> str:
        """Rebuild VMess config with new name"""
        try:
            # Decode
            config_data = original.replace('vmess://', '')
            padding = 4 - len(config_data) % 4
            if padding != 4:
                config_data += '=' * padding
            
            decoded = base64.b64decode(config_data).decode('utf-8')
            data = json.loads(decoded)
            
            # Change name (ps = remarks)
            data['ps'] = new_name
            
            # Re-encode
            new_json = json.dumps(data, separators=(',', ':'), ensure_ascii=False)
            new_b64 = base64.b64encode(new_json.encode('utf-8')).decode('utf-8')
            
            return 'vmess://' + new_b64
            
        except Exception as e:
            logger.debug(f"Error rebuilding VMess: {e}")
            return original
    
    def _rebuild_vless(self, original: str, new_name: str) -> str:
        """Rebuild VLESS config with new name"""
        try:
            # Format: vless://uuid@host:port?params#name
            if '#' in original:
                base = original.split('#')[0]
            else:
                base = original
            
            # URL encode the name (important!)
            encoded_name = quote(new_name, safe='')
            
            return f"{base}#{encoded_name}"
            
        except Exception as e:
            logger.debug(f"Error rebuilding VLESS: {e}")
            return original
    
    def _rebuild_trojan(self, original: str, new_name: str) -> str:
        """Rebuild Trojan config with new name"""
        try:
            # Format: trojan://password@host:port?params#name
            if '#' in original:
                base = original.split('#')[0]
            else:
                base = original
            
            encoded_name = quote(new_name, safe='')
            return f"{base}#{encoded_name}"
            
        except Exception as e:
            logger.debug(f"Error rebuilding Trojan: {e}")
            return original
    
    def _rebuild_shadowsocks(self, original: str, new_name: str) -> str:
        """Rebuild Shadowsocks config with new name"""
        try:
            # Format: ss://base64(method:password)@host:port#name
            if '#' in original:
                base = original.split('#')[0]
            else:
                base = original
            
            encoded_name = quote(new_name, safe='')
            return f"{base}#{encoded_name}"
            
        except Exception as e:
            logger.debug(f"Error rebuilding SS: {e}")
            return original
    
    def _rebuild_ssr(self, original: str, new_name: str) -> str:
        """Rebuild SSR config with new name"""
        try:
            # SSR is complex, better to keep original for now
            # or implement full SSR encoding if needed
            return original
            
        except Exception as e:
            logger.debug(f"Error rebuilding SSR: {e}")
            return original
    
    def _rebuild_hysteria(self, original: str, new_name: str) -> str:
        """Rebuild Hysteria config with new name"""
        try:
            if '#' in original:
                base = original.split('#')[0]
            else:
                base = original
            
            encoded_name = quote(new_name, safe='')
            return f"{base}#{encoded_name}"
            
        except Exception as e:
            logger.debug(f"Error rebuilding Hysteria: {e}")
            return original
    
    def _rebuild_tuic(self, original: str, new_name: str) -> str:
        """Rebuild TUIC config with new name"""
        try:
            if '#' in original:
                base = original.split('#')[0]
            else:
                base = original
            
            encoded_name = quote(new_name, safe='')
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
                
        except Exception as e:
            logger.error(f"Error generating JSON: {e}")
    
    def _generate_txt(self, directory: str, filename: str, configs: List[Dict]):
        """Generate TXT output (one config per line)"""
        try:
            filepath = os.path.join(directory, filename)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                for config in configs:
                    # Use rebuilt config if available
                    config_str = config.get('rebuilt', config.get('original', ''))
                    f.write(config_str + '\n')
                    
        except Exception as e:
            logger.error(f"Error generating TXT: {e}")
    
    def _generate_subscription(self, directory: str, filename: str, configs: List[Dict]):
        """Generate subscription link (base64 encoded)"""
        try:
            filepath = os.path.join(directory, filename)
            
            # Join all configs (use rebuilt version)
            config_lines = []
            for config in configs:
                config_str = config.get('rebuilt', config.get('original', ''))
                if config_str:
                    config_lines.append(config_str)
            
            all_configs = '\n'.join(config_lines)
            
            # Encode to base64
            encoded = base64.b64encode(all_configs.encode('utf-8')).decode('utf-8')
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(encoded)
                
        except Exception as e:
            logger.error(f"Error generating subscription: {e}")
    
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
                
                # Iran section (Priority)
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
                
                # Germany section
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
                
                # Other countries
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
                
        except Exception as e:
            logger.error(f"Error generating README: {e}")
