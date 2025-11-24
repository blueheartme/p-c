"""
Generator module for creating output files
"""

import os
import json
import base64
import logging
import re
from typing import Dict, List
from datetime import datetime
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
            
            cleaned_configs = self._clean_config_names(configs, country)
            
            self._generate_json(country_dir, prefix + "configs.json", cleaned_configs)
            self._generate_txt(country_dir, prefix + "configs.txt", cleaned_configs)
            self._generate_subscription(country_dir, prefix + "subscription.txt", cleaned_configs)
            
            logger.info(f"Generated outputs for {country} ({'tested' if tested else 'all'})")
            
        except Exception as e:
            logger.error(f"Error generating country outputs: {e}")
    
    def _clean_config_names(self, configs: List[Dict], country: str) -> List[Dict]:
        """Clean config names and add flags/CDN info"""
        cleaned = []
        
        for idx, config in enumerate(configs, 1):
            try:
                flag = COUNTRY_FLAGS.get(country, "🌐")
                cdn = config.get('cdn', '')
                cdn_name = CDN_NAMES.get(cdn, '') if cdn else ''
                
                name = config.get('name', '')
                name = re.sub(r'@\w+', '', name)
                name = re.sub(r'\|\w+\|', '', name)
                name = re.sub(r'【.*?】', '', name)
                name = re.sub(r'\[.*?\]', '', name)
                name = name.strip()
                
                new_name = f"{flag} {country}"
                if cdn_name:
                    new_name += f" {cdn_name}"
                new_name += f" #{idx}"
                
                config['name'] = new_name
                cleaned.append(config)
                
            except Exception as e:
                logger.debug(f"Error cleaning config name: {e}")
                cleaned.append(config)
        
        return cleaned
    
    def _generate_json(self, directory: str, filename: str, configs: List[Dict]):
        """Generate JSON output"""
        try:
            filepath = os.path.join(directory, filename)
            
            output_data = {
                'updated': datetime.utcnow().isoformat(),
                'count': len(configs),
                'configs': configs
            }
            
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
                    f.write(config['original'] + '\n')
                    
        except Exception as e:
            logger.error(f"Error generating TXT: {e}")
    
    def _generate_subscription(self, directory: str, filename: str, configs: List[Dict]):
        """Generate subscription link (base64 encoded)"""
        try:
            filepath = os.path.join(directory, filename)
            
            all_configs = '\n'.join([config['original'] for config in configs])
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
                f.write("*🤖 Auto-updated every 4 hours via GitHub Actions*\n")
                
        except Exception as e:
            logger.error(f"Error generating README: {e}")
