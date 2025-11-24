# Configuration file for proxy collector

import os

# ==================== SOURCES CONFIGURATION ====================

TELEGRAM_CHANNELS = [
    "https://t.me/s/v2ray_config_pool",
    "https://t.me/s/PrivateVPNs",
    "https://t.me/s/DirectVPN",
    "https://t.me/s/V2rayNGn",
    "https://t.me/s/free4allVPN",
    "https://t.me/s/vpn_ioss",
    "https://t.me/s/ShadowSocks_s",
    "https://t.me/s/azadi_az_inja_migzare",
    "https://t.me/s/WomanLifeFreedomVPN",
    "https://t.me/s/Outline_Vpn",
    # Add your channels here
]

GITHUB_REPOS = [
    "yebekhe/TelegramV2rayCollector",
    "mfuu/v2ray",
    "aiboboxx/v2rayfree",
    "peasoft/NoMoreWalls",
    "mahdibland/V2RayAggregator",
    "Barry-far/V2ray-Configs",
    "coldwater-10/V2rayCollector",
    # Add your repos here
]

PUBLIC_APIS = [
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/mix",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
    "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2",
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
    # Add your APIs here
]

WEB_SCRAPE_URLS = []

# ==================== IRANIAN CDN CONFIGURATION ====================

ARVAN_CLOUD_RANGES = [
    "185.143.232.0/22",
    "188.114.96.0/20",
    "5.213.255.0/24",
]

DERAK_CLOUD_RANGES = [
    "151.243.0.0/16",
]

IRANIAN_ASNS = {
    "AS44244": "Irancell",
    "AS197207": "MCI", 
    "AS57218": "Rightel",
    "AS31549": "Shatel",
    "AS207994": "ArvanCloud",
    "AS60976": "DerakCloud",
    "AS49666": "ParsOnline",
    "AS41689": "AsiaNet",
    "AS48434": "FaraPik",
}

# ==================== COUNTRY FILTERS ====================

TEST_COUNTRIES = ["IR", "DE"]
PRIORITY_COUNTRY = "IR"

# ==================== OUTPUT CONFIGURATION ====================

OUTPUT_DIR = "output"
IRAN_DIR = os.path.join(OUTPUT_DIR, "iran")
GERMANY_DIR = os.path.join(OUTPUT_DIR, "germany")
OTHERS_DIR = os.path.join(OUTPUT_DIR, "others")
TESTED_DIR = os.path.join(OUTPUT_DIR, "tested")

# ==================== UPDATE CONFIGURATION ====================

UPDATE_INTERVAL_HOURS = 4
CONNECTION_TIMEOUT = 10
MAX_WORKERS = 20

# ==================== GITHUB CONFIGURATION ====================

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
REPO_NAME = os.getenv("GITHUB_REPOSITORY", "")

# ==================== COUNTRY FLAGS ====================

COUNTRY_FLAGS = {
    "IR": "🇮🇷", "DE": "🇩🇪", "US": "🇺🇸", "GB": "🇬🇧",
    "FR": "🇫🇷", "NL": "🇳🇱", "CA": "🇨🇦", "SG": "🇸🇬",
    "JP": "🇯🇵", "KR": "🇰🇷", "HK": "🇭🇰", "TW": "🇹🇼",
    "AU": "🇦🇺", "IN": "🇮🇳", "RU": "🇷🇺", "TR": "🇹🇷",
    "AE": "🇦🇪", "SE": "🇸🇪", "FI": "🇫🇮", "PL": "🇵🇱",
    "UA": "🇺🇦", "BR": "🇧🇷", "AR": "🇦🇷", "MX": "🇲🇽",
    "ZA": "🇿🇦", "EG": "🇪🇬", "CH": "🇨🇭", "AT": "🇦🇹",
}

CDN_NAMES = {
    "arvancloud": "☁️ArvanCloud",
    "derakcloud": "☁️DerakCloud",
    "cloudflare": "☁️Cloudflare",
    "asiatech": "☁️AsiaTech",
    "farapik": "☁️FaraPik",
}
