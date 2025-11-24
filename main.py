"""
Main script for collecting, filtering, testing and generating proxy configs
"""

import logging
from src.collector import ConfigCollector
from src.parser import ConfigParser
from src.filter import ConfigFilter
from src.tester import ConnectionTester
from src.generator import OutputGenerator
from src.config import TEST_COUNTRIES

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def main():
    """Main execution function"""
    try:
        logger.info("=" * 60)
        logger.info("🚀 Starting Proxy Config Collector")
        logger.info("=" * 60)
        
        # STEP 1: Collect configs
        logger.info("\n[STEP 1/6] 📡 Collecting configs from all sources...")
        collector = ConfigCollector()
        raw_configs = collector.collect_all()
        logger.info(f"✅ Collected {len(raw_configs)} raw configs")
        
        if not raw_configs:
            logger.warning("⚠️  No configs collected! Exiting...")
            return
        
        # STEP 2: Parse configs
        logger.info("\n[STEP 2/6] 🔍 Parsing configs...")
        parser = ConfigParser()
        parsed_configs = []
        
        for config in raw_configs:
            try:
                parsed = parser.parse_config(config)
                if parsed:
                    parsed_configs.append(parsed)
            except Exception as e:
                logger.debug(f"Error parsing config: {e}")
                continue
        
        logger.info(f"✅ Successfully parsed {len(parsed_configs)} configs")
        
        if not parsed_configs:
            logger.warning("⚠️  No configs parsed successfully! Exiting...")
            return
        
        # STEP 3: Filter and categorize
        logger.info("\n[STEP 3/6] 🌍 Filtering and categorizing by country...")
        filter_obj = ConfigFilter()
        categorized = filter_obj.filter_and_categorize(parsed_configs)
        
        for country in categorized:
            categorized[country] = filter_obj.remove_duplicates(categorized[country])
        
        logger.info(f"✅ Categorized into {len(categorized)} countries")
        
        # STEP 4: Test configs for specific countries
        logger.info("\n[STEP 4/6] 🧪 Testing configs for Iran and Germany...")
        tester = ConnectionTester()
        tested_configs = {}
        
        for country in TEST_COUNTRIES:
            if country in categorized:
                logger.info(f"Testing {len(categorized[country])} configs for {country}...")
                tested = tester.test_configs(categorized[country])
                if tested:
                    tested_configs[country] = tested
                    logger.info(f"✅ Found {len(tested)} working configs for {country}")
        
        # STEP 5: Generate outputs
        logger.info("\n[STEP 5/6] 📝 Generating output files...")
        generator = OutputGenerator()
        generator.generate_all_outputs(categorized, tested_configs)
        
        # STEP 6: Summary
        logger.info("\n[STEP 6/6] 📊 Summary")
        logger.info("=" * 60)
        total = sum(len(configs) for configs in categorized.values())
        total_tested = sum(len(configs) for configs in tested_configs.values())
        logger.info(f"📦 Total configs: {total}")
        logger.info(f"✅ Tested & working: {total_tested}")
        logger.info(f"🌍 Countries found: {len(categorized)}")
        
        for country, configs in sorted(categorized.items()):
            from src.config import COUNTRY_FLAGS
            flag = COUNTRY_FLAGS.get(country, "🌐")
            logger.info(f"  {flag} {country}: {len(configs)} configs")
        
        logger.info("=" * 60)
        logger.info("✅ Process completed successfully!")
        logger.info("=" * 60)
        
    except Exception as e:
        logger.error(f"❌ Fatal error in main: {e}", exc_info=True)
        raise


if __name__ == "__main__":
    main()
