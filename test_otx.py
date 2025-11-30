"""Quick OTX test with a clean IP."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from utils.logger import setup_logging, get_logger
from services.otx_client import OTXClient

setup_logging(log_level="INFO")
logger = get_logger(__name__)

TEST_IP = "1.1.1.1"  # Cloudflare DNS - should be clean

logger.info("=" * 80)
logger.info(f"Testing OTX API with IP: {TEST_IP}")
logger.info("=" * 80)

try:
    otx_client = OTXClient()
    logger.info("OTX client initialized successfully")

    response = otx_client.get_ip_reputation(TEST_IP)

    logger.info("\n✅ OTX API Response:")
    logger.info(f"  IP: {response.get('ip_address')}")
    logger.info(f"  Pulse Count: {response.get('pulse_count')}")
    logger.info(f"  Reputation: {response.get('reputation')}")

    general = response.get('general', {})
    logger.info(f"\n  General Data Keys: {list(general.keys())}")

except Exception as e:
    logger.error(f"\n❌ OTX API Test Failed: {e}", exc_info=True)
    sys.exit(1)

logger.info("\n" + "=" * 80)
logger.info("✅ OTX API is working!")
logger.info("=" * 80)
