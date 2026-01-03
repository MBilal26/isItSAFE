import os
import logging
from datetime import datetime

# Setup logging directory
LOG_DIR = os.path.join(os.getcwd(), "logs")
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

# Configure logging
LOG_FILE = os.path.join(LOG_DIR, "isItSafe.log")

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(name)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def log_event(module_name, message, level="info"):
    """
    Unified logging function for the isItSafe project.
    
    :param module_name: Name of the module triggering the event (e.g., 'WiFi_Scanner')
    :param message: The event message to log
    :param level: Severity level ('info', 'warning', 'error', 'critical')
    """
    logger = logging.getLogger(module_name)
    level = level.lower()
    
    if level == "info":
        logger.info(message)
    elif level == "warning":
        logger.warning(message)
    elif level == "error":
        logger.error(message)
    elif level == "critical":
        logger.critical(message)
    else:
        logger.info(message)

# Initial log for system startup
if __name__ == "__main__":
    log_event("System", "Logger module initialized directly.")
