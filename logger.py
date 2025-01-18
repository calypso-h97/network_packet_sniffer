import os
from datetime import datetime
import logging
import json
from colorama import Fore, Style
from logging.handlers import RotatingFileHandler

# Logs saving path
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

# JSON colored logger setup
class CustomJSONFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "time": datetime.now().isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
            "module": record.module,
        }
        return json.dumps(log_record, indent=4)
    
class ColorfulHandler(logging.StreamHandler):
    def emit(self, record):
        level_color = {
            "DEBUG": Fore.BLUE,
            "INFO": Fore.GREEN,
            "WARNING": Fore.YELLOW,
            "ERROR": Fore.RED,
            "CRITICAL": Fore.MAGENTA,
        }
        color = level_color.get(record.levelname, Fore.WHITE)
        msg = self.format(record)
        print(f"{color}{msg}{Style.RESET_ALL}")

# Logger configuring
logger = logging.getLogger("security_logger")
logger.setLevel(logging.DEBUG)

# Consol logger handler
console_handler = ColorfulHandler()
console_handler.setLevel(logging.DEBUG)
console_handler.setFormatter(CustomJSONFormatter())

# File handler
file_handler = RotatingFileHandler(
    os.path.join(LOG_DIR, "security.log"), maxBytes=5 * 1024 * 1024, backupCount=3
)
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(CustomJSONFormatter())

logger.addHandler(console_handler)
logger.addHandler(file_handler)

