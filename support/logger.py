
import logging;

class logger_formatter(logging.Formatter):
    log_format = {
        logging.DEBUG: "\033[0m" + "%(asctime)s - %(levelname)s - %(message)s" + "\033[0m",
        logging.INFO: "\033[0;32m" + "%(asctime)s - %(levelname)s - %(message)s" + "\033[0m",
        logging.WARNING: "\033[0;33m" + "%(asctime)s - %(levelname)s - %(message)s" + "\033[0m",
        logging.ERROR: "\033[0;36m" + "%(asctime)s - %(levelname)s - %(message)s" + "\033[0m",
        logging.CRITICAL: "\033[0;31m" + "%(asctime)s - %(levelname)s - %(message)s" + "\033[0m"
    };

    def format(self, record):
        formatter = logging.Formatter(self.log_format.get(record.levelno));
        return formatter.format(record);

logger = logging.getLogger("logger");
logger_stream_handler = logging.StreamHandler();
logger_stream_handler.setFormatter(logger_formatter());
logger.addHandler(logger_stream_handler);
logger.setLevel(logging.DEBUG);
