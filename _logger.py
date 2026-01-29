import logging
import sys
import time
from typing import Optional

try:
    import colorama

    colorama.init()  # Windows support
except ImportError:
    colorama = None


class SelectiveColoredFormatter(logging.Formatter):
    if colorama:
        grey = colorama.Fore.LIGHTBLACK_EX
        blue = colorama.Fore.BLUE
        green = colorama.Fore.GREEN
        yellow = colorama.Fore.YELLOW
        red = colorama.Fore.RED
        bold_red = colorama.Fore.RED + colorama.Style.BRIGHT
        white = colorama.Fore.WHITE
        reset = colorama.Style.RESET_ALL
    else:
        grey = "\x1b[90m"
        blue = "\x1b[34m"
        green = "\x1b[32m"
        yellow = "\x1b[33m"
        red = "\x1b[31m"
        bold_red = "\x1b[31;1m"
        white = "\x1b[37m"
        reset = "\x1b[0m"
    LEVEL_COLORS = {
        logging.DEBUG: grey,
        logging.INFO: blue,
        logging.WARNING: yellow,
        logging.ERROR: red,
        logging.CRITICAL: bold_red,
    }

    def formatTime(self, record, datefmt: Optional[str] = None):
        ct = self.converter(record.created)
        if datefmt:
            if "%f" in datefmt:
                s = time.strftime(datefmt.replace("%f", ""), ct)
                ms = f"{record.msecs:03.0f}"
                return s.replace("%f", ms)
            return time.strftime(datefmt, ct)
        else:
            t = time.strftime("%Y-%m-%d %H:%M:%S", ct)
            return f"{t},{record.msecs:03.0f}"

    def format(self, record):
        timestamp = f"{self.grey}{self.formatTime(record, '%Y-%m-%d %H:%M:%S')}{self.reset}"
        level_color = self.LEVEL_COLORS.get(record.levelno, self.white)

        # Center-align the level name in 8 characters, then apply color
        levelname_centered = record.levelname.center(8)
        levelname = f"{level_color}{levelname_centered}{self.reset}"

        location = f"{self.grey}{record.filename}:{record.lineno}{self.reset}"
        message = f"{self.white}{record.getMessage()}{self.reset}"
        return f"{timestamp} | {levelname} | {location} | {message}"


def setup_logger(name: str = "am", level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(level)
    # logger.propagate = False  # Prevent propagation to root logger

    # If handlers already exist, do not add duplicates
    if logger.handlers:
        return logger

    # Console handler (INFO+ with colors)
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(level)
    console_handler.setFormatter(SelectiveColoredFormatter())
    logger.addHandler(console_handler)

    # File handler (all levels, clear on each run)
    file_handler = logging.FileHandler("logs.log", mode="a", encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(filename)s:%(lineno)d | %(message)s")
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)

    return logger


logger = setup_logger(__name__)
