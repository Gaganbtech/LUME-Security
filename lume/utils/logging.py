"""Logging utilities for LUME."""

import logging
import os
import sys
from typing import Optional

_LOGGER_INITIALIZED = False


def setup_logger(name: str = "lume", level: Optional[str] = None) -> logging.Logger:
    """Configure and return a structured logger for LUME.

    Args:
        name: Logger name.
        level: Optional log level string (DEBUG, INFO, WARNING, ERROR).
    """
    global _LOGGER_INITIALIZED

    logger = logging.getLogger(name)

    if not _LOGGER_INITIALIZED:
        log_level_str = level or os.getenv("LUME_LOG_LEVEL", "INFO").upper()
        log_level = getattr(logging, log_level_str, logging.INFO)
        logger.setLevel(log_level)

        handler = logging.StreamHandler(sys.stderr)
        formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] [%(name)s]: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.propagate = False
        _LOGGER_INITIALIZED = True

    return logger


logger = setup_logger()
