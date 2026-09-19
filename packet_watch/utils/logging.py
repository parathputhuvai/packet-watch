from __future__ import annotations

import logging


def setup_logging(level: str = "INFO") -> logging.Logger:
    logger = logging.getLogger("packet_watch")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s"))
        logger.addHandler(handler)
    return logger
