"""
日志模块
"""

import logging
import sys

_LOGGERS = {}
_DEBUG = False


def set_debug(debug: bool):
    """启用或禁用调试模式"""
    global _DEBUG, _LOGGERS
    _DEBUG = debug

    # Reset loggers to apply new debug setting
    _LOGGERS = {}


def get_logger(name:str):
    """获取日志记录器"""
    global _LOGGERS

    logger = _LOGGERS.get(name)
    if logger is None:
        logger = logging.getLogger(name)
        _LOGGERS[name] = logger

    level = logging.DEBUG if _DEBUG else logging.INFO
    logger.setLevel(level)

    # Remove existing handlers
    logger.handlers = []

    # Create console handler
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(level)

    # Create formatter
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)

    # Add handler to logger
    logger.addHandler(handler)

    # Prevent propagation to root logger
    logger.propagate = False

    return logger
