"""
日志模块
"""

import logging
import sys

_LOGGER = None
_DEBUG = False


def set_debug(debug: bool):
    """启用或禁用调试模式"""
    global _DEBUG, _LOGGER
    _DEBUG = debug

    # Reset logger to apply new debug setting
    _LOGGER = None


def get_logger():
    """获取日志记录器"""
    global _LOGGER

    if _LOGGER is None:
        _LOGGER = logging.getLogger("ida_mcp_s1")
        _LOGGER.setLevel(logging.DEBUG if _DEBUG else logging.INFO)

        # Remove existing handlers
        _LOGGER.handlers = []

        # Create console handler
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(logging.DEBUG if _DEBUG else logging.INFO)

        # Create formatter
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)

        # Add handler to logger
        _LOGGER.addHandler(handler)

        # Prevent propagation to root logger
        _LOGGER.propagate = False

    return _LOGGER
