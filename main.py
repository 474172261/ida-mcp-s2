"""
IDA MCP Server 主入口
使用 FastMCP 和 HTTP transport
"""

import argparse
import sys
import signal
import os
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from ida_mcp_s2.server import init_server, run_server, stop_server
from ida_mcp_s2.logger import set_debug, get_logger


def signal_handler(signum, frame):
    """Handle Ctrl+C signal"""
    logger = get_logger()
    logger.info("Received interrupt signal, shutting down...")
    stop_server()
    sys.exit(0)


def main():
    parser = argparse.ArgumentParser(description="IDA MCP Server")
    parser.add_argument(
        "--host", default="0.0.0.0", help="Server host (default: 0.0.0.0)"
    )
    parser.add_argument(
        "--port", type=int, default=8080, help="Server port (default: 8080)"
    )
    parser.add_argument(
        "--db-dir", required=True, help="Directory containing IDA database files"
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument(
        "--ida-path", default=None, help="Path to IDA installation directory"
    )

    args = parser.parse_args()

    # Setup logging
    if args.debug:
        set_debug(True)

    logger = get_logger()

    # Validate database directory
    db_dir = Path(args.db_dir)
    if not db_dir.exists():
        logger.error(f"Database directory does not exist: {args.db_dir}")
        sys.exit(1)

    if not db_dir.is_dir():
        logger.error(f"Database path is not a directory: {args.db_dir}")
        sys.exit(1)

    # Set IDA path if provided
    if args.ida_path:
        os.environ["IDA_PATH"] = args.ida_path

    # Initialize server with database directory
    init_server(args.db_dir)

    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        run_server(host=args.host, port=args.port)
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
