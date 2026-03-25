"""
IDA MCP Server 实现
使用 FastMCP 和 HTTP transport
"""

import idapro
import ida_auto
import ida_undo
import json
import socket
import struct
import threading
import time
import uuid
from typing import Dict, List, Optional, Any, Optional, Union, Annotated
from pathlib import Path
import multiprocessing
import sys
import os
import logging

from mcp.server.fastmcp import FastMCP
from ida_mcp_s2.logger import get_logger, set_debug

# Initialize FastMCP server
mcp = FastMCP("ida-mcp-s1")

# Global session management
sessions: Dict[str, "IDASession"] = {}
session_lock = threading.Lock()
db_dir: Path = Path(".")
g_persist_changes = False
g_id_nums = 0

def get_session_id():
    global g_id_nums
    g_id_nums += 1
    return 'sid_{:04x}'.format(g_id_nums)


class IDASession:
    """
    IDA会话
    管理一个IDALib工作进程
    """

    def __init__(self, session_id: str, db_path: str):
        global g_persist_changes
        self.session_id = session_id
        self.db_path = db_path
        self.logger = get_logger()
        self.persist_changes = g_persist_changes
        self.parent_sock = None
        self.process = None
        self._start_worker()

    def _start_worker(self):
        """Start the worker process"""
        self.parent_sock, self.child_sock = socket.socketpair()

        self.process = multiprocessing.Process(
            target=_ida_worker,
            args=(
                self.child_sock,
                self.db_path,
                self.persist_changes,
                self.session_id,
                self.logger.level,
            ),
        )
        self.process.start()

        self.child_sock.close()

        self.logger.info(f"Started IDA worker process for session {self.session_id}")

    def call(self, method: str, params: Dict) -> Dict:
        """调用IDA工作进程"""
        request = {"method": method, "params": params}
        self._send_message(self.parent_sock, request)
        response_data = self._recv_message(self.parent_sock)
        return response_data

    def close(self, save: Optional[bool] = None):
        """关闭会话

        Args:
            save: 可选参数，指定是否保存变更。如果提供，会覆盖 worker 启动时的默认设置
        """
        self.logger.info(f"Try to close session {self.session_id}")

        try:
            message = {"method": "shutdown"}
            if save is not None:
                message["params"] = {"save": save}
            self._send_message(self.parent_sock, message)
        except:
            pass

        self.process.join(timeout=10)

        if self.process.is_alive():
            self.logger.warning(
                f"Process for session {self.session_id} did not exit gracefully, terminating..."
            )
            self.process.terminate()
            self.process.join(timeout=5)

        self.parent_sock.close()

        self.logger.info(f"Closed session {self.session_id}")

    def reload(self, save_changes: bool = False):
        """重新载入 IDA worker 进程，保持 session_id 不变

        Args:
            save_changes: 重载前是否保存当前的数据库修改
        """
        self.close(save=save_changes)
        self._start_worker()

    def _send_message(self, sock: socket.socket, data: dict):
        """发送消息（带长度前缀）"""
        encoded = json.dumps(data).encode("utf-8")
        length = len(encoded)
        sock.sendall(struct.pack("!I", length))
        sock.sendall(encoded)

    def _recv_message(self, sock: socket.socket) -> dict:
        """接收消息（带长度前缀）"""
        length_bytes = self._recv_all(sock, 4)
        length = struct.unpack("!I", length_bytes)[0]
        data_bytes = self._recv_all(sock, length)
        return json.loads(data_bytes.decode("utf-8"))

    def _recv_all(self, sock: socket.socket, n: int) -> bytes:
        """接收指定长度的数据"""
        data = bytearray()
        while len(data) < n:
            packet = sock.recv(n - len(data))
            if not packet:
                raise ConnectionError("Socket closed unexpectedly")
            data.extend(packet)
        return bytes(data)


def _ida_worker(
    rpc_sock: socket.socket,
    db_path: str,
    persist_changes: bool,
    session_id: str,
    log_level: bool,
):
    """
    IDA工作进程
    在每个进程中只能打开一个IDA数据库
    """
    logger = get_logger()
    logger.setLevel(log_level)
    logger.info(f"IDA worker started for database: {db_path}")
    logger.info(f"Worker PID: {os.getpid()}, Session: {session_id[:8]}")

    try:
        logger.info(f"Opening database: {db_path}")
        idapro.open_database(db_path, True)

        if not persist_changes:
            if ida_undo.create_undo_point(b"Initial state, auto analysis"):
                logger.info(f"Successfully created an undo point...")
            else:
                logger.info(f"Failed to created an undo point...")

        ida_auto.auto_wait()
        logger.info("Database loaded and auto-analysis complete")

        from ida_mcp_s2.ida_functions import IDAFunctions

        ida_funcs = IDAFunctions()

        while True:
            try:
                length_bytes = rpc_sock.recv(4)
                if not length_bytes:
                    break

                length = struct.unpack("!I", length_bytes)[0]
                data_bytes = bytearray()
                while len(data_bytes) < length:
                    chunk = rpc_sock.recv(length - len(data_bytes))
                    if not chunk:
                        break
                    data_bytes.extend(chunk)

                request = json.loads(bytes(data_bytes).decode("utf-8"))
                method = request.get("method")
                params = request.get("params", {})

                if method == "shutdown":
                    save = params.get("save")
                    if save is not None:
                        persist_changes = save
                    logger.info(f"Received shutdown command (save={persist_changes})")
                    break

                handler = getattr(ida_funcs, method, None)
                if handler:
                    try:
                        result = handler(params)
                        response = {"success": True, "data": result}
                    except Exception as e:
                        import traceback
                        error_info = traceback.format_exc()
                        logger.error(f"Error in {method}: {error_info}")
                        response = {"success": False, "error": str(e)}
                else:
                    response = {"success": False, "error": f"Unknown method: {method}"}

                response_bytes = json.dumps(response).encode("utf-8")
                rpc_sock.sendall(struct.pack("!I", len(response_bytes)))
                rpc_sock.sendall(response_bytes)

            except Exception as e:
                logger.error(f"Error in worker loop: {e}")
                break

        if not persist_changes:
            if ida_undo.perform_undo():
                logger.info("Successfully reverted database changes...")
            else:
                logger.error("Failed to revert database changes...")

        logger.info("Closing database")
        idapro.close_database()

    except ImportError as e:
        logger.error(f"Failed to import IDA modules: {e}")
        logger.error("Make sure this script is run from within IDA environment")
    except Exception as e:
        import traceback
        error_info = traceback.format_exc()
        logger.error(error_info)
    finally:
        rpc_sock.close()
        logger.info("IDA worker terminated")


# Helper functions for session management
def _get_session(session_id: str) -> Optional[IDASession]:
    """获取会话"""
    with session_lock:
        return sessions.get(session_id)


def _call_ida_method(session_id: str, method: str, params: List) -> Any:
    """调用IDA方法"""
    if not session_id:
        return {"error": "Session ID is required"}

    session = _get_session(session_id)
    if not session:
        return {"error": "Session not found"}

    logger = get_logger()
    logger.debug("call ida function: " + method + " " + str(params))
    result = session.call(method, params)
    if result.get("success"):
        logger.debug("call ida function result: " + str(result.get("data")))
        return result.get("data")
    else:
        raise ValueError(result.get("error", "Unknown error"))


# MCP Tools - Database Management
@mcp.tool()
def list_sessions() -> Dict[str, Any]:
    """List all active IDA database sessions"""
    with session_lock:
        session_list = {}
        for session_id, session in sessions.items():
            session_list[session_id] = {
                "database": Path(session.db_path).name,
            }
        return {"sessions": session_list}


@mcp.tool()
def list_databases() -> Dict[str, Any]:
    """List available IDA database files"""
    databases = {}
    for ext in [".idb", ".i64"]:
        for db_file in db_dir.glob(f"*{ext}"):
            databases[db_file.name] = {
                "size": db_file.stat().st_size,
                "modified": db_file.stat().st_mtime,
            }
    return {"databases": databases}


@mcp.tool()
def open_database(name: str) -> Dict[str, Any]:
    """Open an IDA database

    Args:
        name: Database file name (with or without extension)
    """
    logger = get_logger()

    # Security: validate database name (no path traversal)
    if "/" in name or "\\" in name or ".." in name:
        raise ValueError("Invalid database name")

    with session_lock:
        for session_id, session in sessions.items():
            if Path(session.db_path).name == name:
                logger.info(f"already opened {name}")
                return  {
                    "session_id": session_id,
                    "database": Path(session.db_path).name,
                    "path": session.db_path,
                }

    # Check if database exists
    db_path = db_dir / name
    if not db_path.exists():
        # Try with .idb or .i64 extension
        for ext in [".idb", ".i64"]:
            alt_path = db_dir / (name + ext)
            if alt_path.exists():
                db_path = alt_path
                break

    if not db_path.exists():
        raise ValueError(f"Database not found: {name}")

    # Create new session
    session_id = get_session_id()
    try:
        session = IDASession(session_id, str(db_path))
        with session_lock:
            sessions[session_id] = session

        return {
            "session_id": session_id,
            "database": str(db_path.name),
            "path": str(db_path),
        }
    except Exception as e:
        raise ValueError(f"Failed to open database: {e}")


@mcp.tool()
def close_database(session_id: str, save_changes: bool = False) -> Dict[str, Any]:
    """Close an IDA database session

    Args:
        session_id: The session ID returned by open_database
        save_changes: 是否在关闭前保存数据库修改（默认 False）
    """
    session = _get_session(session_id)
    if not session:
        raise ValueError("Session not found")

    with session_lock:
        if session_id in sessions:
            del sessions[session_id]

    session.close(save=save_changes)
    return {"closed": True}


@mcp.tool()
def reload_database(session_id: str, save_changes: bool = False) -> Dict[str, Any]:
    """重新载入 IDA worker 进程，保持 session_id 不变

    Args:
        session_id: 会话 ID
        save_changes: 重载前是否保存当前的数据库修改
    """
    session = _get_session(session_id)
    if not session:
        raise ValueError("未找到会话")

    session.reload(save_changes)
    return {"reloaded": True, "session_id": session_id}


@mcp.tool()
def list_funcs(session_id: str, queries: Optional[List[Tuple[int, int, str]]] = None) -> Dict[str, Any]:
    """List functions in the database

    Args:
        session_id: The session ID
        queries: 可选项, List of Tuple(offset,limit,regex)
            offset: int, 分页偏移
            limit: int, 返回结果限制. 0表示无限制
            regex: str, 正则表达式筛选函数结果
    """
    if queries is None:
        queries = [(0,0,'')]
    return _call_ida_method(session_id, "list_funcs", queries)


@mcp.tool()
def get_func_by_addr(session_id: str, queries: List[str]) -> Dict[str, Any]:
    """Look up functions by name or address

    Args:
        session_id: The session ID
        queries: List of function names or addresses to look up, include regex
    """
    return _call_ida_method(session_id, "get_func_by_addr", queries)


@mcp.tool()
def decompile(session_id: str, addr: str, offset: int = 0, limit: int = 0) -> Dict:
    """Decompile a function

    Args:
        session_id: The session ID
        addr: Function address or name
        offset: Start offset for pagination
        limit: Maximum number of results
    """
    result = _call_ida_method(session_id, "decompile", [addr, offset, limit])
    return result.get("result", "")


@mcp.tool()
def disasm(session_id: str, addr: str, offset: int = 0, limit: int = 0) -> Dict:
    """Disassemble a function

    Args:
        session_id: The session ID
        addr: Function address or name
        offset: Start offset for pagination
        limit: Maximum number of results
    """
    result = _call_ida_method(session_id, "disasm", [addr, offset, limit])
    return result.get("result", "")


# MCP Tools - Cross References and Call Graph


@mcp.tool()
def xrefs_to_addr(session_id: str, addrs: List[str]) -> Dict[str, Any]:
    """Get cross references to addresses

    Args:
        session_id: The session ID
        addrs: List of addresses to find references to. eg: Data address/name, code address, func name/address.
    """
    return _call_ida_method(session_id, "xrefs_to_addr", addrs)


@mcp.tool()
def xrefs_to_field(session_id: str, queries: List[Dict[str, str]]) -> Dict[str, Any]:
    """Get cross references to structure fields

    Args:
        session_id: The session ID
        queries: List of {struct: str, field: str} dictionaries
    """
    return _call_ida_method(session_id, "xrefs_to_field", queries)


@mcp.tool()
def callees(session_id: str, addrs: List[str]) -> Dict[str, Any]:
    """Get functions called by the specified functions

    Args:
        session_id: The session ID
        addrs: List of function addresses
    """
    return _call_ida_method(session_id, "callees", addrs)


# MCP Tools - Data Reading


@mcp.tool()
def get_bytes(session_id: str, addrs: List[str]) -> Dict[str, Any]:
    """Read bytes at addresses

    Args:
        session_id: The session ID
        addrs: List of addresses to read from
    """
    return _call_ida_method(session_id, "get_bytes", addrs)


@mcp.tool()
def get_int(session_id: str, queries: List[Dict[str, str]]) -> Dict[str, Any]:
    """Read integers at addresses

    Args:
        session_id: The session ID
        queries: List of {addr: str, type: str} dictionaries
                type can be: i8, u8, i16le, u16le, i16be, u16be, i32le, u32le, i32be, u32be, i64le, u64le, i64be, u64be
    """
    return _call_ida_method(session_id, "get_int", queries)


@mcp.tool()
def read_string(session_id: str, addrs: List[str]) -> Dict[str, Any]:
    """Read strings at addresses

    Args:
        session_id: The session ID
        addrs: List of addresses to read from
    """
    return _call_ida_method(session_id, "read_string", addrs)


# MCP Tools - Globals and Imports

@mcp.tool()
def search_in_strings_window(session_id: str, pattern: str, offset: int = 0, limit: int = 10)-> Dict:
    """ search strings with pattern
    
    Args:
        pattern: regex
        offset : Start offset for pagination
        limit: Maximum number of results
    """
    return _call_ida_method(session_id, "search_in_strings_window", [pattern, offset, limit])


@mcp.tool()
def list_globals(
    session_id: str, offset: int = 0, limit: int = 10, contain: Optional[str] = "*"
) -> Dict[str, Any]:
    """List global variables

    Args:
        session_id: The session ID
        offset: Start offset for pagination
        limit: Maximum number of results
        contain: contain globals by name substring. Optional
    """
    return _call_ida_method(session_id, "list_globals", [offset, limit, contain])


@mcp.tool()
def get_global_value(session_id: str, queries: List[str]) -> Dict[str, Any]:
    """Get values of global variables

    Args:
        session_id: The session ID
        queries: List of global variable names or addresses
    """
    return _call_ida_method(session_id, "get_global_value", queries)


@mcp.tool()
def list_imports(session_id: str, offset: int = 0, limit: int = 10, contain: Optional[str] = "*") -> Dict[str, Any]:
    """List imported symbols

    Args:
        session_id: The session ID
        offset: Start offset for pagination
        limit: Maximum number of results
        contain: contain globals by name substring. Optional
    """
    return _call_ida_method(session_id, "list_imports", [offset, limit, contain])


# MCP Tools - Stack Frame Operations


@mcp.tool()
def stack_frame(session_id: str, addrs: List[str]) -> Dict[str, Any]:
    """Get stack frame information for functions

    Args:
        session_id: The session ID
        addrs: List of function addresses
    """
    return _call_ida_method(session_id, "stack_frame", addrs)


@mcp.tool()
def declare_stack_variable(
    session_id: str, items: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """Declare stack variables

    Args:
        session_id: The session ID
        items: List of {ea: str/int, offset: str/int, name: str, type: str}
    """
    return _call_ida_method(session_id, "declare_stack_variable", items)


@mcp.tool()
def delete_stack_variable(
    session_id: str, items: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """Delete stack variables

    Args:
        session_id: The session ID
        items: List of {ea: str/int, name: str}
    """
    return _call_ida_method(session_id, "delete_stack_variable", items)


# MCP Tools - Structure Operations


@mcp.tool()
def read_struct_define(session_id: str, queries: List[str]) -> Dict[str, Any]:
    """Read structure definitions

    Args:
        session_id: The session ID
        queries: List of structure names
    """
    return _call_ida_method(session_id, "read_struct_define", queries)


@mcp.tool()
def search_structs(session_id: str, pattern_str: str, ignore_case: bool = True) -> Dict[str, Any]:
    """Search structures by name pattern

    Args:
        session_id: The session ID
        pattern_str: Regex pattern to match structure names
        ignore_case: true or false
    """
    return _call_ida_method(session_id, "search_structs", [pattern_str, ignore_case])


@mcp.tool()
def create_struct_from_c(session_id: str, declarations: List[str], is_update: bool = False) -> Dict[str, Any]:
    """Create structures from C declarations

    Args:
        session_id: The session ID
        declarations: List of C structure declarations
        is_update: if set True, override existing structs
    """
    return _call_ida_method(
        session_id, "create_struct_from_c", [declarations, is_update]
    )


# MCP Tools - Comments


@mcp.tool()
def set_comments_at_disassembly(
    session_id: str, items: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """Set comments at disassembly addresses

    Args:
        session_id: The session ID
        items: List of {ea: str/int, text: str, repeatable: bool}
    """
    return _call_ida_method(session_id, "set_comments_at_disassembly", items)


@mcp.tool()
def add_pseudocode_comment(
    session_id: str, params: List[Dict]
) -> Dict[str, Any]:
    """Add comment to pseudocode

    Args:
        session_id: The session ID
        params: ['ea':xx,'text':xx,'flag':block or semi]
            ea: Address in the function
            text: Comment text
            flag: Comment type ('block' or 'semi', use 'block' unless user specific)
    """
    return _call_ida_method(
        session_id, "add_pseudocode_comment", params
    )


# MCP Tools - Type Operations


@mcp.tool()
def set_lvar_type(
    session_id: str, items: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """Set local variable type in pseudocode

    Args:
        session_id: The session ID
        items: List of dict, [{'ea':str/int, 'var_name':str, 'struct_type':str, 'new_name':str}];
            ea: str/int, function address or name;
            var_name: str, variable name inside function;
            struct_type: str, "structure type to variable";
            new_name: str, this is optianl. the new name of variable
    """
    return _call_ida_method(session_id, "set_lvar_type", items)


# MCP Tools - Code Definition


@mcp.tool()
def define_func(session_id: str, items: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Define functions

    Args:
        session_id: The session ID
        items: List of {addr: str/int, name: str}
    """
    return _call_ida_method(session_id, "define_func", items)


@mcp.tool()
def define_code(session_id: str, items: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Define code at addresses

    Args:
        session_id: The session ID
        items: List of {addr: str/int}
    """
    return _call_ida_method(session_id, "define_code", items)


@mcp.tool()
def undefine(session_id: str, items: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Undefine functions or data at addresses

    Args:
        session_id: The session ID
        items: List of {addr: str/int}
    """
    return _call_ida_method(session_id, "undefine", items)

@mcp.tool()
def find_bytes(session_id: str, patterns:Union[list[str], str], offset:int = 0, limit: int = 1000):
    """Search for byte patterns in the binary (supports wildcards with ??)
        patterns: Byte patterns to search for (e.g. '48 8B ?? ??')
        offset: Skip first N matches (default: 0)
        limit: Max matches per pattern (default: 1000, max: 10000)
    """
    return _call_ida_method(session_id, "find_bytes", [patterns, offset, limit])

@mcp.tool()
def py_eval(session_id: str, code: str) -> Dict[str, Any]:
    """Execute Python code in IDA context

    Args:
        session_id: The session ID
        code: Python code to execute
    """
    return _call_ida_method(session_id, "py_eval", code)
                             
# Server lifecycle functions
def init_server(database_dir: str):
    """Initialize server with database directory"""
    global db_dir
    db_dir = Path(database_dir)


def run_server(host: str = "0.0.0.0", port: int = 8080, persist_changes: bool = False):
    """Run the MCP server with HTTP transport"""
    global g_persist_changes
    g_persist_changes = persist_changes
    logger = get_logger()
    logger.info(f"Starting IDA MCP Server on {host}:{port}")
    logger.info(f"Database directory: {db_dir}")
    mcp.settings.host = host
    mcp.settings.port = port
    mcp.run(transport="streamable-http")
    while 1:
        time.sleep(1)


def stop_server():
    """Stop the server and close all sessions"""
    logger = get_logger()
    logger.info("Stopping server...")

    # Close all sessions
    with session_lock:
        for session_id, session in sessions.items():
            try:
                session.close()
            except Exception as e:
                logger.error(f"Error closing session {session_id}: {e}")
        sessions.clear()

    logger.info("Server stopped")
