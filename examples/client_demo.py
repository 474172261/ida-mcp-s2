"""
IDA MCP Client 示例
演示如何使用IDA MCP Server的API
基于 FastMCP HTTP transport
"""

import requests
import json
import sys
import uuid
from typing import Optional, List, Dict, Any
from fastmcp import Client
import asyncio
import mcp


class IDAMCPClient:
    """IDA MCP Client - 使用官方 MCP SDK"""

    def __init__(self, base_url: str = "http://localhost:8080"):
        self.base_url = base_url
        print(self.base_url)
        self.session_id: Optional[str] = None
        self._exit_stack: Any = None
        self.session: Optional[Client] = Client(self.base_url)

    async def connect(self):
        """建立 MCP SSE 连接并初始化会话"""
        assert self.session is not None
        async with self.session as session:
            await session.ping()
        print("MCP session established and initialized.")

    async def _async_call_tool(self, tool_name: str, params: Dict[str, Any]) -> Any:
        assert self.session is not None
        async with self.session as session:
            result = await session.call_tool(tool_name, arguments=params)
        return result

    async def _call_tool(self, tool_name: str, params: Dict[str, Any]) -> Any:
        """调用 MCP 工具"""
        if not self.session:
            raise Exception("Session not connected. Call connect() first.")
        result = await self._async_call_tool(tool_name, params)
        print(result.content)
        return result.content

    async def close(self):
        """关闭连接"""
        if self._exit_stack:
            await self._exit_stack.aclose()
        self.session = None

    async def list_databases(self) -> Dict:
        """列出可用数据库"""
        content = await self._call_tool("list_databases", {})
        for item in content:
            if item.type == "text":
                return json.loads(item.text if item.text else "{}")
        return {}

    async def open_database(self, name: str) -> bool:
        """打开数据库"""
        try:
            content = await self._call_tool("open_database", {"name": name})
            for item in content:
                if item.type == "text":
                    result = json.loads(item.text if item.text else "{}")
                    self.session_id = result.get("session_id")
                    print(f"Opened database: {result.get('database')}")
                    print(f"Session ID: {self.session_id}")
                    return True
            return False
        except Exception as e:
            print(f"Failed to open database: {e}")
            return False

    async def close_database(self) -> bool:
        """关闭数据库"""
        if not self.session_id:
            print("No active session")
            return False

        try:
            await self._call_tool("close_database", {"session_id": self.session_id})
            print("Database closed successfully")
            self.session_id = None
            return True
        except Exception as e:
            print(f"Failed to close database: {e}")
            return False

    async def list_funcs(
        self, offset: int = 0, limit: int = 10, contain: Optional[str] = "*"
    ) -> Dict:
        """列出函数"""
        if not self.session_id:
            return {"error": "No active session"}

        content = await self._call_tool("list_funcs", {'session_id':self.session_id, 'offset':offset, 'limit':limit, 'contain':contain})
        for item in content:
            if item.type == "text":
                return json.loads(item.text if item.text else "{}")
        return {}

    async def lookup_funcs(self, queries: List[str]) -> Dict:
        """查找函数"""
        if not self.session_id:
            return {"error": "No active session"}

        content = await self._call_tool(
            "lookup_funcs", {"session_id": self.session_id, "queries": queries}
        )
        for item in content:
            if item.type == "text":
                return json.loads(item.text if item.text else "{}")
        return {}

    async def decompile(self, addr: str) -> str:
        """反编译函数"""
        if not self.session_id:
            return "Error: No active session"

        content = await self._call_tool(
            "decompile", {"session_id": self.session_id, "addr": addr}
        )
        for item in content:
            if item.type == "text":
                return item.text if item.text else ""
        return ""

    async def disasm(self, addr: str) -> str:
        """反汇编函数"""
        if not self.session_id:
            return "Error: No active session"

        content = await self._call_tool(
            "disasm", {"session_id": self.session_id, "addr": addr}
        )
        for item in content:
            if item.type == "text":
                return item.text if item.text else ""
        return ""

    async def xrefs_to(self, addrs: List[str]) -> List[Dict]:
        """获取交叉引用"""
        if not self.session_id:
            return []

        content = await self._call_tool(
            "xrefs_to", {"session_id": self.session_id, "addrs": addrs}
        )
        for item in content:
            if item.type == "text":
                return json.loads(item.text if item.text else "[]")
        return []

    async def xrefs_to_field(self, queries: List[Dict[str, str]]) -> List[Dict]:
        """获取结构体字段交叉引用"""
        if not self.session_id:
            return []

        content = await self._call_tool(
            "xrefs_to_field", {"session_id": self.session_id, "queries": queries}
        )
        for item in content:
            if item.type == "text":
                return json.loads(item.text if item.text else "[]")
        return []

    async def callees(self, addrs: List[str]) -> List[List[Dict]]:
        """获取被调用函数"""
        if not self.session_id:
            return []

        content = await self._call_tool(
            "callees", {"session_id": self.session_id, "addrs": addrs}
        )
        for item in content:
            if item.type == "text":
                return json.loads(item.text if item.text else "[]")
        return []

    async def get_bytes(self, addrs: List[str]) -> List[Dict]:
        """读取字节"""
        if not self.session_id:
            return []

        content = await self._call_tool(
            "get_bytes", {"session_id": self.session_id, "addrs": addrs}
        )
        for item in content:
            if item.type == "text":
                return json.loads(item.text if item.text else "[]")
        return []

    async def get_int(self, queries: List[Dict[str, str]]) -> List[Dict]:
        """读取整数"""
        if not self.session_id:
            return []

        content = await self._call_tool(
            "get_int", {"session_id": self.session_id, "queries": queries}
        )
        for item in content:
            if item.type == "text":
                return json.loads(item.text if item.text else "[]")
        return []

    async def read_string(self, addrs: List[str]) -> List[Dict]:
        """读取字符串"""
        if not self.session_id:
            return []

        content = await self._call_tool(
            "read_string", {"session_id": self.session_id, "addrs": addrs}
        )
        for item in content:
            if item.type == "text":
                return json.loads(item.text if item.text else "[]")
        return []

    async def list_globals(
        self, offset: int = 0, limit: int = 10, filter_contains: str = ""
    ) -> List[Dict]:
        """列出全局变量"""
        if not self.session_id:
            return []

        params = {"session_id": self.session_id, "offset": offset, "limit": limit}
        if filter_contains:
            params["filter_contains"] = filter_contains

        content = await self._call_tool("list_globals", params)
        for item in content:
            if item.type == "text":
                return json.loads(item.text if item.text else "[]")
        return []

    async def get_global_value(self, queries: List[str]) -> List[Dict]:
        """获取全局变量值"""
        if not self.session_id:
            return []
        try:
            content = await self._call_tool(
                "get_global_value", {"session_id": self.session_id, "queries": queries}
            )
            for item in content:
                if item.type == "text":
                    return json.loads(item.text if item.text else "[]")
        except Exception as e:
            print(e)
        return []

    async def list_imports(self, offset: int = 0, limit: int = 10, contain:Optional[str] = "*") -> List[Dict]:
        """列出导入符号"""
        if not self.session_id:
            return []

        content = await self._call_tool(
            "list_imports",
            {"session_id": self.session_id, "offset": offset, "limit": limit, 'contain': contain},
        )
        for item in content:
            if item.type == "text":
                return json.loads(item.text if item.text else "[]")
        return []

    async def stack_frame(self, addrs: List[str]) -> List[Dict]:
        """获取栈帧信息"""
        if not self.session_id:
            return []

        content = await self._call_tool(
            "stack_frame", {"session_id": self.session_id, "addrs": addrs}
        )
        for item in content:
            if item.type == "text":
                return json.loads(item.text if item.text else "[]")
        return []

    async def declare_stack_variable(self, items: List[Dict]) -> List[Dict]:
        """声明栈变量"""
        if not self.session_id:
            return []

        content = await self._call_tool(
            "declare_stack_variable", {"session_id": self.session_id, "items": items}
        )
        for item in content:
            if item.type == "text":
                return json.loads(item.text if item.text else "[]")
        return []

    async def delete_stack_variable(self, items: List[Dict]) -> List[Dict]:
        """删除栈变量"""
        if not self.session_id:
            return []

        content = await self._call_tool(
            "delete_stack_variable", {"session_id": self.session_id, "items": items}
        )
        for item in content:
            if item.type == "text":
                return json.loads(item.text if item.text else "[]")
        return []

    async def read_struct_define(self, queries: List[str]) -> List[Dict]:
        """读取结构体定义"""
        if not self.session_id:
            return []

        content = await self._call_tool(
            "read_struct_define", {"session_id": self.session_id, "queries": queries}
        )
        for item in content:
            if item.type == "text":
                return json.loads(item.text if item.text else "[]")
        return []

    async def search_structs(self, pattern_str: str, ignore_case: bool = True) -> List[Dict]:
        """搜索结构体"""
        if not self.session_id:
            return []

        content = await self._call_tool(
            "search_structs",
            {"session_id": self.session_id, "pattern_str": pattern_str, 'ignore_case': ignore_case},
        )
        for item in content:
            if item.type == "text":
                return json.loads(item.text if item.text else "[]")
        return []

    async def create_struct_from_c(self, declarations: List[str]) -> List[Dict]:
        """从C声明创建结构体"""
        if not self.session_id:
            return []

        content = await self._call_tool(
            "create_struct_from_c",
            {"session_id": self.session_id, "declarations": declarations},
        )
        for item in content:
            if item.type == "text":
                return json.loads(item.text if item.text else "[]")
        return []

    async def set_comments_at_disassembly(self, items: List[Dict]) -> List[Dict]:
        """设置反汇编注释"""
        if not self.session_id:
            return []

        content = await self._call_tool(
            "set_comments_at_disassembly",
            {"session_id": self.session_id, "items": items},
        )
        for item in content:
            if item.type == "text":
                return json.loads(item.text if item.text else "[]")
        return []

    async def add_pseudocode_comment(
        self, params:List[Dict]
    ) -> List[Dict]:
        """添加伪代码注释"""
        if not self.session_id:
            return []

        content = await self._call_tool(
            "add_pseudocode_comment",
            {"session_id": self.session_id, 'params':params},
        )
        for item in content:
            if item.type == "text":
                return json.loads(item.text if item.text else "[]")
        return []

    async def set_lvar_type(self, items: List[Dict]) -> List[Dict]:
        """设置局部变量类型为结构体指针"""
        if not self.session_id:
            return []

        content = await self._call_tool(
            "set_lvar_type",
            {"session_id": self.session_id, "items": items},
        )
        for item in content:
            if item.type == "text":
                return json.loads(item.text if item.text else "[]")
        return []

    async def define_func(self, items: List[Dict]) -> List[Dict]:
        """定义函数"""
        if not self.session_id:
            return []

        content = await self._call_tool(
            "define_func", {"session_id": self.session_id, "items": items}
        )
        for item in content:
            if item.type == "text":
                return json.loads(item.text if item.text else "[]")
        return []

    async def define_code(self, items: List[Dict]) -> List[Dict]:
        """定义代码"""
        if not self.session_id:
            return []

        content = await self._call_tool(
            "define_code", {"session_id": self.session_id, "items": items}
        )
        for item in content:
            if item.type == "text":
                return json.loads(item.text if item.text else "[]")
        return []

    async def undefine(self, items: List[Dict]) -> List[Dict]:
        """取消定义"""
        if not self.session_id:
            return []

        content = await self._call_tool(
            "undefine", {"session_id": self.session_id, "items": items}
        )
        for item in content:
            if item.type == "text":
                return json.loads(item.text if item.text else "[]")
        return []


def print_section(title: str):
    """打印章节标题"""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def print_result(name: str, result: Any, max_length: int = 500):
    """打印结果"""
    result_str = json.dumps(result, indent=2) if not isinstance(result, str) else result
    if len(result_str) > max_length:
        result_str = result_str[:max_length] + "..."
    print(f"\n{name}:")
    print(result_str)


async def demo():
    """演示如何使用客户端 - 完整测试所有功能"""
    client = IDAMCPClient("http://127.0.0.1:18888/mcp")
    # Test configuration
    func_name = "CAAHttpServerTransport::HandleReceiveRequestCompletion"
    func_addr = "0x180077C14"
    test_string_addr = "0x1800A21D8"
    test_global_name = "aBadFileDescrip"
    struct_name = "_HTTP_REQUEST_V2"
    struct_field = "RequestInfoCount"
    await client.connect()
    print_section("IDA MCP Client Demo - 完整功能测试")
    try:
        # 1. 列出数据库
        print_section("1. List Databases")
        databases = await client.list_databases()
        print_result("Databases", databases)

        if not databases.get("databases"):
            print("No databases found. Please add .idb or .i64 files to the db-dir.")
            return

        # 2. 打开第一个数据库
        db_name = list(databases["databases"].keys())[0]
        print_section(f"2. Open Database: {db_name}")
        if not await client.open_database(db_name):
            return

        # 3. 列出函数
        print_section("3. List Functions (first 5)")
        funcs = await client.list_funcs(offset=0, limit=5)
        print_result("Functions", funcs)

        # 4. 列出函数（带过滤）
        print_section("4. List Functions with contain 'Handle'")
        funcs_filtered = await client.list_funcs(
            offset=0, limit=5, contain="Handle"
        )
        print_result("Filtered Functions", funcs_filtered)

        # 5. 列出全局变量
        print_section("5. List Globals (first 5)")
        globals_list = await client.list_globals(offset=0, limit=5)
        print_result("Globals", globals_list)

        # 6. 列出导入符号
        print_section("6. List Imports (first 5)")
        imports = await client.list_imports(offset=0, limit=5)
        print_result("Imports", imports)

        # 7. 查找函数（通过地址）
        print_section(f"7. Lookup Function by Address: {func_addr}")
        lookup_addr = await client.lookup_funcs([func_addr])
        print_result("Lookup Result", lookup_addr)

        # 8. 查找函数（通过名称）
        print_section(f"8. Lookup Function by Name: {func_name}")
        lookup_name = await client.lookup_funcs([func_name])
        print_result("Lookup Result", lookup_name)

        # 9. 反编译函数
        print_section(f"9. Decompile Function: {func_addr}")
        decompiled = await client.decompile(func_addr)
        print_result("Decompiled Code", decompiled[:1000])

        # 10. 反汇编函数
        print_section(f"10. Disassemble Function: {func_addr}")
        disassembled = await client.disasm(func_addr)
        print_result("Disassembly", disassembled[:1000])

        # 11. 获取交叉引用
        xref_addr = "0x180079B7E"
        print_section(f"11. Get Xrefs To: {xref_addr}")
        xrefs = await client.xrefs_to([xref_addr])
        print_result("Xrefs", xrefs)

        # 12. 获取结构体字段交叉引用
        print_section(f"12. Get Xrefs To Field: {struct_name}.{struct_field}")
        field_xrefs = await client.xrefs_to_field(
            [{"struct": struct_name, "field": struct_field}]
        )
        print_result("Field Xrefs", field_xrefs)

        # 13. 获取被调用函数
        print_section(f"13. Get Callees: {func_addr}")
        callees = await client.callees([func_addr])
        print_result("Callees", callees)

        # 14. 读取字节
        print_section(f"14. Get Bytes: {func_addr}")
        bytes_data = await client.get_bytes([func_addr])
        print_result("Bytes", bytes_data)

        # 15. 读取整数
        print_section(f"15. Get Int (u32le): {func_addr}")
        int_data = await client.get_int([{"addr": func_addr, "type": "u32le"}])
        print_result("Integers", int_data)

        # 16. 读取字符串
        print_section(f"16. Get String: {test_string_addr}")
        strings = await client.read_string([test_string_addr])
        print_result("Strings", strings)

        # 17. 获取全局变量值（通过地址）
        print_section(f"17. Get Global Value by Address: {func_addr}")
        global_val_addr = await client.get_global_value([func_addr])
        print_result("Global Value", global_val_addr)

        # 18. 获取全局变量值（通过名称）
        print_section(f"18. Get Global Value by Name: {test_global_name}")
        global_val_name = await client.get_global_value([test_global_name])
        print_result("Global Value", global_val_name)

        # 18. 获取全局变量值（通过名称）
        print_section(f"18. Get Global Value by Name: {test_global_name}")
        global_val_name = await client.get_global_value(['not_exist_name'])
        print_result("Global Value", global_val_name)

        # 19. 获取栈帧信息
        print_section(f"19. Get Stack Frame: {func_addr}")
        stack_info = await client.stack_frame([func_addr])
        print_result("Stack Frame", stack_info)

        # 20. 声明栈变量
        print_section("20. Declare Stack Variable")
        declare_result = await client.declare_stack_variable(
            [{"ea": func_addr, "offset": "0x20", "name": "test_var", "type": "int"}]
        )
        print_result("Declare Result", declare_result)

        # 21. 删除栈变量
        print_section("21. Delete Stack Variable")
        delete_result = await client.delete_stack_variable(
            [{"ea": func_addr, "name": "test_var"}]
        )
        print_result("Delete Result", delete_result)

        # 22. 读取结构体定义
        print_section(f"22. Read Struct Definition: {struct_name}")
        struct_def = await client.read_struct_define([struct_name])
        print_result("Struct Definition", struct_def)

        # 23. 搜索结构体
        print_section("23. Search Structs with Pattern 'Request'")
        struct_search = await client.search_structs("Request", True)
        print_result("Struct Search Results", struct_search)

        # 24. 设置反汇编注释
        comment_addr = "0x180077CCE"
        print_section(f"24. Set Comment at {comment_addr}")
        comment_result = await client.set_comments_at_disassembly(
            [
                {
                    "ea": comment_addr,
                    "text": "Test comment from client",
                    "repeatable": False,
                }
            ]
        )
        print_result("Comment Result", comment_result)

        # 25. 添加伪代码注释
        pseudocode_addr = "0x180077CBD"
        print_section(f"25. Add Pseudocode Comment at {pseudocode_addr}")
        pseudocode_comment = await client.add_pseudocode_comment(
            [{'ea':pseudocode_addr, 'text':"Test pseudocode comment from client"}]
        )
        print_result("Pseudocode Comment Result", pseudocode_comment)

        # 26. 从C声明创建结构体
        print_section("26. Create Struct from C Declaration")
        c_struct = "struct MyTestStruct { int a; float b; };"
        create_struct = await client.create_struct_from_c([c_struct])
        print_result("Create Struct Result", create_struct)

        # # 27. 设置局部变量类型
        # print_section("27. Set Local Variable Type")
        # lvar_result = await client.set_lvar_type(
        #     [{"ea": func_addr, "var_name": "connection_info", "struct_type": "int *a;"}]
        # )
        # print_result("Set Lvar Type Result", lvar_result)

        # 28. 取消定义函数
        print_section(f"28. Undefine Function: {func_addr}")
        undefine_result = await client.undefine([{"addr": func_addr}])
        print_result("Undefine Result", undefine_result)

        # 29. 定义代码
        print_section(f"29. Define Code at: {func_addr}")
        define_code_result = await client.define_code([{"addr": func_addr}])
        print_result("Define Code Result", define_code_result)

        # 30. 定义函数
        print_section(f"30. Define Function at: {func_addr}")
        define_func_result = await client.define_func(
            [{"addr": func_addr, "name": func_name}]
        )
        print_result("Define Function Result", define_func_result)

    except Exception as e:
        print(f"\nError during demo: {e}")
        import traceback

        traceback.print_exc()

    finally:
        # 32. 关闭数据库
        print_section("32. Close Database")
        await client.close_database()

    print_section("Demo Complete!")


if __name__ == "__main__":
    asyncio.run(demo())
