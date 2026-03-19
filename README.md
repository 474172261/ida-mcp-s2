# IDA MCP Server

基于IDA Pro IDALib的MCP (Model Context Protocol) Server实现，相较于 ida-pro-mcp, 本项目可以同时打开多个库, 更简洁的架构, 方便测试和添加功能。

## 特性

- **MCP协议**: 通过FastMCP提供标准MCP协议支持
- **多进程架构**: 每个IDA数据库在独立的进程中打开，支持同时处理多个数据库
- **Session管理**: 客户端可以打开、管理和关闭数据库会话
- **安全防护**: 数据库名称验证，防止路径穿越攻击
- **优雅退出**: Ctrl+C信号处理，正确关闭所有子进程

## 安装

### 前提条件

1. 安装IDA Pro 8.4或更高版本
2. 参考 [idalib介绍](https://docs.hex-rays.com/user-guide/idalib), 安装它. 确保在python中可以`import idapro`
3. Python 3.8+

### 设置

```bash
# 克隆项目
git clone <repository-url>
cd ida-mcp-s2

# 安装依赖
pip install -r requirements.txt
```

## 项目结构

```
ida-mcp-s2/
├── main.py                 # 服务入口
├── ida_mcp_s2/
│   ├── server.py           # MCP服务实现
│   ├── ida_functions.py    # IDA功能封装
│   └── logger.py           # 日志模块
├── examples/
│   └── client_demo.py      # 客户端示例
└── tests/
    └── test_ida_functions.py
```

## 使用方法

### 启动服务器

```bash
python main.py --db-dir /path/to/ida/databases --port 18888 --debug
```

参数说明：
- `--host`: 服务器主机地址 (默认: 0.0.0.0)
- `--port`: 服务器端口 (默认: 8080)
- `--db-dir`: IDA数据库文件目录（必需）
- `--debug`: 启用调试日志
- `--save_change`: 默认不存储对ida数据库的改动, 添加此参数可保存改动（可选）


### MCP端点

```
GET /mcp
```

通过MCP客户端连接，使用标准MCP协议进行调用。

**opencode 配置mcp client**
在%USERPROFILE%\.config\opencode\opencode.jsonc`中, 添加如下信息:
```
{
  "mcp": {
    "my_ida-mcp":{
      "type":"remote",
      "url": "http://127.0.0.1:18888/mcp",
      "enabled": true
    },
  }
}
```

### 可用方法

#### 数据库管理
- `open_database`: 打开IDA数据库
- `close_database`: 关闭数据库会话
- `list_databases`: 列出可用数据库

#### 函数操作
- `list_funcs`: 列出函数（支持分页和过滤）
- `lookup_funcs`: 按地址或名称查找函数
- `decompile`: 反编译函数
- `disasm`: 反汇编函数

#### 交叉引用
- `xrefs_to`: 获取地址的交叉引用
- `xrefs_to_field`: 获取结构体字段的交叉引用
- `callees`: 获取函数调用的子函数

#### 数据读取
- `get_bytes`: 读取原始字节
- `get_int`: 读取整数（支持多种类型）
- `read_string`: 读取字符串
- `search_in_strings_window`: 搜索字符串窗口（支持正则、分页）

#### 全局变量和导入
- `list_globals`: 列出全局变量（支持分页和过滤）
- `get_global_value`: 获取全局变量值
- `list_imports`: 列出导入符号

#### 栈帧操作
- `stack_frame`: 获取函数栈帧信息
- `declare_stack_variable`: 声明栈变量
- `delete_stack_variable`: 删除栈变量

#### 结构体操作
- `read_struct_define`: 读取结构体定义
- `search_structs`: 搜索结构体
- `create_struct_from_c`: 从C声明创建结构体

#### 注释操作
- `set_comments_at_disassembly`: 设置反汇编注释
- `add_pseudocode_comment`: 添加反编译代码注释

#### 类型操作
- `set_lvar_type`: 设置伪c代码局部变量类型

#### 修改操作
- `define_func`: 定义函数
- `define_code`: 转换为代码指令
- `undefine`: 取消定义

#### 字节搜索
- `find_bytes`: 搜索字节模式（支持 ?? 通配符、分页）

#### 代码执行
- `py_eval`: 在IDA上下文中执行Python代码

### 使用示例

#### 1. 打开数据库

```bash
curl -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "open_database",
      "arguments": {
        "name": "example.idb"
      }
    }
  }'
```

响应：
```json
{
    "success": true,
    "data": {
        "session_id": "550e8400-e29b-41d4-a716-446655440000",
        "database": "example.idb",
        "path": "/path/to/databases/example.idb"
    }
}
```

#### 2. 列出函数

```bash
curl -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "list_funcs",
      "arguments": {
        "session_id": "550e8400-e29b-41d4-a716-446655440000",
        "offset": 0,
        "limit": 10,
        "contain": "main"
      }
    }
  }'
```

#### 3. 反编译函数

```bash
curl -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "decompile",
      "arguments": {
        "session_id": "550e8400-e29b-41d4-a716-446655440000",
        "addr": "0x401000"
      }
    }
  }'
```

#### 4. 获取全局变量

```bash
curl -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "get_global_value",
      "arguments": {
        "session_id": "550e8400-e29b-41d4-a716-446655440000",
        "queries": ["g_global_var"]
      }
    }
  }'
```

### 使用MCP客户端库

```python
from mcp import ClientSession, StdioServerParameters
import subprocess

# 启动IDA MCP服务器
server_process = subprocess.Popen(
    ["python", "main.py", "--db-dir", "./databases"],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)

# 连接MCP服务器
params = StdioServerParameters(
    command="python",
    args=["main.py", "--db-dir", "./databases"],
)

async def main():
    async with ClientSession(params) as session:
        await session.initialize()
        
        # 打开数据库
        result = await session.call_tool("open_database", {"name": "example.idb"})
        session_id = result["session_id"]
        
        # 列出函数
        funcs = await session.call_tool("list_funcs", {
            "session_id": session_id,
            "limit": 10
        })
        
        print(funcs)

import asyncio
asyncio.run(main())
```

## 架构说明

### 多进程设计

由于IDALib限制每个进程只能打开一个数据库，服务器采用主-从架构：

1. **主进程**: MCP服务器，处理客户端请求，管理Session
2. **工作进程**: 每个Session对应一个工作进程，实际执行IDA操作
3. **通信**: 主进程和工作进程通过Socket进行通信

### Session管理

```
Client -> Server: open_database("example.idb")
Server -> Worker: Fork new process
Worker -> IDALib: open_database()
Server -> Client: session_id

Client -> Server: list_funcs(session_id, ...)
Server -> Worker: Forward request
Worker -> IDALib: Execute
Worker -> Server: Return results
Server -> Client: Response

Client -> Server: close_database(session_id)
Server -> Worker: Shutdown command
Worker -> IDALib: close_database()
Worker: Exit
```

### 信号处理

服务器正确处理Ctrl+C信号：
- 通知所有MCP客户端断开连接
- 关闭所有Session（通知工作进程退出）
- 等待工作进程正常退出或超时终止
- 关闭MCP服务器

### 数据持久化

默认情况下，工作进程会在退出时撤销所有对数据库的修改（通过IDA的undo功能）。如需保存修改，可以在启动server时添加`--save_change` 参数

## 安全注意事项

1. **路径验证**: 数据库名称只能是文件名，不能包含路径分隔符或`..`
2. **文件系统隔离**: 所有数据库必须从指定的`--db-dir`目录加载
3. **进程隔离**: 每个数据库在独立进程中打开，崩溃不会影响其他会话

## 日志

使用Python标准logging模块，模块名为 `ida_mcp_s2`：

```python
from ida_mcp_s2.logger import set_debug, get_logger

# 启用调试模式
set_debug(True)

# 获取logger
logger = get_logger()
logger.info("Info message")
logger.debug("Debug message")
```

## 故障排除

### 端口冲突
如果8080端口被占用，使用 `--port` 参数指定其他端口。

## 许可证

MIT License

## 贡献

欢迎提交Issue和Pull Request！

## 致谢
感谢 https://github.com/mrexodia/ida-pro-mcp 项目, 它给了我很多参考.