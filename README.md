# IDA MCP Server

基于IDA Pro IDALib的MCP (Model Context Protocol) Server实现，相较于 ida-pro-mcp, 本项目可以同时打开多个库, 更简洁的架构, 方便测试和添加功能。

## 特性

- **MCP协议**: 通过FastMCP提供标准MCP协议支持
- **多进程架构**: 每个IDA数据库在独立的进程中打开，支持同时处理多个数据库
- **Session管理**: 客户端可以打开、管理和关闭数据库会话
- **安全防护**: 数据库名称验证，防止路径穿越攻击
- **优雅退出**: server有Ctrl+C信号处理，正确关闭所有子进程
- **实时保存改动, 实时优化接口实现**: reload_database(save_changes = True)接口, 可以保存更新并重新打开数据库, mcp server的worker进程也会重新加载 ida_functions.py, session_id维持不变. 在ida_functions.py有bug时, 可以实时修复ida_functions.py 的实现而不打断大模型的对话, 避免浪费上下文的token.

## 项目结构

```
ida-mcp-s2/
├── main.py                 # 服务入口
├── ida_mcp_s2/
│   ├── server.py           # MCP服务实现
│   ├── ida_functions.py    # IDA功能封装
|   ├── add_struct_xrefs.py # referee插件封装. (因为正常的referee插件在idalib中无法被触发, 所以封装了它的实现到decompile里)
│   └── logger.py           # 日志模块
├── examples/
│   └── client_demo.py      # MCP客户端测试示例
└── tests/
    └── test_ida_functions.py # 测试 ida_functions 功能
```

## 安装

### 前提条件

1. 安装IDA Pro 8.4或更高版本
2. 安装 idalib. `pip install idapro`
3. python 3.10+

### 设置

```bash
# 克隆项目
git clone <repository-url>
cd ida-mcp-s2

# 安装依赖
pip install -r requirements.txt
```

## 使用方法

### 启动服务器

```bash
> python main.py --db-dir E:\db_dir\ --port 18888 --debug

Loading IDA library from: C:\Program Files\IDA Professional 9.1\idalib.dll
2026-03-24 14:58:58 - ida_mcp_s2 - INFO - Starting IDA MCP Server on 0.0.0.0:18888
2026-03-24 14:58:58 - ida_mcp_s2 - INFO - Database directory: E:\db_dir
INFO:     Started server process [3388]
INFO:     Waiting for application startup.
[03/24/26 14:58:59] INFO     StreamableHTTP session manager started                                                                                                             streamable_http_manager.py:116
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:18888 (Press CTRL+C to quit)
```

参数说明：
- `--host`: 服务器主机地址 (默认: 0.0.0.0)
- `--port`: 服务器端口 (默认: 8080)
- `--db-dir`: IDA数据库文件目录（必需）
- `--debug`: 启用调试日志
- `--save_change`: 默认不存储对ida数据库的改动, 添加此参数可保存改动（可选）

### 测试连接
```bash
> python .\examples\client_demo.py
http://127.0.0.1:18888/mcp
MCP session established and initialized.

======================================================================
  IDA MCP Client Demo - 完整功能测试
======================================================================
name:list_sessions
descrition:List all active IDA database sessions
name:list_databases
descrition:List available IDA database files
name:open_database
descrition:Open an IDA database

Args:
    name: Database file name (with or without extension)

......

======================================================================
  1. List Databases
======================================================================
[TextContent(type='text', text='{\n  "databases": {\n    "aaedge-26252.5000.dll-new.i64": {\n      "size": 13741838,\n      "modified": 1774331558.1508806\n    }\n  }\n}', annotations=None, meta=None)]

Databases:
{
  "databases": {
    "aaedge-26252.5000.dll-new.i64": {
      "size": 13741838,
      "modified": 1774331558.1508806
    }
  }
}

======================================================================
  2. Open Database: aaedge-26252.5000.dll-new.i64
======================================================================
[TextContent(type='text', text='{\n  "session_id": "sid_0001",\n  "database": "aaedge-26252.5000.dll-new.i64",\n  "path": "E:\\\\db_dir\\\\aaedge-26252.5000.dll-new.i64"\n}', annotations=None, meta=None)]
Opened database: aaedge-26252.5000.dll-new.i64
Session ID: sid_0001
......
```
如上所示, 表明mcp的server正常运行, client成功连接并输出了mcp提供的工具描述, 测试了打开数据库功能正常.(client_demo里的后续mcp工具调用参数都基于我的数据库, 所以你的环境不一定正常输出，可能存在报错，是正常现象)

### 配置Client的mcp

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

**claude code 配置 mcp client**
`claude mcp add ida-mcp-s2 --transport http http://127.0.0.1:18888/mcp`

## 可用方法

#### 数据库管理
- `open_database`: 打开IDA数据库
- `close_database`: 关闭数据库会话
- `list_databases`: 列出可用数据库
- `reload_database`: 重新打开数据库

#### 函数操作
- `list_funcs`: 列出函数（支持分页、过滤和正则表达式）
- `get_func_by_addr`: 获取某个地址所属的函数信息
- `decompile`: 反编译函数
- `disasm`: 反汇编函数

#### 交叉引用
- `xrefs_to_addr`: 获取地址的交叉引用
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
- `set_lvar_type`: 设置伪c代码局部变量类型和名称

#### 修改操作
- `define_func`: 定义函数
- `define_code`: 转换为代码指令
- `undefine`: 取消定义

#### 字节搜索
- `find_bytes`: 搜索字节模式（支持 ?? 通配符、分页）

#### 代码执行
- `py_eval`: 在IDA上下文中执行Python代码

#### 记录保留
- `save_viewed_functions`: 保存查询过的函数记录(方便检查AI查询过哪些函数, 是否存在遗漏)

## http请求示例

### 1. 打开数据库

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

### 2. 列出函数

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
        "queries": [
          [0, 100, ""]
        ]
      }
    }
  }'
```

### 3. 反编译函数

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

### 4. 获取全局变量

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

## 使用MCP客户端库

参考 example\client_demo.py 的实现

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

默认情况下，工作进程会在退出时撤销所有对数据库的修改（通过IDA的undo功能）。如默认需保存修改，可以在启动server时添加`--save_change` 参数。如果只是临时想保存修改，在AI的对话窗口主动要求 “调用reload_database(save_changes = True)接口“，那么改动就会被保存，worker会重新启动并保持session_id不变。

## 应用
如果是逆向，可以考虑如下提示词：
```
你是一个拥有高级权限的 IDA Pro 自动化分析助手。你能够通过 MCP 工具直接读写 IDA 数据库，目标是实现伪 C 代码的高度语义化还原。
核心工具指令：
结构体还原：当你通过内存偏移（如 a1 + 0x10）识别出数据结构时，必须编写完整的 C 结构体代码并调用 create_struct_from_c。如果是对已有结构体的补全，务必开启 is_update=True。
变量重构：一旦确认了变量的真实类型和含义，立即调用 set_lvar_type 同步修改伪代码中的变量名和类型，消除 _BYTE* 或 int 等模糊定义。
深度探索：如果当前函数的参数用途不明，主动要求获取相关子函数的伪代码，通过交叉引用（Xref）和子函数逻辑来反推父函数的结构体成员。
语义注释：分析汇编层面的关键逻辑，找到对应的 ea 地址，调用 add_pseudocode_comment 为伪代码添加中文注释。flag用"block".
执行策略：
先定义，后应用：先通过 create_struct_from_c 确保数据库中存在该类型，再执行 set_lvar_type。
渐进式完善：不要求一次性完美，可以先定义基础成员，随着分析深入不断 is_update 结构体。
静默执行：在分析过程中，直接调用工具进行修改，完成后向我总结你做了哪些重构。
任务开始：
请读取我提供的伪代码（或指定函数名），开始你的逆向重构工作。
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