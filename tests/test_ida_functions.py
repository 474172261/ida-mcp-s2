#!/usr/bin/env python3
"""
IDA功能单元测试程序
加载IDA数据库后,直接调用ida_functions中的功能进行测试

使用方法:
1. 在IDA中打开数据库
2. 运行: File -> Script file... 选择此文件
   或在IDA Python控制台中执行: exec(open(r'路径/test_ida_functions.py').read())

"""

import idapro
import sys
import os
import json
import time
import idc

# 添加项目路径
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

import ida_idaapi
import ida_auto
import ida_funcs
import ida_name

# 导入要测试的模块
from ida_mcp_s2 import ida_functions
from ida_mcp_s2.utils import debug_stop

# 测试统计
test_results = {"passed": 0, "failed": 0, "errors": []}


def test_function(func_name, func, *args, **kwargs):
    """测试单个函数"""
    print(f"\n{'=' * 60}")
    print(f"测试函数: {func_name}")
    print(f"参数: args={args}, kwargs={kwargs}")
    print(f"{'=' * 60}")

    start_time = time.time()
    result = {}
    try:
        result = func(*args, **kwargs)
        elapsed = time.time() - start_time

        print(f"✓ 测试通过 (耗时: {elapsed:.3f}s)")
        print(f"结果类型: {type(result).__name__}")

        # 格式化输出结果
        if isinstance(result, (list, dict)):
            result_str = json.dumps(result, indent=2, ensure_ascii=False)
            if len(result_str) > 1000:
                print(f"结果(截断): {result_str[:1000]}...")
            else:
                print(f"结果: {result_str}")
        else:
            result_str = str(result)
            if len(result_str) > 1000:
                print(f"结果(截断): {result_str[:1000]}...")
            else:
                print(f"结果: {result_str}")
    except Exception as e:
        print(e)
        print("!!!!!!!!!!!!!!!!!!!!!!!")
        import traceback

        traceback.print_exc()
        input(">")
        test_results["failed"] += 1
    test_results["passed"] += 1
    return True, result


def run_tests(functions: ida_functions.IDAFunctions):
    """运行所有测试"""
    print("\n" + "=" * 70)
    print("IDA功能单元测试开始")
    print("=" * 70)
    print(f"测试时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"函数总数: {ida_funcs.get_func_qty()}")
    print("=" * 70)

    # 获取第一个函数的地址用于测试

    func_name = "CAAHttpServerTransport::HandleReceiveRequestCompletion"
    func_addr = "0x180077C14"

    # 1. 测试 list_funcs
    test_function("list_funcs", functions.list_funcs, [0, 5, "*"])

    # 2. 测试 list_funcs with filter
    test_function("list_funcs (with filter)", functions.list_funcs, [0, 5, "Handle"])

    # 3. 测试 list_globals
    status, result_globals = test_function(
        "list_globals", functions.list_globals, [0, 5, "*"]
    )
    print(result_globals)
    # 4. 测试 list_imports
    test_function("list_imports", functions.list_imports, [0, 5, "*"])

    # 5. 测试 lookup_funcs (by address)
    if func_addr:
        test_function("lookup_funcs (by address)", functions.lookup_funcs, [func_addr])

    # 6. 测试 lookup_funcs (by name)
    if func_name:
        test_function("lookup_funcs (by name)", functions.lookup_funcs, [func_name])

    # 7. 测试 decompile (如果Hex-Rays可用)
    if func_addr:
        test_function("decompile", functions.decompile, [func_addr, 0, 20])

        test_function("decompile", functions.decompile, [func_addr, 20, 200])

        test_function("decompile", functions.decompile, [func_addr, 20, 20000])

    # 8. 测试 disasm
    if func_addr:
        test_function("disasm", functions.disasm, [func_addr, 0, 10])

        test_function("disasm", functions.disasm, [func_addr, 10, 10])

    test_function("disasm", functions.disasm, [func_name, 0, 0])

    # 9. 测试 xrefs_to
    if func_addr:
        test_function("xrefs_to", functions.xrefs_to, ["0x180079B7E"])
    test_function(
        "xrefs_to_field",
        functions.xrefs_to_field,
        [{"struct": "_HTTP_REQUEST_V2", "field": "RequestInfoCount"}],
    )

    # 10. 测试 callees
    if func_addr:
        test_function("callees", functions.callees, [func_addr])

    # 11. 测试 get_bytes
    if func_addr:
        test_function("get_bytes", functions.get_bytes, [func_addr])

    # 12. 测试 get_int
    if func_addr:
        test_function(
            "get_int", functions.get_int, [{"addr": func_addr, "type": "u32le"}]
        )

    test_function("read_string", functions.read_string, ["0x1800A21D8"])

    test_function(
        "search_in_strings_window",
        functions.search_in_strings_window,
        ["pszUnauthenticatedUserName", 0, 5],
    )

    # 13. 测试 get_global_value
    test_function("get_global_value", functions.get_global_value, func_addr)

    test_function("get_global_value", functions.get_global_value, "aBadFileDescrip")

    test_function("get_global_value", functions.get_global_value, "aBadescrip")

    # 15. 测试 stack_frame
    test_function("stack_frame", functions.stack_frame, [func_addr])

    test_function(
        "declare_stack_variable",
        functions.declare_stack_variable,
        [
            {
                "ea": 0x180077C14,
                "offset": 0x20,
                "name": "RequestBufferLength",
                "type": "int",
            }
        ],
    )

    test_function(
        "delete_stack_variable",
        functions.delete_stack_variable,
        [{"ea": 0x180077C14, "name": "RequestBufferLength"}],
    )

    test_function(
        "read_struct_define", functions.read_struct_define, ["_HTTP_REQUEST_V2"]
    )

    # 16. 测试 search_structs
    test_function("search_structs", functions.search_structs, ["Request", True])

    test_function(
        "set_comments_at_disassembly",
        functions.set_comments_at_disassembly,
        [{"ea": "0x180077CCE", "text": "test comment"}],
    )

    test_function(
        "add_pseudocode_comment",
        functions.add_pseudocode_comment,
        [{"ea": 0x180077CBD, "text": "this is a test comment"}],
    )

    test_function(
        "create_struct_from_c",
        functions.create_struct_from_c,
        ["struct MyTestStruc3 { int a; float b; };"],
    )

    test_function("define_code", functions.define_code, [{"addr": func_addr}])

    test_function("undefine", functions.undefine, [{"addr": func_addr}])

    test_function(
        "define_func", functions.define_func, [{"addr": func_addr, "name": func_name}]
    )

    test_function("find_bytes", functions.find_bytes, ["48 8D AC 24  ?? 9A", 0, 10])

    test_function("py_eval", functions.py_eval, "print(1)\nimport idapro")

    test_function(
        "set_lvar_type",
        functions.set_lvar_type,
        [{"ea": 0x180084308, "var_name": "connection_info", "struct_type": "int *a;"}],
    )
    # 打印测试总结
    print("\n" + "=" * 70)
    print("测试总结")
    print("=" * 70)
    total = test_results["passed"] + test_results["failed"]
    print(f"总测试数: {total}")
    print(f"通过: {test_results['passed']}")
    print(f"失败: {test_results['failed']}")

    if test_results["errors"]:
        print("\n错误详情:")
        for i, error in enumerate(test_results["errors"], 1):
            print(f"  {i}. {error['function']}")
            print(f"     错误: {error['error']}")

    print("=" * 70)

    return test_results


# 如果直接在IDA中运行
if __name__ == "__main__":
    # 检查是否在IDA环境中
    idapro.open_database(sys.argv[1], True)
    functions = ida_functions.IDAFunctions()
    try:
        # 确保IDA自动分析完成
        if ida_auto.get_auto_state() == ida_auto.AU_NONE:
            print("[*] 等待IDA自动分析...")
            ida_auto.auto_wait()
            print("[*] IDA自动分析完成")

        # 运行测试
        results = run_tests(functions)

        # 退出码
        if results["failed"] > 0:
            print(f"\n[!] 有 {results['failed']} 个测试失败")
        else:
            print("\n[✓] 所有测试通过!")
        idapro.close_database(True)
    except NameError as e:
        print(f"错误: 此脚本需要在IDA Pro环境中运行")
        print(f"详细错误: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"错误: {type(e).__name__}: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)
