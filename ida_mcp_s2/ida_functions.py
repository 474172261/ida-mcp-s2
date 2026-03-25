"""
IDA功能实现
使用函数式编程范式
"""
import ida_idaapi
import idautils
from typing import List, Dict, Any, Optional, Union, Annotated, Tuple
import json
import ida_funcs
import ida_name
import idc
import ida_nalt
import ida_hexrays
import ida_xref
import idaapi
import struct
import ida_bytes
import ida_frame
import re
import ida_typeinf
import ida_strlist
import ast
import io
import sys
import ida_ida
import ida_dbg
import ida_entry
import ida_kernwin
import ida_lines
import ida_segment
import traceback
from ida_mcp_s2.utils import get_wide_strings_manually, get_readble_name, debug_stop


global_func_lists = []
global_func_dict = {}
global_Nams_lists = []
global_imports_lists = []
global_strings_lists = []

def list_funcs(queries: List[Tuple[int, int, str]]) -> List[Dict]:
    """列出函数 - 函数式实现 (增加 limit 截断状态)"""
    global global_func_lists
    results = []
    if not global_func_lists:
        raise ValueError("not init yet")

    for offset, limit, regex in queries:
        try:
            regex_obj = re.compile(regex or '.*', re.IGNORECASE)
        except re.error:
            results.append({'query': regex, 'msg': "Invalid regex pattern"})
            continue

        matched_items = []
        found_count = 0
        is_limited = False

        for clean_name, func_ea, func in global_func_lists:
            if not func or not regex_obj.search(clean_name):
                continue
            
            # 记录匹配到的总数（用于判断是否越过 offset）
            if found_count < offset:
                found_count += 1
                continue
            
            # 检查是否达到 limit
            if limit and len(matched_items) >= limit:
                is_limited = True
                break

            # 执行耗时操作：反编译
            matched_items.append({
                "addr": hex(func_ea),
                "name": clean_name,
                "byte size": func.size(),
                'decompile size': len(str(ida_hexrays.decompile(func)))
            })
            found_count += 1

        if not matched_items:
            results.append({'query': regex, 'msg': f"no match found"})
        else:
            results.append({
                'query': regex,
                'items': matched_items,
                'has_more': is_limited,  # 告知用户是否还有更多数据未列出
                'count': len(matched_items)
            })

    return results

def list_globals(
    offset: int = 0,
    limit: int = 10,
    contain: str = "*",
) -> Dict:
    """列出全局变量 - 增加截断状态告知 (contain 默认值为 *)"""
    global global_Nams_lists
    if not global_Nams_lists:
        raise ValueError("not init yet")

    matched_items = []
    found_count = 0  # 记录符合过滤条件的条目总数
    has_more = False
    
    # 预处理搜索词
    search_term = contain.lower()
    use_filter = search_term != '*'

    for ea, name in global_Nams_lists:
        # 1. 过滤：如果不匹配则跳过
        if use_filter and search_term not in name.lower():
            continue
        
        # 2. 分页 Offset：统计符合条件但尚未到达起始位置的条目
        if found_count < offset:
            found_count += 1
            continue

        # 3. 限制 Limit：如果达到上限，标记 has_more 并结束
        if len(matched_items) >= limit:
            has_more = True
            break

        matched_items.append({"address": hex(ea), "name": name})
        found_count += 1

    return {
        "items": matched_items,
        "has_more": has_more,
        "offset": offset,
        "limit": limit
    }

def list_imports(
    offset: int = 0, 
    limit: int = 10, 
    contain: str = "*"
) -> Dict:
    """列出导入符号 - 增加截断状态告知"""
    global global_imports_lists
    if not global_imports_lists:
        raise ValueError("not init yet")

    matched_items = []
    found_count = 0  # 记录符合过滤条件的条目数
    has_more = False
    
    # 预处理搜索词
    search_term = contain.lower()
    use_filter = search_term != '*'

    for ea, name, module_name in global_imports_lists:
        # 1. 过滤：先检查是否匹配关键词
        if use_filter and (search_term not in name.lower()):
            continue
            
        # 2. 分页 Offset：跳过前 offset 个匹配项
        if found_count < offset:
            found_count += 1
            continue

        # 3. 限制 Limit：达到上限则标记并停止
        if len(matched_items) >= limit:
            has_more = True
            break

        matched_items.append({
            "address": hex(ea),
            "name": name,
            "module": module_name,
        })
        # 即使加入了结果集，也要增加计数以维持逻辑
        found_count += 1

    return {
        "items": matched_items,
        "has_more": has_more,
        "offset": offset,
        "limit": limit,
        "count_in_page": len(matched_items)
    }

def get_func_by_addr(addresses: List[int]) -> List[Dict]:
    """根据地址获取所属函数信息"""
    results = []

    for addr_input in addresses:
        try:
            # 兼容字符串形式的十六进制 (0x...) 或 整数
            ea = addr_input
            
            # 使用 IDA SDK 获取函数对象
            func = ida_funcs.get_func(ea)
            
            if func:
                results.append({
                    "query_addr": hex(ea),
                    "func_start": hex(func.start_ea),
                    "func_end": hex(func.end_ea),
                    "name": get_readble_name(func.start_ea),
                    'decompile size': len(str(ida_hexrays.decompile(func)))
                })
            else:
                results.append({
                    "query_addr": hex(ea), 
                    "msg": "Address does not belong to any function"
                })
                
        except (ValueError, TypeError):
            results.append({
                "query_addr": str(addr_input), 
                "msg": "Invalid address format"
            })

    return results


def decompile(faddr: int, offset: int = 0, limit: int = 0) -> Dict:
    """反编译函数 - 仅支持地址(int)，增加截断告知"""
    # 1. 获取函数对象
    this_func = ida_funcs.get_func(faddr)
    if not this_func:
        raise ValueError(f"No function found at {hex(faddr)}")

    # 2. 执行反编译
    cfunc = ida_hexrays.decompile(this_func)
    if not cfunc:
        raise ValueError(f"Failed to decompile function at {hex(faddr)}")

    full_code = str(cfunc)
    total_len = len(full_code)

    # 3. 边界检查
    if offset >= total_len:
        return {
            'addr': hex(this_func.start_ea),
            'error': 'offset out of bounds',
            'total_size': total_len
        }

    # 4. 计算截断逻辑
    if limit > 0 and (offset + limit) < total_len:
        code_segment = full_code[offset : offset + limit]
        has_more = True
    else:
        code_segment = full_code[offset:]
        has_more = False

    return {
        'func_name': get_readble_name(this_func.start_ea),
        'addr': hex(this_func.start_ea),
        'code': code_segment,
        'offset': offset,
        'has_more': has_more,
        'next_offset': offset + len(code_segment) if has_more else None,
        'total_size': total_len
    }

def disasm(addr: int, offset: int = 0, limit: int = 0) -> Dict:
    """反汇编 - 仅支持地址(int)，增加截断告知"""
    this_func = ida_funcs.get_func(addr)
    lines = []
    has_more = False
    
    # 情况 A: 地址属于某个函数 (按指令条数分页)
    if this_func:
        curr_addr = this_func.start_ea
        end_addr = this_func.end_ea
        
        found_count = 0
        while curr_addr < end_addr:
            disasm_text = idc.generate_disasm_line(curr_addr, 0)
            if not disasm_text: break
            
            # 分页逻辑
            if found_count >= offset:
                if limit and (len(lines) < limit):
                    lines.append(f"{hex(curr_addr)}: {disasm_text}")
                else:
                    has_more = True
                    break
            
            found_count += 1
            curr_addr = idc.next_head(curr_addr, end_addr)
            if curr_addr == idaapi.BADADDR: break

        return {
            "type": "function",
            "func_name": get_readble_name(this_func.start_ea),
            "codes": "\n".join(lines),
            "offset": offset,
            "has_more": has_more,
            "next_offset": offset + len(lines) if has_more else None
        }

    # 情况 B: 地址不属于函数 (显示固定数量指令)
    else:
        curr_addr = addr
        for _ in range(10):
            disasm_text = idc.generate_disasm_line(curr_addr, 0)
            if not disasm_text: break
            
            lines.append(f"{hex(curr_addr)}: {disasm_text}")
            curr_addr = idc.next_head(curr_addr)
            if curr_addr == idaapi.BADADDR: break
        
        # 散点反汇编通常不谈 offset，直接给下一个地址
        return {
            "type": "raw_address",
            "codes": "\n".join(lines),
            "next_addr": hex(curr_addr) if len(lines) == limit else None,
            "msg": "Address is not in a function, showing raw instructions."
        }


def xrefs_to_addr(addrs: Union[str, List[str]]) -> List[Dict]:
    """获取交叉引用 - 函数式实现"""

    if isinstance(addrs, str):
        addrs = [addrs]

    results = []

    for addr_str in addrs:
        try:
            addr = int(addr_str, 0)
        except:
            results.append(f'"{addr_str}" is not an address')
            continue

        for xref in idautils.XrefsTo(addr):

            from_name = get_readble_name(xref.frm)
            to_name = get_readble_name(xref.to)

            results.append(
                {
                    "from": hex(xref.frm),
                    "from_name": from_name,
                    "to_name": to_name,
                    "type": "code" if xref.iscode else "data",
                }
            )

    return results


def xrefs_to_field(queries: List[Dict]) -> List[Dict]:
    """获取结构体字段交叉引用 - 函数式实现"""

    results = []

    for query in queries:
        struct_name = query.get("struct")
        field_name = query.get("field")

        # Find struct
        struct_id = idc.get_struc_id(struct_name)
        if struct_id == ida_idaapi.BADADDR:
            results.append(
                {
                    "struct": struct_name,
                    "field": field_name,
                    "info": "struct not exist"
                }
            )
            continue
        offset = idc.get_member_offset(struct_id, field_name)
        mid = idc.get_member_id(struct_id, offset)
        if not mid:
            results.append(
                {
                    "struct": struct_name,
                    "field": field_name,
                    "info": "field not exist"
                }
            )
            continue
        refs = []
        for xref in idautils.XrefsTo(mid):
            ref_name = get_readble_name(xref.frm)
            refs.append((hex(xref.frm), 'inside '+ref_name))
        results.append(
            {
                "struct": struct_name,
                "field": field_name,
                "offset": hex(offset),
                "xrefs": refs,  # Would be populated with actual xrefs
            }
        )

    return results


def callees(addrs: Union[str, List[str]]) -> List[Dict]:
    """获取被调用函数 - 函数式实现"""

    if isinstance(addrs, str):
        addrs = [addrs]

    results = []

    for addr_str in addrs:
        addr = int(addr_str, 0)
        func = ida_funcs.get_func(addr)

        if not func:
            continue

        callees_list = []

        # Iterate through function code
        curr_addr = func.start_ea
        func_end = idc.find_func_end(curr_addr)
        callees: list[dict[str, str]] = []
        while curr_addr < func_end:
            insn = idaapi.insn_t()
            idaapi.decode_insn(insn, curr_addr)
            if insn.itype in [idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni]:
                target = idc.get_operand_value(curr_addr, 0)
                target_type = idc.get_operand_type(curr_addr, 0)
                if target_type in [idaapi.o_mem, idaapi.o_near, idaapi.o_far]:
                    func_type = (
                        "internal"
                        if idaapi.get_func(target) is not None
                        else "external"
                    )
                    func_name = get_readble_name(target)
                    if func_name is not None:
                        callees.append(
                            {
                                "addr": hex(target),
                                "name": func_name,
                                "type": func_type,
                            }
                        )
            curr_addr = idc.next_head(curr_addr, func_end)

        unique_callee_tuples = {tuple(callee.items()) for callee in callees}
        unique_callees = [dict(callee) for callee in unique_callee_tuples]
        results.append(unique_callees)
    return results


def get_bytes(addrs: Union[str, List[str]]) -> List[Dict]:
    """读取字节 - 函数式实现"""

    if isinstance(addrs, str):
        addrs = [addrs]

    results = []

    for addr_str in addrs:
        addr = int(addr_str, 0)
        size = 16  # Default read size

        data = idaapi.get_bytes(addr, size)
        if data:
            results.append(
                {
                    "address": hex(addr),
                    "bytes": data.hex(),
                    "ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in data),
                }
            )

    return results


def get_int(queries: List[Dict]) -> List[Dict]:
    """读取整数 - 函数式实现"""

    type_map = {
        "i8": ("b", 1),
        "u8": ("B", 1),
        "i16le": ("<h", 2),
        "u16le": ("<H", 2),
        "i16be": (">h", 2),
        "u16be": (">H", 2),
        "i32le": ("<i", 4),
        "u32le": ("<I", 4),
        "i32be": (">i", 4),
        "u32be": (">I", 4),
        "i64le": ("<q", 8),
        "u64le": ("<Q", 8),
        "i64be": (">q", 8),
        "u64be": (">Q", 8),
    }

    results = []

    for query in queries:
        addr = int(query.get("addr"), 0)
        dtype = query.get("type", "u32le")

        if dtype not in type_map:
            continue

        fmt, size = type_map[dtype]
        data = idaapi.get_bytes(addr, size)

        if data:
            value = struct.unpack(fmt, data)[0]
            results.append({"address": hex(addr), "type": dtype, "value": value})

    return results


def read_string(addrs: Union[str, List[str]]) -> List[Dict]:
    """读取字符串 - 函数式实现"""

    if isinstance(addrs, str):
        addrs = [addrs]

    results = []

    for addr_str in addrs:
        addr = int(addr_str, 0)
        string = ida_bytes.get_strlit_contents(addr, -1, 0)

        if string:
            results.append(
                {
                    "address": hex(addr),
                    "string": string.decode("utf-8", errors="replace"),
                    "length": len(string),
                }
            )

    return results

def search_in_strings_window(pattern: str, offset=0, limit=10) -> Dict:
    global global_strings_lists
    try:
        regex = re.compile(pattern, re.I)
    except:
        return {"error": "Invalid regex"}

    matches, found, more = [], 0, False
    for ea, text in global_strings_lists:
        if regex.search(text):
            if found >= offset:
                if len(matches) < limit:
                    matches.append({"addr": hex(ea), "str": text})
                else:
                    more = True
                    break
            found += 1

    return {
        "results": matches,
        "count": len(matches),
        "next": offset + len(matches) if more else None,
        "has_more": more
    }

def get_global_value(queries: Union[str, List[str]]) -> List[Dict]:
    """获取全局变量值 - 函数式实现"""

    if isinstance(queries, str):
        queries = [q.strip() for q in queries.split(",")]

    results = []
    global global_Nams_lists
    for query in queries:
        # Try as address
        try:
            addr = int(query, 0)
        except ValueError:
            # Try as name
            found = False
            for each in global_Nams_lists:
                if each[1] == query:
                    addr = each[0]
                    found = True
            if not found:
                raise ValueError(f"Can't read data at {query}, not a global Name")

        # Read value (assume 4-byte for now)
        try:
            value = ida_bytes.get_dword(addr)
        except Exception as e:
            raise ValueError(f"Can't read data at {query}. Error:{e}")

        results.append(
            {"name_or_addr": query, "address": hex(addr), "value": hex(value)}
        )

    return results


def stack_frame(addrs: Union[str, List[str]]) -> List[Dict]:
    if isinstance(addrs, str):
        addrs = [addrs]

    results = []
    for addr_str in addrs:
        addr = int(addr_str, 0)
        # 获取栈帧 ID
        frame_id = idc.get_frame_id(addr)
        if frame_id == idc.BADADDR:
            continue

        members = []
        # 使用 idautils 直接获取成员信息 (offset, name, size)
        for offset, name, size in idautils.StructMembers(frame_id):
            members.append({
                "offset": hex(offset),
                "name": name,
                "size": size
            })

        results.append({
            "function": hex(addr),
            "frame_size": idc.get_struc_size(frame_id),
            "variables": members
        })
    return results

def declare_stack_variable(items: List[Dict]) -> List[Dict]:
    """定义栈变量: [{"ea": "0x401000", "offset": 0x20, "name": "var_8", "type": "int"}]"""
    """
    items: List[Dict], 每个字典包含:
      - 'ea': 函数内地址
      - 'offset': 栈偏移, 来自 stack_frame 调用的结果中的offset.
      - 'name': 变量名
      - 'type': C 语言类型字符串 (例如 "int", "char[10]", "MyStruct *")
    """
    results = []
    for item in items:
        ea = int(item.get('ea'), 0) if isinstance(item.get('ea'), str) else item.get('ea')
        raw_offset = int(item.get('offset'), 0) if isinstance(item.get('offset'), str) else item.get('offset')

        name = item.get('name')
        type_str = item.get('type', "int")

        pfn = ida_funcs.get_func(ea)
        if not pfn: continue

        # --- 核心转换步骤 ---
        actual_offset = raw_offset - pfn.frsize
        # --------------------

        # 构造类型对象
        tif = ida_typeinf.tinfo_t()
        if not ida_typeinf.parse_decl(tif, None, f"{type_str} dummy;", 0):
            ida_typeinf.parse_decl(tif, None, "char dummy;", 0)

        # 定义/修改栈变量 (根据你之前的报错，使用 4 参数版本)
        success = ida_frame.define_stkvar(pfn, name, actual_offset, tif)

        results.append({"name": name, "status": "success" if success else "failed"})
    return results



def delete_stack_variable(items: List[Dict]) -> List[Dict]:
    """
    删除指定原始偏移(Raw Offset)的栈变量。
    ea: 函数地址
    name: 变量名
    """
    results = []
    for item in items:
        fn_addr = int(item.get('ea'), 0) if isinstance(item.get('ea'), str) else item.get('ea')
        var_name = item.get("name", "")

        try:
            func = idaapi.get_func(fn_addr)
            if not func:
                results.append(
                    {"addr": fn_addr, "name": var_name, "error": "No function found"}
                )
                continue

            frame_tif = ida_typeinf.tinfo_t()
            if not ida_frame.get_func_frame(frame_tif, func):
                results.append(
                    {"addr": fn_addr, "name": var_name, "error": "No frame returned"}
                )
                continue

            idx, udm = frame_tif.get_udm(var_name)
            if not udm:
                results.append(
                    {
                        "addr": fn_addr,
                        "name": var_name,
                        "error": f"{var_name} not found",
                    }
                )
                continue

            tid = frame_tif.get_udm_tid(idx)
            if ida_frame.is_special_frame_member(tid):
                results.append(
                    {
                        "addr": fn_addr,
                        "name": var_name,
                        "error": f"{var_name} is special frame member",
                    }
                )
                continue

            udm = ida_typeinf.udm_t()
            frame_tif.get_udm_by_tid(udm, tid)
            offset = udm.offset // 8
            size = udm.size // 8
            if ida_frame.is_funcarg_off(func, offset):
                results.append(
                    {
                        "addr": fn_addr,
                        "name": var_name,
                        "error": f"{var_name} is argument member",
                    }
                )
                continue

            if not ida_frame.delete_frame_members(func, offset, offset + size):
                results.append(
                    {"addr": fn_addr, "name": var_name, "error": "Failed to delete"}
                )
                continue

            results.append({"addr": fn_addr, "name": var_name, "status": True})
        except Exception as e:
            results.append({"addr": fn_addr, "name": var_name, "error": str(e)})

    return results


def read_struct_define(queries:List[str]):
    """读取结构体 - 包含成员类型"""
    results = []
    for name in queries:
        tif = idaapi.tinfo_t()

        # 尝试最通用的调用方式：传入本地库指针和名称字符串
        # idati 是 IDA 内置的全局变量，代表当前的 Local Types 库
        if not tif.get_named_type(idaapi.get_idati(), str(name)):
            results.append({'fail':f"类型 {name} 不在 Local Types 中"})
            return results

        # 获取 UDT (User Defined Type) 详情
        udt_data = idaapi.udt_type_data_t()
        if not tif.get_udt_details(udt_data):
            results.append({'fail':f"{name} 不是一个结构体或联合体"})
            return results

        members = []
        for udm in udt_data:
            # 注意：在 udt_member_t 中，offset 和 size 通常是以 bit(位) 为单位的
            members.append({
                "name": udm.name,
                "offset": hex(udm.offset // 8),
                "size": udm.size // 8,
                "type": udm.type.dstr() # 关键：返回 C 风格类型字符串
            })

        results.append( {
            "name": name,
            "size": tif.get_size(),
            "members": members
        })
    return results


def search_structs(pattern_str: str, ignore_case: bool = True) -> List[Dict]:
    """
    通过正则表达式搜索结构体
    输入: {"f_regex": "^sock.*", "flags": 0} (flags可选, 如 re.IGNORECASE)
    """
    results = []

    # 预先获取所有结构体列表，避免在循环中重复解析
    all_structs = list(idautils.Structs())

    if ignore_case:
        flags = re.IGNORECASE
    else:
        flags = 0
    try:
        regex = re.compile(pattern_str, flags)
    except re.error as e:
        results.append({"pattern": pattern_str, "error": str(e)})
        return results
    matched = []
    for idx, sid, name in all_structs:
        if regex.search(name):
            matched.append({
                "name": name,
                "id": hex(sid),
                "size": idc.get_struc_size(sid),
                "idx": idx
            })

    results.append({
        "pattern": pattern_str,
        "matches": matched
    })

    return results


def set_lvar_type(items: List[Dict]) -> List[Dict]:
    """
    在 IDA 9.0 中将伪代码变量设置为指定类型并持久化.
    示例参数: [{'ea': 0x180084308, 'var_name': 'v1', 'struct_type': 'int *a;', 'new_name':'v2'}], new_name is Optional
    """
    results = []

    for item in items:
        # 处理地址格式
        ea_raw = item.get('ea')
        ea = int(ea_raw, 0) if isinstance(ea_raw, str) else ea_raw
        var_name = item.get('var_name')
        struct_type = item.get('struct_type', None)
        new_name = item.get('new_name', None)

        success = 'Fail'

        # 1. 获取函数
        func = ida_funcs.get_func(ea)
        if not func:
            results.append({"ea": hex(ea), "var": var_name, "status": success, "msg": "Function not found"})
            continue

        # 2. 反编译
        cfunc = ida_hexrays.decompile(func.start_ea)
        if not cfunc:
            results.append({"ea": hex(ea), "var": var_name, "status": success, "msg": "Decompilation failed"})
            continue
        if new_name:
            if not ida_hexrays.rename_lvar(ea, var_name, new_name):
                results.append({"ea": hex(ea), "var": var_name, "status": success, "msg": "rename fail, maybe auto updated or new_name invalid"})
                continue
            if not struct_type:
                results.append({"ea": hex(ea), "var": var_name, 'new_name': new_name, "status": "OK"})
                continue
        # 3. 构造 tinfo_t 类型
        # 确保以分号结尾以符合 parse_decl 规范
        decl_str = struct_type.strip()
        if not decl_str.endswith(';'):
            decl_str += " dummy;"

        new_type = ida_typeinf.tinfo_t()
        # PT_TYP 表示解析的是类型声明
        if ida_typeinf.parse_decl(new_type, None, decl_str, 0):
            lvars = cfunc.get_lvars()
            var = None
            for lvar in lvars:
                if lvar.name == var_name:
                    var = lvar
            if var:
                    # var.set_lvar_type(new_type)
                    lsi = ida_hexrays.lvar_saved_info_t()
                    lsi.ll = var
                    lsi.type = new_type
                    ida_hexrays.modify_user_lvar_info(func.start_ea, ida_hexrays.MLI_TYPE, lsi)
                    msg = 'type now is: '+ new_type.dstr()
                    success = "OK"
            else:
                msg = f"can't find var name:{var_name}"

        else:
            msg = "parse c defination fail"
        if new_name:
            results.append({
                "ea": hex(ea),
                "var": var_name,
                "new_name": new_name,
                "msg": msg,
                "status": success
            })
        else:
            results.append({
                "ea": hex(ea),
                "var": var_name,
                "msg": msg,
                "status": success
            })

    return results

def set_comments_at_disassembly(items: List[Dict]) -> List[Dict]:
    """设置注释 - 函数式实现"""

    results = []

    for item in items:
        addr = int(item.get('ea'), 0) if isinstance(item.get('ea'), str) else item.get('ea')
        text = item.get("text", "")
        is_repeatable = item.get("repeatable", False)

        success = ida_bytes.set_cmt(addr, text, is_repeatable)

        results.append({"addr": hex(addr), "success": success})

    return results

def add_pseudocode_comment(params: List[Dict]) -> List[Dict]:
    # 1. 获取该地址所属的函数并反编译
    results = []
    for param in params:
        ea = int(param.get('ea'), 0) if isinstance(param.get('ea'), str) else param.get('ea')
        comment_text = param.get('text')
        is_block = True if param.get('flag') == 'block' else False

        cfunc = ida_hexrays.decompile(ea)
        if not cfunc:
            results.append({"addr": hex(ea), "msg":"can't get decompile at ea"})
            continue

        # 2. 获取该地址对应的 ctree 节点 (citem_t)
        item = cfunc.body.find_closest_addr(ea)
        if not item:
            results.append({"addr": hex(ea), "msg":"can't get decompile at ea"})
            continue

        # ida_hexrays.ITP_SEMI (行末注释) 或 ida_hexrays.ITP_BLOCK (块注释)
        tl = ida_hexrays.ITP_BLOCK1 if is_block else ida_hexrays.ITP_SEMI

        loc = ida_hexrays.treeloc_t()
        loc.ea = item.ea
        loc.itp = tl

        # 设置注释
        cfunc.set_user_cmt(loc, comment_text)
        cfunc.save_user_cmts()
        cfunc.refresh_func_ctext()

        results.append({"addr": hex(ea), "success": True})
    return results

def create_struct_from_c(queries: List[str], is_update: bool = False) -> List[Dict]:
    """
    通过 IDA 内置的 C 解析器直接解析并创建结构体，无需正则。
    :queries: 包含 C 语言结构体字符串的列表
    :is_update bool: 是否覆盖已经存在的结构体.
    """
    results = []
    for c_declaration in queries:
        # 1. 调用 idc.parse_decl 单步解析，它的返回值是一个元组 (name, type, fields)
        # flags = 1 代表 PT_TYP (类型解析)
        res = idc.parse_decl(c_declaration, idc.PT_TYP)

        if not res or not res[0]:
            results.append({'name': 'unknown', "status": "IDA parse failed or anonymous struct"})
            continue

        type_name = res[0] # 获取 IDA 解析出来的顶级结构体名称
        if not is_update:
            # 1. 检查是否作为结构体存在
            sid = idc.get_struc_id(type_name)

            # 2. 检查是否作为枚举存在 (核心修改点)
            eid = idc.get_enum(type_name)

            if sid != idc.BADADDR:
                results.append({'name': type_name, "type": "struct", "status": "already exist"})
                continue
            elif eid != idc.BADADDR:
                results.append({'name': type_name, "type": "enum", "status": "already exist"})
                continue


        # 2. 调用 idc.parse_decls 将整段声明真正加入到 Local Types 中
        if idc.parse_decls(c_declaration, 0) != 0:
            results.append({'name': type_name, "status": "Failed to add to Local Types"})
            continue

        sid = idc.import_type(-1, type_name)

        if sid != idc.BADADDR:
            results.append({'name': type_name, "status": "ok"})
        else:
            results.append({'name': type_name, "status": "can't import, name invalid"})

    return results



def define_func(items: List[Dict]) -> List[Dict]:
    """定义函数 - 函数式实现"""

    results = []

    for item in items:
        addr = int(item.get("addr"), 0)
        name = item.get("name")

        # Create function
        success = ida_funcs.add_func(addr)

        if success and name:
            # Set function name
            ida_name.set_name(addr, name, ida_name.SN_CHECK)

        results.append({"address": hex(addr), "name": name, "success": success})

    return results


def define_code(items: List[Dict]) -> List[Dict]:
    """定义代码 - 函数式实现"""

    results = []
    import ida_ua
    for item in items:
        addr = int(item.get("addr"), 0)

        success = ida_ua.create_insn(addr)

        results.append({"address": hex(addr), "success": success})

    return results


def undefine(items: List[Dict]) -> List[Dict]:
    """取消定义 - 函数式实现"""

    results = []
    for item in items:
        addr = int(item.get("addr"), 0)

        # Try to undefine as function first
        func = ida_funcs.get_func(addr)
        if func:
            success = ida_funcs.del_func(addr)
        else:
            # Undefine as data/code
            success = ida_bytes.del_items(addr, ida_bytes.DELIT_SIMPLE)

        results.append({"address": hex(addr), "success": success})

    return results

def find_bytes(patterns: Union[list, str], offset: int = 0, limit: int = 10) -> dict:
    """字节模式搜索，支持分页与截断告知"""
    if isinstance(patterns, str): patterns = [patterns]
    
    results, found, more = [], 0, False
    min_ea, max_ea = idc.get_inf_attr(idc.INF_MIN_EA), idc.get_inf_attr(idc.INF_MAX_EA)

    for pat in patterns:
        curr_ea = min_ea
        pat_len = len(pat.split())
        # 转换 IDA 识别的通配符格式
        normalized = " ".join("?" if t in ("??", "?") else t for t in pat.split())

        while True:
            curr_ea = ida_bytes.find_bytes(normalized, curr_ea, range_end=max_ea)
            if curr_ea == idc.BADADDR: break

            if found >= offset:
                if len(results) < limit:
                    val = ida_bytes.get_bytes(curr_ea, pat_len)
                    results.append({
                        "addr": hex(curr_ea),
                        "hex": val.hex(' ').upper() if val else "",
                        "asm": idc.generate_disasm_line(curr_ea, 0)
                    })
                else:
                    more = True; break
            
            found += 1
            curr_ea += 1 # 继续向后搜索
        if more: break

    return {
        "results": results,
        "count": len(results),
        "next": offset + len(results) if more else None,
        "more": more
    }

def py_eval(code: Annotated[str, "Python code"]) -> dict:
    """Execute Python code in IDA context with accurate error line reporting."""
    stdout_capture = io.StringIO()
    stderr_capture = io.StringIO()
    old_stdout = sys.stdout
    old_stderr = sys.stderr

    # 预定义执行环境 (建议在函数外初始化以提高性能，这里为了完整性保留)
    def lazy_import(module_name):
        try:
            return __import__(module_name)
        except:
            return None

    exec_globals = {
        "__builtins__": __builtins__,
        "idaapi": idaapi,
        "idc": idc,
        "idautils": lazy_import("idautils"),
        "ida_allins": lazy_import("ida_allins"),
        "ida_auto": lazy_import("ida_auto"),
        "ida_bitrange": lazy_import("ida_bitrange"),
        "ida_bytes": ida_bytes,
        "ida_dbg": ida_dbg,
        "ida_dirtree": lazy_import("ida_dirtree"),
        "ida_diskio": lazy_import("ida_diskio"),
        "ida_entry": ida_entry,
        "ida_expr": lazy_import("ida_expr"),
        "ida_fixup": lazy_import("ida_fixup"),
        "ida_fpro": lazy_import("ida_fpro"),
        "ida_frame": ida_frame,
        "ida_funcs": ida_funcs,
        "ida_gdl": lazy_import("ida_gdl"),
        "ida_graph": lazy_import("ida_graph"),
        "ida_hexrays": ida_hexrays,
        "ida_ida": ida_ida,
        "ida_idd": lazy_import("ida_idd"),
        "ida_idp": lazy_import("ida_idp"),
        "ida_ieee": lazy_import("ida_ieee"),
        "ida_kernwin": ida_kernwin,
        "ida_libfuncs": lazy_import("ida_libfuncs"),
        "ida_lines": ida_lines,
        "ida_loader": lazy_import("ida_loader"),
        "ida_merge": lazy_import("ida_merge"),
        "ida_mergemod": lazy_import("ida_mergemod"),
        "ida_moves": lazy_import("ida_moves"),
        "ida_nalt": ida_nalt,
        "ida_name": ida_name,
        "ida_netnode": lazy_import("ida_netnode"),
        "ida_offset": lazy_import("ida_offset"),
        "ida_pro": lazy_import("ida_pro"),
        "ida_problems": lazy_import("ida_problems"),
        "ida_range": lazy_import("ida_range"),
        "ida_regfinder": lazy_import("ida_regfinder"),
        "ida_registry": lazy_import("ida_registry"),
        "ida_search": lazy_import("ida_search"),
        "ida_segment": ida_segment,
        "ida_segregs": lazy_import("ida_segregs"),
        "ida_srclang": lazy_import("ida_srclang"),
        "ida_strlist": lazy_import("ida_strlist"),
        "ida_struct": lazy_import("ida_struct"),
        "ida_tryblks": lazy_import("ida_tryblks"),
        "ida_typeinf": ida_typeinf,
        "ida_ua": lazy_import("ida_ua"),
        "ida_undo": lazy_import("ida_undo"),
        "ida_xref": ida_xref,
        "ida_enum": lazy_import("ida_enum"),
    }
    exec_locals = {}
    result_value = None

    try:
        sys.stdout = stdout_capture
        sys.stderr = stderr_capture

        # 1. 语法解析阶段
        try:
            tree = ast.parse(code, filename="<user_code>")
        except SyntaxError as e:
            # 语法错误直接返回，避免混入 py_eval 的堆栈
            return {
                "result": "",
                "stdout": "",
                "stderr": f'  File "<user_code>", line {e.lineno}\n    {e.text or ""}\nSyntaxError: {e.msg}',
            }

        # 2. 执行逻辑处理
        if not tree.body:
            pass
        elif len(tree.body) == 1 and isinstance(tree.body[0], ast.Expr):
            # 单行表达式
            expr_code = compile(
                ast.Expression(body=tree.body[0].value), "<user_code>", "eval"
            )
            result_value = eval(expr_code, exec_globals, exec_locals)
        else:
            # 多行逻辑 (Jupyter 风格：最后一行如果是表达式则返回其值)
            last_node = tree.body[-1]
            if isinstance(last_node, ast.Expr):
                # 执行前面的语句
                exec_tree = ast.Module(body=tree.body[:-1], type_ignores=[])
                exec(
                    compile(exec_tree, "<user_code>", "exec"), exec_globals, exec_locals
                )
                # 计算最后的表达式
                eval_tree = ast.Expression(body=last_node.value)
                result_value = eval(
                    compile(eval_tree, "<user_code>", "eval"), exec_globals, exec_locals
                )
            else:
                # 全是语句
                exec(compile(tree, "<user_code>", "exec"), exec_globals, exec_locals)
                # 兼容你原有的逻辑：寻找 result 变量或最后一个局部变量
                if "result" in exec_locals:
                    result_value = exec_locals["result"]
                elif exec_locals:
                    result_value = exec_locals[list(exec_locals.keys())[-1]]

        return {
            "result": str(result_value) if result_value is not None else "None",
            "stdout": stdout_capture.getvalue(),
            "stderr": "",
        }

    except Exception:
        # 3. 运行期错误：过滤掉 py_eval 自身的堆栈
        etype, evalue, tb = sys.exc_info()
        # 这里的 [1:] 是关键，它跳过了 py_eval 函数这一层的调用栈
        fmt_exception = traceback.format_exception(etype, evalue, tb.tb_next)

        return {
            "result": "",
            "stdout": stdout_capture.getvalue(),
            "stderr": "".join(fmt_exception),
        }
    finally:
        sys.stdout = old_stdout
        sys.stderr = old_stderr

def init_globals():
    global global_func_lists
    global global_imports_lists
    global global_Nams_lists
    global global_strings_lists
    global global_func_dict

    for i in range(ida_funcs.get_func_qty()):
        func = ida_funcs.getn_func(i)
        if not func:
            continue
        clean_name = get_readble_name(func.start_ea)
        global_func_lists.append((clean_name, func.start_ea, func))

    global_func_dict = {item[0]: item for item in global_func_lists}

    for ea, name in idautils.Names():
        if ida_funcs.get_func(ea) is None:
            global_Nams_lists.append((ea, get_readble_name(ea)))

    nimps = ida_nalt.get_import_module_qty()
    for i in range(0, nimps):
        module_name = ida_nalt.get_import_module_name(i)
        def imp_cb(ea, name, ord):
            global global_imports_lists
            global_imports_lists.append((ea,name or f"ord_{ord}", module_name))
            return True
        ida_nalt.enum_import_names(i, imp_cb)

    strings = idautils.Strings()
    for string in strings:
        global_strings_lists.append((string.ea, str(string)))
    wide_strings = get_wide_strings_manually() # default string length is 5. only support ascii wide characters
    global_strings_lists.extend(wide_strings)


class IDAFunctions:
    """
    IDA功能包装类
    用于在工作进程中调用函数式实现
    """
    def __init__(self):
        init_globals()

    def list_funcs(self, queries: List[Tuple[int, int, str]]) -> Dict:
        return {"functions": list_funcs(queries)}

    def list_globals(self, params: List) -> Dict:
        offset = params[0]
        limit = params[1]
        contain = params[2]
        return {"globals": list_globals(offset, limit, contain)}

    def list_imports(self, params: List) -> Dict:
        offset = params[0]
        limit = params[1]
        contain = params[2]
        return {"imports": list_imports(offset, limit, contain)}

    def get_func_by_addr(self, params: List) -> Dict:
        return {"functions": get_func_by_addr(params)}

    def decompile(self, params: List) -> Dict:
        addr_or_name = params[0]
        offset = params[1]
        limit = params[2]
        return {"result": decompile(addr_or_name, offset, limit)}

    def disasm(self, params: List) -> Dict:
        addr_or_name = params[0]
        offset = params[1]
        limit = params[2]
        return {"result": disasm(addr_or_name, offset, limit)}

    def xrefs_to_addr(self, addrs: List) -> Dict:
        return {"xrefs": xrefs_to_addr(addrs)}

    def xrefs_to_field(self, params: List[Dict]) -> Dict:
        return {"xrefs": xrefs_to_field(params)}

    def callees(self, params: List[str]) -> Dict:
        return {"callees": callees(params)}

    def get_bytes(self, params: List[str]) -> Dict:
        return {"bytes": get_bytes(params)}

    def get_int(self, params: List[Dict]) -> Dict:
        return {"values": get_int(params)}

    def read_string(self, params: List[str]) -> Dict:
        return {"strings": read_string(params)}

    def search_in_strings_window(self, params: Tuple[str, int, int]) -> Dict:
        pattern = params[0]
        offset = params[1]
        limit = params[2]
        return {'results': search_in_strings_window(pattern, offset, limit)}

    def get_global_value(self, params: List[str]) -> Dict:
        return {"values": get_global_value(params)}

    def stack_frame(self, params: List[str]) -> Dict:
        return {"frames": stack_frame(params)}

    def declare_stack_variable(self, params: List[Dict]) -> Dict:
        return {"results": declare_stack_variable(params)}

    def delete_stack_variable(self, params: List[Dict]) -> Dict:
        return {"results": delete_stack_variable(params)}

    def read_struct_define(self, params: List[str]) -> Dict:
        return {"structs": read_struct_define(params)}

    def search_structs(self, params:List) -> Dict:
        pattern_str = params[0]
        ignore_case = params[1]
        return {"structs": search_structs(pattern_str, ignore_case)}

    def set_comments_at_disassembly(self, params:  List[Dict]) -> Dict:
        return {"results": set_comments_at_disassembly(params)}

    def define_func(self, params: List[Dict]) -> Dict:
        return {"results": define_func(params)}

    def define_code(self, params: List[Dict]) -> Dict:
        return {"results": define_code(params)}

    def undefine(self, params: List) -> Dict:
        return {"results": undefine(params)}

    def create_struct_from_c(self, params: List) -> Dict:
        queries = params[0]
        flag = params[1]
        return {'results': create_struct_from_c(queries, flag)}

    def add_pseudocode_comment(self, params: List[Dict]) -> Dict:
        return {'results': add_pseudocode_comment(params)}

    def set_lvar_type(self, params: Dict) -> Dict:
        return {'results': set_lvar_type(params)}

    def find_bytes(self, params: Tuple[str, int, int]) -> Dict:
        patterns = params[0]
        offset = params[1]
        limit = params[2]
        return {'results': find_bytes(patterns, offset, limit)}

    def py_eval(self, code: str) -> Dict:
        return {"result": py_eval(code)}