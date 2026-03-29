import idapro
import ida_typeinf
import string
import ida_nalt
import idc
import ida_name
import idautils
import ida_bytes
import ida_segment

def debug_stop():
    import pdb
    pdb.set_trace()

def get_readble_name(func_ea):
    name = idc.get_name(func_ea)
    if not name:
        func_name = idc.get_func_name(func_ea)
        if not func_name:
            clean_name = hex(func_ea)
            return clean_name
        name = func_name
    clean_name = ida_name.demangle_name(name, 8)
    if clean_name == None:
        clean_name = name
    return clean_name

def is_printable(data, encoding='utf-8', threshold=0.9):
    try:
        text = data.decode(encoding)
        if not text: return False
        # 计算可打印字符所占比例
        printable_chars = set(string.printable)
        count = sum(1 for char in text if char in printable_chars)
        return (count / len(text)) >= threshold
    except:
        return False

def get_wide_strings_manually(min_len=5):
    found_count = 0
    # 遍历所有段
    wide_string = []
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        start = seg.start_ea
        end = seg.end_ea

        curr = start
        while curr < end:
            # 尝试在当前位置获取 UTF-16 字符串内容
            # STRTYPE_C_16 = 1 (Windows Unicode)
            content = ida_bytes.get_strlit_contents(curr, -1, ida_nalt.STRTYPE_C_16)

            if content and len(content) >= min_len and is_printable(content): # UTF-16 每个字符2字节
                try:

                    text = content.decode('utf-8')
                    wide_string.append((curr, text))
                    found_count += 1
                    curr += len(content)*2
                except UnicodeDecodeError:
                    curr += 2
            else:
                curr += 2 # UTF-16 通常是对齐的，每次移动2字节

    return wide_string

def format_struct(obj, indent=0):
    """
    带 {} 和 [] 分隔的结构化格式化函数，返回字符串。
    支持内容截断（1000字符/项）。
    """
    lines = []
    space = "  " * indent
    next_space = "  " * (indent + 1)
    limit = 1000

    # 1. 处理 字典 或 类对象
    if isinstance(obj, dict) or hasattr(obj, "__dict__"):
        data = obj if isinstance(obj, dict) else obj.__dict__
        if not data:
            return "{}"
            
        lines.append("{\n")
        items = list(data.items())
        for i, (k, v) in enumerate(items):
            if i >= limit:
                lines.append(f"{next_space}... (truncated)\n")
                break
            # 拼接 Key 并递归获取 Value 的字符串
            val_str = format_struct(v, indent + 1)
            comma = "," if i < len(items) - 1 else ""
            lines.append(f"{next_space}'{k}': {val_str}{comma}\n")
        lines.append(f"{space}}}")

    # 2. 处理 列表/元组/集合
    elif isinstance(obj, (list, tuple, set)):
        if not obj:
            return "[]"
            
        lines.append("[\n")
        obj_list = list(obj)
        for i, item in enumerate(obj_list):
            if i >= limit:
                lines.append(f"{next_space}... (truncated)\n")
                break
            val_str = format_struct(item, indent + 1)
            comma = "," if i < len(obj_list) - 1 else ""
            lines.append(f"{next_space}{val_str}{comma}\n")
        lines.append(f"{space}]")

    # 3. 处理 基础类型
    else:
        if isinstance(obj, str):
            content = obj[:limit]
            res = f"'{content}...'" if len(obj) > limit else f"'{obj}'"
        else:
            s_obj = str(obj)
            res = s_obj[:limit] + "..." if len(s_obj) > limit else s_obj
        return res

    return "".join(lines)