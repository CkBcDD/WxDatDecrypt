import ctypes
import json
import os
import re
import threading
import heapq
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from ctypes import wintypes
from functools import lru_cache
from pathlib import Path
from typing import Any

import pymem
import yara
from Crypto.Cipher import AES

# 定义必要的常量
PROCESS_ALL_ACCESS = 0x1F0FFF
PAGE_READWRITE = 0x04
MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000

# Constants
IV_SIZE = 16
HMAC_SHA256_SIZE = 64
HMAC_SHA512_SIZE = 64
KEY_SIZE = 32
AES_BLOCK_SIZE = 16
ROUND_COUNT = 256000
PAGE_SIZE = 4096
SALT_SIZE = 16
READ_CHUNK_SIZE = 1 << 20

finish_flag = False


# 定义 MEMORY_BASIC_INFORMATION 结构
class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", ctypes.c_ulong),
        ("RegionSize", ctypes.c_size_t),
        ("State", ctypes.c_ulong),
        ("Protect", ctypes.c_ulong),
        ("Type", ctypes.c_ulong),
    ]


# Windows API Constants
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400

# Load Windows DLLs
kernel32 = ctypes.windll.kernel32


# 打开目标进程
def open_process(pid):
    return ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)


# 读取目标进程内存
def read_process_memory(process_handle, address, size, chunk_size=READ_CHUNK_SIZE):
    data = bytearray()
    offset = 0
    while offset < size:
        to_read = min(chunk_size, size - offset)
        chunk_buffer = ctypes.create_string_buffer(to_read)
        bytes_read = ctypes.c_size_t(0)
        success = ReadProcessMemory(
            process_handle,
            ctypes.c_void_p(address + offset),
            chunk_buffer,
            to_read,
            ctypes.byref(bytes_read),
        )
        if not success or bytes_read.value == 0:
            break
        read_len = bytes_read.value
        data.extend(chunk_buffer.raw[:read_len])
        offset += read_len
        if read_len < to_read:
            break
    return bytes(data) if data else None


# 获取所有内存区域
def get_memory_regions(process_handle):
    regions = []
    mbi = MEMORY_BASIC_INFORMATION()
    address = 0
    while ctypes.windll.kernel32.VirtualQueryEx(
        process_handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)
    ):
        if mbi.State == MEM_COMMIT and mbi.Type == MEM_PRIVATE:
            regions.append((int(mbi.BaseAddress), int(mbi.RegionSize)))
        address += int(mbi.RegionSize)
    return regions


# 导入 Windows API 函数
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
OpenProcess.restype = wintypes.HANDLE

ReadProcessMemory = kernel32.ReadProcessMemory
ReadProcessMemory.argtypes = [
    wintypes.HANDLE,
    wintypes.LPCVOID,
    wintypes.LPVOID,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
ReadProcessMemory.restype = wintypes.BOOL

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wintypes.HANDLE]
CloseHandle.restype = wintypes.BOOL


@lru_cache
def verify(encrypted: bytes, key: bytes) -> bool:
    aes_key = key[:16]
    cipher = AES.new(aes_key, AES.MODE_ECB)
    text = cipher.decrypt(encrypted)

    if text.startswith(b"\xff\xd8\xff"):
        return True
    else:
        return False


def search_memory_chunk(process_handle, base_address, region_size, encrypted, rules):
    """搜索单个内存块"""
    memory = read_process_memory(process_handle, base_address, region_size)
    if not memory:
        return None

    matches = rules.match(data=memory)
    if matches:
        for match in matches:
            if match.rule == "AesKey":
                for string in match.strings:
                    for instance in string.instances:
                        content = instance.matched_data[1:-1]
                        if verify(encrypted, content):
                            return content[:16]
    return None


YARA_RULE_SOURCE = r"""
rule AesKey {
    strings:
        $pattern = /[^a-z0-9][a-z0-9]{32}[^a-z0-9]/
    condition:
        $pattern
}
"""


@lru_cache(maxsize=1)
def load_yara_rules():
    return yara.compile(source=YARA_RULE_SOURCE)


def get_aes_key(encrypted: bytes, pid: int) -> Any:
    process_handle = open_process(pid)
    if not process_handle:
        print(f"无法打开进程 {pid}")
        return ""

    rules = load_yara_rules()

    process_infos = get_memory_regions(process_handle)
    if not process_infos:
        CloseHandle(process_handle)
        return None

    found_result = threading.Event()
    result = [None]

    def process_chunk(base_address: int, region_size: int):
        if found_result.is_set():
            return None
        res = search_memory_chunk(
            process_handle, base_address, region_size, encrypted, rules
        )
        if res:
            result[0] = res
            found_result.set()
        return res

    max_workers = min(32, len(process_infos)) or 1
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(process_chunk, base_address, region_size)
            for base_address, region_size in process_infos
        ]
        for future in as_completed(futures):
            res = future.result()
            if res:
                executor.shutdown(wait=False, cancel_futures=True)
                break

    CloseHandle(process_handle)
    return result[0]


def dump_wechat_info_v4(encrypted: bytes, pid: int) -> bytes:
    process_handle = open_process(pid)
    if not process_handle:
        raise RuntimeError(f"无法打开微信进程: {pid}")

    result = get_aes_key(encrypted, pid)
    if isinstance(result, bytes):
        return result[:16]
    else:
        raise RuntimeError("未找到 AES 密钥")


def sort_template_files_by_date(template_files, limit: int | None = None):
    """
    根据文件路径中的 YYYY-MM 部分，从大到小（降序）排序文件列表。
    """

    def get_date_from_path(filepath):
        """
        从文件路径中提取 YYYY-MM 格式的日期字符串。
        """
        # 使用正则表达式查找形如 "YYYY-MM" 的模式
        # r'(\d{4}-\d{2})' 匹配四个数字-两个数字，并将其捕获为一个组
        match = re.search(r"(\d{4}-\d{2})", str(filepath))
        if match:
            return match.group(1)  # 返回捕获到的日期字符串
        else:
            # 如果没有找到日期模式，可以根据需要处理。
            # 例如，返回一个非常小的字符串，使其在降序排序时排在最后，
            # 或者抛出错误。这里假设所有路径都包含日期。
            # print(f"警告：路径中未找到 YYYY-MM 格式的日期: {filepath}")
            return "0000-00"  # 返回一个默认值，确保排序行为可预测

    if limit is not None:
        return heapq.nlargest(limit, template_files, key=get_date_from_path)
    return sorted(template_files, key=get_date_from_path, reverse=True)


def find_key(
    weixin_dir: Path,
    version: int = 4,
    xor_key_: int | None = None,
    aes_key_: bytes | None = None,
):
    """
    遍历目录下文件, 找到至多 16 个 (.*)_t.dat 文件,
    收集最后两位字节, 选择出现次数最多的两个字节.
    """
    assert version in [3, 4]
    print(f"[+] 微信 {version}, 读取文件, 收集密钥...")

    # 查找所有 _t.dat 结尾的文件
    template_candidates = list(weixin_dir.rglob("*_t.dat"))
    template_files = sort_template_files_by_date(template_candidates)
    if not template_files:
        raise RuntimeError("未找到模板文件")
    recent_template_files = sort_template_files_by_date(template_candidates, limit=16)

    # 收集所有文件最后两个字节
    last_bytes_list = []
    last_bytes_cache: dict[Path, bytes] = {}
    for file in recent_template_files:
        try:
            with open(file, "rb") as f:
                f.seek(-2, os.SEEK_END)
                last_bytes = f.read(2)
                if len(last_bytes) != 2:
                    continue
                last_bytes_list.append(last_bytes)
                last_bytes_cache[file] = last_bytes
        except Exception as e:
            print(f"[-] 读取文件 {file} 失败: {e}")
            continue

    if not last_bytes_list:
        raise RuntimeError("对于 XOR, 未能成功读取任何模板文件")

    # 使用 Counter 统计最常见的字节组合
    counter = Counter(last_bytes_list)
    most_common = counter.most_common(1)[0][0]

    x, y = most_common
    if (xor_key := x ^ 0xFF) == y ^ 0xD9:
        print(f"[+] 找到 XOR 密钥: 0x{xor_key:02X}")
    else:
        raise RuntimeError("未能找到 XOR 密钥")

    if xor_key_:
        if xor_key_ == xor_key:
            print(f"[+] 验证成功")
            return xor_key_, aes_key_
        else:
            raise RuntimeError

    if version == 3:
        return xor_key, b"cfcd208495d565ef"

    ciphertext = b""
    for file in template_files:
        try:
            with open(file, "rb") as f:
                if f.read(6) != b"\x07\x08V2\x08\x07":
                    continue

                tail_bytes = last_bytes_cache.get(file)
                if tail_bytes is None:
                    f.seek(-2, os.SEEK_END)
                    tail_bytes = f.read(2)
                    last_bytes_cache[file] = tail_bytes

                if tail_bytes != most_common:
                    continue

                f.seek(0xF)
                ciphertext = f.read(16)
                if len(ciphertext) == 16:
                    break
        except Exception as e:
            print(f"[-] 读取文件 {file} 失败: {e}")
            continue
    else:
        raise RuntimeError("对于 AES, 未能成功读取任何模板文件")

    try:
        pm = pymem.Pymem("Weixin.exe")
        pid = pm.process_id
        assert isinstance(pid, int)
    except:
        raise RuntimeError("找不到微信进程")

    aes_key = dump_wechat_info_v4(ciphertext, pid)
    print(f"[+] 找到 AES 密钥: {aes_key}")

    return xor_key, aes_key


CONFIG_FILE = "config.json"


def read_key_from_config() -> tuple[int, bytes]:
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            key_dict = json.loads(f.read())

        x, y = key_dict["xor"], key_dict["aes"]
        return x, y.encode()[:16]

    return 0, b""


def store_key(xor_k: int, aes_k: bytes) -> None:
    key_dict = {
        "xor": xor_k,
        "aes": aes_k.decode(),
    }

    with open(CONFIG_FILE, "w") as f:
        f.write(json.dumps(key_dict))
