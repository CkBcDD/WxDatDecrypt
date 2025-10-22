"""
微信数据库密钥提取模块

该模块用于从微信进程内存中提取 AES 和 XOR 密钥,用于解密微信数据库文件。
支持微信版本 3 和版本 4 的密钥提取。
"""

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
from typing import Any, Optional

import pymem
import yara
from Crypto.Cipher import AES

# ==================== 常量定义 ====================

# Windows 进程访问权限
PROCESS_ALL_ACCESS = 0x1F0FFF
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400

# 内存页属性
PAGE_READWRITE = 0x04
MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000

# 加密相关常量
IV_SIZE = 16
HMAC_SHA256_SIZE = 64
HMAC_SHA512_SIZE = 64
KEY_SIZE = 32
AES_BLOCK_SIZE = 16
ROUND_COUNT = 256000
PAGE_SIZE = 4096
SALT_SIZE = 16
READ_CHUNK_SIZE = 1 << 20  # 1MB

# 配置文件路径
CONFIG_FILE = "config.json"

# 全局标志
finish_flag = False


# ==================== Windows API 结构体定义 ====================


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    """Windows 内存基本信息结构体"""

    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", ctypes.c_ulong),
        ("RegionSize", ctypes.c_size_t),
        ("State", ctypes.c_ulong),
        ("Protect", ctypes.c_ulong),
        ("Type", ctypes.c_ulong),
    ]


# ==================== Windows API 函数导入 ====================

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


# ==================== YARA 规则定义 ====================

YARA_RULE_SOURCE = r"""
rule AesKey {
    strings:
        $pattern = /[^a-z0-9][a-z0-9]{32}[^a-z0-9]/
    condition:
        $pattern
}
"""


# ==================== 内存操作函数 ====================


def open_process(pid: int) -> Optional[int]:
    """
    打开目标进程并返回进程句柄

    Args:
        pid: 目标进程 ID

    Returns:
        进程句柄,失败则返回 None
    """
    return ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)


def read_process_memory(
    process_handle: int, address: int, size: int, chunk_size: int = READ_CHUNK_SIZE
) -> Optional[bytes]:
    """
    读取目标进程内存数据

    Args:
        process_handle: 进程句柄
        address: 内存地址
        size: 读取大小
        chunk_size: 每次读取的块大小

    Returns:
        读取的内存数据,失败则返回 None
    """
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


def get_memory_regions(process_handle: int) -> list[tuple[int, int]]:
    """
    获取进程的所有可读内存区域

    Args:
        process_handle: 进程句柄

    Returns:
        内存区域列表,每个元素为 (基地址, 区域大小) 元组
    """
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


# ==================== 密钥验证和搜索 ====================


@lru_cache(maxsize=128)
def verify(encrypted: bytes, key: bytes) -> bool:
    """
    验证密钥是否正确

    通过解密加密数据并检查 JPEG 文件头来验证密钥

    Args:
        encrypted: 加密的数据
        key: 待验证的密钥

    Returns:
        密钥是否正确
    """
    aes_key = key[:16]
    cipher = AES.new(aes_key, AES.MODE_ECB)
    text = cipher.decrypt(encrypted)

    # 检查是否为 JPEG 文件头
    return text.startswith(b"\xff\xd8\xff")


@lru_cache(maxsize=1)
def load_yara_rules() -> yara.Rules:
    """
    加载 YARA 规则

    Returns:
        编译后的 YARA 规则对象
    """
    return yara.compile(source=YARA_RULE_SOURCE)


def search_memory_chunk(
    process_handle: int,
    base_address: int,
    region_size: int,
    encrypted: bytes,
    rules: yara.Rules,
) -> Optional[bytes]:
    """
    在单个内存块中搜索 AES 密钥

    Args:
        process_handle: 进程句柄
        base_address: 内存块基地址
        region_size: 内存块大小
        encrypted: 加密数据样本
        rules: YARA 规则对象

    Returns:
        找到的密钥,未找到则返回 None
    """
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


def get_aes_key(encrypted: bytes, pid: int) -> Optional[bytes]:
    """
    从微信进程内存中提取 AES 密钥

    Args:
        encrypted: 加密数据样本
        pid: 微信进程 ID

    Returns:
        AES 密钥,未找到则返回 None
    """
    process_handle = open_process(pid)
    if not process_handle:
        print(f"[-] 无法打开进程 {pid}")
        return None

    rules = load_yara_rules()
    process_infos = get_memory_regions(process_handle)

    if not process_infos:
        CloseHandle(process_handle)
        return None

    found_result = threading.Event()
    result: list[Optional[bytes]] = [None]

    def process_chunk(base_address: int, region_size: int) -> Optional[bytes]:
        """处理单个内存块的回调函数"""
        if found_result.is_set():
            return None

        res = search_memory_chunk(
            process_handle, base_address, region_size, encrypted, rules
        )

        if res:
            result[0] = res
            found_result.set()

        return res

    # 使用线程池并行搜索
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
    """
    提取微信版本 4 的 AES 密钥

    Args:
        encrypted: 加密数据样本
        pid: 微信进程 ID

    Returns:
        AES 密钥

    Raises:
        RuntimeError: 无法打开进程或未找到密钥
    """
    process_handle = open_process(pid)
    if not process_handle:
        raise RuntimeError(f"无法打开微信进程: {pid}")

    result = get_aes_key(encrypted, pid)
    if isinstance(result, bytes):
        return result[:16]
    else:
        raise RuntimeError("未找到 AES 密钥")


# ==================== 文件操作和密钥提取 ====================


def sort_template_files_by_date(
    template_files: list[Path], limit: Optional[int] = None
) -> list[Path]:
    """
    根据文件路径中的 YYYY-MM 日期部分对文件进行降序排序

    Args:
        template_files: 模板文件路径列表
        limit: 返回的最大文件数量,None 表示返回全部

    Returns:
        排序后的文件路径列表
    """

    def get_date_from_path(filepath: Path) -> str:
        """从文件路径中提取 YYYY-MM 格式的日期字符串"""
        match = re.search(r"(\d{4}-\d{2})", str(filepath))
        if match:
            return match.group(1)
        else:
            # 返回默认值,确保排序行为可预测
            return "0000-00"

    if limit is not None:
        return heapq.nlargest(limit, template_files, key=get_date_from_path)
    return sorted(template_files, key=get_date_from_path, reverse=True)


def find_key(
    weixin_dir: Path,
    version: int = 4,
    xor_key_: Optional[int] = None,
    aes_key_: Optional[bytes] = None,
) -> tuple[int, bytes]:
    """
    查找微信数据库的加密密钥

    通过分析模板文件和进程内存提取 XOR 和 AES 密钥

    Args:
        weixin_dir: 微信数据目录路径
        version: 微信版本 (3 或 4)
        xor_key_: 已知的 XOR 密钥 (用于验证)
        aes_key_: 已知的 AES 密钥 (用于验证)

    Returns:
        (xor_key, aes_key) 元组

    Raises:
        RuntimeError: 未找到模板文件、密钥提取失败等错误
    """
    assert version in [3, 4], "版本必须为 3 或 4"
    print(f"[+] 微信版本 {version}, 开始读取文件并收集密钥...")

    # 查找所有模板文件 (_t.dat)
    template_candidates = list(weixin_dir.rglob("*_t.dat"))
    template_files = sort_template_files_by_date(template_candidates)

    if not template_files:
        raise RuntimeError("未找到模板文件")

    recent_template_files = sort_template_files_by_date(template_candidates, limit=16)

    # ========== 提取 XOR 密钥 ==========
    # 收集所有文件的最后两个字节
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
        raise RuntimeError("未能成功读取任何模板文件以提取 XOR 密钥")

    # 统计最常见的字节组合
    counter = Counter(last_bytes_list)
    most_common = counter.most_common(1)[0][0]

    x, y = most_common
    if (xor_key := x ^ 0xFF) == y ^ 0xD9:
        print(f"[+] 找到 XOR 密钥: 0x{xor_key:02X}")
    else:
        raise RuntimeError("未能找到有效的 XOR 密钥")

    # 如果提供了已知密钥,进行验证
    if xor_key_:
        if xor_key_ == xor_key:
            print("[+] XOR 密钥验证成功")
            if aes_key_ is None:
                raise RuntimeError("AES 密钥不能为 None")
            return xor_key_, aes_key_
        else:
            raise RuntimeError("XOR 密钥验证失败")

    # 版本 3 使用固定的 AES 密钥
    if version == 3:
        return xor_key, b"cfcd208495d565ef"

    # ========== 提取 AES 密钥 (版本 4) ==========
    ciphertext = b""

    for file in template_files:
        try:
            with open(file, "rb") as f:
                # 检查文件头
                if f.read(6) != b"\x07\x08V2\x08\x07":
                    continue

                # 检查文件尾部字节
                tail_bytes = last_bytes_cache.get(file)
                if tail_bytes is None:
                    f.seek(-2, os.SEEK_END)
                    tail_bytes = f.read(2)
                    last_bytes_cache[file] = tail_bytes

                if tail_bytes != most_common:
                    continue

                # 读取加密数据
                f.seek(0xF)
                ciphertext = f.read(16)

                if len(ciphertext) == 16:
                    break
        except Exception as e:
            print(f"[-] 读取文件 {file} 失败: {e}")
            continue
    else:
        raise RuntimeError("未能成功读取任何模板文件以提取 AES 密钥")

    # 从微信进程内存中提取 AES 密钥
    try:
        pm = pymem.Pymem("Weixin.exe")
        pid = pm.process_id
        assert isinstance(pid, int)
    except Exception:
        raise RuntimeError("找不到微信进程,请确保微信正在运行")

    aes_key = dump_wechat_info_v4(ciphertext, pid)
    print(f"[+] 找到 AES 密钥: {aes_key.hex()}")

    return xor_key, aes_key


# ==================== 配置文件操作 ====================


def read_key_from_config() -> tuple[int, bytes]:
    """
    从配置文件中读取已保存的密钥

    Returns:
        (xor_key, aes_key) 元组,如果配置文件不存在则返回 (0, b"")
    """
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            key_dict = json.loads(f.read())

        xor_key = key_dict["xor"]
        aes_key = key_dict["aes"].encode()[:16]
        return xor_key, aes_key

    return 0, b""


def store_key(xor_k: int, aes_k: bytes) -> None:
    """
    将密钥保存到配置文件

    Args:
        xor_k: XOR 密钥
        aes_k: AES 密钥
    """
    key_dict = {
        "xor": xor_k,
        "aes": aes_k.decode(),
    }

    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        f.write(json.dumps(key_dict, indent=2))
