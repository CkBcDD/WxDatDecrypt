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


# ==================== 进程句柄管理 ====================


class ProcessHandleManager:
    """微信进程句柄管理器,支持句柄复用"""

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self._pm: Optional[pymem.Pymem] = None
        self._pid: Optional[int] = None
        self._initialized = True

    def get_process(self) -> tuple[pymem.Pymem, int]:
        """
        获取微信进程对象和 PID,如果已存在则复用

        Returns:
            (pymem.Pymem 对象, 进程 ID) 元组

        Raises:
            RuntimeError: 找不到微信进程
        """
        if self._pm is not None and self._pid is not None:
            try:
                # 验证进程是否仍然存在
                if self._pm.process_handle:
                    return self._pm, self._pid
            except Exception:
                # 进程已关闭,需要重新打开
                self._pm = None
                self._pid = None

        try:
            self._pm = pymem.Pymem("Weixin.exe")
            self._pid = self._pm.process_id
            assert isinstance(self._pid, int)
            print(f"[+] 已打开微信进程,PID: {self._pid}")
            return self._pm, self._pid
        except Exception as e:
            raise RuntimeError(f"找不到微信进程,请确保微信正在运行: {e}")

    def close(self):
        """关闭进程句柄"""
        if self._pm is not None:
            try:
                self._pm.close_process()
                print("[+] 已关闭微信进程句柄")
            except Exception as e:
                print(f"[-] 关闭进程句柄失败: {e}")
            finally:
                self._pm = None
                self._pid = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


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


def get_aes_key(encrypted: bytes, pid: int) -> Optional[bytes]:
    """
    从微信进程内存中提取 AES 密钥

    使用 YARA 的 pid 参数直接扫描进程内存,避免手动读取

    Args:
        encrypted: 加密数据样本
        pid: 微信进程 ID

    Returns:
        AES 密钥,未找到则返回 None
    """
    try:
        rules = load_yara_rules()

        # 直接使用 YARA 扫描进程内存
        print(f"[+] 开始在进程 {pid} 中扫描 AES 密钥...")
        matches = rules.match(pid=pid)

        if not matches:
            print(f"[-] 在进程 {pid} 中未找到有效的 AES 密钥")
            return None

        for match in matches:
            if match.rule != "AesKey":
                continue

            for string in match.strings:
                for instance in string.instances:
                    content = instance.matched_data[1:-1]
                    # 验证找到的密钥
                    if verify(encrypted, content):
                        print(f"[+] 在进程 {pid} 中找到有效的 AES 密钥")
                        return content[:16]

        print(f"[-] 在进程 {pid} 中未找到有效的 AES 密钥")
        return None

    except Exception as e:
        print(f"[-] YARA 扫描失败: {e}")
        return None


def dump_wechat_info_v4(encrypted: bytes, pid: int) -> bytes:
    """
    提取微信版本 4 的 AES 密钥

    Args:
        encrypted: 加密数据样本
        pid: 微信进程 ID

    Returns:
        AES 密钥

    Raises:
        RuntimeError: 未找到密钥
    """
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

    # 使用进程句柄管理器
    handle_manager = ProcessHandleManager()

    try:
        # 查找所有模板文件 (_t.dat)
        template_candidates = list(weixin_dir.rglob("*_t.dat"))
        template_files = sort_template_files_by_date(template_candidates)

        if not template_files:
            raise RuntimeError("未找到模板文件")

        recent_template_files = sort_template_files_by_date(
            template_candidates, limit=16
        )

        # ========== 提取 XOR 密钥 ==========
        # 收集所有文件的最后两个字节
        last_bytes_list = []

        for file in recent_template_files:
            try:
                with open(file, "rb") as f:
                    f.seek(-2, os.SEEK_END)
                    last_bytes = f.read(2)

                    if len(last_bytes) != 2:
                        continue

                    last_bytes_list.append(last_bytes)
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

        # 关键修复: 遍历所有文件,而不是依赖缓存
        for file in template_files:
            try:
                with open(file, "rb") as f:
                    # 检查文件头
                    if f.read(6) != b"\x07\x08V2\x08\x07":
                        continue

                    # 检查文件尾部字节
                    f.seek(-2, os.SEEK_END)
                    tail_bytes = f.read(2)

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

        # 从微信进程内存中提取 AES 密钥 (复用句柄)
        _, pid = handle_manager.get_process()
        aes_key = dump_wechat_info_v4(ciphertext, pid)
        print(f"[+] 找到 AES 密钥: {aes_key.decode('ascii')}")

        return xor_key, aes_key

    finally:
        # 确保资源释放 (可选: 如果需要保持句柄打开供后续使用,可以不调用 close)
        # handle_manager.close()
        pass


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
