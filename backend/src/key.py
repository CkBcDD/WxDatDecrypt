"""
微信数据库密钥提取模块

该模块用于从微信进程内存中提取 AES 和 XOR 密钥,用于解密微信数据库文件。
支持微信版本 3 和版本 4 的密钥提取。
"""

import json
import logging
import os
import re
import threading
from collections import Counter
from ctypes import Structure, c_void_p, c_ulong, c_size_t
from functools import lru_cache
from pathlib import Path
from typing import Optional, NamedTuple

import pymem
import yara
from Crypto.Cipher import AES
from pydantic import BaseModel, Field

# ==================== 日志配置 ====================

logger = logging.getLogger(__name__)


# ==================== 数据模型定义 ====================


class KeyConfig(BaseModel):
    """密钥配置模型"""

    xor: int = Field(..., description="XOR 密钥")
    aes: str = Field(..., description="AES 密钥")

    class Config:
        """Pydantic 配置"""

        frozen = True

    def to_file(self, path: Path) -> None:
        """保存配置到文件"""
        path.write_text(self.model_dump_json(indent=2), encoding="utf-8")

    @classmethod
    def from_file(cls, path: Path) -> Optional["KeyConfig"]:
        """从文件读取配置"""
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return cls(**data)
        except Exception as e:
            logger.error(f"读取配置文件失败: {e}")
            return None


class ExtractedKeys(NamedTuple):
    """提取的密钥元组"""

    xor_key: int
    aes_key: bytes


class MemoryConstants:
    """内存相关常量"""

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


class CipherConstants:
    """密码学常量"""

    TEMPLATE_FILE_SUFFIX = "_t.dat"
    TEMPLATE_FILE_HEADER = b"\x07\x08V2\x08\x07"
    TEMPLATE_CIPHERTEXT_OFFSET = 0xF
    TEMPLATE_CIPHERTEXT_SIZE = 16
    TEMPLATE_RECENT_LIMIT = 16

    JPEG_HEADER = b"\xff\xd8\xff"
    AES_KEY_SIZE_16 = 16


# ==================== Windows API 结构体定义 ====================


class MEMORY_BASIC_INFORMATION(Structure):
    """Windows 内存基本信息结构体"""

    _fields_ = [
        ("BaseAddress", c_void_p),
        ("AllocationBase", c_void_p),
        ("AllocationProtect", c_ulong),
        ("RegionSize", c_size_t),
        ("State", c_ulong),
        ("Protect", c_ulong),
        ("Type", c_ulong),
    ]


# ==================== 进程管理 ====================


class WechatProcessManager:
    """微信进程管理器（单例模式）"""

    _instance: Optional["WechatProcessManager"] = None
    _lock = threading.Lock()

    def __new__(cls) -> "WechatProcessManager":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        if hasattr(self, "_initialized") and self._initialized:
            return

        self._pm: Optional[pymem.Pymem] = None
        self._pid: Optional[int] = None
        self._initialized = True
        logger.debug("WechatProcessManager 初始化完成")

    def get_process(self) -> tuple[pymem.Pymem, int]:
        """
        获取微信进程对象和 PID,如果已存在则复用

        Returns:
            (pymem.Pymem 对象, 进程 ID) 元组

        Raises:
            RuntimeError: 找不到微信进程
        """
        alive = self._is_process_alive()
        if alive and self._pm is not None and self._pid is not None:
            return self._pm, self._pid
        if alive:
            raise RuntimeError("进程对象或 PID 为空")

        try:
            self._pm = pymem.Pymem("Weixin.exe")
            self._pid = self._pm.process_id
            logger.info(f"已打开微信进程,PID: {self._pid}")
            assert self._pm is not None
            assert self._pid is not None
            return self._pm, self._pid
        except Exception as e:
            raise RuntimeError(f"找不到微信进程,请确保微信正在运行: {e}") from e

    def close(self) -> None:
        """关闭进程句柄"""
        if self._pm is not None:
            try:
                self._pm.close_process()
                logger.info("已关闭微信进程句柄")
            except Exception as e:
                logger.error(f"关闭进程句柄失败: {e}")
            finally:
                self._pm = None
                self._pid = None

    def _is_process_alive(self) -> bool:
        """检查进程是否仍然存在"""
        if self._pm is None or self._pid is None:
            return False
        try:
            return bool(self._pm.process_handle)
        except Exception:
            return False

    def __enter__(self) -> "WechatProcessManager":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()


# ==================== 密钥验证 ====================


class KeyValidator:
    """密钥验证器"""

    @staticmethod
    @lru_cache(maxsize=128)
    def verify_aes_key(encrypted: bytes, key: bytes) -> bool:
        """
        验证 AES 密钥是否正确

        通过解密加密数据并检查 JPEG 文件头来验证密钥

        Args:
            encrypted: 加密的数据
            key: 待验证的密钥 (至少 16 字节)

        Returns:
            密钥是否正确
        """
        try:
            aes_key = key[: CipherConstants.AES_KEY_SIZE_16]
            cipher = AES.new(aes_key, AES.MODE_ECB)
            plaintext = cipher.decrypt(encrypted)
            return plaintext.startswith(CipherConstants.JPEG_HEADER)
        except Exception as e:
            logger.debug(f"验证密钥失败: {e}")
            return False


# ==================== YARA 规则和密钥扫描 ====================


class YaraRuleManager:
    """YARA 规则管理器"""

    YARA_RULE_SOURCE = r"""
        rule AesKey {
            strings:
                $pattern = /[^a-z0-9][a-z0-9]{32}[^a-z0-9]/
            condition:
                $pattern
        }
    """

    @staticmethod
    @lru_cache(maxsize=1)
    def _load_rules() -> yara.Rules:
        """加载 YARA 规则"""
        return yara.compile(source=YaraRuleManager.YARA_RULE_SOURCE)

    @staticmethod
    def scan_process_for_aes_key(encrypted: bytes, pid: int) -> Optional[bytes]:
        """
        从微信进程内存中扫描 AES 密钥

        Args:
            encrypted: 加密数据样本
            pid: 微信进程 ID

        Returns:
            AES 密钥,未找到则返回 None
        """
        try:
            rules = YaraRuleManager._load_rules()
            logger.info(f"开始在进程 {pid} 中扫描 AES 密钥...")

            matches = rules.match(pid=pid)

            if not matches:
                logger.warning(f"在进程 {pid} 中未找到匹配项")
                return None

            for match in matches:
                if match.rule != "AesKey":
                    continue

                for string in match.strings:
                    for instance in string.instances:
                        content = instance.matched_data[1:-1]
                        if KeyValidator.verify_aes_key(encrypted, content):
                            logger.info("找到有效的 AES 密钥")
                            return content[: CipherConstants.AES_KEY_SIZE_16]

            logger.warning("未找到有效的 AES 密钥")
            return None

        except Exception as e:
            logger.error(f"YARA 扫描失败: {e}")
            return None


# ==================== 文件处理 ====================


class TemplateFileHandler:
    """模板文件处理器"""

    @staticmethod
    def find_template_files(weixin_dir: Path) -> list[Path]:
        """查找所有模板文件 (_t.dat)"""
        files = list(weixin_dir.rglob(f"*{CipherConstants.TEMPLATE_FILE_SUFFIX}"))
        logger.info(f"找到 {len(files)} 个模板文件")
        return files

    @staticmethod
    def sort_by_date(files: list[Path], limit: Optional[int] = None) -> list[Path]:
        """
        根据文件路径中的 YYYY-MM 日期部分对文件进行排序

        Args:
            files: 文件路径列表
            limit: 返回的最大文件数量

        Returns:
            排序后的文件路径列表
        """

        def extract_date(filepath: Path) -> str:
            match = re.search(r"(\d{4}-\d{2})", str(filepath))
            return match.group(1) if match else "0000-00"

        sorted_files = sorted(files, key=extract_date, reverse=True)
        return sorted_files[:limit] if limit else sorted_files

    @staticmethod
    def read_last_bytes(file_path: Path, size: int = 2) -> Optional[bytes]:
        """读取文件末尾指定字节数"""
        try:
            with open(file_path, "rb") as f:
                f.seek(-size, os.SEEK_END)
                return f.read(size)
        except Exception as e:
            logger.warning(f"读取文件 {file_path} 末尾字节失败: {e}")
            return None

    @staticmethod
    def read_ciphertext(file_path: Path) -> Optional[bytes]:
        """读取模板文件中的密文"""
        try:
            with open(file_path, "rb") as f:
                # 检查文件头
                if (
                    f.read(len(CipherConstants.TEMPLATE_FILE_HEADER))
                    != CipherConstants.TEMPLATE_FILE_HEADER
                ):
                    return None

                # 跳转到密文位置
                f.seek(CipherConstants.TEMPLATE_CIPHERTEXT_OFFSET)
                ciphertext = f.read(CipherConstants.TEMPLATE_CIPHERTEXT_SIZE)

                return (
                    ciphertext
                    if len(ciphertext) == CipherConstants.TEMPLATE_CIPHERTEXT_SIZE
                    else None
                )
        except Exception as e:
            logger.warning(f"读取文件 {file_path} 密文失败: {e}")
            return None


# ==================== 密钥提取逻辑 ====================


class KeyExtractor:
    """密钥提取器"""

    def __init__(self, weixin_dir: Path, version: int = 4):
        """
        初始化密钥提取器

        Args:
            weixin_dir: 微信数据目录路径
            version: 微信版本 (3 或 4)

        Raises:
            ValueError: 版本号无效
        """
        if version not in [3, 4]:
            raise ValueError("微信版本必须为 3 或 4")

        self.weixin_dir = Path(weixin_dir)
        self.version = version
        self.process_manager = WechatProcessManager()
        logger.info(f"初始化 KeyExtractor (版本 {version})")

    def _extract_xor_key(self) -> int:
        """
        提取 XOR 密钥

        Returns:
            XOR 密钥

        Raises:
            RuntimeError: 未找到有效的 XOR 密钥
        """
        template_files = TemplateFileHandler.find_template_files(self.weixin_dir)
        if not template_files:
            raise RuntimeError("未找到模板文件")

        recent_files = TemplateFileHandler.sort_by_date(
            template_files, limit=CipherConstants.TEMPLATE_RECENT_LIMIT
        )

        last_bytes_list = []
        for file in recent_files:
            last_bytes = TemplateFileHandler.read_last_bytes(file)
            if last_bytes and len(last_bytes) == 2:
                last_bytes_list.append(last_bytes)

        if not last_bytes_list:
            raise RuntimeError("未能成功读取任何模板文件以提取 XOR 密钥")

        # 统计最常见的字节组合
        counter = Counter(last_bytes_list)
        most_common = counter.most_common(1)[0][0]
        x, y = most_common

        xor_key = x ^ 0xFF
        if xor_key == y ^ 0xD9:
            logger.info(f"找到 XOR 密钥: 0x{xor_key:02X}")
            return xor_key
        else:
            raise RuntimeError("未能找到有效的 XOR 密钥")

    def _extract_aes_key(self) -> bytes:
        """
        提取 AES 密钥

        Returns:
            AES 密钥

        Raises:
            RuntimeError: 未找到 AES 密钥
        """
        template_files = TemplateFileHandler.find_template_files(self.weixin_dir)
        if not template_files:
            raise RuntimeError("未找到模板文件")

        # 版本 3 使用固定密钥
        if self.version == 3:
            logger.info("微信版本 3 使用固定 AES 密钥")
            return b"cfcd208495d565ef"

        # 版本 4: 从进程内存扫描
        ciphertext = None
        sorted_files = TemplateFileHandler.sort_by_date(template_files)

        for file in sorted_files:
            ciphertext = TemplateFileHandler.read_ciphertext(file)
            if ciphertext:
                logger.info(f"从 {file} 读取到密文")
                break

        if not ciphertext:
            raise RuntimeError("未能从模板文件中读取密文")

        _, pid = self.process_manager.get_process()
        aes_key = YaraRuleManager.scan_process_for_aes_key(ciphertext, pid)

        if not aes_key:
            raise RuntimeError("未找到 AES 密钥")

        logger.info(f"找到 AES 密钥: {aes_key.decode('ascii')}")
        return aes_key

    def extract(
        self,
        xor_key_: Optional[int] = None,
        aes_key_: Optional[bytes] = None,
    ) -> ExtractedKeys:
        """
        提取密钥

        Args:
            xor_key_: 已知的 XOR 密钥 (用于验证)
            aes_key_: 已知的 AES 密钥 (用于验证)

        Returns:
            ExtractedKeys 对象

        Raises:
            RuntimeError: 密钥验证失败或提取失败
        """
        logger.info(f"微信版本 {self.version}, 开始读取文件并收集密钥...")

        xor_key = self._extract_xor_key()

        # 验证已知的 XOR 密钥
        if xor_key_ is not None:
            if xor_key != xor_key_:
                raise RuntimeError("XOR 密钥验证失败")
            logger.info("XOR 密钥验证成功")

        aes_key = self._extract_aes_key()

        # 验证已知的 AES 密钥
        if aes_key_ is not None:
            if aes_key != aes_key_:
                raise RuntimeError("AES 密钥验证失败")
            logger.info("AES 密钥验证成功")

        return ExtractedKeys(xor_key, aes_key)


# ==================== 配置管理 ====================


class KeyConfigManager:
    """密钥配置文件管理器"""

    def __init__(self, config_path: Path):
        """
        初始化配置管理器

        Args:
            config_path: 配置文件路径
        """
        self.config_path = Path(config_path)

    def read(self) -> Optional[KeyConfig]:
        """读取配置"""
        return KeyConfig.from_file(self.config_path)

    def write(self, xor_key: int, aes_key: bytes) -> None:
        """写入配置"""
        config = KeyConfig(xor=xor_key, aes=aes_key.decode())
        config.to_file(self.config_path)
        logger.info(f"密钥已保存到 {self.config_path}")

    def get_or_extract(self, weixin_dir: Path, version: int = 4) -> ExtractedKeys:
        """
        获取密钥,如果不存在则自动提取

        Args:
            weixin_dir: 微信数据目录
            version: 微信版本

        Returns:
            ExtractedKeys 对象
        """
        config = self.read()
        if config:
            logger.info("从配置文件读取密钥")
            return ExtractedKeys(config.xor, config.aes.encode()[:16])

        logger.info("配置文件不存在,开始提取密钥...")
        extractor = KeyExtractor(weixin_dir, version)
        keys = extractor.extract()
        self.write(keys.xor_key, keys.aes_key)
        return keys
