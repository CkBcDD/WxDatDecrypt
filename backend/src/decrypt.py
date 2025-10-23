"""
微信 .dat 文件解密模块

支持三个版本的 .dat 文件解密:
- v0: 仅使用 XOR 密钥 (微信 3.x 及更早版本)
- v1: 使用固定 AES 密钥 + XOR 密钥 (微信 4.0.x)
- v2: 使用动态 AES 密钥 + XOR 密钥 (微信 4.1.x 及更高版本)
"""

import logging
import struct
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path
from typing import NamedTuple

import numpy as np
from Crypto.Cipher import AES
from Crypto.Util import Padding
from numba import njit


logger = logging.getLogger(__name__)


class DatVersion(Enum):
    """DAT 文件版本枚举"""

    V0_LEGACY = 0
    V1_FIXED_AES = 1
    V2_DYNAMIC_AES = 2


class DecryptResult(NamedTuple):
    """解密结果"""

    version: DatVersion
    data: bytes


@dataclass
class DatConfig:
    """DAT 文件解密配置"""

    V1_AES_KEY: bytes = b"cfcd208495d565ef"
    HEADER_SIZE: int = 0x0F
    SIGNATURE_V1: bytes = b"\x07\x08V1\x08\x07"
    SIGNATURE_V2: bytes = b"\x07\x08V2\x08\x07"
    SIGNATURE_SIZE: int = 6
    AES_KEY_SIZE: int = 16
    HEADER_STRUCT_FORMAT: str = "<6sLLx"


class DatDecryptError(Exception):
    """DAT 文件解密异常基类"""

    pass


class InvalidHeaderError(DatDecryptError):
    """无效的文件头"""

    pass


class InvalidKeyError(DatDecryptError):
    """无效的密钥"""

    pass


class FileReadError(DatDecryptError):
    """文件读取异常"""

    pass


@njit(cache=True, fastmath=True)
def _xor_inplace(buf: np.ndarray, xor_byte: np.uint8) -> None:
    """原地执行 XOR 操作"""
    for i in range(buf.size):
        buf[i] ^= xor_byte


class DatDecryptor:
    """DAT 文件解密器"""

    def __init__(self, config: DatConfig | None = None) -> None:
        """
        初始化解密器

        Args:
            config: 解密配置,使用默认配置则为 None
        """
        self.config = config or DatConfig()
        logger.debug(f"DatDecryptor initialized with config: {self.config}")

    def decrypt(
        self,
        input_file: str | Path,
        xor_key: int,
        aes_key: bytes | None = None,
    ) -> DecryptResult:
        """
        自动识别 .dat 文件版本并解密

        Args:
            input_file: 输入的 .dat 文件路径
            xor_key: XOR 解密密钥 (0-255)
            aes_key: AES 解密密钥 (16字节),仅 v2 版本必须提供

        Returns:
            DecryptResult: 包含版本号和解密后数据的结果

        Raises:
            FileReadError: 文件读取失败
            InvalidHeaderError: 文件头无效
            InvalidKeyError: 密钥格式错误
        """
        path = self._validate_input_file(input_file)
        version = self._detect_version(path)

        logger.info(f"Detected version: {version.name} for file: {path.name}")

        match version:
            case DatVersion.V1_FIXED_AES:
                data = self._decrypt_v1_v2(path, xor_key)
            case DatVersion.V2_DYNAMIC_AES:
                self._validate_aes_key(aes_key)
                data = self._decrypt_v1_v2(path, xor_key, aes_key)
            case DatVersion.V0_LEGACY:
                data = self._decrypt_v0(path, xor_key)

        logger.debug(f"Decryption completed, data size: {len(data)} bytes")
        return DecryptResult(version=version, data=data)

    def _validate_input_file(self, input_file: str | Path) -> Path:
        """验证输入文件"""
        try:
            path = Path(input_file)
            if not path.exists():
                raise FileNotFoundError(f"File not found: {path}")
            if not path.is_file():
                raise ValueError(f"Path is not a file: {path}")
            return path
        except (OSError, TypeError) as e:
            logger.error(f"File validation failed: {e}")
            raise FileReadError(f"Unable to access file: {input_file}") from e

    def _detect_version(self, path: Path) -> DatVersion:
        """检测 DAT 文件版本"""
        try:
            with path.open("rb") as f:
                header = f.read(self.config.SIGNATURE_SIZE)

            if len(header) < self.config.SIGNATURE_SIZE:
                logger.warning("Header too short, defaulting to v0")
                return DatVersion.V0_LEGACY

            if header == self.config.SIGNATURE_V1:
                return DatVersion.V1_FIXED_AES
            elif header == self.config.SIGNATURE_V2:
                return DatVersion.V2_DYNAMIC_AES
            else:
                logger.debug(f"Unknown signature: {header.hex()}, defaulting to v0")
                return DatVersion.V0_LEGACY

        except OSError as e:
            logger.error(f"Failed to detect version: {e}")
            raise FileReadError(f"Cannot read file header: {path}") from e

    def _validate_aes_key(self, aes_key: bytes | None) -> None:
        """验证 AES 密钥"""
        if aes_key is None:
            raise InvalidKeyError("AES key is required for v2 version")
        if not isinstance(aes_key, bytes):
            raise InvalidKeyError("AES key must be bytes")
        if len(aes_key) != self.config.AES_KEY_SIZE:
            raise InvalidKeyError(
                f"AES key must be {self.config.AES_KEY_SIZE} bytes, "
                f"got {len(aes_key)}"
            )

    def _decrypt_v0(self, path: Path, xor_key: int) -> bytes:
        """
        解密 v0 版本的 .dat 文件(仅 XOR 加密)

        Args:
            path: 文件路径
            xor_key: XOR 密钥

        Returns:
            bytes: 解密后的数据
        """
        logger.debug("Decrypting v0 (legacy) format")

        try:
            file_size = path.stat().st_size
            if file_size == 0:
                logger.warning("File is empty")
                return b""

            data = np.fromfile(str(path), dtype=np.uint8)
            if data.size == 0:
                return b""

            xor_byte = np.uint8(xor_key & 0xFF)
            _xor_inplace(data, xor_byte)
            return data.tobytes()

        except (OSError, RuntimeError) as e:
            logger.error(f"v0 decryption failed: {e}")
            raise FileReadError(f"Failed to decrypt v0 format: {e}") from e

    def _decrypt_v1_v2(
        self,
        path: Path,
        xor_key: int,
        aes_key: bytes | None = None,
    ) -> bytes:
        """
        解密 v1/v2 版本的 .dat 文件(AES + XOR 混合加密)

        文件结构:
            - Header (15 bytes): 签名(6) + AES大小(4) + XOR大小(4) + 保留(1)
            - AES 加密数据段 (可选)
            - 原始数据段 (可选)
            - XOR 加密数据段 (可选)

        Args:
            path: 文件路径
            xor_key: XOR 密钥
            aes_key: AES 密钥(仅 v2 需要)

        Returns:
            bytes: 解密后的数据

        Raises:
            InvalidHeaderError: 文件头无效
            FileReadError: 文件读取或解密失败
        """
        logger.debug("Decrypting v1/v2 format")

        if aes_key is None:
            aes_key = self.config.V1_AES_KEY
            logger.debug("Using default v1 AES key")

        try:
            header, remaining_data = self._read_file_header(path)
            _signature, aes_size, xor_size = struct.unpack(
                self.config.HEADER_STRUCT_FORMAT, header
            )

            # AES 解密
            decrypted_data = self._decrypt_aes_section(
                aes_key, aes_size, remaining_data
            )
            tail_data = remaining_data[self._get_padded_aes_size(aes_size) :]

            # XOR 解密
            result = self._decrypt_xor_section(
                xor_key, xor_size, decrypted_data, tail_data
            )

            return result

        except struct.error as e:
            logger.error(f"Header parsing failed: {e}")
            raise InvalidHeaderError(f"Invalid file header format: {e}") from e
        except (OSError, ValueError) as e:
            logger.error(f"v1/v2 decryption failed: {e}")
            raise FileReadError(f"Failed to decrypt v1/v2 format: {e}") from e

    def _read_file_header(self, path: Path) -> tuple[bytes, bytes]:
        """读取文件头和剩余数据"""
        try:
            with path.open("rb") as f:
                header = f.read(self.config.HEADER_SIZE)
                if len(header) != self.config.HEADER_SIZE:
                    raise InvalidHeaderError(
                        f"Expected header size {self.config.HEADER_SIZE}, "
                        f"got {len(header)}"
                    )
                remaining_data = f.read()
            return header, remaining_data
        except OSError as e:
            raise FileReadError(f"Cannot read file: {path}") from e

    def _get_padded_aes_size(self, aes_size: int) -> int:
        """计算 AES 填充后的大小"""
        block_size = AES.block_size
        return aes_size + (block_size - aes_size % block_size) if aes_size > 0 else 0

    def _decrypt_aes_section(self, aes_key: bytes, aes_size: int, data: bytes) -> bytes:
        """解密 AES 部分"""
        if aes_size == 0:
            return b""

        try:
            padded_size = self._get_padded_aes_size(aes_size)
            aes_data = data[:padded_size]

            cipher = AES.new(aes_key, AES.MODE_ECB)
            decrypted_block = cipher.decrypt(aes_data)
            decrypted_data = Padding.unpad(
                decrypted_block, AES.block_size, style="pkcs7"
            )

            logger.debug(f"AES decrypted: {aes_size} -> {len(decrypted_data)} bytes")
            return decrypted_data

        except (ValueError, IndexError) as e:
            raise FileReadError(f"AES decryption failed: {e}") from e

    def _decrypt_xor_section(
        self,
        xor_key: int,
        xor_size: int,
        decrypted_data: bytes,
        tail_data: bytes,
    ) -> bytes:
        """解密 XOR 部分"""
        if xor_size == 0:
            return decrypted_data + tail_data

        if xor_size > len(tail_data):
            raise ValueError(
                f"Invalid xor_size: {xor_size} > available data {len(tail_data)}"
            )

        raw_data = tail_data[:-xor_size]
        xor_section = tail_data[-xor_size:]

        xor_array = np.frombuffer(xor_section, dtype=np.uint8).copy()
        xor_byte = np.uint8(xor_key & 0xFF)
        _xor_inplace(xor_array, xor_byte)

        logger.debug(f"XOR decrypted: {xor_size} bytes")
        return decrypted_data + raw_data + xor_array.tobytes()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
