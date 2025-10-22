"""
微信 .dat 文件解密模块

支持三个版本的 .dat 文件解密:
- v0: 仅使用 XOR 密钥 (微信 3.x 及更早版本)
- v1: 使用固定 AES 密钥 + XOR 密钥 (微信 4.x)
- v2: 使用动态 AES 密钥 + XOR 密钥 (微信 4.x 及更高版本)
"""

import struct
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util import Padding


def decrypt_dat_legacy(input_path: str | Path, xor_key: int) -> bytes:
    """
    解密 v0 版本的 .dat 文件(仅 XOR 加密)。

    Args:
        input_path: 输入的 .dat 文件路径
        xor_key: XOR 解密密钥

    Returns:
        bytes: 解密后的原始数据

    Raises:
        OSError: 文件读取失败

    Note:
        对应微信版本 3.x 及更早版本
    """
    path = Path(input_path)
    file_size = path.stat().st_size

    if file_size == 0:
        return b""

    result = bytearray(file_size)

    with path.open("rb") as f:
        mv = memoryview(result)
        offset = 0

        # 分块读取并解密
        while offset < file_size:
            read_count = f.readinto(mv[offset:])
            if not read_count:
                break

            # 对当前块进行 XOR 解密
            segment = mv[offset : offset + read_count]
            for idx in range(read_count):
                segment[idx] ^= xor_key

            offset += read_count

    return bytes(result)


def decrypt_dat_new(
    input_path: str | Path, xor_key: int, aes_key: bytes | None = None
) -> bytes:
    """
    解密 v1/v2 版本的 .dat 文件(AES + XOR 混合加密)。

    文件结构:
        - Header (15 bytes): 签名(6) + AES大小(4) + XOR大小(4) + 保留(1)
        - AES 加密数据段 (可选)
        - 原始数据段 (可选)
        - XOR 加密数据段 (可选)

    Args:
        input_path: 输入的 .dat 文件路径
        xor_key: XOR 解密密钥
        aes_key: AES 解密密钥(16字节),None 时使用 v1 固定密钥

    Returns:
        bytes: 解密后的原始数据

    Raises:
        ValueError: 文件头无效或密钥错误
        OSError: 文件读取失败

    Note:
        - v1: 使用固定 AES 密钥 (微信 4.x)
        - v2: 需要提供动态 AES 密钥 (微信 4.x+)
    """
    # v1 版本的固定 AES 密钥
    V1_AES_KEY = b"cfcd208495d565ef"

    if aes_key is None:
        aes_key = V1_AES_KEY

    path = Path(input_path)

    with path.open("rb") as f:
        # 读取文件头 (15 字节)
        header = f.read(0x0F)
        if len(header) != 0x0F:
            raise ValueError("Invalid header length")

        # 解析头部: 签名(6) + AES段大小(4) + XOR段大小(4) + 保留字节(1)
        _signature, aes_size, xor_size = struct.unpack("<6sLLx", header)

        # 读取剩余所有数据
        remaining_data = f.read()

    # === AES 解密部分 ===
    block_size = AES.block_size

    if aes_size > 0:
        # 计算填充后的大小(向上取整到 AES 块大小的倍数)
        padded_aes_size = aes_size + (block_size - aes_size % block_size)
        aes_data = remaining_data[:padded_aes_size]
        tail_data = remaining_data[padded_aes_size:]

        # 使用 ECB 模式解密 AES 数据
        cipher = AES.new(aes_key, AES.MODE_ECB)
        decrypted_block = cipher.decrypt(aes_data)

        # 去除 PKCS7 填充
        decrypted_data = Padding.unpad(decrypted_block, block_size, style="pkcs7")
    else:
        decrypted_data = b""
        tail_data = remaining_data

    # === XOR 解密部分 ===
    xor_byte = xor_key & 0xFF

    if xor_size > 0:
        if xor_size > len(tail_data):
            raise ValueError("Invalid xor_size in header")

        # 分离原始数据和 XOR 加密数据
        raw_data = tail_data[:-xor_size]
        xor_section = bytearray(tail_data[-xor_size:])

        # 对 XOR 段进行解密
        for idx in range(xor_size):
            xor_section[idx] ^= xor_byte

        result = decrypted_data + raw_data + bytes(xor_section)
    else:
        result = decrypted_data + tail_data

    return result


def decrypt_dat(
    input_file: str | Path, xor_key: int, aes_key: bytes | None = None
) -> tuple[int, bytes]:
    """
    自动识别 .dat 文件版本并解密。

    根据文件签名自动选择对应的解密方法:
        - "BEL BS V1 BS BEL": v1 版本(固定 AES 密钥)
        - "BEL BS V2 BS BEL": v2 版本(动态 AES 密钥)
        - 其他: v0 版本(仅 XOR)

    Args:
        input_file: 输入的 .dat 文件路径
        xor_key: XOR 解密密钥
        aes_key: AES 解密密钥(16字节),仅 v2 版本必须提供

    Returns:
        tuple[int, bytes]: (版本号, 解密后的数据)
            - 版本号: 0 (legacy), 1 (v1), 2 (v2)

    Raises:
        ValueError: 文件头无效、缺少 v2 密钥或密钥长度错误
        OSError: 文件读取失败

    Example:
        >>> version, data = decrypt_dat("image.dat", 0xFF)
        >>> print(f"Version: {version}, Size: {len(data)}")
    """
    path = Path(input_file)

    # 读取文件头以识别版本
    with path.open("rb") as f:
        header = f.read(0x0F)

    if len(header) < 6:
        raise ValueError("Unsupported .dat header length")

    signature = header[:6]

    # 根据签名匹配版本
    match signature:
        case b"\x07\x08V1\x08\x07":
            # v1 版本: 使用固定 AES 密钥
            return 1, decrypt_dat_new(path, xor_key)

        case b"\x07\x08V2\x08\x07":
            # v2 版本: 需要动态 AES 密钥
            if not aes_key or len(aes_key) != 16:
                raise ValueError("缺少有效的 v2 AES 密钥(16 字节)")
            return 2, decrypt_dat_new(path, xor_key, aes_key)

        case _:
            # v0 版本: 仅使用 XOR
            return 0, decrypt_dat_legacy(path, xor_key)
