import struct
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util import Padding


def decrypt_dat_legacy(input_path: str | Path, xor_key: int) -> bytes:
    """
    解密 v0 版本的 .dat 文件。
    仅使用 XOR 密钥进行解密。

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
        while offset < file_size:
            read_count = f.readinto(mv[offset:])
            if not read_count:
                break
            segment = mv[offset : offset + read_count]
            for idx in range(read_count):
                segment[idx] ^= xor_key
            offset += read_count
    return bytes(result)


def decrypt_dat_new(
    input_path: str | Path, xor_key: int, aes_key: bytes | None = None
) -> bytes:
    """
    解密 v1 + v2 版本的 .dat 文件。
    v1: 使用固定 AES 密钥和 XOR 密钥进行解密。
    v2: 使用动态 AES 密钥和 XOR 密钥进行解密。需要用tool.py中提取的AES密钥。

    对应微信版本 4.x 及更高版本
    """

    V1_AES_KEY = b"cfcd208495d565ef"

    if aes_key is None:
        aes_key = V1_AES_KEY

    path = Path(input_path)
    with path.open("rb") as f:
        header = f.read(0x0F)
        if len(header) != 0x0F:
            raise ValueError("Invalid header length")

        _signature, aes_size, xor_size = struct.unpack("<6sLLx", header)

        # 读取剩余所有数据
        remaining_data = f.read()

    # 关键修复:使用与旧版相同的填充计算方式
    block_size = AES.block_size
    if aes_size > 0:
        # 计算填充后的大小(向上取整到块大小的倍数)
        padded_aes_size = aes_size + (block_size - aes_size % block_size)
        aes_data = remaining_data[:padded_aes_size]
        tail_data = remaining_data[padded_aes_size:]

        # 解密 AES 数据
        cipher = AES.new(aes_key, AES.MODE_ECB)
        decrypted_block = cipher.decrypt(aes_data)

        # 去除填充
        decrypted_data = Padding.unpad(decrypted_block, block_size, style="pkcs7")
    else:
        decrypted_data = b""
        tail_data = remaining_data

    # 处理 XOR 部分
    xor_byte = xor_key & 0xFF
    if xor_size > 0:
        if xor_size > len(tail_data):
            raise ValueError("Invalid xor_size in header")
        raw_data = tail_data[:-xor_size]
        xor_section = bytearray(tail_data[-xor_size:])
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
    根据签名选择对应的 .dat 解密流程,返回 (版本编号, 解密后的数据)。
    """
    path = Path(input_file)
    with path.open("rb") as f:
        header = f.read(0x0F)

    if len(header) < 6:
        raise ValueError("Unsupported .dat header length")

    signature = header[:6]

    match signature:
        case b"\x07\x08V1\x08\x07":
            return 1, decrypt_dat_new(path, xor_key)
        case b"\x07\x08V2\x08\x07":
            if not aes_key or len(aes_key) != 16:
                raise ValueError("缺少有效的 v2 AES 密钥(16 字节)")
            return 2, decrypt_dat_new(path, xor_key, aes_key)
        case _:
            return 0, decrypt_dat_legacy(path, xor_key)
