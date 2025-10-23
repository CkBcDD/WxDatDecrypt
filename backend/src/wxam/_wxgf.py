"""
微信WXAM文件解码模块

该模块提供了将微信WXAM格式文件转换为标准图片格式(JPEG/GIF)的功能。
"""

import ctypes
import logging
import sys
from ctypes import POINTER, byref, c_int, c_int64, create_string_buffer
from enum import IntEnum
from pathlib import Path
from typing import Optional, Any

__all__ = ["ImageFormat", "WxAMDecoder", "wxam_to_image"]

# 配置日志
logger = logging.getLogger(__name__)


class ImageFormat(IntEnum):
    """支持的图片格式"""

    JPEG = 0
    GIF = 3


class WxAMConfig(ctypes.Structure):
    """WXAM解码配置结构体"""

    _fields_ = [
        ("mode", c_int),  # 解码模式
        ("reserved", c_int),  # 保留字段
    ]


class WxAMDecoderError(Exception):
    """WXAM解码异常"""

    pass


class WxAMDecoder:
    """
    WXAM格式解码器

    负责加载DLL并提供WXAM到图片格式的转换功能。
    """

    # DLL加载缓存
    _dll_instance: Optional[ctypes.CDLL] = None
    _dll_function: Optional[Any] = None
    _initialized: bool = False
    _load_error: Optional[str] = None

    # 常量配置
    MAX_OUTPUT_SIZE = 52 * 1024 * 1024  # 52MB
    DLL_NAME = "VoipEngine.dll"

    @classmethod
    def _load_dll(cls) -> bool:
        """
        加载VoipEngine.dll

        Returns:
            bool: DLL加载成功返回True,失败返回False
        """
        if cls._initialized:
            return cls._dll_instance is not None

        try:
            dll_path = Path(__file__).parent / cls.DLL_NAME

            if not dll_path.exists():
                raise FileNotFoundError(f"DLL文件不存在: {dll_path}")

            cls._dll_instance = ctypes.WinDLL(str(dll_path))
            dll_function = cls._dll_instance.wxam_dec_wxam2pic_5

            # 配置函数签名
            dll_function.argtypes = [
                c_int64,  # 输入数据地址
                c_int,  # 输入数据大小
                c_int64,  # 输出缓冲区地址
                POINTER(c_int),  # 输出数据大小指针
                c_int64,  # 配置结构体地址
            ]
            dll_function.restype = c_int64

            cls._dll_function = dll_function
            cls._initialized = True
            logger.info(f"[+] 成功加载 {cls.DLL_NAME}")
            return True

        except FileNotFoundError as e:
            cls._load_error = str(e)
            logger.error(f"[-] {e}")
            cls._initialized = True
            return False
        except OSError as e:
            cls._load_error = f"DLL加载失败: {e}"
            logger.error(f"[-] {cls._load_error}")
            cls._initialized = True
            return False
        except Exception as e:
            cls._load_error = f"未知错误: {e}"
            logger.error(f"[-] 加载 {cls.DLL_NAME} 时发生异常: {e}")
            cls._initialized = True
            return False

    @classmethod
    def decode(
        cls,
        data: bytes,
        format: ImageFormat = ImageFormat.JPEG,
    ) -> bytes:
        """
        将WXAM格式数据转换为图片格式

        Args:
            data: WXAM格式的原始字节数据
            format: 目标图片格式,默认为JPEG

        Returns:
            转换后的图片字节数据

        Raises:
            WxAMDecoderError: 解码失败时抛出
            ValueError: 参数验证失败时抛出

        Example:
            >>> with open('input.wxam', 'rb') as f:
            ...     wxam_data = f.read()
            >>> try:
            ...     image_data = WxAMDecoder.decode(wxam_data, ImageFormat.JPEG)
            ...     with open('output.jpg', 'wb') as f:
            ...         f.write(image_data)
            ... except WxAMDecoderError as e:
            ...     print(f"解码失败: {e}")
        """
        # 验证DLL是否已加载
        if not cls._load_dll():
            raise WxAMDecoderError(cls._load_error or "无法加载VoipEngine.dll")

        if cls._dll_function is None:
            raise WxAMDecoderError("DLL函数未正确初始化")

        # 参数验证
        if not isinstance(data, bytes):
            raise ValueError("输入数据必须是bytes类型")
        if not data:
            raise ValueError("输入数据不能为空")
        if not isinstance(format, ImageFormat):
            raise ValueError(f"不支持的格式: {format}")

        try:
            # 创建配置结构体
            config = WxAMConfig()
            config.mode = int(format)

            # 准备缓冲区
            input_buffer = create_string_buffer(data, len(data))
            output_buffer = create_string_buffer(cls.MAX_OUTPUT_SIZE)
            output_size = c_int(cls.MAX_OUTPUT_SIZE)

            # 调用DLL函数
            logger.debug(f"开始解码WXAM数据,大小: {len(data)} 字节,格式: {format.name}")
            result = cls._dll_function(
                ctypes.addressof(input_buffer),
                len(data),
                ctypes.addressof(output_buffer),
                byref(output_size),
                ctypes.addressof(config),
            )

            # 检查返回值
            if result != 0:
                raise WxAMDecoderError(f"DLL解码失败,错误代码: {result}")

            actual_size = output_size.value
            if actual_size <= 0:
                raise WxAMDecoderError("解码结果大小无效")

            decoded_data = output_buffer.raw[:actual_size]
            logger.debug(f"[+] 解码成功,输出大小: {actual_size} 字节")
            return decoded_data

        except ctypes.ArgumentError as e:
            raise WxAMDecoderError(f"参数传递失败: {e}") from e
        except Exception as e:
            raise WxAMDecoderError(f"解码过程异常: {e}") from e


def wxam_to_image(
    data: bytes,
    format: str = "jpeg",
) -> Optional[bytes]:
    """
    便捷函数: 将WXAM格式数据转换为图片格式

    Args:
        data: WXAM格式的原始字节数据
        format: 目标图片格式 ('jpeg' 或 'gif'),默认为 'jpeg'

    Returns:
        转换后的图片字节数据,失败时返回None

    Example:
        >>> with open('input.wxam', 'rb') as f:
        ...     wxam_data = f.read()
        >>> image_data = wxam_to_image(wxam_data, format='jpeg')
        >>> if image_data:
        ...     with open('output.jpg', 'wb') as f:
        ...         f.write(image_data)
    """
    format_map = {
        "jpeg": ImageFormat.JPEG,
        "gif": ImageFormat.GIF,
    }

    if format.lower() not in format_map:
        logger.error(f"[-] 不支持的格式: {format}")
        return None

    try:
        image_format = format_map[format.lower()]
        return WxAMDecoder.decode(data, image_format)
    except WxAMDecoderError as e:
        logger.error(f"[-] {e}")
        return None
    except ValueError as e:
        logger.error(f"[-] 参数错误: {e}")
        return None
    except Exception as e:
        logger.error(f"[-] 未预期的错误: {e}")
        return None
