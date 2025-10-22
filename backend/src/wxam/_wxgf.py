"""
微信WXAM文件解码模块

该模块提供了将微信WXAM格式文件转换为标准图片格式(JPEG/GIF)的功能。
"""

import ctypes
from ctypes import POINTER, byref, c_int, c_int64, create_string_buffer
from pathlib import Path
from typing import Literal, Optional

# 加载DLL
try:
    # 加载VoipEngine.dll动态链接库
    voip_engine = ctypes.WinDLL(Path(__file__).parent / "VoipEngine.dll")

    # 配置wxam_dec_wxam2pic_5函数的参数和返回类型
    wxam_dec_wxam2pic_5 = voip_engine.wxam_dec_wxam2pic_5
    wxam_dec_wxam2pic_5.argtypes = [
        c_int64,  # 输入数据地址
        c_int,  # 输入数据大小
        c_int64,  # 输出缓冲区地址
        POINTER(c_int),  # 输出数据大小指针
        c_int64,  # 配置结构体地址
    ]
    wxam_dec_wxam2pic_5.restype = c_int64
except Exception as e:
    print(f"[-] 无法加载 VoipEngine.dll: {e}")
    voip_engine = None


class WxAMConfig(ctypes.Structure):
    """
    WXAM解码配置结构体

    Attributes:
        mode: 解码模式 (0=JPEG, 3=GIF)
        reserved: 保留字段
    """

    _fields_ = [
        ("mode", c_int),  # 解码模式
        ("reserved", c_int),  # 保留字段
    ]


def wxam_to_image(
    data: bytes, format: Literal["jpeg", "gif"] = "jpeg"
) -> Optional[bytes]:
    """
    将WXAM格式数据转换为图片格式

    Args:
        data: WXAM格式的原始字节数据
        format: 目标图片格式,支持 'jpeg' 或 'gif',默认为 'jpeg'

    Returns:
        转换后的图片字节数据,失败时返回 None

    Raises:
        AssertionError: 当format参数不是 'jpeg' 或 'gif' 时

    Example:
        >>> with open('input.wxam', 'rb') as f:
        ...     wxam_data = f.read()
        >>> image_data = wxam_to_image(wxam_data, format='jpeg')
        >>> if image_data:
        ...     with open('output.jpg', 'wb') as f:
        ...         f.write(image_data)
    """
    if voip_engine is None:
        print("[-] VoipEngine.dll 未加载")
        return None

    try:
        # 验证格式参数
        assert format in ["jpeg", "gif"], f"不支持的格式: {format}"

        # 创建并配置解码参数
        config = WxAMConfig()
        config.mode = {"jpeg": 0, "gif": 3}[format]

        # 准备输入缓冲区
        input_buffer = create_string_buffer(data, len(data))

        # 准备输出缓冲区 (最大52MB)
        max_output_size = 52 * 1024 * 1024
        output_buffer = create_string_buffer(max_output_size)
        output_size = c_int(max_output_size)

        # 调用DLL解码函数
        result = wxam_dec_wxam2pic_5(
            ctypes.addressof(input_buffer),  # WXAM数据地址
            len(data),  # 输入数据大小
            ctypes.addressof(output_buffer),  # 输出缓冲区地址
            byref(output_size),  # 输出大小指针
            ctypes.addressof(config),  # 配置结构体地址
        )

        # 检查解码结果
        if result == 0:
            actual_size = output_size.value
            return output_buffer.raw[:actual_size]

        print(f"[-] DLL解码失败,错误代码: {result}")
        return None

    except AssertionError as e:
        print(f"[-] 参数错误: {e}")
        return None
    except Exception as e:
        print(f"[-] 解码过程发生异常: {str(e)}")
        return None
