"""微信图片查看器应用程序。

此模块提供一个基于 PyWebview 的桌面应用程序，用于查看和解密微信的 .dat 图片文件。
支持 XOR 和 AES 加密的文件解密，以及 WxGF 格式的转换。
"""

import base64
import json
import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from multiprocessing import freeze_support
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import webview

from backend.src.decrypt import decrypt_dat
from backend.src.wxam import wxam_to_image


CONFIG_FILE = "config.json"
DAT_FILE_EXTENSION = ".dat"

# ==================== 日志配置 ====================
# 调整此处的日志级别来控制输出粒度
# DEBUG: 详细的调试信息
# INFO: 一般信息
# WARNING: 警告信息
# ERROR: 错误信息
# CRITICAL: 严重错误
LOG_LEVEL = logging.WARNING  # 可在此修改全局日志级别
LOG_FILE = "app.log"
LOG_MAX_BYTES = 10 * 1024 * 1024  # 10MB
LOG_BACKUP_COUNT = 3


def setup_logging() -> logging.Logger:
    """配置日志系统。

    Returns:
        配置好的根日志记录器。
    """
    # 创建日志格式器
    formatter = logging.Formatter(
        fmt="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # 配置根日志记录器
    root_logger = logging.getLogger()
    root_logger.setLevel(LOG_LEVEL)

    # 清除现有的处理器
    root_logger.handlers.clear()

    # 控制台处理器
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(LOG_LEVEL)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # 文件处理器（轮转）
    try:
        file_handler = RotatingFileHandler(
            LOG_FILE,
            maxBytes=LOG_MAX_BYTES,
            backupCount=LOG_BACKUP_COUNT,
            encoding="utf-8",
        )
        file_handler.setLevel(LOG_LEVEL)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
    except Exception as e:
        root_logger.warning(f"无法创建日志文件处理器: {e}")

    return root_logger


# 初始化日志系统
logger = setup_logging()


def read_key_from_config() -> Tuple[int, bytes]:
    """从配置文件读取加密密钥。

    Returns:
        包含 XOR 密钥和 AES 密钥的元组。如果读取失败，返回 (0, b'')。
    """
    if not os.path.exists(CONFIG_FILE):
        logger.info(f"配置文件不存在: {CONFIG_FILE}")
        return 0, b""

    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            key_dict = json.load(f)
        xor_key = int(key_dict.get("xor", 0))
        aes_value = key_dict.get("aes", b"")
        logger.info(f"成功从 {CONFIG_FILE} 读取密钥配置")
    except (OSError, json.JSONDecodeError, ValueError, TypeError) as exc:
        logger.error(f"读取配置文件失败: {exc}", exc_info=True)
        return 0, b""

    # 将 AES 值转换为字节类型
    if isinstance(aes_value, str):
        aes_key = aes_value.encode()
    elif isinstance(aes_value, (bytes, bytearray)):
        aes_key = bytes(aes_value)
    else:
        aes_key = b""

    logger.debug(f"解析密钥: XOR={xor_key}, AES长度={len(aes_key)}")
    return xor_key, aes_key[:16]


class WeixinInfo:
    """微信文件信息的全局存储类。

    用于在 PyWebview API 和主线程之间共享微信目录和密钥信息。

    Attributes:
        weixin_dir: 微信文件的根目录路径。
        xor_key: XOR 加密密钥。
        aes_key: AES 加密密钥（最多16字节)。
    """

    weixin_dir: Optional[Path] = None
    xor_key: int = 0
    aes_key: bytes = b""


# 全局 WeixinInfo 实例
info = WeixinInfo()


# 添加类型注解
window: Optional[webview.Window] = None


class Api:
    """PyWebview 的 JavaScript API 接口类。

    提供前端 JavaScript 调用的后端方法，包括目录选择、文件树构建、
    文件列表获取和 .dat 文件解密等功能。
    """

    def __init__(self):
        """初始化 API 实例."""
        self.root_dir: Optional[str] = None
        self.server_url: Optional[str] = None
        self.logger = logging.getLogger(self.__class__.__name__)

    def _is_valid_sns_filename(self, filename: str) -> bool:
        """检查文件名是否为朋友圈 (Sns) 缓存文件的文件名形式。

        Args:
            filename: 要检查的文件名。

        Returns:
            如果文件名符合朋友圈缓存文件格式，返回 True，否则返回 False。
        """
        name = filename.removesuffix("_t")
        is_valid = len(name) in [30, 32] and name.isalnum()
        if is_valid:
            self.logger.debug(f"识别为朋友圈缓存文件: {filename}")
        return is_valid

    def set_server_url(self, url: str) -> None:
        """设置 FastAPI 服务器的 URL。

        Args:
            url: 服务器的完整 URL 地址。
        """
        self.server_url = url
        self.logger.info(f"服务器 URL 已设置: {url}")

    def get_server_url(self) -> Optional[str]:
        """获取 FastAPI 服务器的 URL。

        Returns:
            服务器的 URL 地址，如果未设置则返回 None。
        """
        self.logger.debug(f"获取服务器 URL: {self.server_url}")
        return self.server_url

    def set_root_dir(self, path: str) -> Dict[str, object]:
        """设置微信文件根目录。

        Args:
            path: 目录的完整路径。

        Returns:
            包含操作结果的字典。成功时包含 'success': True 和 'path'，
            失败时包含 'success': False 和 'error'。
        """
        if os.path.isdir(path):
            self.root_dir = path
            self.logger.info(f"根目录已设置: {path}")
            return {"success": True, "path": path}
        self.logger.warning(f"尝试设置无效路径: {path}")
        return {"success": False, "error": "无效的路径"}

    def get_folder_tree(self) -> Optional[Dict[str, object]]:
        """获取文件夹树结构。

        Returns:
            表示文件夹树的嵌套字典，每个节点包含 'name'、'path' 和 'children'。
            如果未设置根目录，返回 None。
        """
        if not self.root_dir:
            self.logger.warning("尝试获取文件夹树但根目录未设置")
            return None

        root_path = Path(self.root_dir)
        self.logger.info(f"开始构建文件夹树: {root_path}")

        def build_tree(dir_path: Path) -> Dict[str, object]:
            """递归构建目录树。

            Args:
                dir_path: 当前目录路径。

            Returns:
                表示当前目录及其子目录的字典。
            """
            tree_node: Dict[str, object] = {
                "name": dir_path.name,
                "path": str(dir_path),
                "children": [],
            }
            try:
                for entry in dir_path.iterdir():
                    if entry.is_dir():
                        children = tree_node["children"]
                        if isinstance(children, list):
                            children.append(build_tree(entry))
                self.logger.debug(f"已扫描目录: {dir_path}")
            except OSError as exc:
                self.logger.error(f"读取目录失败 {dir_path}: {exc}")
            return tree_node

        tree = build_tree(root_path)
        self.logger.info("文件夹树构建完成")
        return tree

    def get_images_in_folder(self, folder_path: str) -> List[str]:
        """获取指定文件夹中所有 .dat 文件的相对路径列表。

        Args:
            folder_path: 文件夹的完整路径。

        Returns:
            相对于根目录的 .dat 文件路径列表。
        """
        if not self.root_dir:
            self.logger.warning("根目录未设置，无法获取图片列表")
            return []

        root_path = Path(self.root_dir).resolve()
        folder = Path(folder_path).resolve()

        # 验证文件夹是否在根目录下
        try:
            folder.relative_to(root_path)
        except ValueError:
            self.logger.error(f"文件夹不在根目录下: {folder}")
            return []

        self.logger.info(f"获取文件夹中的图片: {folder}")
        relative_paths: List[str] = []

        try:
            for entry in folder.iterdir():
                if entry.is_dir():
                    continue
                filename = entry.name
                if filename.lower().endswith(
                    DAT_FILE_EXTENSION
                ) or self._is_valid_sns_filename(filename):
                    relative_paths.append(str(entry.relative_to(root_path)))
            self.logger.info(f"找到 {len(relative_paths)} 个图片文件")
        except OSError as exc:
            self.logger.error(f"读取目录错误 {folder}: {exc}", exc_info=True)

        return relative_paths

    def open_folder_dialog(self) -> Dict[str, object]:
        """打开文件夹选择对话框。

        Returns:
            包含操作结果的字典。成功时包含 'success': True 和 'path'，
            失败时包含 'success': False。
        """
        self.logger.info("打开文件夹选择对话框")
        result = window.create_file_dialog(webview.FileDialog.FOLDER)  # type: ignore

        if result:
            path = result[0]
            if os.path.isdir(path):
                path_ = Path(path).resolve()

                self.root_dir = path
                info.weixin_dir = path_

                # 从配置文件读取密钥
                xor_k, aes_k = read_key_from_config()

                # 设置初始密钥值
                info.xor_key = xor_k
                info.aes_key = aes_k

                self.logger.info(f"根目录已设置: {self.root_dir}")
                self.logger.info(f"全局 info.weixin_dir 已设置: {info.weixin_dir}")
                self.logger.debug(f"初始密钥: XOR={xor_k}, AES长度={len(aes_k)}")

                return {"success": True, "path": path}

        self.logger.info("用户取消文件夹选择")
        return {"success": False}

    def decrypt_dat(self, file_path: str) -> str:
        """解密 .dat 文件并返回 Base64 编码的图片数据。"""
        if info.weixin_dir is None:
            self.logger.error("微信文件目录未设置")
            return ""

        full_path = info.weixin_dir / file_path

        if not full_path.exists():
            self.logger.error(f"文件不存在: {full_path}")
            return ""

        self.logger.info(f"开始解密文件: {full_path}")

        try:
            version, data = decrypt_dat(full_path, info.xor_key, info.aes_key or None)
            self.logger.info(f"解密成功 - 版本: v{version}, 数据大小: {len(data)} 字节")

        except ValueError as exc:
            self.logger.error(f"解密失败: {exc}")
            return ""
        except Exception as exc:
            self.logger.critical(
                f"解密时发生未知错误: {type(exc).__name__}: {exc}", exc_info=True
            )
            return ""

        # 处理 WxGF 格式
        if data.startswith(b"wxgf"):
            self.logger.info("检测到 WxGF 格式，开始转换...")
            data = wxam_to_image(data)
            if data is None:
                self.logger.error("WxGF 转换失败")
                return ""
            self.logger.info(f"WxGF 转换成功，大小: {len(data)} 字节")

        base64_result = base64.b64encode(data).decode("utf-8")
        self.logger.debug(f"Base64 编码完成，长度: {len(base64_result)}")
        return base64_result

    def save_image(
        self, base64_data: str, suggested_name: str, mime_type: str
    ) -> Dict[str, object]:
        """保存 Base64 编码的图片到本地文件。

        Args:
            base64_data: Base64 编码的图片数据。
            suggested_name: 建议的文件名。
            mime_type: 图片的 MIME 类型。

        Returns:
            包含操作结果的字典。
        """
        if not base64_data:
            self.logger.warning("没有可保存的数据")
            return {"success": False, "error": "没有可保存的数据"}

        # 检查 window 是否已初始化
        if window is None:
            self.logger.error("窗口未初始化")
            return {"success": False, "error": "窗口未初始化"}

        filename = (suggested_name or "image.jpg").strip()
        self.logger.info(f"打开保存对话框，建议文件名: {filename}")

        dialog_result = window.create_file_dialog(
            webview.FileDialog.SAVE,
            save_filename=filename,
        )

        if not dialog_result:
            self.logger.info("用户取消保存")
            return {"success": False, "error": "用户取消保存"}

        # 正确处理返回的文件路径
        file_path_str = (
            dialog_result[0]
            if isinstance(dialog_result, (list, tuple))
            else str(dialog_result)
        )
        file_path = Path(file_path_str)

        # 如果没有扩展名，根据 MIME 类型添加
        if not file_path.suffix:
            suffix_map = {
                "image/png": ".png",
                "image/gif": ".gif",
                "image/bmp": ".bmp",
                "image/x-icon": ".ico",
            }
            original_path = file_path
            file_path = file_path.with_suffix(suffix_map.get(mime_type, ".jpg"))
            self.logger.debug(f"添加文件扩展名: {original_path} -> {file_path}")

        try:
            data = base64.b64decode(base64_data)
            file_path.parent.mkdir(parents=True, exist_ok=True)
            with open(file_path, "wb") as f:
                f.write(data)
            self.logger.info(f"图片已保存: {file_path}")
        except (OSError, ValueError) as exc:
            self.logger.error(f"写入文件失败: {exc}", exc_info=True)
            return {"success": False, "error": f"写入文件失败: {exc}"}

        return {"success": True, "path": str(file_path)}


def get_resource_path(relative_path: str) -> str:
    """获取资源文件的绝对路径。

    兼容开发环境和打包后的环境（PyInstaller、Nuitka）。

    Args:
        relative_path: 相对于项目根目录的资源文件路径。

    Returns:
        资源文件的绝对路径。
    """
    if hasattr(sys, "_MEIPASS"):  # PyInstaller
        base_path = sys._MEIPASS  # type: ignore
        logger.debug(f"检测到 PyInstaller 环境: {base_path}")
    elif getattr(sys, "frozen", False):  # Nuitka
        base_path = os.path.dirname(sys.executable)
        logger.debug(f"检测到 Nuitka 环境: {base_path}")
    else:  # 开发环境
        base_path = os.path.abspath(os.path.dirname(__file__))
        logger.debug(f"开发环境: {base_path}")

    resource_path = os.path.join(base_path, relative_path)
    logger.debug(f"资源路径: {resource_path}")
    return resource_path


def main() -> None:
    """应用程序的主入口函数。

    初始化 PyWebview 窗口并启动应用程序。
    """
    logger.info("=" * 60)
    logger.info("微信图片查看器启动")
    logger.info(f"日志级别: {logging.getLevelName(LOG_LEVEL)}")
    logger.info("=" * 60)

    freeze_support()  # Windows 多进程支持

    # 初始化 PyWebview API
    api = Api()

    # 获取 index.html 的路径
    html_path = Path(get_resource_path("frontend/templates/index.html"))
    logger.info(f"加载界面文件: {html_path}")

    global window
    window = webview.create_window(
        "微信图片查看器",
        html_path.as_uri(),
        js_api=api,
        width=1200,
        height=800,
        resizable=True,
        min_size=(800, 600),
    )

    logger.info("PyWebview 窗口即将启动...")
    try:
        webview.start(debug=False)
    except Exception as e:
        logger.critical(f"窗口启动失败: {e}", exc_info=True)
        raise
    finally:
        logger.info("PyWebview 窗口已关闭")
        logger.info("=" * 60)


if __name__ == "__main__":
    main()
