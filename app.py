"""微信图片查看器应用程序。

此模块提供一个基于 PyWebview 的桌面应用程序，用于查看和解密微信的 .dat 图片文件。
支持 XOR 和 AES 加密的文件解密，以及 WxGF 格式的转换。
"""

from __future__ import annotations

import base64
import json
import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, Protocol

import webview

from backend.src.decrypt import DatDecryptor
from backend.src.wxam import WxAMDecoder


# ==================== 常量配置 ====================
class AppConfig:
    """应用程序配置常量。"""

    CONFIG_FILE: Final[str] = "config.json"
    DAT_FILE_EXTENSION: Final[str] = ".dat"
    LOG_FILE: Final[str] = "app.log"
    LOG_MAX_BYTES: Final[int] = 10 * 1024 * 1024  # 10MB
    LOG_BACKUP_COUNT: Final[int] = 3
    LOG_LEVEL: Final[int] = logging.WARNING

    WINDOW_TITLE: Final[str] = "微信图片查看器"
    WINDOW_WIDTH: Final[int] = 1200
    WINDOW_HEIGHT: Final[int] = 800
    WINDOW_MIN_WIDTH: Final[int] = 800
    WINDOW_MIN_HEIGHT: Final[int] = 600

    SNS_FILENAME_LENGTHS: Final[tuple[int, ...]] = (30, 32)


# ==================== 日志配置 ====================
class LoggerFactory:
    """日志工厂类，负责创建和配置日志记录器。"""

    @staticmethod
    def setup_logger(
        name: str = __name__,
        level: int = AppConfig.LOG_LEVEL,
        log_file: str = AppConfig.LOG_FILE,
    ) -> logging.Logger:
        """配置并返回日志记录器。

        Args:
            name: 日志记录器名称
            level: 日志级别
            log_file: 日志文件路径

        Returns:
            配置好的日志记录器
        """
        from logging.handlers import RotatingFileHandler

        logger = logging.getLogger(name)
        logger.setLevel(level)
        logger.handlers.clear()

        # 格式器
        formatter = logging.Formatter(
            fmt="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        # 控制台处理器
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        # 文件处理器
        try:
            file_handler = RotatingFileHandler(
                log_file,
                maxBytes=AppConfig.LOG_MAX_BYTES,
                backupCount=AppConfig.LOG_BACKUP_COUNT,
                encoding="utf-8",
            )
            file_handler.setLevel(level)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except OSError as e:
            logger.warning(f"无法创建日志文件处理器: {e}")

        return logger


# ==================== 数据模型 ====================
@dataclass
class EncryptionKeys:
    """加密密钥数据类。"""

    xor_key: int = 0
    aes_key: bytes = field(default_factory=bytes)

    def is_valid(self) -> bool:
        """检查密钥是否有效。"""
        return self.xor_key != 0 or len(self.aes_key) > 0

    @property
    def aes_key_trimmed(self) -> bytes:
        """返回修剪到16字节的AES密钥。"""
        return self.aes_key[:16]


@dataclass
class AppState:
    """应用程序全局状态。"""

    weixin_dir: Path | None = None
    keys: EncryptionKeys = field(default_factory=EncryptionKeys)

    def is_initialized(self) -> bool:
        """检查应用是否已初始化。"""
        return self.weixin_dir is not None


@dataclass
class FolderNode:
    """文件夹树节点。"""

    name: str
    path: str
    children: list[FolderNode] = field(default_factory=list)

    def to_dict(self) -> dict:
        """转换为字典格式。"""
        return {
            "name": self.name,
            "path": self.path,
            "children": [child.to_dict() for child in self.children],
        }


@dataclass
class ApiResponse:
    """API响应数据类。"""

    success: bool
    data: dict | str | list | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, bool | dict | str | list | None]:
        """转换为字典格式。"""
        result: dict[str, bool | dict | str | list | None] = {"success": self.success}
        if self.data is not None:
            result["data"] = self.data
        if self.error:
            result["error"] = self.error
        return result


# ==================== 接口定义 ====================
class ConfigReader(Protocol):
    """配置读取器接口。"""

    def read_keys(self) -> EncryptionKeys:
        """读取加密密钥。"""
        ...


class FileDecryptor(Protocol):
    """文件解密器接口。"""

    def decrypt(self, file_path: Path, keys: EncryptionKeys) -> bytes:
        """解密文件。"""
        ...


# ==================== 服务类 ====================
class JsonConfigReader:
    """JSON配置文件读取器。"""

    def __init__(self, config_file: str = AppConfig.CONFIG_FILE) -> None:
        self.config_file = Path(config_file)
        self.logger = logging.getLogger(self.__class__.__name__)

    def read_keys(self) -> EncryptionKeys:
        """从JSON配置文件读取加密密钥。

        Returns:
            加密密钥对象
        """
        if not self.config_file.exists():
            self.logger.info(f"配置文件不存在: {self.config_file}")
            return EncryptionKeys()

        try:
            with open(self.config_file, encoding="utf-8") as f:
                config_data = json.load(f)

            xor_key = int(config_data.get("xor", 0))
            aes_value = config_data.get("aes", b"")

            # 转换AES密钥
            if isinstance(aes_value, str):
                aes_key = aes_value.encode()
            elif isinstance(aes_value, (bytes, bytearray)):
                aes_key = bytes(aes_value)
            else:
                aes_key = b""

            keys = EncryptionKeys(xor_key=xor_key, aes_key=aes_key)
            self.logger.info(
                f"成功从配置文件读取密钥: XOR={xor_key}, AES长度={len(aes_key)}"
            )
            return keys

        except (OSError, json.JSONDecodeError, ValueError, TypeError) as e:
            self.logger.error(f"读取配置文件失败: {e}", exc_info=True)
            return EncryptionKeys()


class DatFileDecryptor:
    """DAT文件解密服务。"""

    def __init__(self) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)

    def decrypt(self, file_path: Path, keys: EncryptionKeys) -> bytes:
        """解密DAT文件。

        Args:
            file_path: 文件路径
            keys: 加密密钥

        Returns:
            解密后的字节数据

        Raises:
            FileNotFoundError: 文件不存在
            ValueError: 解密失败
        """
        if not file_path.exists():
            raise FileNotFoundError(f"文件不存在: {file_path}")

        self.logger.info(f"开始解密文件: {file_path}")

        try:
            aes_key = keys.aes_key_trimmed if keys.aes_key else None

            decryptor = DatDecryptor()
            version, data = decryptor.decrypt(file_path, keys.xor_key, aes_key)
            self.logger.info(f"解密成功 - 版本: v{version}, 数据大小: {len(data)} 字节")
        except ValueError as e:
            self.logger.error(f"解密失败: {e}")
            raise
        except Exception as e:
            self.logger.critical(
                f"解密时发生未知错误: {type(e).__name__}: {e}", exc_info=True
            )
            raise ValueError(f"解密失败: {e}") from e

        # 处理 WxGF 格式
        if data.startswith(b"wxgf"):
            self.logger.info("检测到 WxGF 格式，开始转换...")
            decoder = WxAMDecoder()
            converted_data = decoder.decode(data)
            if converted_data is None:
                raise ValueError("WxGF 转换失败")
            data = converted_data
            self.logger.info(f"WxGF 转换成功，大小: {len(data)} 字节")

        return data


class FileSystemService:
    """文件系统服务。"""

    def __init__(self) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)

    @staticmethod
    def is_sns_filename(filename: str) -> bool:
        """检查是否为朋友圈缓存文件名。

        Args:
            filename: 文件名

        Returns:
            是否为朋友圈文件名
        """
        name = filename.removesuffix("_t")
        return len(name) in AppConfig.SNS_FILENAME_LENGTHS and name.isalnum()

    def build_folder_tree(self, root_path: Path) -> FolderNode:
        """构建文件夹树。

        Args:
            root_path: 根目录路径

        Returns:
            文件夹树节点
        """
        self.logger.info(f"开始构建文件夹树: {root_path}")

        def _build_tree(dir_path: Path) -> FolderNode:
            node = FolderNode(name=dir_path.name, path=str(dir_path))

            try:
                for entry in dir_path.iterdir():
                    if entry.is_dir():
                        node.children.append(_build_tree(entry))
                self.logger.debug(f"已扫描目录: {dir_path}")
            except OSError as e:
                self.logger.error(f"读取目录失败 {dir_path}: {e}")

            return node

        tree = _build_tree(root_path)
        self.logger.info("文件夹树构建完成")
        return tree

    def get_dat_files(self, folder_path: Path, root_path: Path) -> list[str]:
        """获取文件夹中的DAT文件列表。

        Args:
            folder_path: 文件夹路径
            root_path: 根目录路径

        Returns:
            相对路径列表
        """
        # 验证路径
        try:
            folder_path.resolve().relative_to(root_path.resolve())
        except ValueError:
            self.logger.error(f"文件夹不在根目录下: {folder_path}")
            return []

        self.logger.info(f"获取文件夹中的图片: {folder_path}")
        relative_paths: list[str] = []

        try:
            for entry in folder_path.iterdir():
                if entry.is_dir():
                    continue

                filename = entry.name
                if filename.lower().endswith(
                    AppConfig.DAT_FILE_EXTENSION
                ) or self.is_sns_filename(filename):
                    relative_paths.append(str(entry.relative_to(root_path)))

            self.logger.info(f"找到 {len(relative_paths)} 个图片文件")
        except OSError as e:
            self.logger.error(f"读取目录错误 {folder_path}: {e}", exc_info=True)

        return relative_paths


# ==================== API 类 ====================
class WeixinViewerApi:
    """微信查看器 API 类。"""

    def __init__(
        self,
        app_state: AppState,
        config_reader: ConfigReader,
        decryptor: FileDecryptor,
        file_service: FileSystemService,
        window: webview.Window | None = None,
    ) -> None:
        """初始化API。

        Args:
            app_state: 应用状态
            config_reader: 配置读取器
            decryptor: 文件解密器
            file_service: 文件系统服务
            window: PyWebview 窗口实例
        """
        self.app_state = app_state
        self.config_reader = config_reader
        self.decryptor = decryptor
        self.file_service = file_service
        self.window = window
        self.logger = logging.getLogger(self.__class__.__name__)

    def open_folder_dialog(self) -> dict:
        """打开文件夹选择对话框。"""
        if self.window is None:
            self.logger.error("窗口未初始化")
            return ApiResponse(success=False, error="窗口未初始化").to_dict()

        self.logger.info("打开文件夹选择对话框")
        result = self.window.create_file_dialog(webview.FileDialog.FOLDER)

        if not result:
            self.logger.info("用户取消文件夹选择")
            return ApiResponse(success=False, error="用户取消选择").to_dict()

        path = Path(result[0])
        if not path.is_dir():
            return ApiResponse(success=False, error="无效的路径").to_dict()

        # 更新应用状态
        self.app_state.weixin_dir = path.resolve()
        self.app_state.keys = self.config_reader.read_keys()

        self.logger.info(f"根目录已设置: {self.app_state.weixin_dir}")

        return ApiResponse(success=True, data={"path": str(path)}).to_dict()

    def get_folder_tree(self) -> dict | None:
        """获取文件夹树结构。"""
        if not self.app_state.is_initialized():
            self.logger.warning("尝试获取文件夹树但应用未初始化")
            return None

        if self.app_state.weixin_dir is None:
            self.logger.error("微信目录未设置")
            return None

        tree = self.file_service.build_folder_tree(self.app_state.weixin_dir)
        return tree.to_dict()

    def get_images_in_folder(self, folder_path: str) -> list[str]:
        """获取文件夹中的图片列表。"""
        if not self.app_state.is_initialized():
            self.logger.warning("应用未初始化")
            return []

        if self.app_state.weixin_dir is None:
            self.logger.error("微信目录未设置")
            return []

        folder = Path(folder_path).resolve()
        return self.file_service.get_dat_files(folder, self.app_state.weixin_dir)

    def decrypt_dat(self, file_path: str) -> str:
        """解密DAT文件并返回Base64编码的数据。"""
        if not self.app_state.is_initialized():
            self.logger.error("应用未初始化")
            return ""

        if self.app_state.weixin_dir is None:
            self.logger.error("微信目录未设置")
            return ""

        full_path = self.app_state.weixin_dir / file_path

        try:
            data = self.decryptor.decrypt(full_path, self.app_state.keys)
            base64_result = base64.b64encode(data).decode("utf-8")
            self.logger.debug(f"Base64 编码完成，长度: {len(base64_result)}")
            return base64_result
        except (FileNotFoundError, ValueError) as e:
            self.logger.error(f"解密失败: {e}")
            return ""

    def save_image(self, base64_data: str, suggested_name: str, mime_type: str) -> dict:
        """保存图片到本地。"""
        if not base64_data:
            return ApiResponse(success=False, error="没有可保存的数据").to_dict()

        if self.window is None:
            return ApiResponse(success=False, error="窗口未初始化").to_dict()

        filename = (suggested_name or "image.jpg").strip()
        self.logger.info(f"打开保存对话框，建议文件名: {filename}")

        dialog_result = self.window.create_file_dialog(
            webview.FileDialog.SAVE,
            save_filename=filename,
        )

        if not dialog_result:
            return ApiResponse(success=False, error="用户取消保存").to_dict()

        file_path = Path(
            dialog_result[0]
            if isinstance(dialog_result, (list, tuple))
            else str(dialog_result)
        )

        # 添加扩展名
        if not file_path.suffix:
            suffix_map = {
                "image/png": ".png",
                "image/gif": ".gif",
                "image/bmp": ".bmp",
                "image/x-icon": ".ico",
            }
            file_path = file_path.with_suffix(suffix_map.get(mime_type, ".jpg"))

        try:
            data = base64.b64decode(base64_data)
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_bytes(data)
            self.logger.info(f"图片已保存: {file_path}")
            return ApiResponse(success=True, data={"path": str(file_path)}).to_dict()
        except (OSError, ValueError) as e:
            self.logger.error(f"保存文件失败: {e}", exc_info=True)
            return ApiResponse(success=False, error=f"写入文件失败: {e}").to_dict()


# ==================== 工具函数 ====================
def get_resource_path(relative_path: str) -> Path:
    """获取资源文件的绝对路径。

    兼容开发环境和打包后的环境（PyInstaller、Nuitka）。

    Args:
        relative_path: 相对路径

    Returns:
        资源文件的绝对路径
    """
    if hasattr(sys, "_MEIPASS"):  # PyInstaller
        base_path = Path(sys._MEIPASS)  # type: ignore[attr-defined]
    elif getattr(sys, "frozen", False):  # Nuitka
        base_path = Path(sys.executable).parent
    else:  # 开发环境
        base_path = Path(__file__).parent

    return base_path / relative_path


# ==================== 应用程序类 ====================
class WeixinViewerApp:
    """微信查看器应用程序主类。"""

    def __init__(self) -> None:
        """初始化应用程序。"""
        self.logger = LoggerFactory.setup_logger()
        self.app_state = AppState()
        self.config_reader = JsonConfigReader()
        self.decryptor = DatFileDecryptor()
        self.file_service = FileSystemService()
        self.window: webview.Window | None = None
        self.api: WeixinViewerApi | None = None

    def run(self) -> None:
        """运行应用程序。"""
        from multiprocessing import freeze_support

        self.logger.info("=" * 60)
        self.logger.info("微信图片查看器启动")
        self.logger.info(f"日志级别: {logging.getLevelName(AppConfig.LOG_LEVEL)}")
        self.logger.info("=" * 60)

        freeze_support()  # Windows 多进程支持

        # 创建API实例
        self.api = WeixinViewerApi(
            app_state=self.app_state,
            config_reader=self.config_reader,
            decryptor=self.decryptor,
            file_service=self.file_service,
        )

        # 获取HTML路径
        html_path = get_resource_path("frontend/templates/index.html")
        self.logger.info(f"加载界面文件: {html_path}")

        # 创建窗口
        self.window = webview.create_window(
            AppConfig.WINDOW_TITLE,
            html_path.as_uri(),
            js_api=self.api,
            width=AppConfig.WINDOW_WIDTH,
            height=AppConfig.WINDOW_HEIGHT,
            resizable=True,
            min_size=(AppConfig.WINDOW_MIN_WIDTH, AppConfig.WINDOW_MIN_HEIGHT),
        )

        # 将窗口实例传递给API
        self.api.window = self.window

        self.logger.info("PyWebview 窗口即将启动...")
        try:
            webview.start(debug=False)
        except Exception as e:
            self.logger.critical(f"窗口启动失败: {e}", exc_info=True)
            raise
        finally:
            self.logger.info("PyWebview 窗口已关闭")
            self.logger.info("=" * 60)


# ==================== 程序入口 ====================
def main() -> None:
    """应用程序入口函数。"""
    app = WeixinViewerApp()
    app.run()


if __name__ == "__main__":
    main()
