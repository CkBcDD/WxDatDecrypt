"""微信图片查看器应用程序。

此模块提供一个基于 PyWebview 的桌面应用程序，用于查看和解密微信的 .dat 图片文件。
支持 XOR 和 AES 加密的文件解密，以及 WxGF 格式的转换。
"""

import base64
import json
import os
import sys
from multiprocessing import freeze_support
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import webview

from backend.src.decrypt import decrypt_dat
from backend.src.wxam import wxam_to_image


CONFIG_FILE = "config.json"
DAT_FILE_EXTENSION = ".dat"


def read_key_from_config() -> Tuple[int, bytes]:
    """从配置文件读取加密密钥。

    Returns:
        包含 XOR 密钥和 AES 密钥的元组。如果读取失败，返回 (0, b'')。
    """
    if not os.path.exists(CONFIG_FILE):
        return 0, b""

    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            key_dict = json.load(f)
        xor_key = int(key_dict.get("xor", 0))
        aes_value = key_dict.get("aes", b"")
    except (OSError, json.JSONDecodeError, ValueError, TypeError) as exc:
        print(f"读取配置失败: {exc}")
        return 0, b""

    # 将 AES 值转换为字节类型
    if isinstance(aes_value, str):
        aes_key = aes_value.encode()
    elif isinstance(aes_value, (bytes, bytearray)):
        aes_key = bytes(aes_value)
    else:
        aes_key = b""

    return xor_key, aes_key[:16]


class WeixinInfo:
    """微信文件信息的全局存储类。

    用于在 PyWebview API 和主线程之间共享微信目录和密钥信息。

    Attributes:
        weixin_dir: 微信文件的根目录路径。
        xor_key: XOR 加密密钥。
        aes_key: AES 加密密钥（最多16字节）。
    """

    weixin_dir: Optional[Path] = None
    xor_key: int = 0
    aes_key: bytes = b""


# 全局 WeixinInfo 实例
info = WeixinInfo()


class Api:
    """PyWebview 的 JavaScript API 接口类。

    提供前端 JavaScript 调用的后端方法，包括目录选择、文件树构建、
    文件列表获取和 .dat 文件解密等功能。
    """

    def __init__(self):
        """初始化 API 实例."""
        self.root_dir: Optional[str] = None
        self.server_url: Optional[str] = None

    def _is_valid_sns_filename(self, filename: str) -> bool:
        """检查文件名是否为朋友圈 (Sns) 缓存文件的文件名形式。

        Args:
            filename: 要检查的文件名。

        Returns:
            如果文件名符合朋友圈缓存文件格式，返回 True，否则返回 False。
        """
        name = filename.removesuffix("_t")
        return len(name) in [30, 32] and name.isalnum()

    def set_server_url(self, url: str) -> None:
        """设置 FastAPI 服务器的 URL。

        Args:
            url: 服务器的完整 URL 地址。
        """
        self.server_url = url

    def get_server_url(self) -> Optional[str]:
        """获取 FastAPI 服务器的 URL。

        Returns:
            服务器的 URL 地址，如果未设置则返回 None。
        """
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
            return {"success": True, "path": path}
        return {"success": False, "error": "无效的路径"}

    def get_folder_tree(self) -> Optional[Dict[str, object]]:
        """获取文件夹树结构。

        Returns:
            表示文件夹树的嵌套字典，每个节点包含 'name'、'path' 和 'children'。
            如果未设置根目录，返回 None。
        """
        if not self.root_dir:
            return None

        root_path = Path(self.root_dir)

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
            except OSError as exc:
                print(f"读取目录 {dir_path} 失败: {exc}")
            return tree_node

        return build_tree(root_path)

    def get_images_in_folder(self, folder_path: str) -> List[str]:
        """获取指定文件夹中所有 .dat 文件的相对路径列表。

        Args:
            folder_path: 文件夹的完整路径。

        Returns:
            相对于根目录的 .dat 文件路径列表。
        """
        if not self.root_dir:
            return []

        root_path = Path(self.root_dir).resolve()
        folder = Path(folder_path).resolve()

        # 验证文件夹是否在根目录下
        try:
            folder.relative_to(root_path)
        except ValueError:
            return []

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
        except OSError as exc:
            print(f"读取目录 {folder} 错误: {exc}")

        return relative_paths

    def open_folder_dialog(self) -> Dict[str, object]:
        """打开文件夹选择对话框。

        Returns:
            包含操作结果的字典。成功时包含 'success': True 和 'path'，
            失败时包含 'success': False。
        """
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

                print(f"初始密钥: xor={xor_k}, aes={aes_k}")
                print(f"PyWebview API: 根目录已通过对话框设置为 {self.root_dir}")
                print(
                    f"FastAPI 全局 info.weixin_dir 已通过对话框设置为 {info.weixin_dir}"
                )
                return {"success": True, "path": path}
        return {"success": False}

    def decrypt_dat(self, file_path: str) -> str:
        """解密 .dat 文件并返回 Base64 编码的图片数据。

        Args:
            file_path: 相对于微信根目录的文件路径。

        Returns:
            Base64 编码的图片数据字符串。如果解密失败，返回空字符串。
        """
        # 使用全局 info 对象
        if info.weixin_dir is None:
            print("微信文件目录未设置。")
            return ""

        full_path = info.weixin_dir / file_path

        if not full_path.exists():
            print("文件未找到")
            return ""

        print(f"[+] 解密文件 {full_path}...")

        try:
            version, data = decrypt_dat(full_path, info.xor_key, info.aes_key or None)
        except ValueError as exc:
            print(f"[-] 解密失败: {exc}")
            return ""

        print(f"[+] 加密版本: v{version}")

        # 处理 WxGF 格式
        if data.startswith(b"wxgf"):
            print("[+] 转换 WxGF 文件...")
            data = wxam_to_image(data)
            if data is None:
                print("[-] WxGF 转换失败")
                return ""

        return base64.b64encode(data).decode("utf-8")


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
    elif getattr(sys, "frozen", False):  # Nuitka
        base_path = os.path.dirname(sys.executable)
    else:  # 开发环境
        base_path = os.path.abspath(os.path.dirname(__file__))

    return os.path.join(base_path, relative_path)


def main() -> None:
    """应用程序的主入口函数。

    初始化 PyWebview 窗口并启动应用程序。
    """
    freeze_support()  # Windows 多进程支持

    # 初始化 PyWebview API
    api = Api()

    # 获取 index.html 的路径
    html_path = Path(get_resource_path("frontend/templates/index.html"))
    print(f"加载界面文件: {html_path}")

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

    print("PyWebview 窗口即将启动...")
    webview.start(debug=False)
    print("PyWebview 窗口已关闭。")


if __name__ == "__main__":
    main()
