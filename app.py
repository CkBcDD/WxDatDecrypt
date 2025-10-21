import base64
import json
import os
import sys
from multiprocessing import freeze_support
from pathlib import Path

import webview

from backend.src.decrypt import decrypt_dat
from backend.src.wxam import wxam_to_image


CONFIG_FILE = "config.json"


def read_key_from_config() -> tuple[int, bytes]:
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

    if isinstance(aes_value, str):
        aes_key = aes_value.encode()
    elif isinstance(aes_value, (bytes, bytearray)):
        aes_key = bytes(aes_value)
    else:
        aes_key = b""

    return xor_key, aes_key[:16]


# 全局对象，用于保存微信文件信息，FastAPI 和主线程都可以访问
class WeixinInfo:
    weixin_dir: Path | None = None  # 初始化为 None
    xor_key: int = 0  # 添加默认值
    aes_key: bytes = b""  # 添加默认值


info = WeixinInfo()


DAT_FILE_EXTENSION = ".dat"


class Api:
    """
    PyWebview 的 JavaScript API 接口。
    """

    def __init__(self):
        self.root_dir = None
        self.server_url = None  # 用于存储 FastAPI 服务器的 URL

    def _is_valid_sns_filename(self, filename: str) -> bool:
        """
        检查文件名是否为朋友圈 (Sns) 缓存文件的文件名形式
        """
        name = filename.removesuffix("_t")
        return len(name) in [30, 32] and name.isalnum()

    def set_server_url(self, url: str):
        """
        设置 FastAPI 服务器的 URL。
        """
        self.server_url = url

    def get_server_url(self):
        """
        获取 FastAPI 服务器的 URL，供前端 JavaScript 调用。
        """
        return self.server_url

    def set_root_dir(self, path):
        """
        设置微信文件根目录。
        """
        if os.path.isdir(path):
            self.root_dir = path
            return {"success": True, "path": path}
        return {"success": False, "error": "无效的路径"}

    def get_folder_tree(self):
        """
        获取文件夹树结构。
        """
        if not self.root_dir:
            return None

        root_path = Path(self.root_dir)

        def build_tree(dir_path: Path):
            tree_node = {
                "name": dir_path.name,
                "path": str(dir_path),
                "children": [],
            }
            try:
                for entry in dir_path.iterdir():
                    if entry.is_dir():
                        tree_node["children"].append(build_tree(entry))
            except OSError as exc:
                print(f"读取目录 {dir_path} 失败: {exc}")
            return tree_node

        return build_tree(root_path)

    def get_images_in_folder(self, folder_path):
        """
        获取指定文件夹中所有 .dat 文件的相对路径列表。
        """
        if not self.root_dir:
            return []

        root_path = Path(self.root_dir).resolve()
        folder = Path(folder_path).resolve()
        try:
            folder.relative_to(root_path)
        except ValueError:
            return []

        relative_paths: list[str] = []
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

    def open_folder_dialog(self):
        """
        打开文件夹选择对话框。
        """
        result = window.create_file_dialog(webview.FileDialog.FOLDER)  # type: ignore
        if result:
            path = result[0]
            if os.path.isdir(path):
                path_ = Path(path).resolve()

                self.root_dir = path
                info.weixin_dir = path_

                # 先从配置文件读取密钥
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

    def decrypt_dat(self, file_path: str):

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
            print(f"解密失败: {exc}")
            return ""

        print(f"[+] 加密版本: v{version}")

        if data.startswith(b"wxgf"):
            print("[+] 转换 WxGF 文件...")
            data = wxam_to_image(data)

        return base64.b64encode(data).decode("utf-8")


def get_resource_path(relative_path):
    """
    获取资源文件的绝对路径，兼容开发环境和打包后的环境
    """
    if hasattr(sys, "_MEIPASS"):  # PyInstaller
        base_path = sys._MEIPASS  # type: ignore
    elif getattr(sys, "frozen", False):  # Nuitka
        base_path = os.path.dirname(sys.executable)
    else:  # 开发环境
        base_path = os.path.abspath(os.path.dirname(__file__))

    return os.path.join(base_path, relative_path)


if __name__ == "__main__":
    freeze_support()  # 用于在 Windows 上打包成可执行文件时支持多进程

    # 3. 初始化 PyWebview API 并传递服务器 URL
    api = Api()

    # 4. 获取 index.html 的路径
    html_path = Path(get_resource_path("frontend/templates/index.html"))
    print(f"加载界面文件: {html_path}")
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
    # 由于服务器线程是守护线程，当主线程退出时它也会自动终止。
