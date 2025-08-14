import webview
import os
import threading
import socket
import struct
import sys
import json
from multiprocessing import freeze_support
from pathlib import Path

# 从 server.py 导入的模块
from Crypto.Cipher import AES
from Crypto.Util import Padding
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
import uvicorn

import dump_key as dk



CONFIG_FILE = "config.json"


def read_key_from_config() -> tuple[int, bytes]:
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            key_dict = json.loads(f.read())

        x, y = key_dict["xor"], key_dict["aes"]
        return x, y.encode()[:16]

    return 0, b""


def store_key(xor_k: int, aes_k: bytes) -> None:
    key_dict = {
        "xor": xor_k,
        "aes": aes_k.decode(),
    }

    with open(CONFIG_FILE, "w") as f:
        f.write(json.dumps(key_dict))


# --- 来自 server.py 的核心组件 ---


# 全局对象，用于保存微信文件信息，FastAPI 和主线程都可以访问
class WeixinInfo:
    weixin_dir: Path | None = None  # 初始化为 None
    xor_key: int = 0  # 添加默认值
    aes_key: bytes = b""  # 添加默认值


info = WeixinInfo()


def decrypt_dat_v3(input_path: str | Path, xor_key: int) -> bytes:
    """
    解密 v3 版本的 .dat 文件。
    """
    with open(input_path, "rb") as f:
        data = f.read()
    return bytes(b ^ xor_key for b in data)


def decrypt_dat_v4(input_path: str | Path, xor_key: int, aes_key: bytes) -> bytes:
    """
    解密 v4 版本的 .dat 文件。
    """
    with open(input_path, "rb") as f:
        header, data = f.read(0xF), f.read()
        signature, aes_size, xor_size = struct.unpack("<6sLLx", header)
        aes_size += AES.block_size - aes_size % AES.block_size

        aes_data = data[:aes_size]
        raw_data = data[aes_size:]

    cipher = AES.new(aes_key, AES.MODE_ECB)
    decrypted_data = Padding.unpad(cipher.decrypt(aes_data), AES.block_size)

    if xor_size > 0:
        raw_data = data[aes_size:-xor_size]
        xor_data = data[-xor_size:]
        xored_data = bytes(b ^ xor_key for b in xor_data)
    else:
        xored_data = b""

    return decrypted_data + raw_data + xored_data


def decrypt_dat(input_file: str | Path) -> int:
    """
    判断 .dat 文件的加密版本。
    """
    with open(input_file, "rb") as f:
        signature = f.read(6)

    match signature:
        case b"\x07\x08V1\x08\x07":
            return 1
        case b"\x07\x08V2\x08\x07":
            return 2
        case _:
            return 0


# FastAPI 应用设置
app = FastAPI()

# 添加 CORS 中间件，允许所有来源进行跨域请求（开发环境常用）
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/decrypt/{file_path:path}")
async def decrypt_file_endpoint(file_path: str) -> Response:
    """
    FastAPI 端点，用于解密指定路径的文件并返回其内容。
    """
    # 使用全局 info 对象
    if info.weixin_dir is None:
        raise HTTPException(status_code=500, detail="微信文件目录未设置。")

    full_path = info.weixin_dir / file_path

    if not full_path.exists():
        raise HTTPException(status_code=404, detail=f"文件未找到: {full_path}")

    print(f"[+] 解密文件 {full_path}...")

    version = decrypt_dat(full_path)
    print(f"[+] 加密版本: v{version}")
    data = b""
    match version:
        case 0:
            data = decrypt_dat_v3(full_path, info.xor_key)
        case 1:
            data = decrypt_dat_v4(full_path, info.xor_key, b"cfcd208495d565ef")
        case 2:
            data = decrypt_dat_v4(full_path, info.xor_key, info.aes_key)
        case _:
            raise HTTPException(status_code=400, detail=f"不支持的解密版本: {version}")


    # 默认返回 image/png，您可以根据实际内容进行更智能的判断
    return Response(content=data, media_type="image/png")


# --- 来自 app.py 的核心组件 ---

DAT_FILE_EXTENSION = ".dat"


class Api:
    """
    PyWebview 的 JavaScript API 接口。
    """

    def __init__(self):
        self.root_dir = None
        self.server_url = None  # 用于存储 FastAPI 服务器的 URL

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

        def build_tree(dir_path):
            tree_node = {
                "name": os.path.basename(dir_path),
                "path": dir_path,
                "children": [],
            }
            try:
                for name in os.listdir(dir_path):
                    path = os.path.join(dir_path, name)
                    if os.path.isdir(path):
                        tree_node["children"].append(build_tree(path))
            except OSError:
                pass
            return tree_node

        return build_tree(self.root_dir)

    def get_images_in_folder(self, folder_path):
        """
        获取指定文件夹中所有 .dat 文件的相对路径列表。
        """
        if not self.root_dir or not folder_path.startswith(self.root_dir):
            return []

        relative_paths = []
        try:
            for item in os.listdir(folder_path):
                if item.lower().endswith(DAT_FILE_EXTENSION):
                    full_path = os.path.join(folder_path, item)
                    relative_path = os.path.relpath(full_path, self.root_dir)
                    relative_paths.append(relative_path)
        except OSError as e:
            print(f"读取目录 {folder_path} 错误: {e}")

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

                # 尝试查找新的密钥
                new_xor, new_aes = dk.find_key(path_, xor_k, aes_k)
                if new_xor and new_aes:
                    info.xor_key = new_xor
                    info.aes_key = new_aes
                    store_key(new_xor, new_aes)  # 保存新的密钥
                    print(f"更新密钥: xor={new_xor}, aes={new_aes}")
                    # 更新 FastAPI 服务器使用的全局 info 对象

                print(f"PyWebview API: 根目录已通过对话框设置为 {self.root_dir}")
                print(
                    f"FastAPI 全局 info.weixin_dir 已通过对话框设置为 {info.weixin_dir}"
                )
                return {"success": True, "path": path}
        return {"success": False}


# --- 服务器启动逻辑 ---


def find_available_port(start_port: int = 49152, end_port: int = 65535) -> int:
    """
    查找一个可用的 TCP 端口。
    """
    for port in range(start_port, end_port + 1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", port))
                return port
        except OSError:
            continue
    raise IOError("没有找到可用的端口。")


def run_fastapi_server(host: str, port: int):
    """
    在单独的线程中运行 FastAPI 服务器 (使用 Uvicorn)。
    """
    print(f"尝试在 http://{host}:{port} 启动 FastAPI 服务器 (使用 Uvicorn)...")
    # uvicorn.run 会自动管理其内部的 asyncio 事件循环。
    # 对于在非主线程中运行，uvicorn 内部会处理好信号问题。
    uvicorn.run(app, host=host, port=port, log_level="info")


def get_resource_path(relative_path):
    """
    获取资源文件的绝对路径，兼容开发环境和打包后的环境
    """
    if hasattr(sys, "_MEIPASS"):  # PyInstaller
        base_path = sys._MEIPASS
    elif getattr(sys, "frozen", False):  # Nuitka
        base_path = os.path.dirname(sys.executable)
    else:  # 开发环境
        base_path = os.path.abspath(os.path.dirname(__file__))

    return os.path.join(base_path, relative_path)


if __name__ == "__main__":
    freeze_support()  # 用于在 Windows 上打包成可执行文件时支持多进程

    # 1. 查找 FastAPI 服务器可用的端口
    try:
        server_port = find_available_port()
        server_host = "127.0.0.1"
        server_full_url = f"http://{server_host}:{server_port}"
    except IOError as e:
        print(f"错误: {e}")
        sys.exit(1)

    # 2. 在单独的守护线程中启动 FastAPI 服务器
    server_thread = threading.Thread(
        target=run_fastapi_server, args=(server_host, server_port), daemon=True
    )
    server_thread.start()

    # 给服务器一些时间启动
    print("等待 FastAPI 服务器启动...")

    # 3. 初始化 PyWebview API 并传递服务器 URL
    api = Api()
    api.set_server_url(server_full_url)

    # 4. 获取 index.html 的路径
    html_path = get_resource_path("index.html")
    print(f"加载界面文件: {html_path}")

    # 5. 创建并启动 PyWebview 窗口
    window = webview.create_window(
        "微信图片查看器",
        html_path,
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
