from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime
from multiprocessing import freeze_support
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.theme import Theme

from backend.src.key import KeyExtractor

# Constants
MAX_CACHE_SIZE = 30
CACHE_TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"
WEIXIN_VERSIONS = ["3", "4"]
DEFAULT_VERSION = "4"
CONFIG_FILE = Path("config.json")

# Theme configuration
THEME = Theme(
    {
        "info": "cyan",
        "success": "green",
        "error": "red bold",
        "warning": "yellow",
        "title": "cyan bold",
    }
)

console = Console(theme=THEME)


@dataclass
class CacheEntry:
    """缓存密钥条目"""

    xor: int
    aes: str
    timestamp: str

    def to_dict(self) -> dict:
        """转换为字典"""
        return {
            "xor": self.xor,
            "aes": self.aes,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: dict) -> CacheEntry:
        """从字典构造"""
        return cls(
            xor=data.get("xor", 0),
            aes=data.get("aes", ""),
            timestamp=data.get("timestamp", ""),
        )


@dataclass
class Config:
    """应用配置"""

    xor: int = 0
    aes: str = ""
    cache: list[CacheEntry] = field(default_factory=list)

    def to_dict(self) -> dict:
        """转换为字典"""
        return {
            "xor": self.xor,
            "aes": self.aes,
            "cache": [entry.to_dict() for entry in self.cache],
        }

    @classmethod
    def from_dict(cls, data: dict) -> Config:
        """从字典构造"""
        cache_entries = [CacheEntry.from_dict(entry) for entry in data.get("cache", [])]
        return cls(
            xor=data.get("xor", 0),
            aes=data.get("aes", ""),
            cache=cache_entries,
        )


class ConfigManager:
    """配置文件管理器"""

    def __init__(self, config_file: Path = CONFIG_FILE):
        self.config_file = Path(config_file)

    def load(self) -> Config:
        """加载配置文件"""
        if not self.config_file.exists():
            return Config()

        try:
            with open(self.config_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                return Config.from_dict(data)
        except (json.JSONDecodeError, IOError) as e:
            console.print(f"加载配置失败: {e}", style="error")
            return Config()

    def save(self, config: Config) -> None:
        """保存配置文件"""
        try:
            self.config_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.config_file, "w", encoding="utf-8") as f:
                json.dump(config.to_dict(), f, indent=2, ensure_ascii=False)
        except IOError as e:
            console.print(f"保存配置失败: {e}", style="error")


class KeyManager:
    """密钥管理器"""

    def __init__(self, config_manager: ConfigManager):
        self.config_manager = config_manager

    def display_cached_keys(self, cache: list[CacheEntry]) -> None:
        """显示缓存的密钥记录"""
        if not cache:
            console.print("没有缓存的密钥记录", style="info")
            return

        table = Table(
            title="历史密钥记录",
            show_header=True,
            header_style="bold magenta",
        )
        table.add_column("时间", style="cyan")
        table.add_column("XOR密钥", style="green")
        table.add_column("AES密钥", style="yellow")

        for entry in cache:
            table.add_row(
                entry.timestamp,
                f"0x{entry.xor:02X}",
                entry.aes[:16] if entry.aes else "N/A",
            )

        console.print(table)

    def display_current_keys(self, config: Config) -> None:
        """显示当前密钥"""
        if config.xor and config.aes:
            console.print("当前密钥:", style="info")
            console.print(f"XOR: 0x{config.xor:02X}", style="success")
            console.print(f"AES: {config.aes[:16]}", style="success")
            console.print()

    def verify_cached_keys(
        self,
        weixin_dir: Path,
        version: int,
        cache: list[CacheEntry],
    ) -> tuple[Optional[int], Optional[str]]:
        """验证缓存的密钥"""
        if not cache:
            return None, None

        if not Confirm.ask("检测到已缓存的密钥,是否验证?", default=True):
            return None, None

        extractor = KeyExtractor(weixin_dir, version)

        for entry in cache:
            if not entry.xor or not entry.aes:
                continue

            try:
                console.print(
                    f"\n正在验证密钥 XOR: 0x{entry.xor:02X}, AES: {entry.aes[:16]}",
                    style="info",
                )
                keys = extractor.extract(
                    xor_key_=entry.xor,
                    aes_key_=entry.aes.encode()[:16],
                )
                console.print("✓ 密钥验证成功!", style="success")
                return keys.xor_key, entry.aes
            except Exception as e:
                console.print(f"✗ 该密钥验证失败: {e}", style="error")
                continue

        return None, None

    def find_new_keys(
        self,
        weixin_dir: Path,
        version: int,
    ) -> tuple[Optional[int], Optional[bytes]]:
        """寻找新密钥"""
        try:
            console.print("正在寻找新密钥...", style="info")
            extractor = KeyExtractor(weixin_dir, version)
            keys = extractor.extract()
            return keys.xor_key, keys.aes_key
        except Exception as e:
            console.print(f"获取密钥失败: {e}", style="error")
            return None, None

    def add_to_cache(
        self,
        config: Config,
        xor_key: int,
        aes_key: bytes,
    ) -> None:
        """添加密钥到缓存"""
        if isinstance(aes_key, bytes):
            aes_str = aes_key.decode()
        elif isinstance(aes_key, (bytearray, memoryview)):
            aes_str = bytes(aes_key).decode()
        else:
            aes_str = aes_key

        new_entry = CacheEntry(
            xor=xor_key,
            aes=aes_str,
            timestamp=datetime.now().strftime(CACHE_TIMESTAMP_FORMAT),
        )

        # 检查是否已存在相同的密钥对
        if any(entry.xor == xor_key and entry.aes == aes_str for entry in config.cache):
            return

        config.cache.append(new_entry)

        # 只保留最近的记录
        if len(config.cache) > MAX_CACHE_SIZE:
            config.cache = config.cache[-MAX_CACHE_SIZE:]


class PathValidator:
    """路径验证器"""

    @staticmethod
    def get_valid_path() -> Path:
        """获取有效的路径"""
        while True:
            path_str = Prompt.ask("请输入微信缓存目录的完整路径")
            custom_path = Path(path_str)

            if not custom_path.exists():
                console.print("✗ 目录不存在", style="error")
                if not Confirm.ask("是否重新输入?", default=True):
                    raise KeyboardInterrupt
                continue

            if not custom_path.is_dir():
                console.print("✗ 不是有效的目录", style="error")
                if not Confirm.ask("是否重新输入?", default=True):
                    raise KeyboardInterrupt
                continue

            return custom_path

    @staticmethod
    def get_version() -> int:
        """获取微信版本"""
        version = int(
            Prompt.ask(
                "选择微信版本",
                choices=WEIXIN_VERSIONS,
                default=DEFAULT_VERSION,
            )
        )
        return version


class Application:
    """主应用程序"""

    def __init__(self):
        self.config_manager = ConfigManager()
        self.key_manager = KeyManager(self.config_manager)
        self.path_validator = PathValidator()

    def show_welcome(self) -> None:
        """显示欢迎信息"""
        console.print(
            Panel.fit(
                "微信数据解密工具",
                title="WxDatDecrypt",
                border_style="cyan",
            )
        )

    def run(self) -> None:
        """运行应用程序"""
        self.show_welcome()

        # 加载配置
        config = self.config_manager.load()

        # 显示历史记录
        if config.cache:
            self.key_manager.display_cached_keys(config.cache)
            console.print()

        # 显示当前密钥
        self.key_manager.display_current_keys(config)

        # 获取输入
        weixin_dir = self.path_validator.get_valid_path()
        console.print(f"✓ 使用目录: {weixin_dir}", style="success")
        console.print()

        version = self.path_validator.get_version()
        console.print()

        # 尝试验证缓存的密钥
        xor_key, aes_key = self.key_manager.verify_cached_keys(
            weixin_dir,
            version,
            config.cache,
        )

        if xor_key is not None and aes_key is not None:
            config.xor = xor_key
            config.aes = aes_key
            self.config_manager.save(config)
            return

        # 如果验证失败，确认是否获取新密钥
        if config.cache and not Confirm.ask(
            "所有缓存密钥验证失败，是否获取新密钥?",
            default=True,
        ):
            return

        # 寻找新密钥
        xor_key, aes_key = self.key_manager.find_new_keys(
            weixin_dir,
            version,
        )

        if xor_key is None or aes_key is None:
            console.print("警告：未获取到密钥", style="warning")
            return

        # 更新配置
        config.xor = xor_key
        if isinstance(aes_key, bytes):
            config.aes = aes_key.decode()
        elif isinstance(aes_key, (bytearray, memoryview)):
            config.aes = bytes(aes_key).decode()
        else:
            config.aes = aes_key
        self.key_manager.add_to_cache(config, xor_key, aes_key)
        self.config_manager.save(config)

        # 显示结果
        console.print("\n新密钥获取成功！", style="success")
        console.print(f"XOR: 0x{xor_key:02X}", style="success")
        console.print(f"AES: {config.aes[:16]}", style="success")

    @staticmethod
    def pause() -> None:
        """暂停程序"""
        console.print("\n按任意键退出...", style="info")
        os.system("pause > nul")


def main() -> None:
    """主程序入口"""
    app = Application()
    try:
        app.run()
    except KeyboardInterrupt:
        console.print("\n程序已取消", style="warning")
    except Exception as e:
        console.print(f"发生错误: {e}", style="error")
    finally:
        Application.pause()


if __name__ == "__main__":
    freeze_support()
    main()
