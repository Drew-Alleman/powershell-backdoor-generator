from core.utils import generate_string


class Config:
    def __init__(self, CWD, **kwargs):
        self.CWD = CWD
        self.ip_address: str = kwargs.get("ip_address")
        self.payload: str = kwargs.get("payload")
        self.port: int = kwargs.get("port")
        self.ip_tuple: tuple = (self.ip_address, self.port)
        self.verbose: bool = kwargs.get("verbose")
        self.out_file: str = kwargs.get("out")
        self.ip_address: str = kwargs.get("ip_address")
        self.delay: int = kwargs.get("delay")
        self.server_port: int = kwargs.get("server_port")
        self.server_ip_tuple: tuple = (self.ip_address, self.server_port)
        self.type: bool = kwargs.get("type")
        self.keyboard_layout: str = kwargs.get("keyboard")
        self.flipper: str = kwargs.get("flipper")
        self.ducky: str = kwargs.get("ducky")
        self.advanced: bool = kwargs.get("advanced")
        self.list_payloads = kwargs.get("list_payloads")
        if kwargs.get("random"):
            self.out_file: str = f"{generate_string(8)}.ps1"
        self.TEMPLATE_DIR = self.CWD + r"core/payloads/templates/"
        self.BACKDOOR_TEMPLATE = self.TEMPLATE_DIR + "template.ps1"
        self.BASIC_PAYLOAD = self.TEMPLATE_DIR + "basic-payload.txt"
        self.ADVANCED_PAYLOAD = self.TEMPLATE_DIR + "advanced-payload.txt"
        self.verbose = kwargs.get("verbose")
        self.just_listen = kwargs.get("actually_listen")
        self.just_listen_and_host = kwargs.get("listen_and_host")
