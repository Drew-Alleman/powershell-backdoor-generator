import os
from core.utils import get_file_content, make_unix_here, get_output


class MissingJava(Exception):
    def __init__(self):
        self.message = "Java is needed to run encoder.jar please install it here: https://www.java.com/download/ie_manual.jsp \n\nPlease restart terminal after installation"
        super().__init__(self.message)


class USBPayload:
    """
    Ducky/Flipper Payload
    """

    def __remove_and_close_temp(self) -> None:
        """Removes and closes the temporary file payload.txt"""
        self.temp.close()
        self.__remove_temp_file()

    def __remove_temp_file(self) -> None:
        """Removes the temporary payload.txt file"""
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            pass
        self.temp = False

    def __build(self) -> bool:
        """Builds a payload text file
        :return: True if the file was created
        """
        self.path = f"{self.config.CWD}\\payload.txt"
        self.source_content = get_file_content(self.config.TEMPLATE_DIR + self.source)
        self.__remove_temp_file()
        self.temp = open(self.path, "ab+")
        if "START_DELAY_TIME" in self.source_content:
            self.source_content = self.source_content.replace(
                "START_DELAY_TIME", str(self.config.delay)
            )
        for key, line in self.lines.items():
            self.source_content = self.source_content.replace(key, line)
        self.temp.seek(0)
        return bool(self.temp.write(self.source_content.encode()))

    def __encode_payload(self):
        """Encodes the payload.txt into inject.bin
        1. Requires java
        2. Requires encode.jar
        :return: True if the file was made
        """
        try:
            out = get_output(
                [
                    "java",
                    "-jar",
                    f"encoder.jar",
                    "-i",
                    f"{self.path}",
                    "-l",
                    self.config.keyboard_layout,
                ]
            )
            return b"DuckyScript Complete" in out
        except FileNotFoundError:
            raise MissingJava

    def execute(self) -> bool:
        self.__build()
        if self.config.ducky:
            self.__encode_payload()
        if self.config.flipper:
            self.temp.seek(0)
            make_unix_here(
                self.temp.read(), self.config.CWD + f"\\{self.config.flipper}.txt"
            )
        self.__remove_and_close_temp()
        return True

    def stop(self):
        if self.temp:
            self.__remove_and_close_temp()
