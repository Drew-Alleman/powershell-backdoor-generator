"""
This is imported by listen.py and is used to fetch the desired flipper/ducky payload 
"""

from core.payloads.custom.execute import Execute
from core.payloads.custom.bindandexecute import BindAndExecute


class InvalidPayloadName(Exception):
    def __init__(self, payload_name: str) -> None:
        self.message = f"{payload_name} is not a valid payload please use one of the following (case insensitive) \n{', '.join(PAYLOADS.keys())}"
        super().__init__(self.message)


PAYLOADS = {
    "execute": Execute,
    "bindandexecute": BindAndExecute,
}


def fetch(name, config):
    """
    Creates an instance of the payload they selected
    """
    payload = PAYLOADS.get(name.lower())
    if not payload:
        raise InvalidPayloadName(name)
    return payload(config)
