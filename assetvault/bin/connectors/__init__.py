"""Built-in device connectors. Add a file and a line in CLASSES to register another."""
from .base import Connector, ConnectorError, public_device
from .entra import EntraConnector
from .ad import AdConnector
from .jamf import JamfConnector
from .generic_rest import GenericRestConnector

CLASSES = {
    "entra": EntraConnector,
    "ad": AdConnector,
    "jamf": JamfConnector,
    "generic_rest": GenericRestConnector,
}

def names():
    return sorted(CLASSES)

def get(name):
    if name not in CLASSES:
        raise ConnectorError("unknown connector", "Unreachable")
    return CLASSES[name]

def build(name, config, **kwargs):
    return get(name)(config, **kwargs)

def describe_all():
    return [CLASSES[name]({}).describe() for name in names()]
