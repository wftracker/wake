import urllib.request

from configparser import ConfigParser

LEVAK_WARFACEBOT_KEYS_URL = "https://raw.githubusercontent.com/Levak/warfacebot/master/cfg/server/{}.cfg"


def get_server_keys_from_warfacebot(server: str) -> dict:
    try:
        response = urllib.request.urlopen(LEVAK_WARFACEBOT_KEYS_URL.format(server.lower()))
    except Exception as e:
        raise e
    else:
        response = response.read().decode('utf-8')

        config = ConfigParser()
        config.read_string(f"[ROOT]{response}")

        return dict(config['ROOT'])

