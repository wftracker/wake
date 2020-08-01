import wake
import unittest

from wake.misc import get_server_keys_from_warfacebot


class TestWakeMethods(unittest.TestCase):
    """
    I know this is a not good way for test case. but, i'll do it later
    """

    NORMAL_TEXT = "</stream:stream>"

    server = get_server_keys_from_warfacebot('EU')
    wake = wake.Wake(**server)

    wake.crypt_init(147)

    def test_wake(self):
        _msg = self.NORMAL_TEXT
        _msg_len = len(self.NORMAL_TEXT)

        emsg = self.wake.crypt_encrypt(_msg.encode(), _msg_len)
        dmsg = self.wake.crypt_decrypt(emsg, _msg_len)

        self.assertEqual(_msg, dmsg.decode())


if __name__ == '__main__':
    unittest.main()
