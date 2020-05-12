import wake
import unittest


class TestWakeMethods(unittest.TestCase):
    """
    I know this is a not good way for test case. but, i'll do it later
    """

    NORMAL_TEXT = "</stream:stream>"

    game_version = "1.21600.651.34300"
    game_crypt_iv = "834724096,29884556,849283813,14157667,779975000,969872986,327122214,893084885"
    game_crypt_key = "4209908010,2271146380,35657388,2443088608,2330988938,2730014908,2925181723,818095673,1444019455,2423077405,1890892272,3301761789,3165868634,312749393,1857255675,3959729711,1605979325,3056971377,4275908276,2361797745,840088409,363287718,932251835,910280416,1863990376,429428670,1120742861,978118767,1793005588,3391878849,1181901046,2074528913"

    wake = wake.Wake(
        game_version,
        game_crypt_iv,
        game_crypt_key
    )

    wake.crypt_init(147)

    def test_wake(self):

        _msg = self.NORMAL_TEXT
        _msg_len = len(self.NORMAL_TEXT)

        emsg = self.wake.crypt_encrypt(_msg.encode(), _msg_len)
        dmsg = self.wake.crypt_decrypt(emsg, _msg_len)

        self.assertEqual(_msg, dmsg.decode())


if __name__ == '__main__':
    unittest.main()
