import copy
import ctypes


class Wake:
    tt: list = [0x726a8f3b, 0xe69a3b5c, 0xd3c71fe5, 0xab3c73d2, 0x4d3a8eb3, 0x0396d6e8, 0x3d4c2f7a, 0x9ee27cf3]
    crypt_iv: list = [0x31C0E100, 0x01C8008C, 0x329F0AE5, 0x00D80763, 0x2E7D7958, 0x39CF165A, 0x137F7D26, 0x00000000]

    WAKE_KEY: dict = {
        't': [None] * 257,
        'r': [None] * 4,
        'counter': None,
        'iv': [None] * 8,
        'ivsize': None,
        'r1': 0x00000000,
        'r2': 0x00000000
    }

    def __init__(self, game_version: str, game_crypt_iv: str, game_crypt_key: str, **kwargs):
        self.game_version: list = self._ready_cls_parm(game_version, '.')
        self.game_crypt_iv: list = self._ready_cls_parm(game_crypt_iv)
        self.game_crypt_key: list = self._ready_cls_parm(game_crypt_key)
        self._is_crypt_ready: bool = False

    @staticmethod
    def _ready_cls_parm(_parm: str, splitter=',') -> list:
        try:
            return list(map(int, _parm.split(splitter)))
        except (ValueError, AttributeError):
            return list()

    @staticmethod
    def _mcrypt_get_key_size() -> int:
        return 32

    @staticmethod
    def _int_m(_x, _y, _wake_key):
        _tmp = ctypes.c_int32(_x + _y).value
        return ((_tmp >> 8) & 0x00ffffff) ^ _wake_key['t'][_tmp & 0xff]

    def __mcrypt_set_key(self, wake_key, crypt_key, crypt_key_len, crypt_iv, crypt_iv_len):

        if crypt_key_len != 32:
            return

        k: list = [crypt_key[0], crypt_key[1], crypt_key[2], crypt_key[3]]

        for p in range(4):
            wake_key['t'][p] = k[p]

        for p in range(4, 256):
            x = ctypes.c_uint32(wake_key['t'][p - 4] + wake_key['t'][p - 1]).value
            x = x >> 3 ^ self.tt[x & 7]
            wake_key['t'][p] = x

        for p in range(0, 23):
            wake_key['t'][p] = ctypes.c_uint32(wake_key['t'][p] + wake_key['t'][p + 89]).value

        x = wake_key['t'][33]
        z = wake_key['t'][59] | 0x01000001
        z &= 0xff7fffff

        for p in range(0, 256):
            x = ctypes.c_uint32((x & 0xff7fffff) + z).value
            wake_key['t'][p] = (wake_key['t'][p] & 0x00ffffff) ^ x

        wake_key['t'][256] = wake_key['t'][0]
        x &= 0xff

        for p in range(0, 256):
            x = (wake_key['t'][p ^ x] ^ x) & 0xff

            wake_key['t'][p] = wake_key['t'][x]
            wake_key['t'][x] = wake_key['t'][p + 1]

        wake_key['counter'] = 0
        wake_key['r'] = [k[0], k[1], k[2], k[3]]
        wake_key['started'] = 0

        if crypt_iv_len > 32:
            wake_key['ivsize'] = 32
        else:
            wake_key['ivsize'] = crypt_iv_len / 4 * 4

        if crypt_iv is None:
            wake_key['ivsize'] = 0

        if wake_key['ivsize'] > 0 and crypt_iv is not None:
            wake_key['iv'] = crypt_iv

    def __mcrypt_encrypt(self, wake_key, msg, msg_len):

        _msg = list(msg)

        if msg_len == 0:
            return

        r3 = wake_key['r'][0]
        r4 = wake_key['r'][1]
        r5 = wake_key['r'][2]
        r6 = wake_key['r'][3]

        for i in range(0, msg_len):

            _msg[i] = _msg[i] ^ r6.to_bytes(4, byteorder='little')[wake_key['counter']]

            _ = list(wake_key['r2'].to_bytes(4, byteorder='little'))
            _[wake_key['counter']] = _msg[i]

            wake_key['r2'] = int.from_bytes(bytes(_), "little")

            wake_key['counter'] += 1

            if wake_key['counter'] == 4:
                wake_key['counter'] = 0

                r3 = self._int_m(r3, wake_key['r2'], wake_key)
                r4 = self._int_m(r4, r3, wake_key)
                r5 = self._int_m(r5, r4, wake_key)
                r6 = self._int_m(r6, r5, wake_key)

        wake_key['r'][0] = r3
        wake_key['r'][1] = r4
        wake_key['r'][2] = r5
        wake_key['r'][3] = r6

        return bytes(_msg)

    def __mcrypt_decrypt(self, wake_key, msg, msg_len):

        _msg = list(msg)

        if msg_len == 0:
            return

        r3 = wake_key['r'][0]
        r4 = wake_key['r'][1]
        r5 = wake_key['r'][2]
        r6 = wake_key['r'][3]

        for i in range(0, msg_len):

            _ = list(wake_key['r1'].to_bytes(4, byteorder='little'))

            _[wake_key['counter']] = _msg[i]
            wake_key['r1'] = int.from_bytes(bytes(_), "little")

            _msg[i] = _msg[i] ^ r6.to_bytes(4, byteorder='little')[wake_key['counter']]

            wake_key['counter'] += 1

            if wake_key['counter'] == 4:
                wake_key['counter'] = 0

                r3 = self._int_m(r3, wake_key['r1'], wake_key)
                r4 = self._int_m(r4, r3, wake_key)
                r5 = self._int_m(r5, r4, wake_key)
                r6 = self._int_m(r6, r5, wake_key)

        wake_key['r'][0] = r3
        wake_key['r'][1] = r4
        wake_key['r'][2] = r5
        wake_key['r'][3] = r6

        return bytes(_msg)

    def is_crypt_ready(self):
        return self._is_crypt_ready

    def crypt_init(self, salt: int):

        for index, value in enumerate(self.crypt_iv):
            self.crypt_iv[index] ^= salt

        if not self.game_crypt_key and not self.game_crypt_iv:

            for index_j, value_j in enumerate(self.crypt_iv):
                for index_i, value_i in enumerate(self.game_version):
                    self.game_crypt_key[index_i + (index_j * 4)] = (self.game_version[index_i] ^ (self.game_version[len(self.game_version) - 1] + index_j)) & 0xFF

        self._is_crypt_ready = True

    def crypt_decrypt(self, msg: bytes, msg_len: int):

        if not self._is_crypt_ready:
            return

        _wake_key = copy.deepcopy(self.WAKE_KEY)

        self.__mcrypt_set_key(_wake_key, self.game_crypt_key, len(self.game_crypt_key), self.game_crypt_iv, len(self.game_crypt_iv))
        return self.__mcrypt_decrypt(_wake_key, msg, msg_len)

    def crypt_encrypt(self, msg: bytes, msg_len: int):

        if not self._is_crypt_ready:
            return

        _wake_key = copy.deepcopy(self.WAKE_KEY)

        self.__mcrypt_set_key(_wake_key, self.game_crypt_key, len(self.game_crypt_key), self.game_crypt_iv, len(self.game_crypt_iv))
        return self.__mcrypt_encrypt(_wake_key, msg, msg_len)

