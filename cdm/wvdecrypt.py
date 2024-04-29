from pywidevine.cdm import Cdm
from pywidevine.device import Device
from pywidevine.pssh import PSSH


class WvDecrypt(object):
    def __init__(self, device, cert_data_b64):
        self.device = Device.load(device)
        self.cdm = Cdm.from_device(self.device)
        self.session = self.cdm.open()
        if cert_data_b64:
            self.cdm.set_service_certificate(self.session, cert_data_b64)

    def get_keys(self):
        keys_wvDecrypt = {}
        try:
            for key in self.cdm.get_keys(self.session):
                if key.type == 'CONTENT':
                    keys_wvDecrypt[key.kid.hex] = key.key.hex()
        except Exception:
            return keys_wvDecrypt
        return keys_wvDecrypt

    def get_challenge(self, pssh_b64):
        return self.cdm.get_license_challenge(self.session, PSSH(pssh_b64))

    def update_license(self, _license):
        self.cdm.parse_license(self.session, _license)

    def close(self):
        self.cdm.close(self.session)


# import base64
# from cdm.cdm import Cdm
# from cdm.deviceconfig import DeviceConfig
# class WvDecrypt(object):
#     WV_SYSTEM_ID = [0xED, 0xEF, 0x8B, 0xA9, 0x79, 0xD6, 0x4A, 0xCE, 0xA3, 0xC8, 0x27, 0xDC, 0xD5, 0x1D, 0x21, 0xED]
#
#     def __init__(self, pssh_b64, cert_data_b64, device):
#         self.pssh_b64 = pssh_b64
#         self.cert_data_b64 = cert_data_b64
#         self.device = device
#         self.cdm = Cdm()
#
#         def fix_pssh(_pssh_b64):
#             pssh = base64.b64decode(_pssh_b64)
#             if not pssh[12:28] == bytes(self.WV_SYSTEM_ID):
#                 new_pssh = bytearray([0, 0, 0])
#                 new_pssh.append(32 + len(pssh))
#                 new_pssh[4:] = bytearray(b'pssh')
#                 new_pssh[8:] = [0, 0, 0, 0]
#                 new_pssh[13:] = self.WV_SYSTEM_ID
#                 new_pssh[29:] = [0, 0, 0, 0]
#                 new_pssh[31] = len(pssh)
#                 new_pssh[32:] = pssh
#                 return base64.b64encode(new_pssh)
#             else:
#                 return _pssh_b64
#
#         self.session = self.cdm.open_session(fix_pssh(self.pssh_b64), DeviceConfig(self.device))
#         if self.cert_data_b64:
#             self.cdm.set_service_certificate(self.session, self.cert_data_b64)
#
#     def get_keys(self):
#         keys_wvDecrypt = {}
#         try:
#             for key in self.cdm.get_keys(self.session):
#                 if key.type == 'CONTENT':
#                     keys_wvDecrypt[key.kid.hex()] = key.key.hex()
#         except Exception:
#             return keys_wvDecrypt
#         return keys_wvDecrypt
#
#     def get_challenge(self):
#         return self.cdm.get_license_request(self.session)
#
#     def update_license(self, _license):
#         self.cdm.provide_license(self.session, _license)
#
#     def close(self):
#         self.cdm.close_session(self.session)
