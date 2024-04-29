import os

device_chrome_cdm_2257 = {
    'name': 'google_chromecdm_2557',
    'description': 'chrome cdm windows 2257',
    'security_level': 3,
    'session_id_type': 'chrome',
    'private_key_available': True,
    'vmp': True,
    'send_key_control_nonce': True
}

device_samsung_sm_g935f = {
    'name': 'samsung_sm-g935f',
    'description': 'samsung sm-g935f',
    'security_level': 3,
    'session_id_type': 'android',
    'private_key_available': True,
    'vmp': False,
    'send_key_control_nonce': True
}

device_asus_t00n = {
    'name': 'ASUS_T00N',
    'description': 'Asus T00N',
    'security_level': 1,
    'session_id_type': 'android',
    'private_key_available': True,
    'vmp': False,
    'send_key_control_nonce': True
}

devices_available = [device_chrome_cdm_2257, device_samsung_sm_g935f, device_asus_t00n]
FILES_FOLDER = 'devices'


class DeviceConfig:
    def __init__(self, device):
        self.vmp = device['vmp']
        self.device_name = device['name']
        self.description = device['description']
        self.security_level = device['security_level']
        self.session_id_type = device['session_id_type']
        self.private_key_available = device['private_key_available']
        self.send_key_control_nonce = device['send_key_control_nonce']

        if 'device_private_key_filename' in device:
            self.device_private_key_filename = os.path.join(os.path.dirname(__file__), FILES_FOLDER, device['name'],
                                                            device['device_private_key_filename'])
        else:
            self.device_private_key_filename = os.path.join(os.path.dirname(__file__), FILES_FOLDER, device['name'],
                                                            'device_private_key')

        if 'device_client_id_blob_filename' in device:
            self.device_client_id_blob_filename = os.path.join(os.path.dirname(__file__), FILES_FOLDER, device['name'],
                                                               device['device_client_id_blob_filename'])
        else:
            self.device_client_id_blob_filename = os.path.join(os.path.dirname(__file__), FILES_FOLDER, device['name'],
                                                               'device_client_id_blob')

        if 'device_vmp_blob_filename' in device:
            self.device_vmp_blob_filename = os.path.join(os.path.dirname(__file__), FILES_FOLDER, device['name'],
                                                         device['device_vmp_blob_filename'])
        else:
            self.device_vmp_blob_filename = os.path.join(os.path.dirname(__file__), FILES_FOLDER, device['name'],
                                                         'device_vmp_blob')

    def __repr__(self):
        return "DeviceConfig(name={}, description={}, security_level={}, session_id_type={}, private_key_available={}, vmp={})".format(
            self.device_name, self.description, self.security_level, self.session_id_type, self.private_key_available,
            self.vmp)
