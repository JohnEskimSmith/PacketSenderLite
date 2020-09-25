from hashlib import sha256, sha1, md5
from typing import List

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import Certificate

__all__ = ['convert_bytes_to_cert', 'get_certificate_domains']


# noinspection PyUnresolvedReferences,PyProtectedMember,PyBroadException
def convert_bytes_to_cert(bytes_cert: bytes) -> dict:
    cert = None
    try:
        cert = x509.load_der_x509_certificate(bytes_cert, default_backend())
    except BaseException:
        try:
            cert = x509.load_pem_x509_certificate(bytes_cert, default_backend())
        except BaseException:
            pass

    if cert:
        result = {}
        serial_number = cert.serial_number
        issuer = cert.issuer
        try:
            result['validity'] = {}
            result['validity']['end_datetime'] = cert.not_valid_after
            result['validity']['start_datetime'] = cert.not_valid_before
            result['validity']['end'] = result['validity']['end_datetime'].strftime('%Y-%m-%dT%H:%M:%SZ')
            result['validity']['start'] = result['validity']['start_datetime'].strftime('%Y-%m-%dT%H:%M:%SZ')
        except Exception:
            pass
        result['issuer'] = {}
        dict_replace = {
            'countryName': 'country',
            'organizationName': 'organization',
            'commonName': 'common_name'
        }
        try:
            for n in issuer.rdns:
                z = n._attributes[0]
                name_k = z.oid._name
                value = z.value
                if name_k in dict_replace:
                    result['issuer'][dict_replace[name_k]] = [value]
        except Exception:
            pass
        try:
            if 'v' in cert.version.name:
                result['version'] = cert.version.name.split('v')[1].strip()
        except BaseException:
            result['version'] = str(cert.version.value)
        dnss = get_certificate_domains(cert)
        atr = cert.subject._attributes
        result['subject'] = {}
        for i in atr:
            for q in i._attributes:
                result['subject'][q.oid._name] = [q.value]
        if 'serialNumber' in list(result.keys()):
            if len(result['serialNumber']) == 16:
                result['serialNumber'] = '00' + result['serialNumber']
        try:
            result['serialNumber_int'] = int('0x' + result['serialNumber'], 16)
            result['serial_number'] = str(result['serialNumber_int'])
        except BaseException:
            result['serialNumber_int'] = 0
        result['names'] = dnss
        if result['serialNumber_int'] == 0:
            result['serial_number'] = str(serial_number)
            result['serial_number_hex'] = str(hex(serial_number))
        result['raw_serial'] = str(serial_number)
        hashs = {
            'fingerprint_sha256': sha256,
            'fingerprint_sha1': sha1,
            'fingerprint_md5': md5
        }
        for namehash, func in hashs.items():
            hm = func()
            hm.update(bytes_cert)
            result[namehash] = hm.hexdigest()
        remove_keys = ['serialNumber_int']
        for key in remove_keys:
            result.pop(key)
        return result


# noinspection PyBroadException
def get_certificate_domains(cert: Certificate) -> List[str]:
    """
    Gets a list of all Subject Alternative Names in the specified certificate.
    """
    try:
        for ext in cert.extensions:
            ext = ext.value
            if isinstance(ext, x509.SubjectAlternativeName):
                return ext.get_values_for_type(x509.DNSName)
    except BaseException:
        return []
