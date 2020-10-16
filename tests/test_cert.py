import datetime
from typing import List, Tuple

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate, Certificate

from lib.core import get_certificate_domains, convert_bytes_to_cert


@pytest.fixture
def mock_certificate_binary() -> Tuple[bytes, dict]:
    return b'''-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----''', \
           {
               'validity': {
                   'end_datetime': datetime.datetime(2021, 8, 28, 22, 17, 2),
                   'start_datetime': datetime.datetime(2020, 8, 28, 22, 17, 2), 'end': '2021-08-28T22:17:02Z',
                   'start': '2020-08-28T22:17:02Z'
               },
               'issuer': {
                   'country': ['US'], 'organization': ['Microsoft Corporation'],
                   'common_name': ['Microsoft RSA TLS CA 01']
               }, 'version': '3',
               'subject': {
                   'countryName': ['US'], 'stateOrProvinceName': ['WA'], 'localityName': ['Redmond'],
                   'organizationName': ['Microsoft Corporation'],
                   'organizationalUnitName': ['Microsoft Corporation'], 'commonName': ['www.microsoft.com']
               },
               'names': ['wwwqa.microsoft.com', 'www.microsoft.com', 'staticview.microsoft.com', 'i.s-microsoft.com',
                         'microsoft.com', 'c.s-microsoft.com', 'privacy.microsoft.com'],
               'serial_number': '2386179741501998393636398893442183158220981236',
               'serial_number_hex': '0x6b000003f4e3a67a2348550c330000000003f4',
               'raw_serial': '2386179741501998393636398893442183158220981236',
               'fingerprint_sha256': 'b241ae144bc9a5d394428afb1e197fcf4389b502578120e14ecfe5bacc49c7f8',
               'fingerprint_sha1': '0249df8a457f53767a07f5542d7f0cde5600896a',
               'fingerprint_md5': 'bf70cda2d0e62949c68397d15dfeaeeb'
           }


@pytest.fixture
def mock_certificate(mock_certificate_binary) -> Tuple[Certificate, List[str]]:
    binary, cert_dict = mock_certificate_binary
    return load_pem_x509_certificate(binary, default_backend()), cert_dict['names']


def test_get_domains(mock_certificate):
    cert, domains_expected = mock_certificate
    domains = get_certificate_domains(cert)
    assert domains
    assert domains == domains_expected


def test_convert_bytes_to_cert(mock_certificate_binary):
    cert_binary, cert_dict_expected = mock_certificate_binary
    cert_dict = convert_bytes_to_cert(cert_binary)
    assert cert_dict
    assert isinstance(cert_dict, dict)
    assert cert_dict == cert_dict_expected
