import logging
from acmen import AcmeN
from acmen.handlers import CloudflareDnsHandler

logging.basicConfig(level=logging.INFO)

handler = CloudflareDnsHandler(api_token='*****')
acme = AcmeN('account.key')
acme.register_account(contact=['mailto:xxx@yyy.zzz'])
acme.get_cert_by_domain('example.com', ['alt1.example.com', 'alt2.example.com'], handler)