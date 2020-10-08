import logging
from AcmeN import AcmeN
from DnsHandlers import GoDaddyDNSHandler

logging.basicConfig(level=logging.INFO)
acme = AcmeN('account.key')
dns = GoDaddyDNSHandler('sso-key *****:****')
acme.get_cert_from_domain('foo.example.com', dns_name=['foo1.example.com', 'foo2.example.com'], cert_type='rsa', dns_handler=dns)
