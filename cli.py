import argparse
from AcmeN import AcmeN
import DnsHandlers
import json

if __name__ == '__main__':
    command = ''
    parser = argparse.ArgumentParser(description='A RFC8555 acme client.')
    parser.add_argument('--key', metavar='KEY_FILE', default='account.key',
                        help='the private key of the account, default:%(default)s')

    subparsers = parser.add_subparsers(dest=command, required=True, metavar='command')
    get_cert = subparsers.add_parser('getcert', help='get a certificate from acme server')
    revoke_cert = subparsers.add_parser('revokecert', help='revoke a certificate')
    rotate_key = subparsers.add_parser('rotatekey', help='change the key of the account')

    # get_cert command
    dns_providers = DnsHandlers.__all__[:]
    dns_providers.remove('DNSHandlerBase')
    get_cert.add_argument('cn', metavar='common_name', help='the CommonName(CN) of the certificate')
    get_cert.add_argument('-s', '--san', action='append',
                          help='the SubjectAlternativeName(SAN) of the certificate ')
    get_cert.add_argument('-t', '--type', choices=('rsa', 'ecc'), default='rsa', metavar='TYPE',
                          help='key type of the certificate, can be one of: %(choices)s')
    get_cert.add_argument('-d', '--dns', choices=dns_providers, default='DefaultDNSHandler',
                          metavar='dns_handler', help='the dns provider api handler, can be one of: %(choices)s')
    get_cert.add_argument('dns_param', nargs='*', metavar='dns_api_params',
                          help='optional, parameters for the DNSHandler')
