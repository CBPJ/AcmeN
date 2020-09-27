import argparse
import sys

import DnsHandlers


def cli(args):
    parser = argparse.ArgumentParser(description='A RFC8555 acme client.')
    parser.add_argument('--key', metavar='KEY_FILE', default='account.key',
                        help='the private key of the account, default:%(default)s')

    subparsers = parser.add_subparsers(dest='command', required=True, metavar='command')
    get_cert = subparsers.add_parser('getcert', help='get a certificate from acme server')
    revoke_cert = subparsers.add_parser('revokecert', help='revoke a certificate')
    rotate_key = subparsers.add_parser('rotatekey', help='change the key of the account')
    deactivate_account = subparsers.add_parser('deactivate', help='DEACTIVATE current account, this is UNDOABLE')

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

    # revoke_cert command
    revoke_cert.add_argument('cert', metavar='CERT_PATH', help='the path to the certificate you want to revoke')
    revoke_cert.add_argument('-p', '--pri-key', metavar='PRIVATE_KEY', default=argparse.SUPPRESS,
                             help='the private key of the certificate')
    revoke_cert.add_argument('-d', '--dns', choices=dns_providers, default='DefaultDNSHandler',
                          metavar='dns_handler', help='the dns provider api handler, can be one of: %(choices)s')
    revoke_cert.add_argument('dns_param', nargs='*', metavar='dns_api_params',
                          help='optional, parameters for the DNSHandler')

    # rotate_key command
    rotate_key.add_argument('newkey', metavar='NEW_ACCOUNT_KEY',
                            help='path to the new account key file')

    result, dns_params = parser.parse_known_args(args)
    result = vars(result)
    # TODO: --key and -p are mutually exclusive.
    # TODO: --dns should store a instance of DNSHandler initiated with command line params.
    return vars(result)


if __name__ == '__main__':
    # TODO: invoke AcmeN functions
    pass
