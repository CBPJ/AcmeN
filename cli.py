import argparse
import sys

import DnsHandlers


def cli(args):
    parser = argparse.ArgumentParser(description='A RFC8555 acme client.')

    subparsers = parser.add_subparsers(dest='command', required=True, metavar='command')
    get_cert = subparsers.add_parser('getcert', help='get a certificate from acme server')
    revoke_cert = subparsers.add_parser('revokecert', help='revoke a certificate')
    rotate_key = subparsers.add_parser('rotatekey', help='change the key of the account')
    deactivate_account = subparsers.add_parser('deactivate', help='DEACTIVATE current account, this is UNDOABLE')

    # get_cert command
    dns_providers = DnsHandlers.__all__[:]
    dns_providers.remove('DNSHandlerBase')
    get_cert.add_argument('cn', metavar='common_name', help='the CommonName(CN) of the certificate')
    get_cert.add_argument('-k', '--key', metavar='KEY_FILE', default=argparse.SUPPRESS,
                          help='the private key of the account')
    get_cert.add_argument('-s', '--san', action='append',
                          help='the SubjectAlternativeName(SAN) of the certificate ')
    get_cert.add_argument('-t', '--type', choices=('rsa', 'ecc'), default='rsa', metavar='TYPE',
                          help='key type of the certificate, can be one of: %(choices)s')
    get_cert.add_argument('-d', '--dns', choices=dns_providers, default='DefaultDNSHandler',
                          metavar='dns_handler', help='the dns provider api handler, can be one of: %(choices)s')
    get_cert.add_argument('--dns-param', action='append', metavar='dns_api_params',
                          help='optional, parameters for the DNSHandler')

    # revoke_cert command
    revoke_cert.add_argument('cert', metavar='CERT_PATH', help='the path to the certificate you want to revoke')
    group = revoke_cert.add_mutually_exclusive_group()  # -k and -p are mutually exclusive
    group.add_argument('-k', '--key', metavar='KEY_FILE', default=argparse.SUPPRESS,
                       help='the private key of the account')
    group.add_argument('-p', '--pri-key', metavar='PRIVATE_KEY', default=argparse.SUPPRESS,
                             help='the private key of the certificate')
    revoke_cert.add_argument('-d', '--dns', choices=dns_providers, default='DefaultDNSHandler',
                             metavar='dns_handler', help='the dns provider api handler, can be one of: %(choices)s')
    revoke_cert.add_argument('--dns-param', action='append', metavar='dns_api_params', default=argparse.SUPPRESS,
                             help='optional, parameters for the DNSHandler')

    # rotate_key command
    rotate_key.add_argument('-k', '--key', metavar='KEY_FILE', default=argparse.SUPPRESS,
                            help='the private key of the account')
    rotate_key.add_argument('newkey', metavar='NEW_ACCOUNT_KEY',
                            help='path to the new account key file')

    # deactivate_account command
    deactivate_account.add_argument('-k', '--key', metavar='KEY_FILE', default=argparse.SUPPRESS,
                                    help='the private key of the account')

    result = vars(parser.parse_args(args))
    # TODO: --dns should store a instance of DNSHandler initiated with command line params.
    # parse dns parameters
    params = {}
    for i in result.get('dns_param', []):
        k, v = i.split(':', 1)
        params[k] = v

    # create dns handler instance
    if 'dns' in result:
        if result['dns'] == 'DefaultDNSHandler':
            result['dns'] = DnsHandlers.DefaultDNSHandler()
        elif result['dns'] == 'TencentDNSHandler':
            if 'secretid' not in params or 'secretkey' not in params:
                raise ValueError('secretid and secretkey is required when using TencentDNSHandler')
            result['dns'] = DnsHandlers.TencentDNSHandler(params['secretid'], params['secretkey'])
        elif result['dns'] == 'GodaddyDNSHandler':
            if 'sso-key' not in params:
                raise ValueError('sso-key is required when using GodaddyDNSHandler')
            result['dns'] = DnsHandlers.GoDaddyDNSHandler('sso-key {0}'.format(params['sso-key']))
    return result


if __name__ == '__main__':
    cli('revokecert -k key cert'.split())
    # TODO: invoke AcmeN functions
    pass
