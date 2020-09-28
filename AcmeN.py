import subprocess, json, sys, base64, binascii, time, hashlib, re, logging, os, uuid

import requests
import dns.resolver
from DnsHandlers import *


class AcmeN:
    def __init__(self, account_key_file='account.key', account_key_password='', contact=None):
        # logger
        self.__log = logging.getLogger()
        self.__log.addHandler(logging.StreamHandler())
        self.__log.setLevel(logging.INFO)

        # ACME params
        # production
        self.__ACME_DIRECTORY = 'https://acme-v02.api.letsencrypt.org/directory'
        # self.__ACME_DIRECTORY = 'https://api.buypass.com/acme/directory'

        # staging
        # self.__ACME_DIRECTORY = 'https://acme-staging-v02.api.letsencrypt.org/directory'
        # self.__ACME_DIRECTORY = 'https://api.test4.buypass.no/acme/directory'

        self.__CERTIFICATE_FORMAT = 'application/pem-certificate-chain'

        # Account params
        self.__CONTACT = contact
        self.__ACCOUNT_KEY_FILE = account_key_file
        self.__ACCOUNT_KEY_PASSWORD = account_key_password

        # DNS params
        self.__DNS_TTL = 20
        self.__NAME_SERVERS = ['8.8.8.8', '9.9.9.9', '1.1.1.1']

        # Program params
        self.__GET_HEADERS = {
            'User-Agent': 'acmen/0.1.0',
            'Accept-Language': 'en'
        }

        self.__OPENSSL_CONFIG_TEMPLATE = 'openssl_config_template.cfg'
        self.__POST_HEADER = self.__GET_HEADERS.copy()
        self.__POST_HEADER['Content-Type'] = 'application/jose+json'
        self.__PERFORM_DNS_SELF_CHECK = True
        self.__DNS_SELF_CHECK_RETRY = 10

        # Runtime params
        self.__nonce = None
        self.__requests_session = requests.Session()
        self.__requests_session.headers.update(Connection='Keep-Alive')
        self.__kid = None

        self.__log.info('Fetching information from the ACME directory')
        self.__DIRECTORY = self.__requests_session.get(self.__ACME_DIRECTORY, headers=self.__GET_HEADERS).json()

        self.__JWS_HEADERS, \
        self.__THUMB_PRINT = self.__read_key(self.__ACCOUNT_KEY_FILE, self.__ACCOUNT_KEY_PASSWORD)
        pass

    def __del__(self):
        self.__requests_session.close()

    @staticmethod
    def __b64(b):
        """"Encodes string as base64 as specified in ACME RFC """
        return base64.urlsafe_b64encode(b).decode("utf8").rstrip("=")

    @staticmethod
    def __openssl(command, options, communicate=None):
        """Run openssl command line and raise IOError on non-zero return."""
        openssl = subprocess.Popen(["openssl", command] + options,
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = openssl.communicate(communicate)
        if openssl.returncode != 0:
            raise IOError("OpenSSL Error: {0}".format(err))
        return out

    def __convert_signature(self, signature: bytes):

        len_r = signature[3]
        len_s = signature[3 + len_r + 2]
        r = signature[4:4 + len_r]
        s_start = 4 + len_r + 2
        s_end = s_start + len_s
        s = signature[s_start:s_end]
        if r.startswith(b'\x00'):
            r = r[1:]
        if s.startswith(b'\x00'):
            s = s[1:]
        self.__log.debug('signature converted: \n{0}\n{1}'.format(signature.hex(), (r + s).hex()))
        return r + s

    def __get_nonce(self):
        temp = None
        if self.__nonce:
            temp, self.__nonce = self.__nonce, temp  # swap nonce and temp
        else:
            self.__log.debug('getting new nonce from server')
            temp = self.__requests_session.get(self.__DIRECTORY['newNonce'], headers=self.__GET_HEADERS)
            temp = temp.headers['Replay-Nonce']

        return temp

    def __read_key(self, key_file, password=''):
        try:
            return self.__read_rsa_key(key_file, password=password)
        except IOError:
            return self.__read_ecc_key(key_file, password=password)

    def __read_rsa_key(self, key_file, password=''):
        """Read rsa key , return jws_header and jwk_thumbprint"""
        self.__log.debug('reading rsa key')
        account_key = self.__openssl("rsa", ["-in", key_file,
                                             "-passin", "pass:{0}".format(password),
                                             "-noout", "-text"])
        pub_hex, pub_exp = re.search(
            r"modulus:\r?\n\s+00:([a-f0-9:\s]+?)\r?\npublicExponent: ([0-9]+)",
            account_key.decode("utf8"), re.MULTILINE | re.DOTALL).groups()
        pub_exp = "{0:x}".format(int(pub_exp))
        pub_exp = "0{0}".format(pub_exp) if len(pub_exp) % 2 else pub_exp
        jws_header = {
            "alg": "RS256",
            "jwk": {
                "e": self.__b64(binascii.unhexlify(pub_exp.encode("utf-8"))),
                "kty": "RSA",
                "n": self.__b64(binascii.unhexlify(re.sub(r"(\s|:)", "", pub_hex).encode("utf-8"))),
            }
        }
        account_key_json = json.dumps(jws_header["jwk"], sort_keys=True, separators=(",", ":"))
        jwk_thumbprint = self.__b64(hashlib.sha256(account_key_json.encode("utf8")).digest())
        return jws_header, jwk_thumbprint

    def __read_ecc_key(self, key_file, password=''):
        self.__log.debug('reading ecc key')
        key = self.__openssl('ec', ["-in", key_file,
                                    "-passin", "pass:{0}".format(password),
                                    '-pubout', "-noout", "-text",
                                    '-conv_form', 'uncompressed'])
        key = key.decode('utf8')
        pub_hex = re.search(
            r'pub:\r?\n\s+04:([a-f0-9:\s]+?)\r?\nASN1 OID:',
            key, re.MULTILINE | re.DOTALL).groups()[0]
        pub_hex = re.sub(r'\s|:', '', pub_hex)
        nist_curve = re.search(r'NIST CURVE: ([A-Za-z0-9\-]*)', key)
        nist_curve = nist_curve.groups()[0] if nist_curve else None
        curve_alg = {
            'P-256': 'ES256',
            'P-384': 'ES384',
            'P-521': 'ES521'
        }
        if nist_curve not in curve_alg.keys():
            raise ValueError(
                'Only {0} are accepted, but {1} is provided'.format(', '.join(curve_alg.keys()), nist_curve))
        index = int(len(pub_hex) / 2)
        param_x = pub_hex[:index]
        param_y = pub_hex[index:]
        jws_header = {
            "alg": curve_alg[nist_curve],
            "jwk": {
                'kty': "EC",
                'crv': nist_curve,
                'x': self.__b64(binascii.unhexlify(param_x.encode('utf8'))),
                'y': self.__b64(binascii.unhexlify(param_y.encode('utf8')))
            }
        }
        account_key_json = json.dumps(jws_header["jwk"], sort_keys=True, separators=(",", ":"))
        jwk_thumbprint = self.__b64(hashlib.sha256(account_key_json.encode("utf8")).digest())
        return jws_header, jwk_thumbprint

    def __sign_request(self, protected, payload, sign_key=None, key_password=''):
        # on POST-as-GET, final payload has to be just empty string
        payload64 = '' if payload == '' else self.__b64(json.dumps(payload).encode("utf8"))
        protected64 = self.__b64(json.dumps(protected).encode("utf8"))
        sign_alg = {
            'RS256': '-sha256',
            'ES256': '-sha256',
            'ES384': '-sha384',
            'ES521': '-sha512'
        }
        openssl_alg = sign_alg[protected['alg']]
        signature = self.__openssl("dgst", [openssl_alg, "-sign", sign_key or self.__ACCOUNT_KEY_FILE,
                                            '-passin', 'pass:{0}'.format(key_password or self.__ACCOUNT_KEY_PASSWORD)],
                                   "{0}.{1}".format(protected64, payload64).encode("utf8"))

        # convert ECDSA signature from ASN1 DER format to raw r|s format
        if protected['alg'].startswith('ES'):
            signature = self.__convert_signature(signature)
        return self.__b64(signature)

    def __send_signed_request(self, url, payload, sign_key=None, key_password='', http_headers=None):
        """Sends signed requests to ACME server."""
        if sign_key:
            protected, _ = self.__read_key(sign_key)
        else:
            protected = self.__JWS_HEADERS.copy()

        protected["nonce"] = self.__get_nonce()
        protected["url"] = url
        protected['kid'] = self.__kid
        if url == self.__DIRECTORY["newAccount"] or (url == self.__DIRECTORY['revokeCert'] and sign_key is not None):
            del protected["kid"]
        else:
            del protected["jwk"]

        payload64 = '' if payload == '' else self.__b64(json.dumps(payload).encode("utf8"))
        protected64 = self.__b64(json.dumps(protected).encode("utf8"))

        jose = {
            "protected": protected64, "payload": payload64,
            "signature": self.__sign_request(protected, payload, sign_key, key_password)
        }
        self.__log.debug('sending signed request to: {0}, with payload: {1}'.format(url, json.dumps(payload)))
        response = requests.post(url, json=jose, headers=http_headers or self.__POST_HEADER)
        self.__nonce = response.headers.get('Replay-Nonce', None) or self.__nonce
        try:
            return response, response.json()
        except json.decoder.JSONDecodeError:
            return response, {}

    def generate_csr(self, domain, key_file, key_pass='', dns_name: list = None):
        self.__log.info('reading openssl config template: {0}'.format(self.__OPENSSL_CONFIG_TEMPLATE))
        with open(self.__OPENSSL_CONFIG_TEMPLATE, 'r', encoding='utf8') as file:
            template = file.read()
        if not template.endswith('\n'):
            template += '\n'

        if dns_name:
            dns_name_temp = []
            for i in range(len(dns_name)):
                dns_name_temp.append('DNS.{0} = {1}'.format(str(i), dns_name[i]))
            template += '\n'.join(dns_name_temp)
        else:
            template += 'DNS.0 = {0}'.format(domain)

        temp_filename = str(uuid.uuid4())
        self.__log.debug('openssl temp config filename: {0}'.format(temp_filename))
        with open(temp_filename, 'w', encoding='utf8') as temp_file:
            temp_file.write(template)

        csr = self.__openssl('req', ['-new', '-batch',
                                     '-key', key_file, '-passin', 'pass:{0}'.format(key_pass),
                                     '-subj', '/CN={0}'.format(domain),
                                     '-outform', 'der', '-text',
                                     '-config', temp_filename
                                     ])
        os.remove(temp_filename)
        index = csr.index(b'\x30\x82')
        return csr[:index].decode(), csr[index:]

    def __get_domains_from_csr(self, csr):
        self.__log.info("Read CSR to find domains to validate.")
        # csr = self.__openssl("req", ["-in", csr_file, "-noout", "-text"]).decode("utf8")
        domains = set()
        common_name = re.search(r"Subject:.*?\s+?CN\s*?=\s*?([^\s,;/]+)", csr)
        if common_name is not None:
            domains.add(common_name.group(1))
        subject_alt_names = re.search(r"X509v3 Subject Alternative Name: \r?\n +([^\r\n]+)\r?\n", csr,
                                      re.MULTILINE | re.DOTALL)
        if subject_alt_names is not None:
            for san in subject_alt_names.group(1).split(", "):
                if san.startswith("DNS:"):
                    domains.add(san[4:])
        if len(domains) == 0:
            raise ValueError("Didn't find any domain to validate in the provided CSR.")
        return domains

    def __get_domains_from_cert(self, cert_file):
        self.__log.info("Read certificate to find domains.")
        cert = self.__openssl("x509", ["-in", cert_file, "-noout", "-text"]).decode("utf8")
        domains = set()
        common_name = re.search(r"Subject:.*?\s+?CN\s*?=\s*?([^\s,;/]+)", cert)
        if common_name is not None:
            domains.add(common_name.group(1))
        subject_alt_names = re.search(r"X509v3 Subject Alternative Name: \r?\n +([^\r\n]+)\r?\n", cert,
                                      re.MULTILINE | re.DOTALL)
        if subject_alt_names is not None:
            for san in subject_alt_names.group(1).split(", "):
                if san.startswith("DNS:"):
                    domains.add(san[4:])
        return domains

    def __register_new_account(self):
        """Register new account and return kid"""
        self.__log.info('Register ACME Account')
        account_request = {}
        tos = self.__DIRECTORY.get('meta', {}).get('termsOfService', '')
        if tos != '':
            self.__log.info('Terms Of Service is automatically agreed: {0}'.format(tos))
            account_request['termsOfServiceAgreed'] = True

        if self.__CONTACT:
            account_request['contact'] = self.__CONTACT

        self.__log.debug('sending register request')
        response, account_info = self.__send_signed_request(self.__DIRECTORY['newAccount'], account_request)
        if response.status_code == 201:
            self.__log.info('New account Registered: {0}'.format(response.headers['Location']))
        elif response.status_code == 200:
            self.__log.info('Account is already exist: {0}'.format(response.headers['Location']))
        else:
            raise ValueError("Error registering account: {0} {1}".format(response.status_code, account_info))

        self.__kid = response.headers['Location']
        return response.headers['Location'], account_info

    def __update_contact_info(self, kid, contact: list):
        self.__log.info('Updating account contact information')
        update_request = {
            'termsOfServiceAgreed': True,
            'contact': contact.copy()
        }
        response, result = self.__send_signed_request(kid, update_request)
        if response.status_code == 200:
            self.__log.info('Update completed')
        else:
            raise ValueError('Error updating contact information: {0}, {1}', response.status_code, result)

    def __create_order(self, domains):
        # Create order and return order's information and location
        self.__log.info('Creating new order')

        # TODO: add notBefore and notAfter
        order_info = {"identifiers": [{"type": "dns", "value": i} for i in domains]}
        response, order = self.__send_signed_request(self.__DIRECTORY['newOrder'], order_info)
        if response.status_code == 201:
            order_location = response.headers['Location']
            self.__log.info('Order received: {0}'.format(order_location))
            if order["status"] != "pending" and order["status"] != "ready":
                raise ValueError("Order status is neither pending neither ready, we can't use it: {0}".format(order))
        elif response.status_code == 403 and order["type"] == "urn:ietf:params:acme:error:userActionRequired":
            raise ValueError(
                "Order creation failed ({0}). Read Terms of Service ({1}), then follow your CA instructions: {2}".format(
                    order["detail"], response.headers['Link'], order["instance"]))
        else:
            raise ValueError("Error getting new Order: {0} {1}".format(response.status_code, order))
        return order, order_location

    def __dns_self_check(self, dns_domain, value):
        dns_domain += '.'
        self.__log.info("Prepare DNS resolver.")
        resolver = dns.resolver.Resolver(configure=False)
        resolver.retry_servfail = True
        resolver.nameservers = self.__NAME_SERVERS

        challenge_verified = False
        try:
            self.__log.debug('sending dns query: {0}'.format(dns_domain))
            for response in dns.resolver.resolve(dns_domain, rdtype='TXT').rrset:
                self.__log.info("Found dns value {0}".format(response.to_text()))
                challenge_verified = challenge_verified or response.to_text() == '"{0}"'.format(value)
        except dns.exception.DNSException as dns_exception:
            self.__log.info("DNS error occurred while checking challenge: {0} : {1}".format(
                type(dns_exception).__name__, dns_exception))
        return challenge_verified

    def __complete_challenge(self, order: dict, dns_operator: DNSHandlerBase = None):
        dns_operator = dns_operator or DefaultDNSHandler()
        dns_operator.session = self.__requests_session

        if order['status'] == 'ready':
            self.__log.info('No challenge to process: order is already ready')
            return

        for authz in order['authorizations']:
            self.__log.info("Process challenge for authorization: {0}".format(authz))
            response, authorization = self.__send_signed_request(authz, "")
            if response.status_code != 200:
                raise ValueError("Error fetching challenges: {0} {1}".format(response.status_code, authorization))
            domain = authorization["identifier"]["value"]

            challenge = [c for c in authorization["challenges"] if c["type"] == "dns-01"][0]
            token = re.sub(r"[^A-Za-z0-9_\-]", "_", challenge["token"])
            key_authorization = "{0}.{1}".format(token, self.__THUMB_PRINT)
            key_digest64 = self.__b64(hashlib.sha256(key_authorization.encode("utf8")).digest())
            dns_domain = "_acme-challenge.{0}".format(domain)
            self.__log.info('Setting DNS TXT record : \n{0}\n{1}'.format(dns_domain, key_digest64))

            set_result = dns_operator.set_record(dns_domain, key_digest64)
            if not set_result:
                self.__log.warning('auto set dns record filed, set it manually, press ENTER when continue')
                input()

            if self.__PERFORM_DNS_SELF_CHECK:
                self.__log.info(
                    'Checking dns record, waiting 1 TTL ({0}s) before send dns query'.format(self.__DNS_TTL))
                for i in range(self.__DNS_SELF_CHECK_RETRY):
                    self.__log.debug('waiting 1 TTL ({0}s)'.format(self.__DNS_TTL))
                    time.sleep(self.__DNS_TTL)
                    if self.__dns_self_check(dns_domain, key_digest64):
                        break
                else:
                    self.__log.warning('dns self check failed after {0} retries'.format(self.__DNS_SELF_CHECK_RETRY))
                    input('')

            self.__log.info("Asking ACME server to validate challenge")
            response, result = self.__send_signed_request(challenge["url"], {"keyAuthorization": key_authorization})
            if response.status_code != 200:
                raise ValueError("Error triggering challenge: {0} {1}".format(response.status_code, result))

            while True:
                response, challenge_status = self.__send_signed_request(challenge["url"], "")
                if response.status_code != 200:
                    raise ValueError("Error during challenge validation: {0} {1}".format(
                        response.status_code, challenge_status))
                if challenge_status["status"] == "pending":
                    time.sleep(2)
                elif challenge_status["status"] == "valid":
                    self.__log.info("ACME has verified challenge for domain: {0}".format(domain))
                    break
                else:
                    raise ValueError("Challenge for domain {0} did not pass: {1}".format(domain, challenge_status))

            self.__log.info('Deleting DNS TXT record : \n{0}\n{1}'.format(dns_domain, key_digest64))
            # TODO: Auto get tld
            del_result = dns_operator.del_record(dns_domain, key_digest64)
            if not del_result:
                self.__log.warning('failed to del dns record, del it manually, press ENTER to continue')
                input()

        self.__log.info('all challenge completed')

    def __finalize_order(self, order: dict, order_location, csr_der):
        self.__log.info("Request to finalize the order (all challenge have been completed)")

        csr_der64 = self.__b64(csr_der)
        response, result = self.__send_signed_request(order["finalize"], {"csr": csr_der64})
        if response.status_code != 200:
            raise ValueError("Error while sending the CSR: {0} {1}".format(response.status_code, result))

        while True:
            response, order = self.__send_signed_request(order_location, "")

            if order["status"] == "processing":
                if response.headers["Retry-After"]:
                    time.sleep(int(response.headers["Retry-After"]))
                else:
                    time.sleep(2)
            elif order["status"] == "valid":
                self.__log.info("Order finalized!")
                break
            else:
                raise ValueError("Finalizing order, got errors: {0}".format(order))

        finalize_header = self.__POST_HEADER.copy()
        finalize_header['Accept'] = self.__CERTIFICATE_FORMAT
        response, result = self.__send_signed_request(order["certificate"], "", http_headers=finalize_header)
        if response.status_code != 200:
            raise ValueError("Finalizing order {0} got errors: {1}".format(response.status_code, result))

        self.__log.info("Certificate signed and chain received: {0}".format(order["certificate"]))
        return response.text

    def __get_cert(self, csr_pem, csr_der, dns_handler: DNSHandlerBase):
        kid, account_info = self.__register_new_account()

        if self.__CONTACT and set(account_info['contact']) != set(self.__CONTACT):
            self.__update_contact_info(kid, self.__CONTACT)

        csr_domains = self.__get_domains_from_csr(csr_pem)
        order, order_location = self.__create_order(csr_domains)
        self.__complete_challenge(order, dns_handler)
        cert = self.__finalize_order(order, order_location, csr_der)
        return cert

    def get_cert_from_domain(self, domain, dns_name: list = None, cert_type='rsa', dns_handler: DNSHandlerBase = None):
        filename = domain.replace('*', '_')
        t = str(int(time.time()))
        key_filename = '{0}.{1}.{2}.key'.format(filename, t, cert_type.lower())
        cert_filename = '{0}.{1}.{2}.crt'.format(filename, t, cert_type.lower())

        if cert_type.lower() == 'rsa':
            self.__openssl('genrsa', ['-out', key_filename, '4096'])
        elif cert_type.lower() == 'ecc':
            self.__openssl('ecparam', ['-genkey', '-name', 'secp384r1', '-noout', '-out', key_filename])
        else:
            raise ValueError('Invalid cert type, only rsa and ecc are supported')
        csr_pem, csr_der = self.generate_csr(domain, key_filename, '', dns_name)

        cert = self.__get_cert(csr_pem, csr_der, dns_handler)
        with open(cert_filename, 'w') as file:
            file.write(cert)
        sys.stdout.write(cert)

    def get_cert_from_csr(self, csr_file: str, dns_handler: DNSHandlerBase = None):
        if not os.path.exists(csr_file):
            raise FileNotFoundError('csr file does not exist')

        csr_pem = self.__openssl("req", ["-in", csr_file, "-noout", "-text"]).decode("utf8")
        csr_der = self.__openssl("req", ["-in", csr_file, "-outform", "der"])
        cert = self.__get_cert(csr_pem, csr_der, dns_handler)

        cert_filename = '{0}.{1}.crt'.format(re.sub(r'(\.csr*)$', '', csr_file), str(int(time.time())))
        with open(cert_filename, 'w') as file:
            file.write(cert)
        sys.stdout.write(cert)

    def revoke_cert_by_account(self, cert_file, reason: int = 0, dns_handler: DNSHandlerBase = None):
        self.__register_new_account()
        self.__log.info('Revoking certificate')
        cert_der = self.__openssl('x509', ['-in', cert_file, '-outform', 'der'])
        cert_der64 = self.__b64(cert_der)
        revoke_request = {
            'certificate': cert_der64,
            'reason': reason
        }
        response, result = self.__send_signed_request(self.__DIRECTORY['revokeCert'], revoke_request)
        if response.status_code == 403 and result['type'] == 'urn:ietf:params:acme:error:unauthorized':
            self.__log.info('Server refused to revoke the certificate:{0} {1}, {2}'.format(
                response.status_code, result['type'], result['detail'] if 'detail' in result else None))

            domains = self.__get_domains_from_cert(cert_file)
            self.__log.info('Trying to validate domains: {0}'.format(', '.join(domains)))
            order, _ = self.__create_order(domains)
            self.__complete_challenge(order, dns_handler)

            self.__log.info('Revoking certificate (retry)')
            response, result = self.__send_signed_request(self.__DIRECTORY['revokeCert'], revoke_request)
        if response.status_code != 200:
            raise ValueError("Error during revocation: {0} {1}".format(response.status_code, result))
        self.__log.info('Certificate Revoked')

    def revoke_cert_by_private_key(self, cert_file, private_key_file, key_password='', reason: int = 1):
        self.__log.info('Revoking certificate')
        jws_header, _ = self.__read_key(private_key_file, key_password)
        cert_der = self.__openssl('x509', ['-in', cert_file, '-outform', 'der'])
        cert_der64 = self.__b64(cert_der)
        revoke_request = {
            'certificate': cert_der64,
            'reason': reason
        }
        response, result = self.__send_signed_request(self.__DIRECTORY['revokeCert'],
                                                      revoke_request, sign_key=private_key_file, )
        if response.status_code != 200:
            raise ValueError("Error during revocation: {0} {1}".format(response.status_code, result))
        self.__log.info('Certificate Revoked')

    def key_change(self, new_key_file, password: str = ''):
        self.__register_new_account()  # to get kid
        protected, _ = self.__read_key(new_key_file, password)
        protected['url'] = self.__DIRECTORY['keyChange']
        payload = {
            'account': self.__kid,
            'oldKey': self.__JWS_HEADERS['jwk']
        }
        payload64 = '' if payload == '' else self.__b64(json.dumps(payload).encode("utf8"))
        protected64 = self.__b64(json.dumps(protected).encode("utf8"))
        new_payload = {
            'protected': protected64,
            'payload': payload64,
            'signature': self.__sign_request(protected, payload, new_key_file, password)
        }
        response, result = self.__send_signed_request(self.__DIRECTORY['keyChange'], new_payload)
        if response.status_code != 200:
            raise ValueError('Error during key change: {0} {1}'.format(response.status_code, result))

        self.__ACCOUNT_KEY_FILE = new_key_file
        self.__ACCOUNT_KEY_PASSWORD = password
        self.__JWS_HEADERS, \
        self.__THUMB_PRINT = self.__read_key(self.__ACCOUNT_KEY_FILE, self.__ACCOUNT_KEY_PASSWORD)
        self.__log.info('key Changed')

    def deactivate_account(self):
        self.__register_new_account()
        payload = {
            'status': 'deactivated'
        }
        response, result = self.__send_signed_request(self.__kid, payload)
        if response.status_code != 200:
            raise ValueError('Error during account deactivation: {0} {1}'.format(response.status_code, result))
        self.__log.info('account deactivated')
        pass
