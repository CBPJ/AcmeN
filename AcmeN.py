import subprocess, json, time, logging, collections, enum, typing, base64, functools

import requests
from jwcrypto import jws, jwk
from cryptography import x509
from cryptography.hazmat import backends
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec

from ChallengeHandlers import ChallengeHandlerBase

__version__ = '0.4.2'
__all__ = ['SupportedCA', 'AcmeNetIO', 'AcmeN', 'KeyType', 'KeyGenerationMethod', 'RevocationReason']

AcmeResponse = collections.namedtuple('AcmeResponse', ('code', 'headers', 'content'))


class SupportedCA(enum.Enum):
    LETSENCRYPT = 'https://acme-v02.api.letsencrypt.org/directory'
    BUYPASS = 'https://api.buypass.com/acme/directory'
    ZEROSSL = 'https://acme.zerossl.com/v2/DV90'
    LETSENCRYPT_STAGING = 'https://acme-staging-v02.api.letsencrypt.org/directory'
    BUYPASS_STAGING = 'https://api.test4.buypass.no/acme/directory'


class AcmeAction(enum.Enum):
    NewNonce = enum.auto()
    NewAccount = enum.auto()
    NewOrder = enum.auto()
    NewAuthz = enum.auto()
    RevokeCertByAccountKey = enum.auto()
    RevokeCertByCertKey = enum.auto()
    KeyChangeInner = enum.auto()
    # This is used by sign_request function to distinguish two sign processes in the keyChange action.
    KeyChangeOuter = enum.auto()
    VariableUrlAction = enum.auto()


class KeyType(enum.Enum):
    ECC384 = enum.auto()
    ECC256 = enum.auto()
    RSA4096 = enum.auto()
    RSA3072 = enum.auto()
    RSA2048 = enum.auto()


class KeyGenerationMethod(enum.Enum):
    CryptographyLib = enum.auto()
    OpenSSLCLI = enum.auto()


class RevocationReason(enum.IntEnum):
    Unspecified = 0
    KeyCompromise = 1
    AffiliationChanged = 3
    Superseded = 4
    CessationOfOperation = 5


class AcmeNetIO:
    # A map from the AcmeAction to the directory field name.
    __BasicFields = {
        AcmeAction.NewNonce: 'newNonce',
        AcmeAction.NewAccount: 'newAccount',
        AcmeAction.NewOrder: 'newOrder',
        AcmeAction.NewAuthz: 'newAuthz',
        AcmeAction.RevokeCertByAccountKey: 'revokeCert',
        AcmeAction.RevokeCertByCertKey: 'revokeCert',
        AcmeAction.KeyChangeInner: 'keyChange',
        AcmeAction.KeyChangeOuter: 'keyChange'
    }

    def __init__(self, keyfile, password=None, ca: typing.Union[SupportedCA, str] = SupportedCA.LETSENCRYPT,
                 session=None, proxy=None):
        """This object performs ACME requests.

        :param keyfile: The pem format private key used for sign ACME requests.
        :param password: Optional, the password of the keyfile.
        :param ca: Optional, the CA server. Could be a member of SupportedCA or a valid directory URL.
                   If omitted, 'Let's Encrypt' will be used.
        :param session: Optional, a requests.Session object shared by other code.
                        If omitted, a new session will be created.
        :raises TypeError: If the ca is neither a member of SupportedCA nor a string.
        """
        self.__log = logging.getLogger()
        self.__directory = None
        if isinstance(ca, SupportedCA):
            self.__directory_url = ca.value
        elif isinstance(ca, str):
            self.__directory_url = ca
        else:
            raise TypeError('Invalid ca, the ca parameter should be a member of SupportedCA or a valid directory URL')
        self._nonce = ''

        # set up session
        headers = {
            'User-Agent': f'AcmeN/{__version__}',
            'Accept-Language': 'en',
            'Content-Type': 'application/jose+json'
        }
        if session:
            self.__session = session
        else:
            self.__session = requests.Session()
            self.__session.headers.update(headers)
        # set up proxy
        if proxy:
            # according to RFC8555 section 6.1, 'Use of HTTPS is REQUIRED'.
            # thus the http proxy is not necessary.
            self.__session.proxies.update({'http': proxy, 'https': proxy})

        # read keyfile
        with open(keyfile, 'rb') as file:
            data = file.read()
        if password:
            self.__key = jwk.JWK.from_pem(data, password)
        else:
            self.__key = jwk.JWK.from_pem(data)
        pass

    @property
    def directory(self) -> dict:
        """Get the directory object of given ACME server.

        :return: A json object representing the directory object.
        :raise RuntimeError: If the server send a failed response code.
        """
        if self.__directory:
            return self.__directory

        self.__log.info('Fetching information from the ACME directory.')
        res = self.__session.get(self.__directory_url)
        if res.ok:
            self.__directory = res.json()
        else:
            raise RuntimeError(f'Failed to get ACME directory: {res.status_code} {res.reason}, {res.text}')

        if 'meta' in self.__directory:
            if 'termsOfService' in self.__directory['meta']:
                self.__log.warning(f'Terms Of Service will be automatically agreed. '
                                   f'you could find them at {self.__directory["meta"]["termsOfService"]}')
                # TODO: Add a property to indicate whether the CA has a TOS.
            if 'externalAccountRequired' in self.__directory['meta'] \
                    and self.__directory['meta']['externalAccountRequired'] is True:
                self.__log.warning('This server requires an external account.')

        return self.__directory

    @property
    def directory_url(self) -> str:
        return self.__directory_url

    @property
    def pubkey(self) -> dict:
        """Get the public key in the standard json format."""
        result = self.__key.export_public(as_dict=True)
        # The kid of the account key produced by the jwcrypto lib is unnecessary.
        # It's not the same thing as the kid of an ACME account.
        del result['kid']
        return result

    @property
    def key_thumbprint(self) -> str:
        return self.__key.thumbprint()

    def _get_nonce(self):
        """Get a Replay-Nonce, either comes from the last response or request a new one.

        :raises RuntimeError: If the http status code indicates the request is failed.
        TODO: according to RFC8555 section 6.5.1, client MUST check the validity of the Replay-Nonce.
        """

        if self._nonce:
            result = self._nonce
            self._nonce = None
            return result

        # According to RFC8555 section 7.2, both HEAD and GET will work.
        # But I don't think the Content-Type header should present when using the HEAD or GET method.
        # But it works for now.
        # TODO: Delete Content-Type header from HEAD or GET request.
        res = self.__session.head(self.directory[self.__BasicFields[AcmeAction.NewNonce]])
        if not res.ok:
            raise RuntimeError(f'Failed to get nonce: {res.status_code} {res.reason}, {res.text}')
        return res.headers['Replay-Nonce']

    def sign_request(self, payload, action: AcmeAction, url: str = None) -> str:
        """Sign a request and return the jws string.

        :param payload: The payload of the jws. If the payload is a string, it will be used directly for the signing
                        process. If the payload is a dict, it will be serialized.
        :param action: The reason of signing this payload, used for constructing the protected header.
        :param url: The custom url. When url is provided, action must set to VariableUrlAction.
        :raises ValueError: If the action is VariableUrlAction but the url is not provided.
                            Or the action is not VariableUrlAction but the url is provided.
        :raises TypeError: If the payload is neither a string nor a dict.
        :raises ValueError: If the given account key is neither an RSA key nor an ECC key
        """

        if not ((action != AcmeAction.VariableUrlAction) ^ (bool(url))):
            raise ValueError('When action is VariableUrlAction there must be an url. '
                             'Otherwise there must not be an url.')
            # So action != VariableUrlAction xor url must be True.

        if action != AcmeAction.VariableUrlAction:
            # Any fixed-url-action has an entry in the directory.
            url = self.directory[self.__BasicFields[action]]

        # serialize payload.
        if isinstance(payload, dict):
            payload = json.dumps(payload)
        elif isinstance(payload, str):
            # TODO: Validate the payload. It could be an empty string only when sending a POST-as-GET string.
            pass
        else:
            raise TypeError('"payload" must be a string or a dict.')

        # construct protected header
        ecc_alg = {
            'P-256': 'ES256',
            'P-384': 'ES384',
            'P-521': 'ES521'
        }
        if self.__key.key_type == 'RSA':
            alg = 'RS256'
        elif self.__key.key_type == 'EC':
            alg = ecc_alg[self.__key.key_curve]
        else:
            raise ValueError(f'Unsupported key type:{self.__key.key_type}, RSA and ECC are supported.')

        protected = {
            'alg': alg,
            'url': url
        }

        if action != AcmeAction.KeyChangeInner:
            protected['nonce'] = self._get_nonce()

        # only the newAccount and revokeCert by a certificate key use the jwk header.
        # besides, the inner jws of a changeKey request also use the jwk header.
        if action == AcmeAction.NewAccount or action == AcmeAction.RevokeCertByCertKey \
                or action == AcmeAction.KeyChangeInner:
            protected['jwk'] = self.pubkey
        else:
            protected['kid'] = self.query_kid()

        s = jws.JWS(payload=payload)
        s.add_signature(self.__key, protected=protected)
        return s.serialize()

    def send_request(self, payload, action: AcmeAction, url: str = None, deserialize_response=True) -> AcmeResponse:
        """
        sign and send an ACME request.

        :param payload: The payload dict of the jws. it must be None or an empty string for POST-as-GET requests.
        :param action: The AcmeAction, used for determining the request URL and constructing the protected header.
        :param url: The URL which the request will be sent to. It should present if and only if the action is VariableUrlAction,
                    which means the url is determined by the upper layer code.
                    Read the documentation for more information.
        :param deserialize_response: Whether to deserialize the server response using json format.
                                   When set to True, the response will be deserialized to a json object(usually a dict).
                                   Otherwise, it will be kept as bytes.
                                   It should be set to False only when downloading a certificate.
        :return: An AcmeResponse object representing the server response.
        :raises RuntimeError: If the server returns a non-successful status code(<200 or >=400).
        """

        content = self.sign_request(payload, action, url)

        # sign_request will check the validity of action an url.
        if action != AcmeAction.VariableUrlAction:
            url = self.directory[self.__BasicFields[action]]
        r = self.__session.post(url, data=content)
        if deserialize_response:
            # zerossl.com sends responses like "externalAccountBinding": {{"payload": "***", ..., "signature": "***"}}
            # which is not a valid json object, so r.json() will fail.
            # And they say they are sending "application/json"....
            result = r.content.decode().replace('{{', '{').replace('}}', '}')
            # certificate revocation will return empty body.
            if len(r.content) == 0:
                result = '{}'
            result = json.loads(result)
            result = AcmeResponse(r.status_code, r.headers, result)
        else:
            result = AcmeResponse(r.status_code, r.headers, r.content)

        # every successful response will contain a Replay-Nonce header, RFC8555 section 6.5.
        # besides, a badNonce error will also contain a Replay-Nonce (RFC8555 section 6.5), but let's just ignored it.
        if r.ok:
            # TODO: check the validity of the Replay-Nonce, duplicated with the todo in _get_nonce.
            # Maybe I should make the nonce a property.
            self._nonce = r.headers['Replay-Nonce']

            # Replay-Nonce could be transparent to the higher layer code.
            # By doing this, the headers of the response object is changed.
            # But, since the response object is no longer used, it shouldn't cause any trouble.
            del r.headers['Replay-Nonce']
        else:
            raise RuntimeError(f'ACME request failed: {r.status_code} {r.reason}, {r.text}')

        return result

    @functools.lru_cache
    def query_kid(self) -> str:
        """Query the kid of the given keyfile.

        :return: The URL of the account.
        :raise RuntimeError: If status code between 201 and 399.
        """

        # TODO: catch account-not-found exception.
        r = self.send_request({'onlyReturnExisting': True}, AcmeAction.NewAccount)
        if r.code == 200:
            return r.headers['Location']
        else:
            # We shouldn't reach here.
            raise RuntimeError(f'Request failed: unknown error. {r.code}, {r.content}')


class AcmeN:
    def __init__(self, key_file, key_passphrase='', ca=SupportedCA.LETSENCRYPT, proxy=None):
        # logger
        self.__log = logging.getLogger()

        # Account params
        self.__netio = AcmeNetIO(key_file, key_passphrase, ca, proxy=proxy)

    @staticmethod
    def __openssl(command, options, communicate=None):
        """Run openssl command line and raise IOError on non-zero return."""
        openssl = subprocess.Popen(["openssl", command] + options,
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = openssl.communicate(communicate)
        if openssl.returncode != 0:
            raise IOError("OpenSSL Error: {0}".format(err))
        return out

    def register_account(self, contact: typing.List[str] = None, eab_key_identifier: str = None,
                         eab_mac_key: str = None) -> str:
        """Register a new account, query an existed account or update the contact info.

        :param contact: The contact information of the account.
        :param eab_key_identifier: The key identifier provided by a CA which require external account binding.
        :param eab_mac_key: The MAC key provided by a CA which require external account binding.
        :raises RuntimeError: If account key is not provided.
        :raises ValueError: If one of eab_key_identifier and eab_mac_key is provided but the other one is not.
        :raises RuntimeError: If server return a status code between 202-399.
        :return: The url(kid) of new account or existed account.
        """

        if not self.__netio:
            raise RuntimeError('Registering account needs an account key.')
        if bool(eab_key_identifier) ^ bool(eab_mac_key):
            raise ValueError('One of eab_key_identifier and eab_mac_key is provided but the other one is not.')

        # TODO: provide some user action.
        payload = {
            'termsOfServiceAgreed': True
        }
        if contact:
            payload['contact'] = contact

        if eab_key_identifier:
            k = jwk.JWK(kty='oct', k=eab_mac_key)
            protected_header = {
                'alg': 'HS256',
                'kid': eab_key_identifier,
                'url': self.__netio.directory['newAccount']
            }
            s = jws.JWS(payload=json.dumps(self.__netio.pubkey))
            s.add_signature(k, protected=protected_header)
            payload['externalAccountBinding'] = s.serialize()

        r = self.__netio.send_request(payload, AcmeAction.NewAccount)
        kid = r.headers['Location']
        if r.code == 201:
            self.__log.info(f'Account registered: {r.headers["Location"]}.')
        elif r.code == 200:
            self.__log.info(f'Account is already exist: {r.headers["Location"]}, updating contact info.')
            self.__netio.send_request({'contact': contact}, AcmeAction.VariableUrlAction, url=kid)
            self.__log.info(f'Contact information updated.')
        else:
            raise RuntimeError(f'Unexpected status code: {r.code}, {r.headers}, {r.content}')
        return kid

    def get_cert_by_domain(self, common_name: str, subject_alternative_name: typing.List[str],
                           challenge_handler: ChallengeHandlerBase,
                           key_generation_method: KeyGenerationMethod = KeyGenerationMethod.CryptographyLib,
                           key_type: KeyType = KeyType.RSA3072, output_name: str = '') -> typing.Tuple[bytes, bytes]:
        """Get certificate by domains.

        :param common_name: The commonName field of the certificate.
        :param subject_alternative_name:  The subjectAlternativeName extension of the certificate.
        :param challenge_handler:  The challenge handler to handle challenge.
        :param key_type: The type of the private key, must be a member of KeyType enum, default to RSA3072.
        :param output_name: The output name of the files, the key file will be appended '.key' as suffix,
                            the certificate file will be appended '.crt' as suffix,
                            if empty string '' is provided {common_name}.{timestamp}.key/crt will be used,
                            if None is provided, key and certificate will not be written to file.
        :param key_generation_method: How to generate the private key, using the cryptography lib or openssl cli.
        :raises TypeError: If key_type is not a member of KeyType enum.
        :raises TypeError: If key_generation_method is not a member of KeyGenerationMethod.
        :raises ValueError: If key_type is not supported.
        :raises ValueError: If key_generation_method is not supported.
        :return: The tuple of (private_key, certificate) both in pem format.
        """

        common_name = common_name.encode('idna').decode()
        subject_alternative_name = [i.encode('idna').decode() for i in subject_alternative_name]
        # generate private key
        if not isinstance(key_type, KeyType):
            raise TypeError('key_type must be a member of KeyType enum.')
        if not isinstance(key_generation_method, KeyGenerationMethod):
            raise TypeError('key_generation_method must be a member of KeyGenerationMethod enum.')
        if key_generation_method == KeyGenerationMethod.CryptographyLib:
            self.__log.info('Generating private key using cryptography lib.')
            if key_type == KeyType.ECC384:
                key = ec.generate_private_key(ec.SECP384R1())
            elif key_type == KeyType.ECC256:
                key = ec.generate_private_key(ec.SECP256R1())
            elif key_type == KeyType.RSA4096:
                key = rsa.generate_private_key(65537, 4096)
            elif key_type == KeyType.RSA3072:
                key = rsa.generate_private_key(65537, 3072)
            elif key_type == KeyType.RSA2048:
                key = rsa.generate_private_key(65537, 2048)
            else:
                raise ValueError(f'Unsupported key_type: {key_type.name}.')
        elif key_generation_method == KeyGenerationMethod.OpenSSLCLI:
            self.__log.info('Generating private key using openssl cli.')
            if key_type == KeyType.ECC384:
                key = self.__openssl('ecparam', ['-genkey', '-name', 'secp384r1', '-noout'])
            elif key_type == KeyType.ECC256:
                key = self.__openssl('ecparam', ['-genkey', '-name', 'secp256r1', '-noout'])
            elif key_type == KeyType.RSA4096:
                key = self.__openssl('genrsa', ['4096'])
            elif key_type == KeyType.RSA3072:
                key = self.__openssl('genrsa', ['3072'])
            elif key_type == KeyType.RSA2048:
                key = self.__openssl('genrsa', ['2048'])
            else:
                raise ValueError(f'Unsupported key_type: {key_type.name}')
            key = serialization.load_pem_private_key(key, password=None)
        else:
            raise ValueError('Unsupported key_generation_method.')

        # generate CSR
        c = x509.CertificateSigningRequestBuilder()
        c = c.subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name)]))
        if subject_alternative_name:
            c = c.add_extension(x509.SubjectAlternativeName([x509.DNSName(i) for i in subject_alternative_name]), True)
        c = c.sign(key, hashes.SHA256())

        # process order
        domains = set(subject_alternative_name)
        domains.add(common_name)
        cert = self.get_cert_by_csr(c.public_bytes(serialization.Encoding.DER), challenge_handler, None)
        key = key.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
        if output_name is not None:
            output_name = output_name or f'{common_name.encode().decode("idna")}.{str(int(time.time()))}'
            # write private key
            with open(f'{output_name}.key', 'wb') as file:
                file.write(key)

            # write certificate
            with open(f'{output_name}.crt', 'wb') as file:
                file.write(cert)
        return key, cert

    def get_cert_by_csr(self, csr: typing.Union[str, bytes], challenge_handler: ChallengeHandlerBase,
                        output_name: str = None) -> bytes:
        """Get certificate by csr.

        :param csr: The path to the csr file or the content of a csr file.
        :param challenge_handler: The challenge handler to handle challenge.
        :param output_name: The output certificate name. If an empty string ('') is provided,
                            {Common Name}.{Timestamp}.crt will be used. If None is provided, the certificate will not
                            be written to a file.
        :raises RuntimeError: If the order status is not valid after finalization.
        :return: The bytes representing the certificate.
        """

        # read csr
        self.__log.info('Loading CSR.')
        if isinstance(csr, str) and csr.startswith('-----BEGIN CERTIFICATE REQUEST-----'):
            csr = csr.encode()

        if isinstance(csr, str):
            with open(csr, 'rb') as file:
                csr = file.read()
        try:
            self.__log.debug('Trying to loading CSR using der format.')
            csr = x509.load_der_x509_csr(csr, backends.default_backend())
        except ValueError:
            self.__log.debug('CSR is not in der format, trying to loading CSR using pem format.')
            csr = x509.load_pem_x509_csr(csr, backends.default_backend())

        # get domains from csr
        domains = set()
        cn = csr.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
        domains.add(cn)  # add commonName
        self.__log.debug(f'commonName: {cn}')
        # add SAN if existed
        try:
            san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            for i in san:
                domains.add(i.value)
                self.__log.debug(f'subjectAlternativeName: {i.value}')
        except x509.extensions.ExtensionNotFound:
            self.__log.debug('No subjectAlternativeName found in CSR.')
            pass

        # process order
        self.__log.info(f'All domains in CSR: {str(domains)}')
        r_order = self.process_order(domains, challenge_handler)

        # finalize order by sending csr to server.
        self.__log.info('Finalizing order.')
        csr = base64.urlsafe_b64encode(csr.public_bytes(serialization.Encoding.DER)).decode().rstrip('=')
        r_order = self.__netio.send_request({'csr': csr}, AcmeAction.VariableUrlAction, r_order.content['finalize'])

        # poll order status
        retry_counter = 5
        while r_order.content['status'] == 'processing' and retry_counter > 0:
            time.sleep(int(r_order.headers.get('Retry-After', '5')))
            self.__log.debug('Order is processing, polling order status.')
            r_order = self.__netio.send_request('', AcmeAction.VariableUrlAction, r_order.headers['Location'])
            retry_counter -= 1
        if r_order.content['status'] != 'valid':
            raise RuntimeError(f'Order status is not valid after finalization. {r_order.headers["Location"]}, '
                               f'status: {r_order.content["status"]}.')

        # download certificate and write it to a file.
        self.__log.info('Certificate is issued.')
        # TODO: send download-certificate request using 'Accept: application/pem-certificate-chain' header.
        r_cert = self.__netio.send_request('', AcmeAction.VariableUrlAction, r_order.content['certificate'], False)
        if output_name is not None:
            output_name = output_name or f'{cn.encode().decode("idna")}.{str(int(time.time()))}.crt'
            with open(output_name, 'wb') as file:
                file.write(r_cert.content)
        return r_cert.content

    def process_order(self, domains: typing.Set[str], challenge_handler: ChallengeHandlerBase) -> AcmeResponse:
        """Create an order and fulfill the challenges in it.

        :param domains: The domains in the order.
        :param challenge_handler: The challenge handler to fulfill the challenges.
        :raises RuntimeError: If the status of an order is neither ready nor pending after its creation.
        :raises RuntimeError: If the status of an authorization is neither valid nor pending before processing.
        :raises RuntimeError: If there is no appropriate challenge_handler for an authorization.
        # :raises RuntimeError: If the status of a challenge is not valid after handling the challenge.
        :raises RuntimeError: If the status of an authorization is not valid after fulfill one of the challenge in it,
                              usually it could not happen.
        :raises RuntimeError: If the status of an order is not ready after fulfill all necessary challenges.
        :return: The AcmeResponse object representing the final order status.
        """
        # create newOrder
        self.__log.info(f'Creating order for: {str(domains)}')
        identifiers = [{'type': 'dns', 'value': i} for i in domains]
        r_order = self.__netio.send_request({'identifiers': identifiers}, AcmeAction.NewOrder)
        order_url = r_order.headers.get('Location')

        # check order status.
        self.__log.debug(f'Order status: {r_order.content["status"]}, url: {order_url}')
        if r_order.content['status'] == 'ready':
            self.__log.info('Order status is ready after creation.')
            return r_order

        if r_order.content['status'] != 'pending':
            raise RuntimeError(f'Order is neither ready nor pending after creation, '
                               f'status: {r_order.content["status"]}.')

        for authz_url in r_order.content['authorizations']:
            # fetch authorization
            r_authz = self.__netio.send_request('', AcmeAction.VariableUrlAction, authz_url)
            self.__log.info(f'Processing authorization for {r_authz.content["identifier"]["value"]}, '
                            f'status: {r_authz.content["status"]}')
            if r_authz.content['status'] == 'valid':
                continue
            if r_authz.content['status'] != 'pending':
                raise RuntimeError(f'Cannot process authorization {authz_url}, status: {r_authz.content["status"]}, '
                                   f'identifier: {r_authz.content["identifier"]["value"]}.')

            # determine which challenge to fulfill
            challenge = [c for c in r_authz.content['challenges']
                         if c['type'] == challenge_handler.get_handler_type(r_authz.content['identifier']['value'])]
            if len(challenge) == 0:
                raise RuntimeError(f'No appropriate challenge_handler for this authorization: {authz_url}, '
                                   f'identifier: {r_authz.content["identifier"]["value"]}.')
            challenge = challenge[0]

            # handle challenge
            self.__log.debug(f'Fulfilling challenge for {r_authz.content["identifier"]["value"]}, '
                             f'type: {challenge["type"]}')
            r = challenge_handler.handle(challenge['url'], r_authz.content['identifier']['value'],
                                         challenge['token'], self.__netio.key_thumbprint)
            self.__log.debug('Notifying server to validate the challenge.')
            r_challenge = self.__netio.send_request({}, AcmeAction.VariableUrlAction, challenge['url'])

            # According to RFC8555 section 7.5.1, client should send Post-as-Get request to authorization url.
            # check the challenge status, retry 5 times if it's still processing.

            # retry_counter = 5
            # while r_challenge.content['status'] in ('processing', 'pending')  and retry_counter > 0:
            #     time.sleep(int(r_challenge.headers.get('Retry-After', '5')))
            #     r_challenge = self.__netio.send_request('', AcmeAction.VariableUrlAction, r_challenge.content['url'])
            #     retry_counter -= 1
            #
            # if r_challenge.content['status'] != 'valid':
            #     raise RuntimeError(f'Challenge status is not valid: {r_challenge.content["url"]}, '
            #                        f'status: {r_challenge.content["status"]}, authorization: {authz_url}, '
            #                        f'identifier: {r_authz.content["identifier"]["value"]}.')

            # check the authorization status.
            retry_counter = 5
            self.__log.debug('Checking authorization status.')
            r_authz = self.__netio.send_request('', AcmeAction.VariableUrlAction, authz_url)
            while r_authz.content['status'] == 'pending' and retry_counter > 0:
                time.sleep(int(r_authz.headers.get('Retry-After', 5)))
                self.__log.debug('Retrying to check the authorization status.')
                r_authz = self.__netio.send_request('', AcmeAction.VariableUrlAction, authz_url)
                retry_counter -= 1
            r = challenge_handler.post_handle(challenge['url'], r_authz.content['identifier']['value'],
                                              challenge['token'], self.__netio.key_thumbprint, r)
            if r_authz.content['status'] != 'valid':
                raise RuntimeError(f'Authorization status is not valid: {authz_url}, '
                                   f'status: {r_authz.content["status"]}, '
                                   f'identifier: {r_authz.content["identifier"]["value"]}.')

        # check the order status
        self.__log.debug('Checking order status.')
        r_order = self.__netio.send_request('', AcmeAction.VariableUrlAction, order_url)
        if r_order.content['status'] != 'ready':
            raise RuntimeError(f'Order status is not ready after fulfill all necessary challenge: {order_url}, '
                               f'status: {r_order.content["status"]}')
        self.__log.info('Order is ready.')
        return r_order

    def revoke_cert(self, cert_file, reason: RevocationReason = None, challenge_handler: ChallengeHandlerBase = None):
        """Revoke the given certificate

        :param cert_file: The certificate file to be revoked.
        :param reason: The revocation reason.
        :param challenge_handler: The challenge handler to handler challenge when revoking certificate by authorization.
        :return: None
        """

        self.__log.info('Loading certificate file.')
        with open(cert_file, 'rb') as file:
            data = file.read()
        try:
            self.__log.debug('Trying to load certificate as PEM format.')
            crt = x509.load_pem_x509_certificate(data)
        except ValueError:
            self.__log.debug('Trying to load certificate as DER format.')
            crt = x509.load_der_x509_certificate(data)

        payload = {
            'certificate': base64.urlsafe_b64encode(crt.public_bytes(serialization.Encoding.DER)).decode().rstrip('=')
        }
        if reason is not None:
            payload['reason'] = reason.value

        try:
            self.__log.info('Trying to revoke certificate by account.')
            r = self.__netio.send_request(payload, AcmeAction.RevokeCertByAccountKey)
            self.__log.info('Certificate revoked.')
            return
        except RuntimeError as ex:
            self.__log.debug(f'Revoke certificate by account failed: {str(ex)}')

        if challenge_handler:
            domains = set()
            domains.add(crt.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value)
            for i in crt.extensions.get_extension_for_class(x509.SubjectAlternativeName).value:
                domains.add(i.value)
            try:
                self.__log.info('Trying to revoke certificate by authorization.')
                self.process_order(domains, challenge_handler)
                r = self.__netio.send_request(payload, AcmeAction.RevokeCertByAccountKey)
                self.__log.info('Certificate revoked.')
                return
            except RuntimeError as ex:
                self.__log.debug(f'Revoke certificate by account failed: {str(ex)}')

        try:
            self.__log.info('Trying to revoke certificate by private key.')
            r = self.__netio.send_request(payload, AcmeAction.RevokeCertByCertKey)
            self.__log.info('Certificate revoked.')
            return
        except RuntimeError as ex:
            self.__log.debug(f'Revoke certificate by private key failed: {str(ex)}.')

        raise RuntimeError('Revoke certificate failed.')

    def key_change(self, new_key_file, password: str = '') -> None:
        """Change the account key of an ACME account.

        :param new_key_file: The new account key file.
        :param password: The passphrase of the new account key file.
        :return: None
        """

        new_key = AcmeNetIO(new_key_file, password, self.__netio.directory_url)
        payload = new_key.sign_request({'account': self.__netio.query_kid(), 'oldKey': self.__netio.pubkey},
                                       AcmeAction.KeyChangeInner)
        r = self.__netio.send_request(payload, AcmeAction.KeyChangeOuter)
        self.__netio = new_key
        self.__log.info('key Changed')

    def deactivate_account(self):
        self.__netio.send_request({'status': 'deactivated'}, AcmeAction.VariableUrlAction, self.__netio.query_kid())
        self.__log.info('account deactivated')

    def query_kid(self):
        """Query the kid of the given keyfile.

        :return: The URL of the account.
        """
        return self.__netio.query_kid()
