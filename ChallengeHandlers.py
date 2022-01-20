import abc, base64, hashlib, functools, time

import tld, requests, dns
import AcmeN

__all__ = ['CloudflareDnsHandler']


class ChallengeHandlerBase(abc.ABC):

    @abc.abstractmethod
    def get_handler_type(self, domain: str) -> str:
        """Get handler type of the domain.

        :param domain: The domain.
        :return: Which type of challenge this handler can handle for the domain.
        """
        pass

    @abc.abstractmethod
    def pre_handle(self):
        """Preserved for future use."""
        pass

    @abc.abstractmethod
    def handle(self, url, identifier, token, key_thumbprint) -> bool:
        """Process the challenge.

        :param url: The url of the challenge. This could be used for uniquely identify a challenge.
        :param identifier: The identifier value of the authorization object.
        :param token: The challenge token.
        :param key_thumbprint: The account key's thumbprint.
        :return: Whether the challenge is fulfilled.
        """
        pass

    @abc.abstractmethod
    def post_handle(self, url, identifier, token, key_thumbprint, succeed) -> bool:
        """Undo the action have been taken before to fulfill the challenge.

        :param url: The url of the challenge. This could be used for uniquely identify a challenge.
        :param identifier: The identifier value of the authorization object.
        :param token: The challenge token.
        :param key_thumbprint: The account key's thumbprint.
        :param succeed: Whether the previous challenge handling process is succeed. It should be the return value of
                        handle(), not the response of the ACME server.
        :return: Whether the process is succeeded.
        """
        pass


class Dns01Handler(ChallengeHandlerBase):
    """This class handles dns-01 challenge."""

    # A map from the challenge url to the dns provider's record id.
    def __init__(self):
        self.__record_ids = {}
        self.__resolver = dns.resolver.Resolver(configure=False)
        self.__resolver.nameservers = ['8.8.8.8', '1.1.1.1', '9.9.9.9']
        self.__resolver.retry_servfail = False

    @staticmethod
    def txt_value(token, key_thumbprint):
        """Compute the value of the TXT record.

        :param token: The token from the challenge.
        :param key_thumbprint: The thumbprint of the account key.
        :return: The desired TXT record value.
        """
        key_authz = f'{token}.{key_thumbprint}'
        key_authz = hashlib.sha256(key_authz.encode('utf8')).digest()
        return base64.urlsafe_b64encode(key_authz).decode().rstrip('=')

    def check_txt_record(self, domain: str, value: str) -> bool:
        """Query the dns server to check whether the record match the expected value.

        :param domain: The domain.
        :param value: The expected value.
        :return: whether the record match the expected value.
        """
        records = set()
        try:
            for record in self.__resolver.resolve(domain, rdtype='TXT').rrset:
                records.add(record.to_text().strip('"'))
        except dns.exception.DNSException:
            return False
        return bool(value in records)

    def get_handler_type(self, domain: str):
        return 'dns-01'

    def pre_handle(self):
        pass

    def handle(self, url, identifier, token, key_thumbprint) -> bool:
        # TODO: Check the validity of the token.
        # possibly, token = re.sub(r"[^A-Za-z0-9_\-]", "_", token)
        domain = tld.get_tld(identifier, as_object=True, fix_protocol=True)
        r = self.set_record(f'_acme-challenge.{domain.subdomain}', domain.fld, self.txt_value(token, key_thumbprint))

        if not r:
            return False

        # check dns record every 10 seconds, 600 seconds at most.
        for i in range(60):
            if self.check_txt_record(f'_acme-challenge.{identifier}', self.txt_value(token, key_thumbprint)):
                return True
            else:
                time.sleep(10)
        return False

    def post_handle(self, url, identifier, token, key_thumbprint, succeed) -> bool:
        domain = tld.get_tld(identifier, as_object=True, fix_protocol=True)
        return self.del_record(f'_acme-challenge.{domain.subdomain}', domain.fld,
                               self.txt_value(token, key_thumbprint), self.__record_ids.pop(url, None))

    @abc.abstractmethod
    def set_record(self, subdomain, fld, value):
        """Set a DNS TXT record to fulfill the dns-01 challenge.

        The return value of this method should be the id of the dns record. And will pass directly to the del_record
        method. If the action failed, return False.
        :param subdomain: The subdomain of the identifier value.
        :param fld: The top level domain of the identifier value.
        :param value: The value of the TXT record.
        :return: The id of the TXT record if succeeded. False if the action failed.
        """
        pass

    @abc.abstractmethod
    def del_record(self, subdomain, fld, value, record_id) -> bool:
        """Delete the DNS record set to fulfill the challenge.

        :param subdomain: The subdomain of the identifier value.
        :param fld: The top level domain of the identifier value.
        :param value: The expected value of the TXT record. If this is mismatch with dns server's record, abort the
                      action and return False.
        :param record_id: The return value of the set_record.
        :return: Whether the action is succeeded.
        """
        pass


class CloudflareDnsHandler(Dns01Handler):
    """A dns-01 handler using the cloudflare api."""

    def __init__(self, api_token: str):
        """
        :param api_token: The cloudflare token, api-key is deprecated.
        """
        super().__init__()
        self.__session = requests.Session()
        self.__api_url = 'https://api.cloudflare.com/client/v4'
        headers = {
            'Content-type': 'application/json',
            'Accept': 'application/json',
            'User-Agent': f'AcmeN/{AcmeN.__version__}',
            'Authorization': f'Bearer {api_token}'
        }
        self.__session.headers.update(headers)

    @functools.lru_cache()
    def _get_zone_id(self, fld):
        """Get zone id of a domain.

        :param fld: the domain.
        :raises RuntimeError: If server return an unsuccessful status code.
        :raises RuntimeError: If query result is empty.
        :return: the zone id.
        """

        r = self.__session.get(f'{self.__api_url}/zones', params={'name': fld, 'match': 'all', 'status': 'active'})
        if not (r.ok and r.json()['success']):
            raise RuntimeError(f'Query zone id failed: {fld}, {r.status_code} {r.reason}, {r.text}')

        result = r.json()['result']
        if len(result) == 0:
            raise RuntimeError(f'Cannot get zone id of "{fld}", possibly it does not exist or is inactive.')
        return r.json()['result'][0]['id']

    def set_record(self, subdomain, fld, value):
        r = self.__session.post(f'{self.__api_url}/zones/{self._get_zone_id(fld)}/dns_records',
                                json={'type': 'TXT', 'name': f'{subdomain}.{fld}', 'content': value, 'ttl': 60})
        if not (r.ok and r.json()['success']):
            raise RuntimeError(f'Set record for {subdomain}.{fld} failed: {r.status_code} {r.reason}, {r.text}')
        return r.json()['result']['id']

    def del_record(self, subdomain, fld, value, record_id) -> bool:
        # delete record directly if record_id is provided.
        if record_id:
            r = self.__session.delete(f'{self.__api_url}/zones/{self._get_zone_id(fld)}/dns_records/{record_id}')
            if r.ok:
                return True
            else:
                raise RuntimeError(f'Del record {subdomain}.{fld} failed: {r.status_code} {r.status_code}, {r.text}')

        # otherwise, query the record first.
        r = self.__session.get(f'{self.__api_url}/zones/{self._get_zone_id(fld)}/dns_records',
                               params={'match': 'all', 'name': f'{subdomain}.{fld}', 'content': value, 'type': 'TXT'})
        if not (r.ok and r.json()['success']):
            raise RuntimeError(f'Query record id failed: {subdomain}.{fld}, {r.status_code} {r.reason}, {r.text}')
        result = r.json()['result']
        if len(result) == 0:
            # TODO: return false, make log, and do not raise RuntimeError.
            raise RuntimeError('No matching record.')
        else:
            return self.del_record(subdomain, fld, value, result[0]['id'])
