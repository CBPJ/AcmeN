import abc, base64, hashlib

import tld


class ChallengeHandlerBase(abc.ABC):

    @property
    @abc.abstractmethod
    def handler_type(self):
        pass

    @abc.abstractmethod
    def pre_handle(self):
        """Preserved for future use."""
        pass

    @abc.abstractmethod
    def handle(self, url, id_type, id_value, token, key_thumbprint) -> bool:
        """Process the challenge.

        :param url: The url of the challenge. This could be used for uniquely identify a challenge.
        :param id_type: The identifier type of the authorization object. Currently, it's preserved for future use.
        :param id_value: The identifier value of the authorization object.
        :param token: The challenge token.
        :param key_thumbprint: The account key's thumbprint.
        :return: Whether the challenge is fulfilled.
        """
        pass

    @abc.abstractmethod
    def post_handle(self, url, id_type, id_value, token, key_thumbprint, succeed) -> bool:
        """Undo the action have been taken before to fulfill the challenge.

        :param url: The url of the challenge. This could be used for uniquely identify a challenge.
        :param id_type: The identifier type of the authorization object. Currently, it's preserved for future use.
        :param id_value: The identifier value of the authorization object.
        :param token: The challenge token.
        :param key_thumbprint: The account key's thumbprint.
        :param succeed: Whether the previous challenge handling process is succeed. It should be the return value of
                        handle(), not the response of the ACME server.
        :return: Whether the process is succeeded.
        """
        pass

    # TODO: add_domain(), remove_domain(), list_domain().


class Dns01Handler(ChallengeHandlerBase):
    """This class handles dns-01 challenge."""

    # A map from the challenge url to the dns provider's record id.
    __record_ids = {}

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

    @property
    def handler_type(self):
        return 'dns-01'

    def pre_handle(self):
        pass

    def handle(self, url, id_type, id_value, token, key_thumbprint) -> bool:
        # TODO: Check the validity of the token.
        # possibly, token = re.sub(r"[^A-Za-z0-9_\-]", "_", token)
        domain = tld.get_tld(id_value, as_object=True, fix_protocol=True)
        r = self.set_record(f'_acme-challenge.{domain.subdomain}', domain.fld, self.txt_value(token, key_thumbprint))
        if r:
            self.__record_ids[url] = r
            return True
        else:
            return False

    def post_handle(self, url, id_type, id_value, token, key_thumbprint, succeed) -> bool:
        domain = tld.get_tld(id_value, as_object=True, fix_protocol=True)
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
