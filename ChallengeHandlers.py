import abc


class ChallengeHandlerBase(abc.ABC):
    @abc.abstractmethod
    def pre_handle(self):
        """Preserved for future use."""
        pass

    @abc.abstractmethod
    def handle(self, url, subdomain, domain, token, key_thumbprint) -> bool:
        """Process the challenge.

        :param url: The url of the challenge. This could be used for uniquely identify a challenge.
        :param subdomain: The subdomain of the entire FQDN. For example, the "abc.def" of "abc.def.example.org".
        :param domain: The first level domain. For example, the "example.org" of "abc.def.example.org".
        :param token: The challenge token.
        :param key_thumbprint: The account key's thumbprint.
        :return: Whether the challenge is fulfilled.
        """
        pass

    @abc.abstractmethod
    def post_handle(self, url, subdomain, domain, token, key_thumbprint, succeed) -> bool:
        """Undo the action have been taken before to fulfill the challenge.

        :param url: The url of the challenge. This could be used for uniquely identify a challenge.
        :param subdomain: The subdomain of the entire FQDN. For example, the "abc.def" of "abc.def.example.org".
        :param domain: The first level domain. For example, the "example.org" of "abc.def.example.org".
        :param token: The challenge token.
        :param key_thumbprint: The account key's thumbprint.
        :param succeed: Whether the previous challenge handling process is succeed. It should be the return value of
                        handle(), not the response of the ACME server.
        :return: Whether the process is succeeded.
        """
        pass
