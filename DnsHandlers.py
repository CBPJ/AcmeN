import json, re, time, secrets, hmac, base64, urllib.parse, abc, typing
from functools import lru_cache
import requests, tld

__all__ = ['DNSHandlerBase', 'DefaultDNSHandler', 'GoDaddyDNSHandler', 'TencentDNSHandler', 'CloudflareDNSHandler']


class DNSHandlerBase(abc.ABC):
    __session = None
    __share_session = False

    def __close_unshared_session(self):
        if (not self.__share_session) and (self.__session is not None):
            self.__session.close()
        self.__session = None
        self.__share_session = False

    @property
    def session(self):
        if self.__session is None:
            self.__session = requests.session()
            self.__session.headers.update(Connection='Keep-Alive')
            self.__share_session = False
        return self.__session

    @session.setter
    def session(self, s):
        self.__close_unshared_session()
        self.__share_session = True
        self.__session = s

    @session.deleter
    def session(self):
        self.__close_unshared_session()

    def __del__(self):
        self.__close_unshared_session()

    @abc.abstractmethod
    def set_record(self, dns_domain, value):
        pass

    @abc.abstractmethod
    def del_record(self, dns_domain, value):
        pass

    @staticmethod
    def get_subdomain(dns_domain):
        return tld.get_tld(dns_domain, as_object=True, fix_protocol=True).subdomain

    @staticmethod
    def get_first_level_domain(dns_domain):
        return tld.get_tld(dns_domain, as_object=True, fix_protocol=True).fld


class DefaultDNSHandler(DNSHandlerBase):
    def set_record(self, dns_domain, value):
        return False
        pass

    def del_record(self, dns_domain, value):
        return False
        pass


class GoDaddyDNSHandler(DNSHandlerBase):
    def __init__(self, sso_key):
        self.__sso_key = sso_key
        self.__header = {
            'Authorization': self.__sso_key,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }

    def set_record(self, dns_domain, value):
        domain = self.get_first_level_domain(dns_domain)
        name = self.get_subdomain(dns_domain)
        res = self.session.put(f'https://api.godaddy.com/v1/domains/{domain}/records/TXT/{name}', headers=self.__header,
                               data=json.dumps([{'data': value, 'name': name, 'ttl': 600, 'type': 'TXT'}]))

        return res.status_code == 200
        pass

    def del_record(self, dns_domain, value):
        """delete dns record with specific name and value"""
        domain = self.get_first_level_domain(dns_domain)
        name = self.get_subdomain(dns_domain)
        info = self.session.get(f'https://api.godaddy.com/v1/domains/{domain}/records/TXT/',
                                headers=self.__header).json()

        # when value is None, the record will be deleted whatever the value it has
        data = [i for i in info if i['name'] != name or i['data'] != value and value is not None]

        if len(data) == len(info) or len(data) == 0:  # godaddy API cannot delete a single record
            return False
        res = self.session.put(f'https://api.godaddy.com/v1/domains/{domain}/records/TXT/', headers=self.__header,
                               data=json.dumps(data))
        return res.status_code == 200


class TencentDNSHandler(DNSHandlerBase):
    def __init__(self, secret_id, secret_key):
        self.__secret_id = secret_id
        self.__secret_key = secret_key
        self.__path = 'https://cns.api.qcloud.com/v2/index.php'

    def __get_signature(self, method, data: dict):
        result = {
            'Timestamp': int(time.time()),
            'Nonce': secrets.randbits(64),
            'SecretId': self.__secret_id,
            'SignatureMethod': 'HmacSHA256'
        }
        result.update(data)

        param = ['{0}={1}'.format(key, result[key]) for key in sorted(result)]
        param = '&'.join(param)

        sign_path = re.sub(r'^https?://', '', self.__path)
        final_string = '{0}{1}?{2}'.format(method, sign_path, param)

        signature = hmac.new(self.__secret_key.encode('utf8'), final_string.encode('utf8'), 'sha256').digest()
        signature = base64.b64encode(signature)

        result.update(Signature=signature)
        return result, signature, '{0}&Signature={1}'.format(param, urllib.parse.quote(signature))

    def __get_record(self, domain):
        data = {
            'Action': 'RecordList',
            'domain': domain,
            'recordType': 'TXT'
        }
        req, _, _ = self.__get_signature('POST', data)
        res = self.session.post(self.__path, data=req, headers={})
        if res.status_code == 200:
            return res.json()
        else:
            raise ValueError(res.status_code, res.content.decode('utf8'))

    def set_record(self, dns_domain, value):
        domain = self.get_first_level_domain(dns_domain)
        name = self.get_subdomain(dns_domain)
        records = self.__get_record(domain)['data']['records']
        for i in records:
            if i['name'] == name:
                self.__del_record_by_id(i['id'], domain)
        data = {
            'Action': 'RecordCreate',
            'domain': domain,
            'subDomain': name,
            'recordType': 'TXT',
            'recordLine': '默认',
            'value': value,
            'ttl': 600
        }
        req, _, _ = self.__get_signature('POST', data)
        res = self.session.post(self.__path, data=req, headers={})
        return res.status_code == 200 and res.json()['code'] == 0

    def del_record(self, dns_domain, value):
        domain = self.get_first_level_domain(dns_domain)
        name = self.get_subdomain(dns_domain)
        records = self.__get_record(domain)['data']['records']
        result = True
        for i in records:
            if i['name'] == name and (i['value'] == value or value is None):
                result = result & self.__del_record_by_id(i['id'], domain)
            elif i['name'] == name and i['value'] != value and value is not None:
                return False
        return result

    def __del_record_by_id(self, record_id, domain):
        data = {
            'Action': 'RecordDelete',
            'domain': domain,
            'recordId': record_id
        }
        req, _, _ = self.__get_signature('POST', data)
        res = self.session.post(self.__path, data=req, headers={})
        return res.status_code == 200 and res.json()['code'] == 0
        pass


class CloudflareDNSHandler(DNSHandlerBase):
    def __init__(self, api_token='', api_key: typing.Tuple[str, str] = None):
        """
        :param api_token: api token
        :param api_key: tuple of (api_key, email)
        """
        if not bool(api_token) ^ bool(api_key):
            raise ValueError('one of api_token and (api_key, email) must be provided')
        self.__headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        if api_token:
            self.__headers['Authorization'] = 'Bearer {0}'.format(api_token)
        elif api_key:
            self.__headers['X-Auth-Key'] = api_key[0]
            self.__headers['X-Auth-Email'] = api_key[1]

    @lru_cache
    def __get_zone_id(self, domain):
        res = self.session.get(f'https://api.cloudflare.com/client/v4/zones', params={'match': 'all', 'name': domain},
                               headers=self.__headers, )
        if res.status_code != 200:
            raise ValueError(res.status_code, res.content.decode('utf8'))
        result = res.json()
        if len(result['result']) == 0:
            raise ValueError('domain not exist')
        elif len(result['result']) != 1:
            raise ValueError('server returns {0} domains'.format(len(result['result'])))
        return result['result'][0]['id']

    def __get_record(self, domain, name):
        zone_id = self.__get_zone_id(domain)
        dns_domain = '.'.join([name, domain])
        res = self.session.get(f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records',
                               headers=self.__headers, params={'match': 'all', 'name': dns_domain, 'type': 'TXT'})
        if res.status_code != 200:
            raise ValueError(res.status_code, res.content.decode('utf8'))

        result = res.json()
        return result['result']

    def __del_record_by_id(self, record_id, domain):
        zone_id = self.__get_zone_id(domain)
        res = self.session.delete(f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}',
                                  headers=self.__headers)
        return res.status_code == 200 and res.json()['result']['id'] == record_id

    def set_record(self, dns_domain, value):
        domain = self.get_first_level_domain(dns_domain)
        name = self.get_subdomain(dns_domain)
        data = {
            'type': 'TXT',
            'name': name,
            'content': value,
            'ttl': 120
        }
        zone_id = self.__get_zone_id(domain)
        res = self.session.post(f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records',
                                headers=self.__headers, json=data)
        return res.status_code == 200 and res.json()['success']

    def del_record(self, dns_domain, value):
        domain = self.get_first_level_domain(dns_domain)
        name = self.get_subdomain(dns_domain)
        records = self.__get_record(domain, name)

        result = True
        for record in records:
            if record['name'] == dns_domain and record['content'] == value:
                return self.__del_record_by_id(record['id'], domain)
            elif record['name'] == dns_domain and value is None:
                result &= self.__del_record_by_id(record['id'], domain)
        return result
