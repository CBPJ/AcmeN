import re, time, secrets, hmac, base64, abc, typing, binascii, datetime, uuid
from urllib.parse import quote
from functools import lru_cache
import requests, tld

__all__ = [
    'DNSHandlerBase', 'DefaultDNSHandler', 'GoDaddyDNSHandler', 'TencentDNSHandler', 'CloudflareDNSHandler',
    'AliyunDNSHandler'
]


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
    def del_record(self, dns_domain, value, record_id):
        pass

    @staticmethod
    def split_domain(dns_domain):
        result = tld.get_tld(dns_domain, as_object=True, fix_protocol=True)
        return result.subdomain, result.fld

    @staticmethod
    def is_acme_challenge(value):
        try:
            return bool(re.match('^[-_0-9A-Za-z]{43}$', value)) and len(base64.urlsafe_b64decode(value + '=')) == 32
        except binascii.Error:
            return False


class DefaultDNSHandler(DNSHandlerBase):
    def set_record(self, dns_domain, value):
        return False
        pass

    def del_record(self, dns_domain, value, record_id):
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

    def __get_record(self, domain):
        res = self.session.get(f'https://api.godaddy.com/v1/domains/{domain}/records/TXT/', headers=self.__header)
        if res.status_code != 200:
            raise ValueError(res.status_code, res.content.decode('utf8'))
        return res.json()

    def set_record(self, dns_domain, value):
        name, domain = self.split_domain(dns_domain)
        records = self.__get_record(domain)
        records.append({'data': value, 'name': name, 'ttl': 600, 'type': 'TXT'})
        res = self.session.put(f'https://api.godaddy.com/v1/domains/{domain}/records/TXT/', headers=self.__header,
                               json=records)

        return res.status_code == 200, None
        pass

    def del_record(self, dns_domain, value, record_id):
        """delete dns record with specific name and value"""
        name, domain = self.split_domain(dns_domain)

        records = self.__get_record(domain)
        records_to_delete = []
        for record in records:
            if record['name'] == name and record['data'] == value:
                records_to_delete.append(record)
            elif (record['name'] == name) and (value is None) and (self.is_acme_challenge(record['data'])):
                records_to_delete.append(record)

        if len(records_to_delete) == 0:
            return False

        for record in records_to_delete:
            records.remove(record)

        if len(records) == 0:  # godaddy API cannot delete a single record
            return False
        res = self.session.put(f'https://api.godaddy.com/v1/domains/{domain}/records/TXT/', headers=self.__header,
                               json=records)
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
        return result, signature, '{0}&Signature={1}'.format(param, quote(signature))

    def __get_record(self, domain, name):
        data = {
            'Action': 'RecordList',
            'domain': domain,
            'recordType': 'TXT',
            'subDomain': name
        }
        req, _, _ = self.__get_signature('POST', data)
        res = self.session.post(self.__path, data=req, headers={})
        if res.status_code != 200:
            raise ValueError(res.status_code, res.content.decode('utf8'))
        return res.json()['data']['records']

    def set_record(self, dns_domain, value):
        name, domain = self.split_domain(dns_domain)
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
        result = res.json()
        succeed = bool(res.status_code == 200 and result['code'] == 0)
        return succeed , result['data']['record']['id'] if succeed else None

    def del_record(self, dns_domain, value, record_id):
        name, domain = self.split_domain(dns_domain)

        records_to_delete = []
        if record_id is not None:
            records_to_delete.append(record_id)
        else:
            records = self.__get_record(domain, name)
            for record in records:
                if record['name'] == name and record['value'] == value:
                    records_to_delete.append(record['id'])
                elif (record['name'] == name) and (value is None) and (self.is_acme_challenge(record['value'])):
                    records_to_delete.append(record['id'])

        if len(records_to_delete) == 0:
            return False

        result = True
        for record_id in records_to_delete:
            result &= self.__del_record_by_id(record_id, domain)
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
        name, domain = self.split_domain(dns_domain)
        data = {
            'type': 'TXT',
            'name': name,
            'content': value,
            'ttl': 120
        }
        zone_id = self.__get_zone_id(domain)
        res = self.session.post(f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records',
                                headers=self.__headers, json=data)
        result = res.json()
        succeed = bool(res.status_code == 200 and result['success'])
        return succeed, result['result']['id'] if succeed else None

    def del_record(self, dns_domain, value, record_id):
        name, domain = self.split_domain(dns_domain)
        records_to_delete = []
        if record_id is not None:
            records_to_delete.append(record_id)
        else:
            records = self.__get_record(domain, name)
            for record in records:
                if record['name'] == dns_domain and record['content'] == value:
                    records_to_delete.append(record['id'])
                elif (record['name'] == dns_domain) and (value is None) and (self.is_acme_challenge(record['content'])):
                    records_to_delete.append(record['id'])

        if len(records_to_delete) == 0:
            return False

        result = True
        for record_id in records_to_delete:
            result &= self.__del_record_by_id(record_id, domain)
        return result


class AliyunDNSHandler(DNSHandlerBase):
    def __init__(self, access_key_id, access_key_secret):
        self.__id = access_key_id
        self.__key = access_key_secret
        self.__path = 'https://alidns.aliyuncs.com'

    def __get_signature(self, data: dict):
        t = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).replace(microsecond=0)
        result = {
            'Format': 'JSON',
            'Version': '2015-01-09',
            'AccessKeyId': self.__id,
            'SignatureMethod': 'HMAC-SHA1',
            'Timestamp': re.sub(r'\+00:00', 'Z', t.isoformat()),
            'SignatureNonce': str(uuid.uuid4()),
            'SignatureVersion': '1.0'
        }
        result.update(data)
        param = ['{0}={1}'.format(quote(key), quote(result[key])) for key in sorted(result)]
        param = '&'.join(param)

        string_to_sign = param.replace('%3D', '=')
        string_to_sign = f'GET&%2F&{quote(string_to_sign)}'

        signature = hmac.new(f'{self.__key}&'.encode('utf8'), string_to_sign.encode('utf8'), 'sha1').digest()
        signature = base64.b64encode(signature)

        result['Signature'] = quote(signature)
        param = ['{0}={1}'.format(key, result[key]) for key in sorted(result)]  # add Signature to proper position
        param = '&'.join(param)
        return result, signature, param

    def __get_record(self, domain, name):
        data = {
            'Action': 'DescribeDomainRecords',
            'DomainName': domain,
            'PageSize': '500',
            'KeyWord': name,
            'TypeKeyword': 'TXT',
            'SearchMode': "EXACT"
        }

        _, _, param = self.__get_signature(data)
        res = self.session.get(f'{self.__path}?{param}')
        if res.status_code != 200:
            raise ValueError(res.status_code, res.content.decode('utf8'))
        return res.json()['DomainRecords']['Record']

    def set_record(self, dns_domain, value):
        name, domain = self.split_domain(dns_domain)
        data = {
            'Action': 'AddDomainRecord',
            'DomainName': domain,
            'RR': name,
            'Type': 'TXT',
            'Value': value,
            'Line': 'default',
            'ttl': '600'
        }
        _, _, param = self.__get_signature(data)
        res = self.session.get(f'{self.__path}?{param}')
        succeed = bool(res.status_code == 200)
        return succeed, res.json()['RecordId'] if succeed else None
        pass

    def del_record(self, dns_domain, value, record_id):
        name, domain = self.split_domain(dns_domain)

        records_to_delete = []
        if record_id is not None:
            records_to_delete.append(record_id)
        else:
            records = self.__get_record(domain, name)
            for record in records:
                if record['RR'] == name and record['Value'] == value:
                    records_to_delete.append(record['RecordId'])
                elif (record['RR'] == name) and (value is None) and (self.is_acme_challenge(record['Value'])):
                    records_to_delete.append(record['RecordId'])

        if len(records_to_delete) == 0:
            return False

        result = True
        for record_id in records_to_delete:
            result &= self.__del_record_by_id(record_id)
        return result
        pass

    def __del_record_by_id(self, record_id):
        data = {
            'Action': 'DeleteDomainRecord',
            'RecordId': record_id
        }
        _, _, param = self.__get_signature(data)
        res = self.session.get(f'{self.__path}?{param}')
        return res.status_code == 200
        pass
