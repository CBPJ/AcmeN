from unittest import TestCase
import unittest
from cli import cli
from DnsHandlers import *


class TestCli(TestCase):

    def test_get_cert1(self):
        result = cli(('getcert -k account.pem  -s test.foo.com -s test2.foo.com -t ecc -d TencentDNSHandler ' +
                     '--dns-param secretid:id --dns-param secretkey:seckey foo.com').split())
        self.assertEqual(result['command'], 'getcert')
        self.assertEqual(result['san'], ['test.foo.com', 'test2.foo.com'])
        self.assertEqual(result['cn'], 'foo.com')
        self.assertEqual(result['key'], 'account.pem')
        self.assertIsInstance(result['dns'], TencentDNSHandler)
        pass
