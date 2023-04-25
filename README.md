# AcmeN

AcmeN is an ACME([RFC8555](https://tools.ietf.org/html/rfc8555)) client implemented in Python.

**Note:** AcmeN is still under actively development, there will be some breaking changes until the first stable version v1.0.0 is released. Please keep an eye on the change log.

## Quick Start

Install AcmeN using pip:

```shell
pip install acmen
```

Generate account key using openssl:

```shell
openssl ecparam -genkey -noout -name secp384r1 -out account.key
```

Create a python file named `main.py` as follows and modify necessary parameters:

```python
import logging
from acmen import AcmeN
from acmen.handlers import CloudflareDnsHandler

logging.basicConfig(level=logging.INFO)
acme = AcmeN('account.key')
handler = CloudflareDnsHandler('<your_api_token>')
acme.register_account(contact=['mailto:you@your-mail-provider.tld'])
acme.get_cert_by_domain('example.com', ['www.example.com', 'alt1.example.com'], handler)
```

After a few seconds, you will get your certificate and key file in the working directory.

For more information, please refer to [AcmeN docs](https://cbpj.github.io/AcmeN/).(Chinese Simplified)
