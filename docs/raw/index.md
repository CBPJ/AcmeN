# AcmeN

[RFC8555](https://tools.ietf.org/html/rfc8555) 自动证书管理环境Python客户端。

## 特性

AcmeN实现了RFC8555中描述的以下特性：

- 注册新账户
- 更新联系方式
- 轮换账户密钥
- 注销账户
- 签发证书
- 吊销证书

**注意：** 我们尚未对AcmeN进行完整的测试，如需在生产环境中使用，你需要自行测试其可靠性。另外，AcmeN仍在开发阶段，`v0.*.*`版本无法保证API向后兼容性。

## 安装

自0.5.0起，AcmeN已发布到PyPI，你可以使用pip安装AcmeN：

```bash
pip install acmen
```

## 创建ACME账户

```python
from acmen import AcmeN
acme = AcmeN('account.key', key_passphrase='<your_password>')
acme.register_account(contact=['mailto:xxx@yyy.zzz'])
```

这将在Let's Encrypt的ACME服务器上创建一个账户，并使用邮箱xxx@yyy.zzz作为联系方式。在进行接下来的大部分操作前，都需要一个ACME账户。当此密钥已经注册过账户时，此方法会更新contact信息，不会因账户已存在而发生异常。

## 签发证书

AcmeN使用RFC8555中的`dns-01`、`http-01`或`tls-alpn-01`验证方式验证域名控制权。可以通过调用DNS服务商的API更新或删除DNS记录、自动或手动创建http-01认证文件、创建tls-alpn-01所需的tls服务器。<br />
目前，AcmeN集成了`Cloudflare`、`Godaddy`、`Aliyun`、`DnsPod`的API客户端。<br />
以Cloudflare为例，[`main.py`](https://github.com/CBPJ/AcmeN/blob/master/main.py) 中给出了签发证书的过程:

```python
import logging
from acmen import AcmeN
from acmen.handlers import CloudflareDnsHandler

logging.basicConfig(level=logging.INFO)

handler = CloudflareDnsHandler(api_token='*****')
acme = AcmeN('account.key')
acme.register_account(contact=['mailto:xxx@yyy.zzz'])
acme.get_cert_by_domain('example.com', ['alt1.example.com', 'alt2.example.com'], handler)
```

这将使用`account.key`在默认CA(Let's Encrypt)注册一个ACME账户，使用`xxx@yyy.zzz`作为联系方式，并为example.com获取证书，且包含alt1.example.com和alt2.example.com两个可选名称(subjectAlternativeName)，并通过调用Cloudflare的DNS API来完成认证。<br />
默认情况下，这将使用[Cryptography](https://cryptography.io)库生成3072位RSA私钥，如果希望使用OpenSSL命令行生成私钥或者希望生成其他类型和长度的私钥，请参阅[文档](developer/acmen.md#get_cert_by_domain)。

-----

### 指定私钥位置

上述实例中，`account.key`代表账户私钥位置。

如果账户私钥使用密码保护，可以在创建AcmeN实例时传入密码。

```python
from acmen import AcmeN
acme = AcmeN('account.key', key_passphrase='<your_password>')
```

如果你没有账户私钥，可以使用OpenSSL生成：

```bash
openssl genrsa -out account.key 4096
```

-----

### 注册ACME账户及更改账户联系方式

```python
from acmen import AcmeN
acme = AcmeN('account.key')
acme.register_account(contact=['mailto:xxx@yyy.zzz'])
```

此方法将注册新账户并将联系方式设置为xxx@yyy.zzz。若账户已存在，将更新联系方式为xxx@yyy.zzz。<br />
此方法在账户已存在时不会发生异常。

-----

### 指定证书签发机构(CA)

AcmeN目前内置了来自3个CA机构的5个服务器。三个CA机构是：[Let's Encrypt](https://letsencrypt.org)、[BuyPass](https://www.buypass.com)、[ZeroSSL](https://zerossl.com/)。

```python
from acmen import AcmeN, SupportedCA
acme = AcmeN('account.key', ca=SupportedCA.LETSENCRYPT)
```

ca的默认值是`SupportedCA.LETSENCRYPT`，其他有效值是：`SupportedCA.LETSENCRYPT`、`SupportedCA.BUYPASS`、`SupportedCA.ZEROSSL`、`SupportedCA.LETSENCRYPT_STAGING`、`SupportedCA.BUYPASS_STAGING`。

-----

### 创建ChallengeHandler

目前AcmeN内置了Cloudflare、Godaddy、Aliyun、Dnspod的DNS API，更多的ChallengeHandler将在未来添加。

```python
from acmen.handlers import CloudflareDnsHandler
# Cloudflare (APIToken):
dns = CloudflareDnsHandler(api_token='<your_token>')
```

另外，你也可以实现自己的ChallengeHandler，详见[ChallengeHandlers](./developer/challenge_handlers/index.md)。

-----

### 获取证书

有以下两种方式可以获取证书

- 通过CSR文件获取证书：

```python
from acmen import AcmeN
from acmen.handlers import CloudflareDnsHandler
acme = AcmeN(...)
dns = CloudflareDnsHandler(...)
acme.get_cert_by_csr('<path/to/csr_file>', challenge_handler=dns)
```

- 通过域名获取证书：

```python
from acmen import AcmeN, KeyType
from acmen.handlers import CloudflareDnsHandler
acme = AcmeN(...)
dns = CloudflareDnsHandler(...)
acme.get_cert_by_domain('foo.example.com', subject_alternative_name=['foo1.example.com', 'foo2.example.com'], key_type=KeyType.RSA3072, challenge_handler=dns)
```

其中`foo.example.com`是证书的CommonName。<br />
`subject_alternative_name`：DNS名称，指定DNS名称可以创建多域名证书，当不需要SAN时，可传入空列表`[]`。<br />
`key_type`：证书类型，默认值是3072位RSA证书，你也可以选择使用KeyType.ECC384、KeyType.ECC256、KeyType.RSA4096、KeyType.RSA2048。其中ECC384和ECC256分别使用secp384r1和secp256r1(prime256v1)曲线。<br />
`challenge_handler`：在上面步骤中创建的challenge_handler。

-----

正常情况下，AcmeN会生成：<br />
密钥文件：`{域名}.{时间戳}.{密钥类型}.key`<br />
证书文件：`{域名}.{时间戳}.{密钥类型}.crt`

## 吊销证书

### 使用证书私钥吊销证书

使用证书的私钥实例化AcmeN，并调用revoke_cert方法，传入证书文件的路径。

```python
from acmen import AcmeN
acme = AcmeN('cert_private_key.key', ca=...)
acme.revoke_cert('/path/to/cert_file.crt')
```

`cert_file`：需要吊销的证书文件的路径。<br />

-----

### 使用账户密钥吊销证书

```python
from acmen import AcmeN
from acmen.handlers import CloudflareDnsHandler
handler = CloudflareDnsHandler(...)
acme = AcmeN('account.key', ca=...)
acme.revoke_cert('/path/to/cert_file.crt', challenge_handler=handler)
```

`cert_file`：需要吊销的证书文件路径。<br />

在使用账户密钥吊销证书时，若Acme服务器缓存了对域名所有权的验证，或签发此证书的账户与当前账户是同一账户，则可以直接吊销。否则AcmeN会使用challenge_handler完成域名所有权验证，然后吊销证书。详情请见[文档](developer/acmen.md#revoke_cert)。

## 账户密钥轮换

以旧密钥创建AcmeN实例后，调用`key_change`方法：

```python
from acmen import AcmeN
acme = AcmeN('old_key.key')
acme.key_change('/path/to/new_key_file.key', password='')
```

`new_key_file`：新密钥文件<br />
`password`：保护新密钥的密码

## 注销账户

```python
from acmen import AcmeN
acme = AcmeN(...)
acme.deactivate_account()
```

**注意：** 根据[RFC8555 Account Deactivation](https://tools.ietf.org/html/rfc8555#section-7.3.6)的规定，ACME **不提供** 重新启用账户的方法。

## 使用其他ACME服务商

默认情况下，AcmeN使用[Let's Encrypt](https://letsencrypt.org/) 提供的证书签发服务。但同时，AcmeN也内置了[buypass](https://www.buypass.com/ssl/products/acme)和[zerossl](https://zerossl.com/features/acme/) 的服务器地址。如需使用其他服务商，可在实例化AcmeN时传入ACME服务器的Directory目录：

```python
from acmen import AcmeN
acme = AcmeN('account.key', ca='https://acme.zerossl.com/v2/DV90')
```

## 查找旧版本的文档

目前我们暂未单独提供旧版本的文档，但文档与代码一同进行版本控制，你可以使用git检出之前的版本，在/docs目录下可找到对应的文档。目前文档使用[`mkdocs`](https://www.mkdocs.org)渲染，你可以使用mkdocs在/docs文件夹下构建html版本。

## 国际化域名(IDN)

*目前AcmeN提供实验性国际化域名支持

非英语域名会使用punycode转义后传递给ACME服务器，默认输出文件名仍然是原文。当使用CSR申请证书时，若CSR中包含经punycode编码的CommonName，确定默认输出文件名时会将CN中punycode编码的域名转义回非英语域名。<br />
我并未测试IDN与DNS服务商API的兼容性，而且并不是所有ACME服务商都同意签发IDN证书。

## 为不同的域名设置不同的Handler

若`example.com`通过Cloudflare进行DNS解析、`example.org`通过Dnspod进行DNS解析，但需要一个同时包含二者的证书，可使用HandlerSet。

```python
from acmen import AcmeN
from acmen.handlers import *
s = HandlerSet()
s['example.com'] = CloudflareDnsHandler(...)
s['example.org'] = DnspodDnsHandler(...)

a = AcmeN(...)
a.get_cert_by_domain('example.com', subject_alternative_name=['example.org', 'www.example.com'],challenge_handler=s)
```

## 通过代理服务器访问

为AcmeN提供网络操作的requests库会遵循`http_proxy`和`https_proxy`环境变量的设置。也可以手动设置代理服务器，如：

```python
from acmen import AcmeN
acme = AcmeN('account.key', proxy='http://localhost:8080')
``` 
