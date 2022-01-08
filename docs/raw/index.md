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

## 安装依赖

使用git克隆代码：

```bash
git clone https://github.com/CBPJ/AcmeN
cd AcmeN
pip install -r requirements.txt
```

或者手动下载解压后使用pip安装依赖

然后打开`main.py`按照需要修改其中的代码并执行。

另外，AcmeN依赖[OpenSSL](https://www.openssl.org/) 才能运行，请确保openssl在你的`PATH`变量中，如果你使用windows且没有安装openssl，你可以在[Release](https://github.com/CBPJ/AcmeN/releases/) 页面下载我们编译好的版本。对于Linux，你可以使用软件包管理器安装。

## 签发证书

AcmeN使用RFC8555规定的`dns-01`验证方式验证域名控制权，并通过调用DNS服务商的API更新或删除DNS记录。目前，AcmeN集成了Godaddy和腾讯云的API客户端。以Godaddy为例，[`main.py`](https://github.com/CBPJ/AcmeN/blob/master/main.py) 中给出了签发证书的过程:

```python
import logging
from AcmeN import AcmeN
from DnsHandlers import GoDaddyDNSHandler

logging.basicConfig(level=logging.INFO)
acme = AcmeN('account.key')
dns = GoDaddyDNSHandler('sso-key *****:****')
acme.get_cert_from_domain('foo.example.com', dns_name=['foo1.example.com', 'foo2.example.com'], cert_type='rsa', dns_handler=dns)
```

-----

### 指定私钥位置

上述实例中，`account.key`代表账户私钥位置，如果此私钥尚未注册账户，在需要时会自动注册。

如果账户私钥使用密码保护，可以在创建AcmeN实例时传入密码，如果希望设定账户的联系方式，也可以在此时设定。这两个参数都是可选的。

```python
acme = AcmeN('account.key', account_key_password='<your_password>', contact=['mailto:foo@example.com'])
```

如果你没有账户私钥，可以使用OpenSSL生成：

```bash
openssl genrsa -out account.key 4096
```

-----

### 指定证书签发机构(CA)

AcmeN目前内置了来自3个CA机构的5个服务器。三个CA机构是：[Let's Encrypt](https://letsencrypt.org)、[BuyPass](https://www.buypass.com)、[ZeroSSL](https://zerossl.com/)。

```python
acme = AcmeN('account.key', ca='LETSENCRYPT')
```

ca的默认值是`LETSENCRYPT`，有效值是：`LETSENCRYPT`、`BUYPASS`、`ZEROSSL`、`LETSENCRYPT_STAGING`、`BUYPASS_STAGING`。

-----

### 创建DNSHandler

目前AcmeN内置了Godaddy、腾讯云、Cloudflare、阿里云的DNSHandler。

使用Godaddy提供的DNS服务时，访问令牌以`sso-key`开头，创建`GodaddyDNSHandler`时传入即可。

使用腾讯与提供的DNS服务时，访问令牌包括`secret_id`和`secret_key`两部分，创建`TencentDnsHandler`时传入。

其他服务商：

```python
from DnsHandlers import *
# Tencent:
dns = TencentDNSHandler('<your_secret_id>', '<your_secret_key>')
# Godaddy:
dns = GodaddyDNSHandler('sso-key *****')
# Cloudflare (APIToken):
dns = CloudflareDNSHandler(api_token='<your_token>')
# Cloudflare (APIKey):
dns = CloudflareDNSHandler(api_key=('<your_api_key>', 'your_email'))
# Aliyun:
dns = AliyunDNSHandler('<your_accesskey_id>', '<your_accesskey_secret>')
```

如果你希望手动设置/删除DNS记录，可以跳过此步骤。另外，你也可以实现自己的DNSHandler。

-----

### 获取证书

有以下两种方式可以获取证书

- 通过CSR文件获取证书：

```python
acme.get_cert_from_csr('<path/to/csr_file>', dns_handler=dns)
```

- 通过域名获取证书：

```python
acme.get_cert_from_domain('foo.example.com', dns_name=['foo1.example.com', 'foo2.example.com'], cert_type='rsa', dns_handler=dns)
```

其中`foo.example.com`是证书的CommonName，是唯一一个必须参数。<br />
`dns_name`：DNS名称，指定DNS名称可以创建多域名证书，可选参数。<br />
`cert_type`：证书类型，可以设置为`rsa`或`ecc`，设置为rsa时，将生成4096位RSA私钥，设置为ecc时，使用secp384r1曲线生成私钥。如果你希望使用不同的密钥长度，你需要修改代码。可选参数。<br />
`dns_handler`：在上面步骤中创建的DNSHandler，如果你希望手动操作DNS记录，忽略此参数。可选参数。

-----

正常情况下，AcmeN会生成：<br />
密钥文件：`{域名}.{时间戳}.{密钥类型}.key`<br />
证书文件：`{域名}.{时间戳}.{密钥类型}.crt`

如果DNS记录操作失败，或者你没有传入`dns_handler`参数，AcmeN会在需要添加/删除DNS记录时停下来，你需要根据日志提示信息设置或删除DNS记录。完成后按`Enter`键继续。另外，在设置DNS记录后，通知Acme服务器验证记录前，AcmeN会尝试解析DNS记录，如果经过数次尝试后解析失败，你同样需要根据日志提示，等待DNS记录正确扩散后按`Enter`键继续运行。

## 吊销证书

### 使用证书私钥吊销证书

```python
acme.revoke_cert_by_private_key(cert_file, private_key_file, key_password='', reason=1)
```

`cert_file`：需要吊销的证书文件，必须参数。<br />
`private_key_file`： 与证书文件对应的私钥，必须参数。<br />
`key_password`：保护私钥的密码，可选参数。<br />
`reason`：[RFC5280](https://tools.ietf.org/html/rfc5280#section-5.3.1)规定的吊销原因，默认值是1，表示私钥泄露。可选参数。

使用私钥吊销证书时，`AcmeN`的`accountkey`参数可以不写。

-----

### 使用账户密钥吊销证书

```python
acme.revoke_cert_by_private_key(self, cert_file, private_key_file, key_password='', reason:=1):
```

`cert_file`：需要吊销的证书文件，必须参数。<br />
`private_key_file`： 账户私钥文件，必须参数。<br />
`key_password`：保护私钥的密码，可选参数。<br />
`reason`：[RFC5280](https://tools.ietf.org/html/rfc5280#section-5.3.1)规定的吊销原因，默认值是1，表示私钥泄露。可选参数。

在使用账户密钥吊销证书时，若Acme服务器缓存了对域名所有权的验证，则可以直接吊销。否则AcmeN会自动执行和签发证书相同的域名所有权验证流程。详情请见[RFC8555 Certificate Revocation](https://tools.ietf.org/html/rfc8555#section-7.6)

## 账户密钥轮换

以旧密钥创建AcmeN实例后，调用`key_change`方法：

```python
acme = AcmeN('old_key.key')
acme.key_change(new_key_file, password='')
```

`new_key_file`：新密钥文件<br />
`password`：保护新密钥的密码

## 注销账户

```python
acme.deactivate_account():
```

**注意：** 根据[RFC8555 Account Deactivation](https://tools.ietf.org/html/rfc8555#section-7.3.6)的规定，Acme**不提供**重新启用账户的方法。

## 关于Godaddy API的特别说明

由于[Godaddy Domain API v1](https://developer.godaddy.com/doc/endpoint/domains#/)中并未提供删除DNS记录的方法，因此在使用`GodaddyDNSHandler`删除DNS记录时，我们采用了一种折中方案。这导致当你只有一条DNS记录时，将无法删除这条记录。在AcmeN第一次要求你手动删除记录时，你可以暂时忽略它，直接按`Enter`键继续，后续删除操作将可以正常运行，等程序结束后手动删除第一条记录。或者，你可以永久保留一条TXT记录。

尽管我们在Godaddy域名管理器的网页版中发现了API v3提供了删除DNS记录的方法，但是Godaddy并没有公开发布API v3，我们也未找到相关文档，目前，AcmeN只使用已经公开发布的API接口。

## 其他用法

### 使用其他ACME服务商

默认情况下，AcmeN使用[Let's Encrypt](https://letsencrypt.org/) 提供的证书签发服务。但同时，AcmeN也内置了[buypass](https://www.buypass.com/ssl/products/acme) 的服务器地址。如需切换服务商，在`AcmeN.py`中找到：

```python
# ACME params
# production
self.__ACME_DIRECTORY = 'https://acme-v02.api.letsencrypt.org/directory'
# self.__ACME_DIRECTORY = 'https://api.buypass.com/acme/directory'

# staging
# self.__ACME_DIRECTORY = 'https://acme-staging-02.api.letsencrypt.org/directory'
# self.__ACME_DIRECTORY = 'https://api.test4.buypass.no/acme/directory'
```

注释letsencrypt的url改为使用buypass的即可。另外，AcmeN也内置了二者的测试环境，供测试使用。

但是注意，AcmeN是为使用letsencrypt的服务而设计的，由于buypass也使用Acme协议，因此AcmeN与其兼容。但目前(2020.09.23)，buypass对384位ECC证书的支持并不完善，选择使用buypass API前，请使用其测试服务器测试兼容性。

### 使用不同密钥长度的数字证书

AcmeN默认使用4096位RSA密钥，或384位ECC密钥(secp384r1)。如果你希望使用不同的密钥长度，你可以自行生成密钥，并创建对应的CSR，然后通过CSR获取证书。

也可以修改代码实现，在`AcmeN.py`中找到`get_cert_from_domain`方法：

```python
def get_cert_from_domain(self, domain, dns_name: list = None, cert_type='rsa', dns_handler: DNSHandlerBase = None):
    # ....
    if cert_type.lower() == 'rsa':
        self.__openssl('genrsa', ['-out', key_filename, '4096'])
    elif cert_type.lower() == 'ecc':
        self.__openssl('ecparam', ['-genkey', '-name', 'secp384r1', '-noout', '-out', key_filename])
    # ....
```

这是AcmeN使用Openssl生成证书私钥的逻辑，对于RSA证书，你可以将`'4096'`替换为你希望的长度，但注意不应低于2048。对于ECC证书，你可以将`'secp384r1'`替换为你希望使用的曲线。但是同样的，不恰当的曲线可能会引起程序异常，或者服务商拒绝签发证书，请在使用前进行测试。

## 查找旧版本的文档

目前我们暂未单独提供旧版本的文档，但文档与代码一同进行版本控制，你可以使用git检出之前的版本，在/docs目录下可找到对应的文档。目前文档使用[`mkdocs`](https://www.mkdocs.org)渲染，你可以使用mkdocs在/docs文件夹下构建html版本。