# AcmeN

AcmeN封装了常见的ACME操作的时序控制。通过调用AcmeNetIO，完成常见的ACME操作。

## 实例化

```python
acmen = AcmeN(key_file, key_passphrase='', ca=SupportedCA.LETSENCRYPT)
```

`key_file`：执行签名时将使用的私钥文件。<br>
`key_passphrase`：保护私钥文件的短语，若私钥未加密可留空。<br>
`ca`：要使用的ACME服务器，可以是SupportedCA枚举的一个成员，也可以是其他有效ACME服务器的directory目录地址。

## 方法

### register_account

使用实例化时指定的私钥注册ACME账户。

```python
def register_account(contact: typing.List[str] = None) -> str
```

`contact`：此账户的联系方式列表，例如`['mailto:admin@example.com', 'mailto:admin2@example.com']`，可选。

此方法返回账户的URL。

### get_cert_by_csr

通过CSR文件获取证书。

```python
def get_cert_by_csr(csr: typing.Union[str, bytes], challenge_handler: ChallengeHandlerBase, output_name: str = None):
```

`csr`：CSR文件的路径或文件内容，当传入文件内容时既可以是str也可以是bytes。<br>
`challenge_handler`：完成认证过程使用的Challenge Handler。<br>
`output_name`：输出的证书文件绝对或相对路径，未提供此参数时，输出文件名是"{commonName}.{timestamp}.crt"

此方法返回服务器所返回的证书内容。

### process_order

创建一个证书订单并完成其中的认证。

```python
def process_order(domains: typing.Set[str], challenge_handler: ChallengeHandlerBase) -> AcmeResponse
```

`domains`：订单所包含的域名集合(Set)。<br>
`challenge_handler`：完成认证过程使用的Challenge Handler。

此方法返回完成订单后从订单URL获取到的订单对象。