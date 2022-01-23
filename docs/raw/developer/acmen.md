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
def register_account(contact: typing.List[str] = None, eab_key_identifier: str = None, eab_mac_key: str = None) -> str
```

`contact`：此账户的联系方式列表，例如`['mailto:admin@example.com', 'mailto:admin2@example.com']`，可选。<br>
`eab_key_identifier`：外部密钥绑定(externalKeyBinding)使用的key identifier。<br>
`eab_mac_key`：外部密钥绑定(externalKeyBinding)使用的mac key。

此方法返回账户的URL。

### get_cert_by_domain

通过域名获取证书。

```python
get_cert_by_domain(common_name: str, subject_alternative_name: typing.List[str],
                   challenge_handler: ChallengeHandlerBase,
                   key_generation_method: KeyGenerationMethod = KeyGenerationMethod.CryptographyLib,
                   key_type: KeyType = KeyType.RSA3072, output_name: str = '') -> (bytes, bytes):
```

`common_name`：证书的commonName字段，通常是主域名。<br>
`subject_alternative_name`：证书的subjectAlternativeName字段，可选的附加域名，不需要此扩展时可传入空列表`[]`。<br>
`challenge_handler`：完成认证过程使用的Challenge Handler。<br>
`key_generation_method`：生成私钥的方法，默认使用[cryptography](https://cryptography.io)库生成，改为KeyGenerationMethod.OpenSSLCLI可使用openssl 命令行工具生成。<br>
`key_type`：密钥类型，KeyType枚举的成员，默认是RSA3072。其中ECC384使用的是secp384r1曲线，ECC256使用的是secp256r1曲线。<br>
`output_name`：输出的证书文件绝对或相对路径，当参数是空字符串`''`时，输出文件名是`{commonName}.{timestamp}.key`和`{commonName}.{timestamp}.crt`，当参数是`None`时，证书不会被写入文件。

此方法返回(私钥,证书)二元组，均是PEM字节序列(bytes)。

### get_cert_by_csr

通过CSR文件获取证书。

```python
def get_cert_by_csr(csr: typing.Union[str, bytes], challenge_handler: ChallengeHandlerBase, output_name: str = None) -> bytes:
```

`csr`：CSR文件的路径或文件内容，当传入文件内容时既可以是str也可以是bytes。<br>
`challenge_handler`：完成认证过程使用的Challenge Handler。<br>
`output_name`：输出的证书文件绝对或相对路径，当参数是空字符串`''`时，输出文件名是`{commonName}.{timestamp}.crt`，当参数是`None`时，证书不会被写入文件。

此方法返回服务器所签发的证书的bytes字节序列。

### process_order

创建一个证书订单并完成其中的认证。

```python
def process_order(domains: typing.Set[str], challenge_handler: ChallengeHandlerBase) -> AcmeResponse
```

`domains`：订单所包含的域名集合(Set)。<br>
`challenge_handler`：完成认证过程使用的Challenge Handler。

此方法返回完成订单后从订单URL获取到的订单对象。

### key_change

更换ACME账户的密钥。

```python
key_change(self, new_key_file, password: str = '') -> None
```

`new_key_file`：新的账户密钥。<br>
`password`：保护新密钥的密码。

此方法完成后，会更换AcmeN的签名密钥，后续基于此AcmeN对象的操作均由新密钥签名。

### deactivate_account

注销此密钥所对应的账户。

```python
def deactivate_account():
```

### query_kid

获取密钥文件对应的Account URL。通过调用下层AcmeNetIO.query_kid实现。