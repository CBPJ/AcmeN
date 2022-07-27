# Challenge Handling

ChallengeHandlers的结构如下：

![ChallengeHandler's Structure](ChallengeHandler.drawio.svg)

ChanllengeHandlerBase是所有Handler的基类，定义了`pre_handle`、`handle`、`post_handle`三个抽象方法。pre_handle保留备用。handle()
用于设置网络资源以满足ACME服务器的"挑战"要求，post_handle用于完成认证后解除这些网络资源。

## ChallengeHandlerBase

### get_handler_type 抽象方法

获取此Handler可为指定的标识符处理何种类型的"挑战"，与[RFC8555 section-9.7.8](https://datatracker.ietf.org/doc/html/rfc8555#section-9.7.8)
对应，通常是http-01、dns-01、tls-alpn-01。

```python
def get_handler_type(identifier) -> str
```

`identifier`: ACME Authorization Object中的identifier。<br>
返回可为此标识符处理何种挑战。

### pre_handle 抽象方法

保留备用，所有子类应当实现此方法但不进行任何操作。

### handle 抽象方法

handle方法用于设置"挑战"所需的网络资源。

```python
def handle(url, identifier, token, key_thumbprint) -> bool
```

`url`：Challenge的URL，通常可唯一确定一个Challenge。<br>
`identifier`：identifier的value。通常是等待认证的域名。<br>
`token`：服务器为此Challenge指定的token，用来计算key authorization。见[RFC8555 section-8.1](https://datatracker.ietf.org/doc/html/rfc8555#section-8.1) 。<br>
`key_thumbprint`：账户密钥的指纹，与token一起，用于计算key authorization。

handle方法返回True或False，指示"挑战"所需的网络资源是否被成功设置。

### post_handle 抽象方法

post_handle方法用于撤销为满足挑战所设置的网络资源。

```python
def post_handle(url, identifier, token, key_thumbprint, succeed) -> bool
```

`succeed`：之前的handle方法是否成功。<br>
其余参数与handle相同。

post_handle方法应返回True或False，指示资源是否被成功撤销。

## HandlerSet

ChallengeHandler集合，可为不同的域名分别设置Handler。

```python
s = HandlerSet(default_handler=None)
```

`default_handler`：通过域名寻找Handler时，若没有与指定域名对应的Handler，则返回default_handler，当default_handler时None时，查找不存在将引发KeyError。

### default_handler属性

设置或获取default_handler。

### 添加、查找、删除Handler

HandlerSet实现了 `__setitem__`、`__getitem__`和`__delitem__`。可使用`handler_set[domain] = handler`的风格设置、查找和删除Handler。

## Dns01Handler

用于处理`dns-01`挑战。

Dns01Handler是一个抽象基类，包含set_record和del_record两个抽象方法。handle方法会调用set_record方法，post_handle方法调用del_record方法。<br>
`handle`方法将待处理的域名(id_value)分割成子域名和一级域名，并在子域名前加上`_acme-challenge.`前缀，计算满足挑战所需的TXT记录的值，传递给子类的set_record方法。`post_handle`方法进行同样的操作，并传递给子类的del_record方法。

考虑到有些DNS服务商使用唯一ID来标识一个DNS记录，大部分可通过此ID来删除对应的记录。Dns01Handler添加了record_id机制来简化此过程：<br>
set_record方法可返回所设置的DNS记录的ID，此返回值会原样传递给del_record方法的record_id参数。<br>
若set_record方法的返回值的真值判断为真，即`bool(set_record(...)) == True`，则此操作被认为是成功的，handle方法将返回True。同时在一个字典中建立从挑战url到此返回值的映射关系。post_handle方法被调用时，从此字典中弹出(pop)此返回值，作为record_id参数传递给del_record方法。若字典中不存在与之对应的返回值，record_id将传入None。

### txt_value 静态方法

计算TXT记录的值。`{token}.{key_thumbprint}`计算sha256哈希值，再用base64_url编码，去掉末尾填充的等号`=`。

### check_txt_record 方法

向DNS服务器查询指定域名的TXT记录，并检查DNS服务器返回的结果与预期值是否相符。目前此方法使用['8.8.8.8', '1.1.1.1', '9.9.9.9']作为DNS服务器。

```python
def check_txt_record(self, domain: str, value: str) -> bool
```

`domain`：要检查TXT记录的的域名。<br>
`value`：预期的TXT记录值。

check_txt_record方法返回DNS服务器记录的TXT值与预期值是否相符。

### set_record 抽象方法

设置DNS TXT记录。

```python
def set_record(subdomain, fld, value)
```

`subdomain`：需要设置记录的子域名，已附加_acme-challenge.前缀。<br>
`fld`：需要设置记录的一级域名。<br>
`value`：需要设置的TXT记录值。

例如，需要认证的域名是abc.def.example.co.uk，则subdomain是abc.def，fld是example.co.uk。

当设置成功时，若DNS服务商提供记录ID，应返回记录ID，若不提供则返回True。当设置失败时应返回False。

### del_record 抽象方法

删除DNS TXT记录

```python
def del_record(subdomain, fld, value, record_id)
```

其余参数与set_record相同<br>
`record_id`：set_record返回的记录ID，注意对一个挑战，此参数只会被传递一次。例如<br>

```python
handler.handle(url, 'examplr.org', token, thumbprint)
handler.post_handle(url, 'examplr.org', token, thumbprint, True)
handler.post_handle(url, 'examplr.org', token, thumbprint, True)
```

则第二次调用post_handle进而调用del_record时，此次调用的record_id参数将为None。

删除成功返回True，失败返回False。

## CloudflareDnsHandler

处理托管在Cloudflare上的域名的dns-01挑战。

```python
c = CloudflareDnsHandler(api_token)
```

`api_token`：Cloudflare API-Token，我们已删除对API-Key的支持。

API-Token需要Zone.Zone.Read和Zone.DNS.Edit权限。前者用于通过域名获取Zone ID，后者用于编辑DNS记录。

**注意：** 若在调用del_record时提供了record_id，则del_record方法将直接删除此ID对应的记录，不检查value是否与DNS记录值相同。

## GodaddyDnsHandler

处理托管在Godaddy上的域名的dns-01挑战。

```python
g = GodaddyDnsHandler(api_key, api_secret)
```

`api_key`：API key中的"key"字段。<br>
`api_secret`：API key中的"secret"字段

## AliyunDnsHandler

处理托管在Aliyun上的域名的dns-01挑战。

```python
g = AliyunDnsHandler(access_key_id, access_key_secret)
```

`access_key_id`：Aliyun提供的AccessKey ID。<br>
`access_key_secret`：Aliyun提供的AccessKey Secret。

## DnspodDnsHandler

处理托管在腾讯云Dnspod上的域名的dns-01挑战。

```python
g = DnspodDnsHandler(secret_id, secret_key)
```

`secret_id`: 腾讯云提供的SecretId<br>
`secret_key`: 腾讯云提供的SecretKey

## ManualDnsHandler

用于手动添加和删除DNS记录。

**注意：** 此方法包含交互式操作，无法用于自动化脚本。

此方法会显示需要设置的TXT记录，设置完成后按ENTER，程序会自动等待DNS记录扩散。挑战完成后，按提示删除记录即可。

## Http01Handler

用于处理`http-01`挑战。

`Http01Handler`是一个抽象基类。包含`set_resource`和`del_resource`两个方法，分别用于设置和删除认证所需的HTTP资源。

### set_resource

```python
def set_resource(identifier, filename: str, content: bytes) -> bool
```

`identifier`：要进行认证的标识符。<br>
`filename`：需要设置的文件名。<br>
`content`：需要设置的文件内容

根据RFC8555，设置的文件路径始终为/.well-known/acme-challenge/<filename>。

### del_resource

```python
def del_resource(identifier, filename: str, content: bytes) -> bool
```

`identifier`：要进行认证的标识符。<br>
`filename`：需要设置的文件名。<br>
`content`：需要设置的文件内容

在实现此方法时，可以校验文件内容。


## ManualHttpHandler

用于手动处理`http-01`挑战。

**注意：** 此方法包含交互式操作，无法用于自动化脚本。

此方法会显示需要设置的文件名称、路径和内容，设置完成后按ENTER键。认证完成后按提示删除文件即可。

## FileHttpHandler

在Web Server根目录中创建http-01挑战所需的文件，自动完成http-01挑战。

```python
f = FileHttpHandler(base_dir)
```

`base_dir`：Web Server根目录。
