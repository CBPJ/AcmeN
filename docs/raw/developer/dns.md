# DNS

## 创建DNS服务商API客户端

要创建API客户端你需要继承`DnsHandlers.py`中的`DNSHandlerBase`，并实现`set_record`和`del_record`两个抽象方法。

### set_record方法

```python
def set_record(self, dns_domain, value)
```

`dns_domain`：要设置TXT记录的DNS域名，例如`_acme-challenge.foo.example.com`。<br />
`value`：TXT记录的值。

返回：(设置结果, 记录ID)<br />
若DNS服务商不使用唯一ID标志一条解析记录，记录ID返回`None`

`DNSHandlerBase`中提供了分离域名和子域名的方法`split_domain()`，split_domain将返回`(subdomain, domain)`二元组。例如：

```python
result = self.split_domain(_acme-challenge.foo.example.com)
# result == ('_acme-challenge.foo', 'example.com')
```

### del_record方法

```python
def del_record(self, dns_domain, value, record_id)
```

`dns_domain`：要删除TXT记录的DNS域名，例如`_acme-challenge.foo.example.com`。<br />
`value`：TXT记录的值。<br />
`record_id`：记录ID，`set_record()`方法返回的值。

`del_record`方法需要按以下规则删除记录：

- 若record_id不是None，直接删除此ID对应的记录，并返回结果。
- 若未找到名称与dns_domain匹配的记录，返回False。
- 若记录中只存在名称与dns_domain匹配且值与value匹配的记录，返回删除结果。
- 若记录中只存在名称与dns_domain匹配但值与value不匹配的记录，返回False。
- 若记录中既存在名称与dns_domain匹配且值与value匹配的记录，又存在名称匹配但值不匹配的记录，返回匹配记录的删除结果。

### session属性

自v0.2.0起，DNSHandlerBase中添加了session属性，session属性是requests.Session的实例。

session的创建与关闭机制集成在DNSHandlerBase中，若外部没有传入session，DNSHandler会在第一次使用session时创建新的实例，并且在被删除时将其关闭。若session是外部传入的，DNSHandler不会关闭这个会话。

若在传入session时，DNSHandler已经自行创建了session实例，则会先将自行创建的会话关闭，然后应用外部传入的会话。**注意：** 这个操作不是线程安全的，若一个线程正在使用自行创建的session时，另一个线程传入session，会立即调用`session.close()`方法，当前正在进行的HTTP请求可能会失败。

在默认实现中，AcmeN会在调用`self.__complete_challenge()`时设置DNSHandler的session属性，AcmeN与DNSHandler将共用同一个会话，在AcmeN退出时，会关闭这个会话。
