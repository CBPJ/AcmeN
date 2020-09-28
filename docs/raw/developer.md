# Developer

## 创建DNS服务商API客户端

要创建API客户端你需要继承`DnsHandlers.py`中的`DNSHandlerBase`，并实现`set_record`和`del_record`两个抽象方法。

### set_record方法

```python
def set_record(self, dns_domain, value)
```

`dns_domain`：要设置TXT记录的DNS域名，例如`_acme-challenge.foo.example.com`。

`value`：TXT记录的值。

有时候你可能需要从域名中分离出First level domain以调用DNS服务商的API，`DNSHandlerBase`中提供了此方法，你可以在你实现的子类中调用：

```python
self.get_first_level_domain(dns_domain)
```

对于上述情况，这将返回：`example.com`

`DNSHandlerBase`中也提供了分离子域名的方法：

```python
self.get_subdomain(dns_doamin)
```

对于上述情况这将返回：`_acme-challenge.foo`

### del_record方法

```python
def del_record(self, dns_domain, value)
```

`dns_domain`：要删除TXT记录的DNS域名，例如`_acme-challenge.foo.example.com`。

`value`：TXT记录的值。

在大多数DNS服务商的API中，删除一条记录并不需要提供这条记录的值。但是在默认DNSHandler实现中，会先从DNS服务商获取`dns_doamin`对应的记录值，并于`value`进行比较，相符时才会进行删除操作。我们建议你也使用类似的做法，以尽可能避免错误的DNS操作。

### session属性

自v0.2.0起，DNSHandlerBase中添加了session属性，session属性是requests.Session的实例。

session的创建与关闭机制集成在DNSHandlerBase中，若外部没有传入session，DNSHandler会在第一次使用session时创建新的实例，并且在被删除时将其关闭。若session是外部传入的，DNSHandler不会关闭这个会话。

若在传入session时，DNSHandler已经自行创建了session实例，则会先将自行创建的会话关闭，然后应用外部传入的会话。**注意：**这个操作不是线程安全的，若一个线程正在使用自行创建的session时，另一个线程传入session，会立即调用`session.close()`方法，当前正在进行的HTTP请求可能会失败。

在默认实现中，AcmeN会在调用`self.__complete_challenge()`时设置DNSHandler的session属性，AcmeN与DNSHandler将共用同一个会话，在AcmeN退出时，会关闭这个会话。

