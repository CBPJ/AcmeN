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
