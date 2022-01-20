# AcmeNetIO

AcmeNetIO 组件负责签名请求以及与ACME服务器交互。另外，在轮换密钥时，AcmeNetIO也用于对InnerJWS签名。<br>
一个AcmeNetIO与一个私钥相对应，并使用此私钥对请求进行签名。<br>

## 实例化

```python
n = AcmeNetIO(keyfile, password=None, ca=SupportedCA.LETSENCRYPT, session=None)
```

`keyfile`：用于签名的密钥文件。<br>
`password`：保护密钥文件的密码，可选。<br>
`ca`：使用的CA服务器，可以是SupportedCA枚举的一个成员，也可以是ACME服务的Directory URL，默认使用Let's Encrypt服务，可选。<br>
`session`：共享的requests.Session对于，AcmeNetIO可以与外部代码共享一个Session，若没有提供共享Session，会自动创建一个新的Session，可选。

在实例化时，init方法创建session，并读取密钥文件。若在实例化时传入session参数，则不会更新此session的header。

## 请求类型判断与URL转换

上层代码通过向send_request或sign_request传递一个AcmeAction枚举来传入请求类型。sign_request通过此枚举来构建适当的protected header。<br>
除VariableUrlAction外，AcmeAction中每个成员对应的请求url都可以从directory中找到，例如NewAccount、NewOrder。对于这类请求，只需传入action参数即可。<br>
一些请求，例如获取订单信息，其URL包含在服务器对上一个请求的响应中。上层代码负责解析此类URL，并将action设为VariableUrlAction，通过url传入实际要请求的地址。<br>
当action被设为VariableUrlAction时，protected header将使用kid而不是jwk参数。

最长调用栈为：<br>
上层代码 -> send_request() -> sign_request() -> \_get\_url() -> directory

## 属性

### directory

获取指定CA的ACME Directory。由于CA参数在AcmeNetIO的整个生命周期中不会改变，因此仅在第一次使用directory的值时向ACME服务器查询数据。后续将使用第一次查询的结果。

### pubkey

获取json格式表示的密钥公钥，可用于jwk字段。

### key_thumbprint

获取密钥的SHA256指纹。

## 方法

### sign_request

```python
s = AcmeNetIO(...).sign_request(payload, action, url=None)
```

`payload`：jws中要进行签名的payload，可以是字典(dict)或字符串(str)。当且仅当对POST-as-GET请求进行签名时，payload是一个空字符串。<br>
`action`：要发送的ACME请求类型，AcmeNetIO据此构建jws的protected header。必须是AcmeAction枚举的成员。<br>
`url`：自定义URL，当action是VariableUrlAction时，通过此参数指定目的URL。

对传入的payload进行签名，此方法最常用于签名keyChange请求的InnerJWS或用于调试。其他请求可直接使用send_request。

### send_request

```python
r = AcmeNetIO(...).send_request(pyload, action, url=None, deserialize_response=True)
```

`deserialize_response`：是否将服务器响应转换为json对象(通常是字典)，在大部分情况下，ACME服务器响应都是json格式，只需在获取证书时将此参数设置为False。<br>
参数与sign_request相同。向ACME服务器发送action指定的请求，并通过命名元组`AcmeResponse`返回`code`(状态码)、`headers`(HTTP响应头，其中Replay-Nonce头已被移除)、`content`(json反序列化后的响应体，通常是字典(dict))<br>
send_request方法会截留Replay-Nonce头并将其加入缓存。获取和添加Replay-Nonce对高层代码是透明的。<br>
当HTTP状态码不在200-399之间时，会引发RuntimeError异常。

### query_kid

获取密钥文件对应的Account URL。当账户不存在时，会由send_request引发RuntimeError。

### \_get\_nonce

获取一个Replay-Nonce，若没有缓存的Nonce，则向ACME服务器请求新的Nonce。

### \_get\_url

获取与AcmeAction对应的请求URL。
