# ChangeLog

## v0.2.0

- 添加CloudflareDNSHandler
- 将读取账户密钥时机从创建AcmeN实例时推迟到需要使用时
- 向DNSHandler添加了session属性
- AcmeN退出时将关闭session会话
- 从AcmeN中移除了LogHandler

## v0.3.0

**包含向后不兼容的更改**
- 添加AliyunDNSHandler
- 为DNSHandler添加了request_id处理机制，对于使用唯一ID标识解析记录的服务商，删除流程将更加快速
- 更新文档
