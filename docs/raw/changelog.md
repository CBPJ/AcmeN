# ChangeLog

## v0.2.0

- 添加CloudflareDNSHandler
- 将读取账户密钥时机从创建AcmeN实例时推迟到需要使用时
- 向DNSHandler添加了session属性
- AcmeN退出时将关闭session会话
- 从AcmeN中移除了LogHandler

