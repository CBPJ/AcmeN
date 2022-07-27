# ChangeLog

## v0.4.2

- 添加代理设置
- 添加http-01挑战处理器
- 添加HandlerSet用于处理不同域名的挑战
- 添加国际化域名(IDN)支持
- 添加DnsPod API
- 添加Aliyun API

## v0.4.1

- 迁移GodaddyDnsHandler
- 修复循环引用错误

## v0.4.0

**重构代码，包含(很多很多)向后不兼容的更改**
- 如果你以前曾使用过AcmeN，请重新阅读文档并重写相关调用。
- **在v1.0.0发布以前，很可能还会有其他不兼容更改**

## v0.3.0

**包含向后不兼容的更改**
- 添加AliyunDNSHandler
- 为DNSHandler添加了request_id处理机制，对于使用唯一ID标识解析记录的服务商，删除流程将更加快速
- 更新文档

## v0.2.0

- 添加CloudflareDNSHandler
- 将读取账户密钥时机从创建AcmeN实例时推迟到需要使用时
- 向DNSHandler添加了session属性
- AcmeN退出时将关闭session会话
- 从AcmeN中移除了LogHandler