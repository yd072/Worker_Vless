# 项目
![eom](./eom.png)
这是在[cmliu edgetunnel](https://github.com/cmliu/edgetunnel)基础上进行修改，优化响应快稳定连接。

内置简易的 Clash/Sing-box/Loon 配置生成无需转换，如（let subConverter = '';）未配订阅转换将使用内置配置生成
## ⚠️注意
使用过旧版的，KV中存在多个配置，请移除多余的配置只保留 `settinggs.txt` ，以免增加KV的消耗。

## 邦定KV
KV变量名：KV

添加在线设置：PROXYIP、SOCKS5、SUB 、SUBAPI、SUBCONFIG、NAT64、HTTP

# 变量
| 常用变量 | 示例 |
|--------|---------|
| UUID  | fca6e4ec-c882-4876-992c-cf354fd3f2ae |
| PROXYIP | bpb.radically.pro/1.2.3.4 |
| SOCKS5 | user:password@1.2.3.4 :2222 |
| HTTP | user:password@1.2.3.4 :2222 |
| ADD | icook.tw:8443#优选域名/1.2.3.4 :8443#优选IP |
| ADDAPI | https://raw.githubusercontent.com/yd072/youxuanyuming/refs/heads/main/ip.txt |
| ADDNOTLS | icook.tw:80#优选域名/1.2.3.4 :80#优选IP |
| ADDNOTLSAPI | https://raw.githubusercontent.com/yd072/youxuanyuming/refs/heads/main/ip.txt |
| NAT64 | dns64.example.com或2001:67c:2960:6464::/96 |
| SUB | 自定义 |
| SUBAPI | 自定义 |
| ····· | ····· |

# 感谢
[cmliu](https://github.com/cmliu/edgetunnel)


