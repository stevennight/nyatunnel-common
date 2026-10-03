# NyaTunnel Common

NyaTunnel 服务端与客户端共用的 Go 库，保证隧道协议只有一份实现。

```
go get github.com/stevennight/nyatunnel-common
```

| 包 | 内容 |
|---|---|
| `tunnelproto` | 设备连接协议：WebSocket 握手（Ed25519 挑战签名，绑定服务器域名与一次性 nonce）、yamux 多路复用、控制流消息与配置快照、数据流流头与应答字节、UDP 数据报分帧。解析函数均有模糊测试 |
| `deeplink` | `nyatunnel://` 深链的生成与严格解析、一次性注册码（Crockford Base32）的生成与规范化 |

协议文档：[nyatunnel-server/docs/协议.md](https://github.com/stevennight/nyatunnel-server/blob/main/docs/协议.md)。改协议时先改文档和本库，再同步服务端与客户端。

## 开发

```powershell
go test ./...
go test -run '^$' -fuzz FuzzReadStreamHeader -fuzztime 30s ./tunnelproto
```

在 NyaTunnel 工作区（`D:\Projects\Self\NyaTunnel`）里，根目录的 `go.work` 用 `replace` 把服务端和客户端指向本地的本仓库，改动无需发布即可联调。发布后两边的 `go.mod` 用 `go get github.com/stevennight/nyatunnel-common@<tag 或 commit>` 更新。

## 版本

`VERSION` 是唯一来源；推送 `vX.Y.Z` 标签即为发布（CI 校验标签与 `VERSION` 一致）。同一主版本内协议只增不改。
