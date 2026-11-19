# rdp-go

[English](README.md)

纯Go编写的客户端侧RDP协议库，用于从 Windows、macOS、Linux 客户端连接 Windows RDP 服务端（Windows 10/11 与 Windows Server）。

## 功能

- **连接**：TLS（可选证书指纹固定）、NLA/CredSSP（NTLMv2、Kerberos）、RD Gateway、KDCProxy、服务端重定向、自动重连、UDP 侧带传输。
- **图形**：绘图命令、位图缓存、Surface 命令；NSCodec、RemoteFX、Progressive、planar/RLE；纯 Go H.264 解码；fast-path 输出与 MPPC 压缩。
- **输入与剪贴板**：扫描码/Unicode/文本输入；cliprdr 文本、HTML、图片与文件传输；Windows OLE 拖放、延迟渲染与虚拟文件。
- **设备与音频**：rdpdr 驱动器、打印机、智能卡协议切片（后端由应用提供）；rdpsnd PCM/ADPCM 播放、audin PCM 采集。
- **RemoteApp 与显示**：RAIL 窗口命令、显示器布局与动态分辨率调整、受管动态通道。
- **自带客户端**：`rdpnative`（Windows 原生窗口，含 IME/TSF）与 `rdpview`（浏览器客户端）。库只负责解码事件，渲染由你的代码或自带客户端完成。

## 安装

```sh
go get github.com/hq0101/rdp-go@v0.2.0
```

## 快速开始

```go
package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/hq0101/rdp-go"
	"github.com/hq0101/rdp-go/gcc"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	s, err := rdp.DialSession(ctx, os.Getenv("RDPGO_ADDR"), rdp.Credentials{
		Username: os.Getenv("RDPGO_USER"),
		Domain:   os.Getenv("RDPGO_DOMAIN"),
		Password: os.Getenv("RDPGO_PASSWORD"),
	}, rdp.Options{
		CertificateSHA256: os.Getenv("RDPGO_CERT_SHA256"), // 可选，经可信渠道核对的指纹
	}, gcc.ClientSettings{Width: 1280, Height: 720})
	if err != nil {
		log.Fatal(err)
	}
	defer s.Close() // 先发送 MCS Disconnect Provider Ultimatum，再关闭连接

	for {
		e, err := s.ReadEvent(ctx)
		if err != nil {
			log.Fatal(err)
		}
		switch e.Kind {
		case rdp.EventLogonInfo:
			log.Println("logon:", e.Logon.Logon)
		case rdp.EventData:
			// 通道数据在 e.Payload
		case rdp.EventSurfaceCommands, rdp.EventLargePointer:
			// 交给你的渲染器的图形更新
		}
	}
}
```

更底层入口：`DialTLS`、`DialNLA`，之后用 `OpenChannels` 手动处理 MCS/PDU。网络故障后可用 `Session.Reconnect` 恢复，服务端确认原会话 ID 后才恢复。

## 命令与示例

| 命令 | 用途 |
| --- | --- |
| `cmd/rdpcheck` | 连接/NLA/会话诊断 |
| `cmd/rdpshot` | 桌面截图 |
| `cmd/rdpview` | 浏览器客户端 |
| `cmd/rdpnative` | Windows 原生查看器 |
| `cmd/rdpaudiocheck` / `cmd/rdpincheck` | 音频输出 / 输入检查 |
| `cmd/rdpudpcheck` | UDP 侧带检查 |

```sh
RDPGO_PASSWORD='...' go run ./cmd/rdpview -addr server.example:3389 -user alice -password-env RDPGO_PASSWORD
```

`examples/` 提供可运行示例（`session`、`tls`、`nla`、`reconnect`、`resize`、`monitors`）。需要凭据的示例从文件头注明的环境变量读取；`tls` 仅建立传输层，无需凭据。

## 安全与限制

- 凭据不做持久化；建议使用证书指纹固定或私有 CA 池。Gateway 重定向策略由应用在建立隧道前执行；本地资源只通过你配置的后端共享。
- 打印机 spooler/XPS 与智能卡 winscard/NDR 后端属于应用职责；库实现协议切片。
- Windows 上的原生系统集成最完整；macOS/Linux 原生宿主集成尚不完整。真机证据以 Windows 10 为主，Windows 11/arm64 及部分 RDS/AD/Gateway 部署仍待验证。

## 贡献

欢迎提 Issue 和 PR！无论是缺陷报告、协议功能补充、性能改进还是文档完善，都非常感谢，一起把 rdp-go 做得更好。

## 许可证

Apache-2.0，见 [LICENSE](LICENSE)。