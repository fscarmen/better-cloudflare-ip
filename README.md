# better-cloudflare-ip-c

一个用 C 编写的 Cloudflare Anycast IP 优选与测速工具，用于在当前网络环境下从 Cloudflare IP 地址段中筛选更合适的入口 IP。

程序提供 IPv4 / IPv6、TLS / 非 TLS、单 IP 测速、缓存清理和数据更新等交互功能。首次运行会自动获取测速地址、IP 地址段和数据中心位置文件；如果网络或上游数据源不可用，也会使用内置备用数据继续启动。

## 项目说明

本项目根据 [badafans/better-cloudflare-ip](https://github.com/badafans/better-cloudflare-ip) 的 Go 语言实现思路，使用 C 语言重新迁移实现。

迁移目标是保留 Cloudflare Anycast IP 优选的核心流程，包括地址段读取、随机候选 IP 生成、RTT 测试、下载测速、数据中心识别、IPv4 / IPv6 与 TLS / 非 TLS 场景选择等能力，同时减少运行时依赖，方便在 Linux、macOS、Windows 等平台编译和分发单文件二进制程序。

本项目不是原 Go 项目的直接复制版本，而是基于其功能逻辑和使用方式进行的 C 语言重写。感谢原项目作者提供的实现思路。

## 使用声明

本项目用于网络连通性、Anycast 路由表现、RTT 与下载速度关系等技术研究和自用测试。

请勿将本项目用于违反当地法律法规、侵犯他人权益、破坏网络服务、绕过服务条款或干扰 Cloudflare 及其他网络服务正常运行的用途。使用者应自行承担使用风险和合规责任。

## 用户数据安全声明

本程序在本地运行，不要求上传用户数据到任何服务器。

程序只会根据需要下载以下公开数据，并缓存在本地数据目录中。默认数据源托管在 `github.com/fscarmen/better-cloudflare-ip`，程序通过 jsDelivr CDN 访问，便于国内网络下载：

| 文件 | 默认下载地址 | 说明 |
| --- | --- | --- |
| `url.txt` | `https://cdn.jsdelivr.net/gh/fscarmen/better-cloudflare-ip@main/url.txt` | 下载测速地址 |
| `ips-v4.txt` | `https://cdn.jsdelivr.net/gh/fscarmen/better-cloudflare-ip@main/ips-v4.txt` | IPv4 地址段 |
| `ips-v6.txt` | `https://cdn.jsdelivr.net/gh/fscarmen/better-cloudflare-ip@main/ips-v6.txt` | IPv6 地址段 |
| `locations.json` | `https://cdn.jsdelivr.net/gh/fscarmen/better-cloudflare-ip@main/locations.json` | Cloudflare 数据中心位置映射 |

默认数据目录为程序所在目录。也可以通过环境变量或参数指定：

```bash
BETTER_CF_IP_DATA_DIR=./data ./better-cloudflare-ip-c
```

```bash
./better-cloudflare-ip-c --data-dir ./data
```

Windows PowerShell 示例：

```powershell
$env:BETTER_CF_IP_DATA_DIR = ".\data"
.\better-cloudflare-ip-c-windows-amd64.exe
```

## 功能菜单

程序启动后显示交互菜单：

```text
1. IPV4 优选 (TLS)
2. IPV4 优选 (非 TLS)
3. IPV6 优选 (TLS)
4. IPV6 优选 (非 TLS)
5. 单 IP 测速 (TLS)
6. 单 IP 测速 (非 TLS)
7. 清空缓存
8. 更新数据
0. 退出
```

### IPv4 / IPv6 优选

从 `ips-v4.txt` 或 `ips-v6.txt` 中读取地址段，随机生成候选 IP，并进行 RTT 和下载速度测试。

### TLS / 非 TLS

- TLS：适合 HTTPS、443 端口等 TLS 场景。
- 非 TLS：适合普通 TCP、80 端口等非 TLS 场景。

### 单 IP 测速

手动输入一个 IP 和端口，对指定 IP 进行速度与延迟测试，适合验证已有候选 IP。

### 清空缓存

删除本地缓存的 `url.txt`、`ips-v4.txt`、`ips-v6.txt`、`locations.json`。下次运行会重新下载；下载失败时会写入内置备用数据。

### 更新数据

删除并重新获取测速地址、IP 地址段和数据中心位置文件。

## 测试流程

1. **生成候选 IP**
   - IPv4：从地址段中保留前三段，最后一段随机生成。
   - IPv6：支持 `::` 压缩形式，保留前三段，后五段随机生成。

2. **RTT 测试**
   - 并发测试多个候选 IP。
   - 通过 TCP 连接和 HTTP 请求检测连通性。
   - 读取响应头中的 Cloudflare 信息，识别数据中心。
   - 按延迟筛选较优候选 IP。

3. **下载测速**
   - 使用 `url.txt` 中的测速地址进行下载测试。
   - 按瞬时峰值速度判断是否达到用户设定带宽。
   - 输出优选 IP、实测带宽、峰值速度、RTT、数据中心和总用时。

## 用户自定义数据

可以手动编辑本地 `ips-v4.txt` 和 `ips-v6.txt` 来测试自定义地址段。

### IPv4 格式

```text
1.1.1.0/24
104.16.0.0/13
```

程序会保留前三段，随机生成最后一段。

### IPv6 格式

```text
2606:4700::/32
2400:cb00::/32
```

程序会展开并处理 IPv6 地址，保留前三段，随机生成后五段。

注意：选择“更新数据”会覆盖本地缓存文件。如果要长期使用自定义列表，请先备份。

## 下载预编译版本

在 GitHub Releases 中下载对应系统和架构的文件。

| 文件名 | 说明 |
| --- | --- |
| `better-cloudflare-ip-c-linux-amd64` | Linux x86_64 glibc |
| `better-cloudflare-ip-c-linux-arm64` | Linux ARM64 glibc |
| `better-cloudflare-ip-c-linux-amd64-musl` | Linux x86_64 musl |
| `better-cloudflare-ip-c-linux-arm64-musl` | Linux ARM64 musl |
| `better-cloudflare-ip-c-macos-amd64` | macOS Intel |
| `better-cloudflare-ip-c-macos-arm64` | macOS Apple Silicon |
| `better-cloudflare-ip-c-windows-amd64.exe` | Windows x64 |
| `better-cloudflare-ip-c-windows-386.exe` | Windows x86 |
| `better-cloudflare-ip-c-windows-arm64.exe` | Windows ARM64 |

Linux / macOS：

```bash
chmod +x better-cloudflare-ip-c-linux-amd64
./better-cloudflare-ip-c-linux-amd64
```

Windows：

```powershell
.\better-cloudflare-ip-c-windows-amd64.exe
```

## 从源码编译

### Linux

Debian / Ubuntu：

```bash
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libcurl4-openssl-dev libssl-dev

cc -O2 -pipe -std=c11 -Wall -Wextra -Wno-unused-parameter \
  better_cf_ip.c \
  -o better-cloudflare-ip-c \
  $(pkg-config --cflags --libs libcurl openssl) \
  -pthread
```

Alpine / musl：

```bash
apk add --no-cache build-base pkgconf curl-dev openssl-dev linux-headers

cc -O2 -pipe -std=c11 -Wall -Wextra -Wno-unused-parameter \
  better_cf_ip.c \
  -o better-cloudflare-ip-c \
  $(pkg-config --cflags --libs libcurl openssl) \
  -pthread
```

### macOS

```bash
brew install openssl@3

OPENSSL_PREFIX="$(brew --prefix openssl@3)"

clang -O2 -pipe -std=c11 -Wall -Wextra -Wno-unused-parameter \
  -I"$OPENSSL_PREFIX/include" \
  better_cf_ip.c \
  -o better-cloudflare-ip-c \
  "$OPENSSL_PREFIX/lib/libssl.a" \
  "$OPENSSL_PREFIX/lib/libcrypto.a" \
  -lcurl -lz \
  -framework Security \
  -framework CoreFoundation
```

### Windows

推荐使用 MSYS2 MinGW-w64。

Windows x64：

```bash
pacman -S --needed \
  mingw-w64-x86_64-gcc \
  mingw-w64-x86_64-pkgconf \
  mingw-w64-x86_64-curl \
  mingw-w64-x86_64-openssl \
  mingw-w64-x86_64-winpthreads

cc -O2 -pipe -std=c11 -Wall -Wextra -Wno-unused-parameter \
  -DWINVER=0x0601 -D_WIN32_WINNT=0x0601 -DCURL_STATICLIB \
  $(pkg-config --static --cflags libcurl openssl) \
  better_cf_ip.c \
  -o better-cloudflare-ip-c.exe \
  $(pkg-config --static --libs libcurl openssl) \
  -lws2_32 -lcrypt32 -lbcrypt -lwinpthread \
  -static -Wl,-s
```

Windows x86 将依赖包名中的 `x86_64` 换成 `i686`。

## GitHub Actions 构建

仓库内置 GitHub Actions 工作流，可自动构建多个平台产物。

- 手动运行 workflow 会直接编译全部平台，不需要选择 target。
- 推送 tag，例如 `v2.1.4`，会创建 Release 并上传所有构建产物。
- 构建流程不依赖 Makefile。

## 常见问题

### Windows 首次运行提示下载失败怎么办？

程序会自动使用内置备用数据继续启动。如果仍然无法进入菜单，请确认当前目录有写入权限，或使用 `--data-dir` 指定可写目录。

### macOS 提示 `Library not loaded` 怎么办？

请重新下载最新构建产物。发布版不应依赖 Homebrew 的 curl 动态库路径。

### 为什么速度结果每次不一样？

Cloudflare Anycast 路由会随运营商、地区、时间、网络拥塞和本机网络状态变化。建议多测试几轮，并选择稳定性更好的结果。

### 为什么有些 IP 延迟低但速度一般？

低 RTT 不一定等于高下载带宽。程序会先筛选延迟，再进行下载测速，最终结果以实际测速为准。

## 引用声明

- Cloudflare IP 地址段可参考 Cloudflare 官方 IP Ranges。
- 程序默认测速文件使用 Cloudflare speed test 地址。
- 数据中心位置文件来源于公开的 Cloudflare 位置数据整理。

## 许可证

请以仓库中的许可证文件为准。
