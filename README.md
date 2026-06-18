# Subscription Certificate Converter / 订阅证书指纹转换器

HTTPS subscription converter for replacing deprecated insecure flags with certificate pinning.

HTTPS 订阅转换器，用于把已废弃的不安全证书验证参数转换为证书固定参数。

## Supported Link Types / 支持的链接类型

- `hysteria2://` / `hy2://` -> `pinSHA256`
- `vless://` -> `pcs`
- `trojan://` -> `pcs`

The service fetches a subscription from `/?url=<subscription_url>`, converts supported node links, and returns a base64 encoded subscription.

服务会从 `/?url=<subscription_url>` 拉取订阅，转换支持的节点链接，然后返回 base64 编码后的订阅内容。

## Why This Exists / 项目背景

v2rayN discussion [#9460](https://github.com/2dust/v2rayN/discussions/9460) explains that recent Xray-core versions removed the `allowInsecure` TLS option and migrated the safe replacement to certificate pinning with `pinnedPeerCertSha256`. Subscriptions that still contain `insecure` or `allowInsecure` can make newer clients fail to start or import unusable nodes.

v2rayN 的相关讨论 [#9460](https://github.com/2dust/v2rayN/discussions/9460) 说明：新版 Xray-core 已移除 TLS 里的 `allowInsecure` 选项，长期替代方案是使用证书固定，也就是 `pinnedPeerCertSha256`。如果订阅里的节点仍然带有 `insecure` 或 `allowInsecure`，新版客户端可能会启动失败，或者导入后节点不可用。

This converter is a small helper for that transition: it fetches a subscription, probes each supported node certificate, removes the insecure flags, and writes the certificate pin back into the share link format expected by clients.

这个转换器用于处理这类订阅：它会拉取订阅内容，探测支持节点的证书指纹，移除不安全参数，并把证书指纹写回客户端可识别的分享链接参数中。

## Public Instance / 公共实例

A public instance is available and you are welcome to use it.

你可以直接使用下面的公共实例。

```text
https://convert.192172.xyz:8443/?url=<url-encoded-subscription-url>
```

You can also open the web page and paste your subscription URL.

也可以打开网页，把订阅地址粘贴进去生成转换链接。

```text
https://convert.192172.xyz:8443/
```

Example:

示例：

```text
https://convert.192172.xyz:8443/?url=https%3A%2F%2Fexample.com%2Fsubscribe%3Ftoken%3D...
```

Please URL-encode the subscription URL before placing it in the `url` query parameter. Do not share subscription URLs or tokens publicly.

请先对订阅地址做 URL 编码，再放入 `url` 查询参数。不要公开分享订阅地址或 token。

## Security / 安全设计

This project is designed for public deployment with SSRF protections.

本项目按公开部署场景设计，并内置 SSRF 防护。

- Allows only `http` and `https` subscription URLs.
- 只允许 `http` 和 `https` 订阅地址。
- Allows subscription fetches only on ports `80` and `443`.
- 订阅拉取只允许访问 `80` 和 `443` 端口。
- Rejects localhost, private, link-local, reserved, and non-global IP targets after DNS resolution.
- DNS 解析后会拒绝 localhost、私有地址、链路本地地址、保留地址和非公网 IP。
- Revalidates every redirect target.
- 每一次重定向都会重新校验目标地址。
- Applies the same public-IP checks before TCP/QUIC certificate probing.
- TCP/QUIC 证书探测前也会执行同样的公网 IP 校验。
- Limits response size, redirect count, line count, certificate targets, request rate, and concurrency.
- 限制响应大小、重定向次数、订阅行数、证书探测目标数量、请求频率和并发数。

This public version does not write request logs and the web page does not use browser local storage.

公开版本不会写请求日志，网页也不会使用浏览器本地存储。

## Local Deployment / 本地部署

If your subscription uses DNS-based geo-routing (e.g. Alibaba Cloud GTM), running the converter locally ensures DNS resolution matches your client.

如果你的订阅使用了基于地理的 DNS 调度（如阿里云 GTM），本地部署可以确保 DNS 解析结果与客户端一致。

```bash
git clone https://github.com/iloveandyegg/subscription-cert-converter.git
cd subscription-cert-converter
pip install -r requirements.txt
CONVERTER_SSL=0 python3 converter.py
```

This starts a plain HTTP server on port 8080 by default. Use it as:

服务默认在 8080 端口以 HTTP 模式启动。使用方式：

```text
http://localhost:8080/?url=<url-encoded-subscription-url>
```

Environment variables:

环境变量：

| Variable | Default | Description |
|---|---|---|
| `CONVERTER_SSL` | `1` | Set to `0` to disable TLS (plain HTTP) |
| `CONVERTER_HOST` | `0.0.0.0` | Listen address |
| `CONVERTER_PORT` | `8443` / `8080` | Port (8443 with SSL, 8080 without) |
| `CONVERTER_CERT` | `fullchain.pem` | TLS certificate path (when SSL enabled) |
| `CONVERTER_KEY` | `privkey.pem` | TLS private key path (when SSL enabled) |

## Install / 安装

Install Python dependencies in a virtual environment.

在虚拟环境中安装 Python 依赖。

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

## Run / 运行

Set certificate paths and start the server.

设置证书路径后启动服务。

```bash
export CONVERTER_CERT=/path/to/fullchain.pem
export CONVERTER_KEY=/path/to/privkey.pem
export CONVERTER_HOST=0.0.0.0
export CONVERTER_PORT=8443
python3 converter.py
```

Use it as:

使用方式：

```text
https://your-domain.example:8443/?url=https%3A%2F%2Fexample.com%2Fsubscribe%3Ftoken%3D...
```

## Notes / 注意事项

Some nodes may keep their original insecure flag if the service cannot obtain a certificate fingerprint. Hysteria2 certificate probing requires QUIC connectivity.

如果服务无法获取某个节点的证书指纹，该节点可能会保留原来的 insecure 参数。Hysteria2 证书探测需要目标支持 QUIC 连通。
