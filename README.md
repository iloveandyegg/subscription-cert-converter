# Subscription Certificate Converter

HTTPS subscription converter for replacing deprecated insecure flags with certificate pinning.

Supported link types:

- `hysteria2://` / `hy2://` -> `pinSHA256`
- `vless://` -> `pcs`
- `trojan://` -> `pcs`

The service fetches a subscription from `/?url=<subscription_url>`, converts supported node links, and returns a base64 encoded subscription.

## Why This Exists

v2rayN discussion [#9460](https://github.com/2dust/v2rayN/discussions/9460) explains that recent Xray-core versions removed the `allowInsecure` TLS option and migrated the safe replacement to certificate pinning with `pinnedPeerCertSha256`. Subscriptions that still contain `insecure` or `allowInsecure` can make newer clients fail to start or import unusable nodes.

This converter is a small helper for that transition: it fetches a subscription, probes each supported node certificate, removes the insecure flags, and writes the certificate pin back into the share link format expected by clients.

## 中文说明

v2rayN 的相关讨论 [#9460](https://github.com/2dust/v2rayN/discussions/9460) 说明：新版 Xray-core 已移除 TLS 里的 `allowInsecure` 选项，长期替代方案是使用证书固定，也就是 `pinnedPeerCertSha256`。如果订阅里的节点仍然带有 `insecure` 或 `allowInsecure`，新版客户端可能会启动失败，或者导入后节点不可用。

这个转换器用于处理这类订阅：它会拉取订阅内容，探测支持节点的证书指纹，移除不安全参数，并把证书指纹写回客户端可识别的分享链接参数中。

## Public Instance

A public instance is available and you are welcome to use it:

```text
https://convert.192172.xyz:8443/?url=<url-encoded-subscription-url>
```

You can also open the web page and paste your subscription URL:

```text
https://convert.192172.xyz:8443/
```

Example:

```text
https://convert.192172.xyz:8443/?url=https%3A%2F%2Fexample.com%2Fsubscribe%3Ftoken%3D...
```

Please URL-encode the subscription URL before placing it in the `url` query parameter. Do not share subscription URLs or tokens publicly.

## Security

This project is designed for public deployment with SSRF protections:

- Allows only `http` and `https` subscription URLs.
- Allows subscription fetches only on ports `80` and `443`.
- Rejects localhost, private, link-local, reserved, and non-global IP targets after DNS resolution.
- Revalidates every redirect target.
- Applies the same public-IP checks before TCP/QUIC certificate probing.
- Limits response size, redirect count, line count, certificate targets, request rate, and concurrency.

This public version does not write request logs and the web page does not use browser local storage.

## Install

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

## Run

Set certificate paths and start the server:

```bash
export CONVERTER_CERT=/path/to/fullchain.pem
export CONVERTER_KEY=/path/to/privkey.pem
export CONVERTER_HOST=0.0.0.0
export CONVERTER_PORT=8443
python3 converter.py
```

Use it as:

```text
https://your-domain.example:8443/?url=https%3A%2F%2Fexample.com%2Fsubscribe%3Ftoken%3D...
```

## Notes

Some nodes may keep their original insecure flag if the service cannot obtain a certificate fingerprint. Hysteria2 certificate probing requires QUIC connectivity.
