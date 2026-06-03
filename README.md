# Subscription Certificate Converter

HTTPS subscription converter for replacing deprecated insecure flags with certificate pinning.

Supported link types:

- `hysteria2://` / `hy2://` -> `pinSHA256`
- `vless://` -> `pcs`
- `trojan://` -> `pcs`

The service fetches a subscription from `/?url=<subscription_url>`, converts supported node links, and returns a base64 encoded subscription.

## Public Instance

A public instance is available and you are welcome to use it:

```text
https://convert.108848.xyz:8443/?url=<url-encoded-subscription-url>
```

Example:

```text
https://convert.108848.xyz:8443/?url=https%3A%2F%2Fexample.com%2Fsubscribe%3Ftoken%3D...
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

This public version does not write request logs.

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
