# APISIX plugins

Install Go 1.25 or later, then run `make` to build the WASM plugins as WASI
reactors using the standard Go compiler.

## Query parameter filter

Configure `query-param-filter` with a JSON array of parameter names. APISIX
requires the array to be passed as a string in `conf`:

```yaml
plugins:
  query-param-filter:
    conf: '["page", "language"]'
```

Only the named parameters are forwarded. Matching uses decoded names; retained
parameters keep their original encoding, order, and repeated values. Use
`conf: '[]'` to remove every query parameter. Invalid configuration prevents
the plugin from starting.

## Secure URLs

`secure-urls` authorizes signed URLs and prefix session cookies using
HMAC-SHA256. Configure it in the rewrite phase with a higher priority than
`query-param-filter`, `proxy-rewrite`, and `proxy-cache`. It must run on every
request, including cache hits, before signature parameters are removed.

The APISIX cache controller enables it for static-origin services with
`spec.secureKeys`. It copies the key names and values to the generated
`ApisixRoute` configuration. **Those resources contain signing secrets**:
restrict Kubernetes and APISIX configuration access accordingly.

```yaml
spec:
  secureKeys:
    - name: current
      value: "<32-character-secret>"
    - name: previous
      value: "<32-character-secret>"
  secureURL:
    disablePrefixes: false
    bindClientIP: true
```

`disablePrefixes` and `bindClientIP` default to false. Trusted proxies are
configured by the operator for all services, using the cache controller's
`--apisix-trusted-proxies=192.0.2.0/24,2001:db8::/32` flag or its Helm
`apisixTrustedProxies` list. An empty list trusts no forwarded IP headers.
When IP binding is
enabled, headers are considered only if the actual connecting proxy is in a
trusted CIDR. `X-Real-IP` takes precedence over `X-Forwarded-For`; the latter
is traversed from right to left, skipping trusted proxies. Without a trusted
header, the peer IP is used. Trusted proxies must overwrite or remove
client-supplied `X-Real-IP` and sanitize their forwarding chain. Do not trust
an arbitrary internet-facing CIDR.

For an operator-managed APISIX route, the WASM plugin configuration is:

```yaml
secure-urls:
  conf:
    secure_keys:
      - name: current
        value: "<secret>"
    disable_prefixes: false
    bind_client_ip: true
    trusted_proxies:
      - 192.0.2.0/24
```

URLs include `EX-Expires`, `EX-KeyName`, and the hexadecimal `EX-Sign`. For
single-object URLs, the signed payload is the complete URL with `EX-Sign`
removed, including every other query parameter in its original order and
encoding. Legacy signatures without extra query parameters remain supported.
Extra unsigned query parameters are rejected.

Prefix URLs also include `EX-UrlPrefix`, a padded URL-safe base64 encoding of
the full prefix URL. For compatibility with the existing service, the signed
payload is reconstructed in this order:

```
<scheme>://<host>/<path>?EX-UrlPrefix=<decoded-query-value>&EX-Expires=<expiry>&EX-KeyName=<name>
```

The prefix value in this payload is the base64 value after query decoding,
including any `=` padding. Prefix URLs do not support additional query
parameters. Prefix matching uses string-prefix semantics within the same
scheme and host; use a trailing `/` for directory boundaries.

When `bindClientIP` is true, add `&EX-Client-IP=<client-ip>` to the signed
payload and the URL before `EX-Sign`. For IPv6, URL-encode the IP in the URL;
single-object signatures cover that encoded representation, while prefix
signatures use the decoded IP value in the reconstructed payload. The plugin
compares it with the resolved client IP and stores the IP in the signed
cookie. Enabling binding invalidates previously issued unbound cookies.

Valid prefix URLs issue `ex-sec-session` cookies with `Secure`, `HttpOnly`,
and `SameSite=None`. The controller also adds a `serverless-post-function`
header-filter guard that marks protected responses `Cache-Control: private,
no-store` to prevent downstream caches from bypassing authentication or
sharing cookies. APISIX's own cache remains usable. APISIX's WASM host cannot
reliably change this header, so manually configured routes **must** include
the same guard:

```yaml
serverless-post-function:
  phase: header_filter
  functions:
    - |
      return function()
        ngx.header["Cache-Control"] = "private, no-store"
      end
```

As in the existing service, sessions last one hour and
are refreshed when less than 20 minutes remain. Single-object URLs do not
issue cookies. Removing a key invalidates its URLs and cookies immediately
after the updated route is applied.

Deploy the updated service CRD and an APISIX image containing both WASM
plugins, and confirm the plugins are loaded, **before** rolling out the
controller that generates `secure-urls` routes. Sign the URL using the scheme
and host visible to APISIX; TLS termination in front of APISIX must preserve
the intended scheme. Test authentication and cache hits after rollout.

GitHub Actions builds and pushes `fr6nco/apisix` when `main` or a Git tag is
pushed. Native AMD64 and ARM64 runners build the images, which are published
under one multi-architecture tag. The image tag combines the APISIX base image
tag from the Dockerfile with the branch or Git tag name, for example
`3.21.0-ubuntu-main` or `3.21.0-ubuntu-v1.0.0`. Ref names must form valid
Docker tags.

Set the repository secrets `DOCKER_LOGIN` and `DOCKER_PASSWORD` to Docker Hub
credentials with permission to push to `fr6nco/apisix`.
