<div align="center">
  <p>
    <h3>
      <b>
        Auth Proxy
      </b>
    </h3>
  </p>
  <p>
    <b>
      Add webauthn/oauth2 proxy to your application
    </b>
  </p>
  <p>

  </p>
  <br />
  <p>


  </p>
</div>

<details open>
  <summary><b>Table of contents</b></summary>

---

- [Features](#features)
- [Usage](#usage)
- [Contributing](#contributing)
- [Changelog](CHANGELOG.md)
- [License](#license)

---

</details>

## **Homepage**



## **Features**

- Origin codebase from https://github.com/Quiq/webauthn_proxy
- Webauthn (included discoverable process) supports
- OAuth2 supports

**To suggest anything, please join our [Discussion board](https://github.com/MartinPham/auth_proxy/discussions).**


## **Usage**

**Golang**
```
go run .
```
or
```
WEBAUTHN_PROXY_CONFIGPATH=/path/to/config/dir/ go run .
```

**Docker**
```
docker run --rm -ti -p 8080:8080 martinpham/authn_proxy:latest
```
or
```
docker run --rm -ti -p 8080:8080 -v /path/to/config:/opt/config:ro martinpham/authn_proxy:latest
```

**nginx**
```
location / {
        auth_request /auth_proxy/auth;
        error_page 401 = /auth_proxy/login?redirect_url=$uri;

        # ...
}

# WebAuthn Proxy.
location /auth_proxy/ {
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Host $host;
        proxy_pass http://127.0.0.1:8080;
}
```

**Kubernetes & Traefik IngressRoute**
- Error Middleware
```
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: auth-errors
  namespace: <change me>
spec:
  errors:
    status:
      - "401"
    service:
      name: auth-proxy
      namespace: auth-system
      port: 8080
    query: "/auth_proxy/login?redirect_url=https://<change me>{url}"
```
- Auth Middleware
```
apiVersion: traefik.io/v1alpha1
kind: IngressRoute
metadata:
  name: <change me>-ingressroute
  namespace: <change me>
spec:
  entryPoints:
    - websecure
  routes:
    - match: Host(`<change me>`)
      kind: Rule
      services:
        - name: <change me>
          port: <change me>
      middlewares:
        - name: <change me>-errors
        - name: auth-auth
          namespace: auth-system
    - match: Host(`<change me>`) && PathPrefix(`/auth_proxy/`)
      kind: Rule
      services:
        - name: auth-proxy
          namespace: auth-system
          port: 8080
  tls:
    secretName: <change me>
```

## **Contributing**

Please contribute using [GitHub Flow](https://guides.github.com/introduction/flow). Create a branch, add commits, and then [open a pull request](https://github.com/MartinPham/auth_proxy/compare).



## **License**

This project is licensed under the [GNU General Public License v3.0](https://opensource.org/licenses/gpl-3.0.html), still includes code originally licensed under Apache 2.0 from https://github.com/Quiq/webauthn_proxy - see the [`LICENSE`](LICENSE) file for details.
