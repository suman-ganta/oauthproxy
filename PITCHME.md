---
### Dynamic Processes
<span style="color:gray">DP on Kubernetes</span>
![Flow Chart](./dp-k8s.png)
---
@title[Tenant Request]
### Tenant Request Lifecycle
```
https://t1.sumanganta.com/eng/ic/api/process/v1/dp-executions
```
---
### Host Resolution
![Flow Chart](./dns.png)
+++
### TLS
Wild card certificate for OIC
 ```
 *.sumanganta.com
 ```
---

### Ingress Definition
```Yaml
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: dp-ing
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
    nginx.ingress.kubernetes.io/auth-url: "https://www.sumanganta.com/p/p/auth"
    nginx.ingress.kubernetes.io/auth-signin: "https://www.sumanganta.com/p/p/login"
spec:
  tls:
  - secretName: sumanganta-domain-tls
  rules:
  - http:
      paths:
      - path: /eng
        backend:
          serviceName: dp-service
          servicePort: 80
```
---
### Authentication

![request lifecycle](oauthproxy.png "Logo Title Text 1")
+++
<span style="color:gray">OAuth Proxy</span>
- Each unauthenticated request is routed to the proxy - https://www.sumanganta.com/p/p
- Proxy is pre-seeded with clientId, secret per tenant via config maps (TODO)
- Takes care of routing requests to IDCS and get access token.
- Also acts as auth enforcement point
---
### Multi tenancy

<span style="color:gray">Engine Config.</span>

```Yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: dp-config
  namespace: dp
data:
  t1.properties: |-
    engine.name=t1
    db.driverClass=oracle.jdbc.driver.OracleDriver
    db.url=jdbc:oracle:thin:@dbaas:1521:XE
    db.secret=t1secret
    db.prefix=t1
  t2.properties: |-
    engine.name=t2
    db.driverClass=oracle.jdbc.driver.OracleDriver
    db.url=jdbc:oracle:thin:@dbaas:1521:XE
    db.secret=t2secret
    db.prefix=t2
```
---
### Tenant Onboarding
#### OCI
- Update DNS Zone records for the tenant
#### IDCS
- Add new IDCS App for tenant
- Add oauth client secret for tenant
#### OIC
- Update Runtime ConfigMap(s) (If there is tenant specific config)
- Add secrets of tenant (if DB credentials are different per tenant)
