# Security

## JWT Configuration

Access tokens expire in 15 minutes by default. Refresh tokens expire in 7 days. Both secrets must be at least 32 random characters.

```env
JWT_SECRET=<openssl rand -base64 48>
JWT_REFRESH_SECRET=<openssl rand -base64 48>
JWT_EXPIRES_IN=15m
JWT_REFRESH_EXPIRES_IN=7d
```

**Never reuse `JWT_SECRET` and `JWT_REFRESH_SECRET`.**

Generate strong secrets:

```bash
openssl rand -base64 48   # run twice, use each value for one variable
```

---

## RBAC — Role-Based Access Control

Three roles are supported, ordered by privilege:

| Role | Capabilities |
|---|---|
| `viewer` | Read events, alerts, analytics, system health |
| `analyst` | All viewer permissions + create/update events and alerts |
| `admin` | All analyst permissions + delete events/alerts, access Prometheus metrics |

The `requireRole` middleware enforces exact role match. `requireMinRole` enforces a minimum level (e.g., `requireMinRole('analyst')` allows analyst and admin).

When creating the first user, use `"role": "admin"`. Subsequent users default to `"viewer"` unless explicitly set.

---

## TLS / HTTPS

### Docker Compose

By default, the frontend nginx container listens on HTTP port 3000. To enable TLS, mount your certificates into the nginx container and update `nginx.conf`:

```nginx
server {
    listen 443 ssl;
    ssl_certificate     /etc/nginx/certs/fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    ...
}
```

### Kubernetes

The Ingress manifest in `kubernetes/services.yaml` uses `cert-manager` with a `ClusterIssuer` for automatic Let's Encrypt TLS:

```yaml
annotations:
  cert-manager.io/cluster-issuer: letsencrypt-prod
```

Install cert-manager before applying manifests:

```bash
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/latest/download/cert-manager.yaml
```

---

## Secrets Management

### Development

Use `.env` (never commit it — it is gitignored). Copy from `.env.example`:

```bash
cp .env.example .env
```

### Production — Kubernetes Secrets

```bash
kubectl create secret generic ai-firewall-secrets \
  --namespace ai-firewall \
  --from-literal=JWT_SECRET="$(openssl rand -base64 48)" \
  --from-literal=JWT_REFRESH_SECRET="$(openssl rand -base64 48)" \
  --from-literal=MONGO_URI="mongodb+srv://user:pass@cluster/ai-firewall" \
  --from-literal=ABUSEIPDB_API_KEY="your-key"
```

Reference in Deployment:

```yaml
env:
  - name: JWT_SECRET
    valueFrom:
      secretKeyRef:
        name: ai-firewall-secrets
        key: JWT_SECRET
```

### Production — AWS Secrets Manager

Store secrets in AWS Secrets Manager and use the AWS Secrets Manager CSI driver or the AWS SDK to retrieve them at runtime.

---

## Firewall Enforcement Safety

The firewall engine defaults to **dry-run mode** (`FW_DRY_RUN=true`). In dry-run mode, enforcement commands are logged but not executed.

To enable live enforcement:

```env
FW_DRY_RUN=false
```

**Test thoroughly in a non-production environment before enabling live enforcement.** Misconfigured rules can block legitimate traffic or lock you out of the host.

---

## Hardening Checklist

- [ ] Set unique, ≥ 32-character values for `JWT_SECRET` and `JWT_REFRESH_SECRET`
- [ ] Set `NODE_ENV=production`
- [ ] Enable TLS on all external endpoints
- [ ] Rotate API keys (AbuseIPDB, Spamhaus) and store in a secrets manager
- [ ] Restrict MongoDB network access to the backend API only (no public exposure)
- [ ] Enable MongoDB authentication (`--auth` flag or Atlas ACLs)
- [ ] Set Redis `requirepass` or use Redis ACLs
- [ ] Run containers as non-root users (Dockerfiles already set `USER appuser`)
- [ ] Enable `FW_DRY_RUN=false` only after validating rules in staging
- [ ] Set up log shipping (Loki, CloudWatch, etc.) and alert on error rates
- [ ] Enable Trivy scanning in CI (already configured in `.github/workflows/ci.yml`)
- [ ] Review and tighten Kubernetes RBAC — use least-privilege `ServiceAccount`s
- [ ] Enable network policies in Kubernetes to restrict pod-to-pod traffic
- [ ] Rotate JWT secrets periodically and invalidate all existing sessions

---

## Reporting Vulnerabilities

Please do **not** open a public GitHub issue for security vulnerabilities. Instead, email the maintainer directly or use the GitHub private vulnerability reporting feature (Security → Report a vulnerability).
