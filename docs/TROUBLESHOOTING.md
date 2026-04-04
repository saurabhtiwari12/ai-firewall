# Troubleshooting

## Backend API / MongoDB

### `MongoServerError: connect ECONNREFUSED`

**Cause:** MongoDB is not running or the connection string is wrong.

**Fix:**
1. Check MongoDB is running: `docker compose ps mongodb` or `mongod --version`
2. Verify `MONGO_URI` in `.env` (default: `mongodb://localhost:27017/ai-firewall`)
3. If using Docker Compose, ensure the `mongodb` service started: `docker compose up -d mongodb`

---

### `JWT_SECRET is not set` / `Error: secretOrPrivateKey must have a value`

**Cause:** `JWT_SECRET` or `JWT_REFRESH_SECRET` is missing from the environment.

**Fix:**
1. Copy `.env.example` to `.env`: `cp .env.example .env`
2. Set `JWT_SECRET` and `JWT_REFRESH_SECRET` to unique strings of ≥ 32 characters
3. Restart the backend: `docker compose restart backend-api`

---

### `401 Unauthorized` on all API calls

**Causes:**
- Access token has expired (tokens expire in 15 minutes)
- Wrong `Authorization` header format

**Fix:**
1. Call `POST /api/auth/refresh` with your refresh token to get a new access token
2. Ensure the header format is exactly: `Authorization: Bearer <token>` (note the space)

---

### `403 Forbidden` — insufficient role

**Cause:** The authenticated user does not have the required role for the endpoint.

**Fix:** Create an admin user or update the existing user's role in MongoDB:

```js
// In mongosh
use ai-firewall
db.users.updateOne({ email: "user@example.com" }, { $set: { role: "admin" } })
```

---

### Rate limit: `429 Too Many Requests`

**Cause:** Auth endpoints are rate-limited to prevent brute force.

**Fix:** Wait 15 minutes, or in development set `RATE_LIMIT_SKIP=true` in `.env`.

---

## Firewall Engine

### `PermissionError: [Errno 1] Operation not permitted` on packet capture

**Cause:** Scapy requires root or `CAP_NET_RAW` capability to capture raw packets.

**Fix:**
- **Docker:** The firewall engine container should run with `--cap-add NET_RAW NET_ADMIN` (already set in `docker-compose.yml`)
- **Local:** Run with `sudo python main.py` or grant capabilities: `sudo setcap cap_net_raw,cap_net_admin+eip $(which python3)`

---

### `Interface eth0 not found`

**Cause:** `FW_INTERFACE` is set to an interface that does not exist on the host.

**Fix:** List available interfaces with `ip link show` or `ifconfig`, then update `FW_INTERFACE` in `.env`.

---

### ML models not found — using mock detection

**Cause:** No trained model files exist in `ml_training/models/` (or `MODEL_PATH`).

**Fix:** Train models following [docs/ML_PIPELINE.md](ML_PIPELINE.md), or the engine runs in mock mode (safe for development).

---

### Firewall rules not being applied

**Cause:** `FW_DRY_RUN=true` (default).

**Fix:** Set `FW_DRY_RUN=false` in `.env` after validating in a test environment. Verify iptables is installed: `which iptables`.

---

## Frontend Dashboard

### Blank page / `Failed to fetch` errors in browser console

**Cause:** Frontend cannot reach the backend API.

**Fix:**
1. Check `REACT_APP_API_URL` in `frontend-dashboard/src/.env.example` (defaults to `http://localhost:3001`)
2. Ensure the backend is running: `curl http://localhost:3001/api/system/health`
3. Check for CORS issues — the backend allows `FRONTEND_URL` origin (set in `.env`)

---

### Attack map shows no markers

**Cause:** No events with geolocation data in the database, or the mock data flag is disabled.

**Fix:** The `MapPage` component falls back to mock data if the API returns zero results. Ingest events via the firewall engine or `POST /api/events` directly.

---

### WebSocket connection fails

**Cause:** Socket.io cannot reach the backend on port 3001.

**Fix:**
1. Check `REACT_APP_SOCKET_URL` environment variable
2. Ensure port 3001 is not blocked by a local firewall
3. In production, confirm your reverse proxy forwards WebSocket upgrade headers

---

## Docker Compose

### `docker compose up` fails with `port already in use`

**Cause:** Another process is using port 3000, 3001, or 27017.

**Fix:**
```bash
# Find the process using port 3001
lsof -i :3001
kill <PID>
# Or change the port mapping in docker-compose.yml
```

---

### Container keeps restarting

**Fix:**
```bash
# Check container logs
docker compose logs --tail 50 <service-name>

# Common causes:
# - backend-api: missing JWT_SECRET in .env
# - firewall-engine: missing NET_RAW capability
# - mongodb: corrupted data volume (remove: docker compose down -v)
```

---

## Kubernetes

### Pods stuck in `Pending`

**Cause:** Insufficient cluster resources or missing PersistentVolume for MongoDB.

**Fix:**
```bash
kubectl describe pod <pod-name> -n ai-firewall
# Look for "Insufficient cpu/memory" or "no persistent volumes available"

# Scale up node group or create a StorageClass for the PVC
```

### `ImagePullBackOff`

**Cause:** Kubernetes cannot pull the container image (wrong registry, missing credentials, or image not pushed).

**Fix:**
```bash
kubectl describe pod <pod-name> -n ai-firewall
# Verify the image tag and registry URL
# If using a private registry, create an image pull secret:
kubectl create secret docker-registry regcred \
  --docker-server=ghcr.io \
  --docker-username=<username> \
  --docker-password=<PAT> \
  -n ai-firewall
```
