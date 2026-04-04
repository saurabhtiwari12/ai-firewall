# API Documentation

Base URL: `http://localhost:3001`

All protected endpoints require:

```
Authorization: Bearer <access_token>
Content-Type: application/json
```

---

## Authentication Flow

```
Client                         Backend API
  │                                │
  │── POST /api/auth/login ────────►│  Returns access_token (15 min)
  │                                │           + refresh_token (7 days)
  │── GET  /api/events  ──────────►│  Bearer access_token
  │
  │  (access_token expires)
  │
  │── POST /api/auth/refresh ─────►│  Returns new access_token + refresh_token
```

---

## Authentication

### Register

```
POST /api/auth/register
```

**Body:**
```json
{
  "username": "analyst01",
  "email": "analyst@example.com",
  "password": "SecurePass123!",
  "role": "analyst"
}
```

**Response 201:**
```json
{
  "success": true,
  "data": {
    "_id": "64f...",
    "username": "analyst01",
    "email": "analyst@example.com",
    "role": "analyst"
  }
}
```

**curl:**
```bash
curl -X POST http://localhost:3001/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"analyst01","email":"analyst@example.com","password":"SecurePass123!","role":"analyst"}'
```

---

### Login

```
POST /api/auth/login
```

**Body:**
```json
{
  "email": "analyst@example.com",
  "password": "SecurePass123!"
}
```

**Response 200:**
```json
{
  "success": true,
  "accessToken": "eyJ...",
  "refreshToken": "eyJ..."
}
```

**curl:**
```bash
curl -X POST http://localhost:3001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"analyst@example.com","password":"SecurePass123!"}'
```

---

### Refresh Token

```
POST /api/auth/refresh
```

**Body:**
```json
{ "refreshToken": "eyJ..." }
```

**Response 200:**
```json
{
  "success": true,
  "accessToken": "eyJ...",
  "refreshToken": "eyJ..."
}
```

---

### Get Current User

```
GET /api/auth/me
Authorization: Bearer <token>
```

**Response 200:**
```json
{
  "success": true,
  "data": { "_id": "...", "username": "analyst01", "role": "analyst" }
}
```

---

## Events

### List Events

```
GET /api/events?page=1&limit=20&status=open&severity=high
Authorization: Bearer <token>
```

**Query parameters:**

| Param | Type | Description |
|---|---|---|
| `page` | int | Page number (default: 1) |
| `limit` | int | Items per page (max: 100, default: 20) |
| `status` | string | Filter: `open`, `resolved` |
| `severity` | string | Filter: `low`, `medium`, `high`, `critical` |
| `src_ip` | string | Filter by source IP |

**curl:**
```bash
curl http://localhost:3001/api/events?page=1&limit=10 \
  -H "Authorization: Bearer $TOKEN"
```

---

### Ingest Event (firewall engine → API)

```
POST /api/events
Authorization: Bearer <token>   (min role: analyst)
```

**Body:**
```json
{
  "src_ip": "192.168.1.100",
  "dst_ip": "10.0.0.5",
  "src_port": 54321,
  "dst_port": 443,
  "protocol": "TCP",
  "threat_level": "high",
  "threat_score": 0.87,
  "attack_type": "port_scan",
  "action": "BLOCK",
  "bytes_sent": 1024,
  "bytes_recv": 256,
  "duration_ms": 450
}
```

**Response 201:**
```json
{
  "success": true,
  "data": { "_id": "...", "src_ip": "192.168.1.100", ... }
}
```

---

### Get Event

```
GET /api/events/:id
Authorization: Bearer <token>
```

---

### Resolve Event

```
PUT /api/events/:id/resolve
Authorization: Bearer <token>   (min role: analyst)
```

**Body:**
```json
{ "resolution_notes": "False positive — internal scanner" }
```

---

### Delete Event

```
DELETE /api/events/:id
Authorization: Bearer <token>   (role: admin)
```

---

### Event Statistics

```
GET /api/events/stats/summary
Authorization: Bearer <token>
```

**Response:**
```json
{
  "success": true,
  "data": {
    "total": 1842,
    "open": 24,
    "resolved": 1818,
    "by_severity": { "low": 400, "medium": 900, "high": 400, "critical": 142 }
  }
}
```

---

## Alerts

### List Alerts

```
GET /api/alerts?status=open&severity=critical&page=1&limit=20
Authorization: Bearer <token>
```

---

### Create Alert

```
POST /api/alerts
Authorization: Bearer <token>   (min role: analyst)
```

**Body:**
```json
{
  "title": "Unusual outbound traffic",
  "severity": "high",
  "message": "Host 10.0.0.42 sent 500 MB in 5 minutes.",
  "source_ip": "10.0.0.42"
}
```

---

### Update Alert

```
PUT /api/alerts/:id
Authorization: Bearer <token>   (min role: analyst)
```

**Body:**
```json
{
  "status": "acknowledged",
  "notes": "Investigating — ticket #1234"
}
```

Valid statuses: `open`, `acknowledged`, `resolved`, `false_positive`

---

### Delete Alert

```
DELETE /api/alerts/:id
Authorization: Bearer <token>   (role: admin)
```

---

## Analytics

All analytics endpoints require authentication (viewer role minimum).

### Traffic Time Series

```
GET /api/analytics/traffic?hours=24
```

Returns per-hour packet counts for the last N hours.

---

### Threat Distribution

```
GET /api/analytics/threats?hours=24
```

Returns counts grouped by threat level.

---

### Top Attackers

```
GET /api/analytics/top-attackers?hours=24&limit=10
Authorization: Bearer <token>   (min role: analyst)
```

Returns top source IPs by event count.

---

### Attack Types

```
GET /api/analytics/attack-types?hours=24
```

Returns counts grouped by `attack_type`.

---

### Hourly Breakdown

```
GET /api/analytics/hourly
```

Returns a 24-element array of hourly event counts.

---

## System

### Health Check (Public)

```
GET /api/system/health
```

**Response 200:**
```json
{
  "status": "ok",
  "timestamp": "2026-04-04T06:00:00.000Z",
  "database": "connected",
  "uptime_s": 3600
}
```

Returns `503` when the database is not connected.

---

### Runtime Status

```
GET /api/system/status
Authorization: Bearer <token>
```

---

### Prometheus Metrics

```
GET /api/system/metrics
Authorization: Bearer <token>   (role: admin)
```

Requires `METRICS_ENABLED=true` in environment.

---

## Error Codes

| HTTP Code | Meaning |
|---|---|
| 400 | Validation error (see `errors` array in body) |
| 401 | Missing or invalid JWT |
| 403 | Insufficient role |
| 404 | Resource not found |
| 429 | Rate limit exceeded |
| 500 | Internal server error |

**Error body:**
```json
{
  "success": false,
  "message": "Human-readable description",
  "errors": [{ "field": "email", "message": "must be a valid email" }]
}
```
