# Deployment

## Docker Compose

The simplest production-like deployment runs all services with Docker Compose.

```bash
# 1. Configure environment
cp .env.example .env
# Set JWT_SECRET, JWT_REFRESH_SECRET, and optionally ABUSEIPDB_API_KEY

# 2. Set FW_DRY_RUN=false in .env to enable live firewall enforcement
#    Leave FW_DRY_RUN=true (default) for testing

# 3. Start
docker compose up -d

# 4. Check health
curl http://localhost:3001/api/system/health

# 5. View logs
docker compose logs -f backend-api
```

To upgrade:

```bash
git pull
docker compose pull          # pull latest images (if using a registry)
docker compose up -d --build # rebuild local images and restart
```

---

## Kubernetes

### Prerequisites

- `kubectl` configured against your cluster
- Container images pushed to a registry (see [scripts/deploy.sh](../scripts/deploy.sh))

### Deploy

```bash
# 1. Push images to your registry
REGISTRY=ghcr.io/yourorg/ai-firewall TAG=v1.0.0 PUSH=true ./scripts/deploy.sh

# 2. Create the namespace
kubectl create namespace ai-firewall

# 3. Create secrets
kubectl create secret generic ai-firewall-secrets \
  --namespace ai-firewall \
  --from-literal=JWT_SECRET="$(openssl rand -base64 48)" \
  --from-literal=JWT_REFRESH_SECRET="$(openssl rand -base64 48)" \
  --from-literal=MONGO_URI="mongodb://mongodb:27017/ai-firewall"

# 4. Apply manifests
kubectl apply -f kubernetes/ -n ai-firewall

# 5. Watch rollout
kubectl rollout status deployment/ai-firewall-backend -n ai-firewall
kubectl rollout status deployment/ai-firewall-engine  -n ai-firewall
kubectl rollout status deployment/ai-firewall-frontend -n ai-firewall
```

### Manifests overview

| File | Description |
|---|---|
| `kubernetes/mongodb-statefulset.yaml` | MongoDB StatefulSet with PVC |
| `kubernetes/backend-deployment.yaml` | Backend API Deployment + HPA |
| `kubernetes/firewall-deployment.yaml` | Firewall engine Deployment (hostNetwork) |
| `kubernetes/frontend-deployment.yaml` | nginx frontend Deployment |
| `kubernetes/services.yaml` | Services + TLS Ingress |

### Scaling

```bash
# Scale backend horizontally
kubectl scale deployment ai-firewall-backend --replicas=3 -n ai-firewall
```

### Updating images

```bash
kubectl set image deployment/ai-firewall-backend \
  backend=ghcr.io/yourorg/ai-firewall/backend:v1.1.0 \
  -n ai-firewall
```

---

## AWS (Terraform + EKS)

### Prerequisites

- AWS CLI configured (`aws configure`)
- Terraform 1.x (`brew install terraform` or https://developer.hashicorp.com/terraform/install)
- `kubectl`

### Provision infrastructure

```bash
cd terraform

# Initialize providers
terraform init

# Preview changes
terraform plan -var-file=variables.tfvars

# Apply (creates VPC + EKS cluster, ~15 minutes)
terraform apply -var-file=variables.tfvars
```

Key variables (`terraform/variables.tf`):

| Variable | Default | Description |
|---|---|---|
| `aws_region` | `us-east-1` | AWS region |
| `cluster_name` | `ai-firewall-eks` | EKS cluster name |
| `node_instance_type` | `t3.medium` | Worker node type |
| `desired_capacity` | `2` | Initial node count |
| `min_size` | `1` | Minimum nodes |
| `max_size` | `5` | Maximum nodes |

### Configure kubectl

```bash
aws eks update-kubeconfig --region us-east-1 --name ai-firewall-eks
kubectl get nodes
```

### Deploy application

Follow the [Kubernetes](#kubernetes) steps above using the EKS cluster context.

### Tear down

```bash
# Remove application first
kubectl delete namespace ai-firewall

# Destroy infrastructure
cd terraform && terraform destroy -var-file=variables.tfvars
```

---

## CI/CD — GitHub Actions

The repository includes two workflows:

| Workflow | Trigger | Description |
|---|---|---|
| `.github/workflows/ci.yml` | Push/PR to `main`, `develop` | Lint, test, Docker build, Trivy scan |
| `.github/workflows/deploy.yml` | Push to `main` | Build + push images to `ghcr.io` |

To enable the deploy workflow, add these repository secrets:

| Secret | Value |
|---|---|
| `KUBE_CONFIG` | base64-encoded kubeconfig for your cluster (optional, for K8s apply) |

Images are pushed to `ghcr.io/<owner>/ai-firewall/{engine,backend,frontend}`.
