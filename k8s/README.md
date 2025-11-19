# R-Map Kubernetes Deployment

This directory contains production-ready Kubernetes manifests for deploying R-Map in any Kubernetes cluster.

## Directory Structure

```
k8s/
├── base/                       # Base Kustomize manifests
│   ├── deployment.yaml        # Main application deployment
│   ├── service.yaml           # Services (ClusterIP + headless)
│   ├── configmap.yaml         # Configuration
│   ├── secret.yaml            # Secrets (JWT, etc.)
│   ├── serviceaccount.yaml    # Service accounts
│   ├── rbac.yaml              # RBAC roles and bindings
│   ├── hpa.yaml               # HorizontalPodAutoscaler
│   ├── networkpolicy.yaml     # Network policies
│   ├── poddisruptionbudget.yaml # PodDisruptionBudget
│   └── kustomization.yaml     # Kustomize base config
├── overlays/                   # Environment-specific overlays
│   ├── dev/
│   ├── staging/
│   └── production/
└── monitoring/                 # Prometheus monitoring
    ├── servicemonitor.yaml    # Prometheus ServiceMonitor
    └── prometheusrule.yaml    # Alert rules

```

## Prerequisites

### Required Tools

- **kubectl** >= 1.25.0 - Kubernetes CLI
- **kustomize** >= 4.5.0 - Template-free customization (optional, built into kubectl)
- **helm** >= 3.10.0 - Package manager (if using Helm charts)

### Cluster Requirements

- Kubernetes >= 1.25.0
- Metrics Server (for HPA)
- Prometheus Operator (optional, for monitoring)
- Ingress Controller (optional, for external access)

### Access Requirements

- kubectl configured with cluster access
- Sufficient RBAC permissions to create:
  - Deployments, Services, ConfigMaps, Secrets
  - ServiceAccounts, Roles, RoleBindings
  - HorizontalPodAutoscalers, NetworkPolicies

## Quick Start

### Option 1: Deploy with Kustomize (Recommended)

#### Development Environment

```bash
# Deploy to development
kubectl apply -k k8s/overlays/dev/

# Verify deployment
kubectl get pods -n rmap-dev -l app=rmap

# Port-forward to access locally
kubectl port-forward -n rmap-dev svc/dev-rmap 8080:8080
```

#### Staging Environment

```bash
# Deploy to staging
kubectl apply -k k8s/overlays/staging/

# Verify deployment
kubectl get pods -n rmap-staging -l app=rmap

# Check HPA status
kubectl get hpa -n rmap-staging
```

#### Production Environment

```bash
# IMPORTANT: Update secrets before deploying!
# Use Sealed Secrets or External Secrets Operator

# Deploy to production
kubectl apply -k k8s/overlays/production/

# Verify deployment
kubectl get all -n rmap-prod -l app=rmap

# Check rollout status
kubectl rollout status deployment/prod-rmap -n rmap-prod
```

### Option 2: Deploy Base Manifests

```bash
# Create namespace
kubectl create namespace rmap

# Apply base manifests
kubectl apply -k k8s/base/ -n rmap

# Verify
kubectl get all -n rmap
```

## Configuration

### Environment Variables

Configure via ConfigMap (`k8s/base/configmap.yaml`):

- `RUST_LOG` - Log level (debug, info, warn, error)
- `JWT_SECRET` - JWT signing secret (from Secret)
- `PORT` - API server port (default: 8080)
- `METRICS_PORT` - Metrics port (default: 3001)

### Secrets Management

**IMPORTANT**: Never commit real secrets to Git!

#### For Development

Edit `k8s/overlays/dev/kustomization.yaml` and use secretGenerator:

```yaml
secretGenerator:
- name: rmap-secret
  literals:
  - jwt-secret=your-dev-secret
```

#### For Production

Use one of these secret management solutions:

**Option 1: Sealed Secrets**

```bash
# Install Sealed Secrets controller
kubectl apply -f https://github.com/bitnami-labs/sealed-secrets/releases/download/v0.24.0/controller.yaml

# Create sealed secret
echo -n "your-production-secret" | kubectl create secret generic rmap-secret \
  --dry-run=client \
  --from-file=jwt-secret=/dev/stdin \
  -o yaml | \
  kubeseal -o yaml > k8s/overlays/production/sealed-secret.yaml

# Apply sealed secret
kubectl apply -f k8s/overlays/production/sealed-secret.yaml -n rmap-prod
```

**Option 2: External Secrets Operator**

```bash
# Install External Secrets Operator
helm repo add external-secrets https://charts.external-secrets.io
helm install external-secrets external-secrets/external-secrets -n external-secrets-system --create-namespace

# Create SecretStore and ExternalSecret (see examples in production overlay)
```

**Option 3: HashiCorp Vault**

```bash
# Configure Vault integration (see Vault documentation)
# Use Vault Agent Injector or CSI Secret Store Driver
```

### Resource Limits

Adjust in overlay kustomization files:

```yaml
patches:
- target:
    kind: Deployment
    name: rmap
  patch: |-
    - op: replace
      path: /spec/template/spec/containers/0/resources/limits/cpu
      value: "4000m"
    - op: replace
      path: /spec/template/spec/containers/0/resources/limits/memory
      value: "2Gi"
```

### Autoscaling

Edit `k8s/base/hpa.yaml` to adjust:

- Min/max replicas
- CPU/memory thresholds
- Scaling behavior

## Monitoring

### Prometheus Integration

If you have Prometheus Operator installed:

```bash
# Apply ServiceMonitor
kubectl apply -f k8s/monitoring/servicemonitor.yaml -n rmap-prod

# Apply PrometheusRule (alerts)
kubectl apply -f k8s/monitoring/prometheusrule.yaml -n rmap-prod

# Verify ServiceMonitor is picked up
kubectl get servicemonitor -n rmap-prod
```

### Metrics Endpoint

Metrics are exposed at: `http://<pod-ip>:3001/metrics`

Access metrics locally:

```bash
kubectl port-forward -n rmap-prod svc/prod-rmap 3001:3001
curl http://localhost:3001/metrics
```

### Grafana Dashboards

Import the R-Map dashboard (if available):

```bash
# Dashboard JSON should be in docs/grafana/
```

## Verification & Testing

### Check Pod Status

```bash
# List pods
kubectl get pods -n rmap-prod -l app=rmap

# Describe pod
kubectl describe pod -n rmap-prod -l app=rmap

# Check logs
kubectl logs -n rmap-prod -l app=rmap -f

# Check resource usage
kubectl top pods -n rmap-prod -l app=rmap
```

### Test Health Endpoints

```bash
# Port-forward
kubectl port-forward -n rmap-prod svc/prod-rmap 8080:8080

# Test liveness
curl http://localhost:8080/health

# Test readiness
curl http://localhost:8080/ready

# Test API
curl http://localhost:8080/api/v1/scan
```

### Verify HPA

```bash
# Check HPA status
kubectl get hpa -n rmap-prod

# Describe HPA
kubectl describe hpa prod-rmap -n rmap-prod

# Watch HPA in real-time
kubectl get hpa -n rmap-prod -w
```

### Test Network Policy

```bash
# From a test pod in the same namespace
kubectl run -it --rm debug --image=curlimages/curl -n rmap-prod -- sh
# Inside the pod:
curl http://prod-rmap:8080/health
```

## Troubleshooting

### Pod not starting

```bash
# Check pod events
kubectl describe pod <pod-name> -n rmap-prod

# Check logs
kubectl logs <pod-name> -n rmap-prod

# Common issues:
# 1. ImagePullBackOff - check image name/tag
# 2. CrashLoopBackOff - check logs and liveness probe
# 3. Pending - check resource requests and node capacity
```

### HPA not working

```bash
# Check metrics server is running
kubectl get pods -n kube-system -l k8s-app=metrics-server

# Check HPA can get metrics
kubectl describe hpa prod-rmap -n rmap-prod

# Check pod resource requests are set (required for HPA)
kubectl get pod <pod-name> -n rmap-prod -o yaml | grep -A 5 resources
```

### Network connectivity issues

```bash
# Check NetworkPolicy
kubectl get networkpolicy -n rmap-prod

# Describe NetworkPolicy
kubectl describe networkpolicy rmap -n rmap-prod

# Temporarily disable for testing (NOT in production!)
kubectl delete networkpolicy rmap -n rmap-prod
```

### Secret not found

```bash
# List secrets
kubectl get secrets -n rmap-prod

# Check secret content
kubectl describe secret prod-rmap-secret -n rmap-prod

# Recreate secret if needed
kubectl delete secret prod-rmap-secret -n rmap-prod
kubectl create secret generic prod-rmap-secret \
  --from-literal=jwt-secret=your-secret \
  -n rmap-prod
```

## Upgrading

### Rolling Update

```bash
# Update image tag in kustomization.yaml or overlay
# Then apply:
kubectl apply -k k8s/overlays/production/

# Watch rollout
kubectl rollout status deployment/prod-rmap -n rmap-prod

# If issues occur, rollback:
kubectl rollout undo deployment/prod-rmap -n rmap-prod
```

### Blue-Green Deployment

```bash
# Create new deployment with different name
# Update service selector when ready
# Delete old deployment
```

### Canary Deployment

Use a service mesh (Istio, Linkerd) or Argo Rollouts for advanced canary deployments.

## Cleanup

### Delete specific environment

```bash
# Delete development
kubectl delete -k k8s/overlays/dev/

# Delete staging
kubectl delete -k k8s/overlays/staging/

# Delete production (BE CAREFUL!)
kubectl delete -k k8s/overlays/production/
```

### Delete base resources

```bash
kubectl delete -k k8s/base/ -n rmap
```

## Security Best Practices

1. **Never commit secrets** - Use Sealed Secrets or External Secrets Operator
2. **Use specific image tags** - Avoid `latest` in production
3. **Enable NetworkPolicy** - Restrict pod-to-pod communication
4. **Run as non-root** - Already configured (UID 65532)
5. **Read-only filesystem** - Already configured
6. **Resource limits** - Always set CPU/memory limits
7. **Pod Security Standards** - Use restricted profile
8. **Regular updates** - Keep base images and dependencies updated
9. **Audit logs** - Enable Kubernetes audit logging
10. **RBAC least privilege** - Grant only necessary permissions

## GitOps Integration

### ArgoCD

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: rmap-production
  namespace: argocd
spec:
  project: default
  source:
    repoURL: https://github.com/your-org/R-map
    targetRevision: main
    path: k8s/overlays/production
  destination:
    server: https://kubernetes.default.svc
    namespace: rmap-prod
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
```

### Flux

```yaml
apiVersion: kustomize.toolkit.fluxcd.io/v1
kind: Kustomization
metadata:
  name: rmap-production
  namespace: flux-system
spec:
  interval: 5m
  path: ./k8s/overlays/production
  prune: true
  sourceRef:
    kind: GitRepository
    name: rmap
```

## Support

For issues or questions:

- GitHub Issues: https://github.com/Ununp3ntium115/R-map/issues
- Documentation: https://github.com/Ununp3ntium115/R-map/docs

## License

MIT OR Apache-2.0
