# R-Map Helm Chart

Official Helm chart for deploying R-Map - a modern network scanner written in Rust.

## TL;DR

```bash
# Add repository (if published)
helm repo add rmap https://charts.rmap.example.com
helm repo update

# Install
helm install rmap rmap/rmap --namespace rmap --create-namespace

# Or install from local chart
helm install rmap ./helm/rmap --namespace rmap --create-namespace
```

## Introduction

This chart bootstraps an R-Map deployment on a Kubernetes cluster using the Helm package manager.

**Features:**
- Production-ready defaults
- High availability with HPA
- Comprehensive monitoring integration
- Security hardened (non-root, read-only FS, NetworkPolicy)
- Multi-environment support (dev, staging, production)
- WebSocket support for real-time events
- Prometheus metrics and alerts

## Prerequisites

- Kubernetes 1.25+
- Helm 3.10+
- PV provisioner support in the underlying infrastructure (optional)
- Metrics Server (for HPA)
- Prometheus Operator (optional, for ServiceMonitor)

## Installing the Chart

### Quick Start

```bash
# Install with default values
helm install rmap ./helm/rmap \
  --namespace rmap \
  --create-namespace

# Install with custom values
helm install rmap ./helm/rmap \
  --namespace rmap \
  --create-namespace \
  --values ./helm/rmap/values-production.yaml \
  --set secrets.jwtSecret=your-secure-secret
```

### Development Environment

```bash
helm install rmap-dev ./helm/rmap \
  --namespace rmap-dev \
  --create-namespace \
  --values ./helm/rmap/values-dev.yaml
```

### Staging Environment

```bash
helm install rmap-staging ./helm/rmap \
  --namespace rmap-staging \
  --create-namespace \
  --values ./helm/rmap/values-staging.yaml \
  --set secrets.jwtSecret=$STAGING_JWT_SECRET
```

### Production Environment

```bash
# IMPORTANT: Use external secret management in production!
helm install rmap-prod ./helm/rmap \
  --namespace rmap-prod \
  --create-namespace \
  --values ./helm/rmap/values-production.yaml \
  --set secrets.externalSecret.enabled=true \
  --set image.tag=v0.2.0
```

## Uninstalling the Chart

```bash
helm uninstall rmap --namespace rmap
```

This removes all the Kubernetes components associated with the chart and deletes the release.

## Configuration

### Configuration Files

The chart includes several values files for different environments:

- `values.yaml` - Default values with production-ready settings
- `values-dev.yaml` - Development environment (1 replica, debug logging)
- `values-staging.yaml` - Staging environment (2 replicas, moderate resources)
- `values-production.yaml` - Production environment (3+ replicas, full resources)

### Key Configuration Parameters

#### Image Settings

| Parameter | Description | Default |
|-----------|-------------|---------|
| `image.repository` | R-Map image repository | `ghcr.io/ununp3ntium115/r-map` |
| `image.tag` | Image tag (overrides appVersion) | `""` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |

#### Deployment Settings

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replicaCount` | Number of replicas | `3` |
| `podAnnotations` | Annotations for pods | `{}` |
| `podSecurityContext` | Security context for pods | See values.yaml |
| `securityContext` | Security context for containers | See values.yaml |

#### Service Settings

| Parameter | Description | Default |
|-----------|-------------|---------|
| `service.type` | Service type | `ClusterIP` |
| `service.port` | Service port | `8080` |
| `service.metricsPort` | Metrics port | `3001` |
| `service.sessionAffinity` | Session affinity (for WebSocket) | `ClientIP` |

#### Ingress Settings

| Parameter | Description | Default |
|-----------|-------------|---------|
| `ingress.enabled` | Enable ingress | `false` |
| `ingress.className` | Ingress class | `nginx` |
| `ingress.hosts` | Ingress hosts | See values.yaml |
| `ingress.tls` | TLS configuration | See values.yaml |

#### Resource Settings

| Parameter | Description | Default |
|-----------|-------------|---------|
| `resources.limits.cpu` | CPU limit | `2000m` |
| `resources.limits.memory` | Memory limit | `1Gi` |
| `resources.requests.cpu` | CPU request | `500m` |
| `resources.requests.memory` | Memory request | `256Mi` |

#### Autoscaling Settings

| Parameter | Description | Default |
|-----------|-------------|---------|
| `autoscaling.enabled` | Enable HPA | `true` |
| `autoscaling.minReplicas` | Minimum replicas | `2` |
| `autoscaling.maxReplicas` | Maximum replicas | `10` |
| `autoscaling.targetCPUUtilizationPercentage` | CPU target | `70` |
| `autoscaling.targetMemoryUtilizationPercentage` | Memory target | `80` |

#### Application Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.logLevel` | Log level | `info` |
| `config.maxConcurrentScans` | Max concurrent scans | `10` |
| `config.rateLimitEnabled` | Enable rate limiting | `true` |
| `config.rateLimitRequests` | Rate limit requests | `100` |

#### Monitoring Settings

| Parameter | Description | Default |
|-----------|-------------|---------|
| `monitoring.serviceMonitor.enabled` | Enable Prometheus ServiceMonitor | `false` |
| `monitoring.prometheusRule.enabled` | Enable Prometheus alerts | `false` |

#### Security Settings

| Parameter | Description | Default |
|-----------|-------------|---------|
| `secrets.jwtSecret` | JWT signing secret | `CHANGE_ME_IN_PRODUCTION` |
| `secrets.externalSecret.enabled` | Use external secret management | `false` |
| `networkPolicy.enabled` | Enable NetworkPolicy | `true` |
| `podDisruptionBudget.enabled` | Enable PDB | `true` |

### Configuration Examples

#### Enable Ingress with TLS

```bash
helm install rmap ./helm/rmap \
  --set ingress.enabled=true \
  --set ingress.hosts[0].host=rmap.example.com \
  --set ingress.hosts[0].paths[0].path=/ \
  --set ingress.hosts[0].paths[0].pathType=Prefix \
  --set ingress.tls[0].secretName=rmap-tls \
  --set ingress.tls[0].hosts[0]=rmap.example.com
```

#### Enable Prometheus Monitoring

```bash
helm install rmap ./helm/rmap \
  --set monitoring.serviceMonitor.enabled=true \
  --set monitoring.prometheusRule.enabled=true
```

#### Customize Resources

```bash
helm install rmap ./helm/rmap \
  --set resources.limits.cpu=4000m \
  --set resources.limits.memory=2Gi \
  --set resources.requests.cpu=1000m \
  --set resources.requests.memory=512Mi
```

#### Configure Autoscaling

```bash
helm install rmap ./helm/rmap \
  --set autoscaling.minReplicas=5 \
  --set autoscaling.maxReplicas=20 \
  --set autoscaling.targetCPUUtilizationPercentage=60
```

#### Use External Secrets

```bash
# With External Secrets Operator
helm install rmap ./helm/rmap \
  --set secrets.externalSecret.enabled=true \
  --set secrets.externalSecret.backend=vault \
  --set secrets.externalSecret.path=secret/rmap/production
```

#### Custom Environment Variables

```bash
helm install rmap ./helm/rmap \
  --set extraEnv[0].name=CUSTOM_VAR \
  --set extraEnv[0].value=custom-value
```

## Upgrading

### Standard Upgrade

```bash
# Upgrade with new values
helm upgrade rmap ./helm/rmap \
  --namespace rmap \
  --values ./helm/rmap/values-production.yaml

# Upgrade to specific version
helm upgrade rmap ./helm/rmap \
  --namespace rmap \
  --set image.tag=v0.3.0
```

### Rollback

```bash
# View release history
helm history rmap --namespace rmap

# Rollback to previous version
helm rollback rmap --namespace rmap

# Rollback to specific revision
helm rollback rmap 2 --namespace rmap
```

## Verification

### Check Release Status

```bash
helm status rmap --namespace rmap
helm list --namespace rmap
```

### Test Deployment

```bash
# Run Helm tests (if defined)
helm test rmap --namespace rmap

# Manual tests
kubectl get pods -n rmap -l app.kubernetes.io/name=rmap
kubectl logs -n rmap -l app.kubernetes.io/name=rmap
```

### Access the Application

```bash
# Port-forward
kubectl port-forward -n rmap svc/rmap 8080:8080

# Test endpoints
curl http://localhost:8080/health
curl http://localhost:8080/metrics
```

## Monitoring

### Prometheus Metrics

If ServiceMonitor is enabled, Prometheus will automatically scrape metrics from:

```
http://<pod-ip>:3001/metrics
```

### Grafana Dashboards

Import the R-Map dashboard:

1. In Grafana, go to Dashboards → Import
2. Upload `docs/grafana/rmap-dashboard.json` (if available)
3. Select Prometheus datasource

### Alerts

If PrometheusRule is enabled, the following alerts are configured:

- **RMapPodDown** - Pod has been down for >5 minutes
- **RMapHighCPU** - CPU usage >80% for >10 minutes
- **RMapHighMemory** - Memory usage >90% for >10 minutes
- **RMapFrequentRestarts** - Pod restarting >5 times/hour
- **RMapHPAMaxReplicas** - HPA at max replicas for >15 minutes

## Security

### Secret Management

**NEVER use default secrets in production!**

#### Option 1: Set via Helm values

```bash
helm install rmap ./helm/rmap \
  --set secrets.jwtSecret=$(openssl rand -base64 32)
```

#### Option 2: External Secrets Operator

```bash
# Install External Secrets Operator first
# Then enable in chart:
helm install rmap ./helm/rmap \
  --set secrets.externalSecret.enabled=true \
  --set secrets.externalSecret.backend=vault \
  --set secrets.externalSecret.path=secret/rmap
```

#### Option 3: Sealed Secrets

```bash
# Create sealed secret
kubectl create secret generic rmap-secret \
  --from-literal=jwt-secret=your-secret \
  --dry-run=client -o yaml | \
  kubeseal -o yaml > sealed-secret.yaml

# Install chart without creating secret
helm install rmap ./helm/rmap \
  --set serviceAccount.create=false
```

### Security Features

- **Non-root user** (UID 65532)
- **Read-only root filesystem**
- **No privilege escalation**
- **Dropped all capabilities**
- **Network policies** (optional)
- **Pod Disruption Budget**
- **Security context** on pod and container level

## Troubleshooting

### Common Issues

#### 1. ImagePullBackOff

```bash
# Check image name and tag
helm get values rmap -n rmap | grep image

# Check image pull secrets
kubectl get pods -n rmap -o jsonpath='{.items[0].spec.imagePullSecrets}'
```

#### 2. CrashLoopBackOff

```bash
# Check logs
kubectl logs -n rmap -l app.kubernetes.io/name=rmap --tail=100

# Check liveness probe settings
helm get values rmap -n rmap | grep -A 5 livenessProbe
```

#### 3. HPA Not Working

```bash
# Check metrics server
kubectl get deployment metrics-server -n kube-system

# Check HPA status
kubectl describe hpa -n rmap
```

#### 4. Ingress Not Working

```bash
# Check ingress controller
kubectl get pods -n ingress-nginx

# Check ingress resource
kubectl describe ingress -n rmap

# Check cert-manager (if using TLS)
kubectl get certificate -n rmap
```

### Debug Mode

```bash
# Install with debug values
helm install rmap ./helm/rmap \
  --namespace rmap \
  --set config.logLevel=debug \
  --set resources.limits.cpu=500m \
  --set resources.limits.memory=512Mi
```

## Development

### Testing Changes Locally

```bash
# Lint the chart
helm lint ./helm/rmap

# Template the chart (dry-run)
helm template rmap ./helm/rmap \
  --values ./helm/rmap/values-dev.yaml \
  --debug

# Install with --dry-run
helm install rmap ./helm/rmap \
  --dry-run \
  --debug \
  --namespace rmap
```

### Package Chart

```bash
# Package chart
helm package ./helm/rmap

# This creates: rmap-0.2.0.tgz
```

### Publish Chart

```bash
# Create chart repository index
helm repo index .

# Upload to chart repository (GitHub Pages, ChartMuseum, etc.)
```

## GitOps Integration

### ArgoCD

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: rmap
  namespace: argocd
spec:
  project: default
  source:
    repoURL: https://github.com/your-org/R-map
    path: helm/rmap
    targetRevision: HEAD
    helm:
      valueFiles:
      - values-production.yaml
      parameters:
      - name: image.tag
        value: v0.2.0
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
apiVersion: helm.toolkit.fluxcd.io/v2beta1
kind: HelmRelease
metadata:
  name: rmap
  namespace: rmap-prod
spec:
  interval: 5m
  chart:
    spec:
      chart: ./helm/rmap
      sourceRef:
        kind: GitRepository
        name: rmap
        namespace: flux-system
  values:
    image:
      tag: v0.2.0
  valuesFrom:
  - kind: ConfigMap
    name: rmap-values
```

## Support

- **Documentation**: https://github.com/Ununp3ntium115/R-map/docs
- **Issues**: https://github.com/Ununp3ntium115/R-map/issues
- **Discussions**: https://github.com/Ununp3ntium115/R-map/discussions

## Contributing

Contributions are welcome! Please:

1. Test changes with `helm lint` and `helm template`
2. Update documentation in this README
3. Follow semantic versioning for chart version
4. Submit PR with clear description

## License

This chart is licensed under MIT OR Apache-2.0, same as R-Map.

## Maintainers

- R-Map Team (@rmap-team)

## Changelog

See [CHANGELOG.md](./CHANGELOG.md) for release notes.
