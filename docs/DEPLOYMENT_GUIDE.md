# R-Map Kubernetes Deployment Guide

**Time to complete:** 30 minutes
**Prerequisites:** Kubernetes cluster, kubectl, helm

## Overview

This guide walks you through deploying R-Map to Kubernetes for production use.

---

## Quick Start

### 1-Command Deployment

```bash
helm install rmap rmap/rmap \
  --namespace rmap \
  --create-namespace
```

**That's it!** R-Map is now running on Kubernetes.

---

## Step-by-Step Deployment

### Prerequisites

```bash
# Verify kubectl is configured
kubectl version --client

# Verify cluster access
kubectl get nodes

# Install Helm (if not already installed)
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
helm version
```

### Step 1: Create Namespace

```bash
kubectl create namespace rmap

# Set as default for convenience
kubectl config set-context --current --namespace=rmap
```

### Step 2: Create Secrets

**Generate JWT secret:**
```bash
JWT_SECRET=$(openssl rand -base64 32)

kubectl create secret generic rmap-secrets \
  --namespace=rmap \
  --from-literal=JWT_SECRET="$JWT_SECRET"
```

### Step 3: Add Helm Repository

```bash
helm repo add rmap https://ununp3ntium115.github.io/R-map
helm repo update
helm search repo rmap
```

### Step 4: Review Values

```bash
# Download default values
helm show values rmap/rmap > values.yaml

# Edit as needed
nano values.yaml
```

**Key settings:**
```yaml
# values.yaml
replicaCount: 3

image:
  repository: ghcr.io/ununp3ntium115/r-map
  tag: "1.0.0"

resources:
  limits:
    cpu: 2000m
    memory: 2Gi
  requests:
    cpu: 500m
    memory: 512Mi

ingress:
  enabled: true
  className: nginx
  hosts:
    - host: rmap.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: rmap-tls
      hosts:
        - rmap.example.com

autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70
```

### Step 5: Install with Helm

```bash
helm install rmap rmap/rmap \
  --namespace=rmap \
  --values=values.yaml \
  --wait

# Verify deployment
helm list -n rmap
kubectl get pods -n rmap
```

### Step 6: Verify Installation

```bash
# Check pod status
kubectl get pods -n rmap -w

# Check service
kubectl get svc -n rmap

# Check logs
kubectl logs -n rmap -l app=rmap -f

# Port forward to test
kubectl port-forward -n rmap svc/rmap-api 8080:8080

# Test API
curl http://localhost:8080/api/v1/health
```

---

## Configuration Options

### Resource Limits

**Small environment (dev/test):**
```yaml
resources:
  limits:
    cpu: 1000m
    memory: 1Gi
  requests:
    cpu: 250m
    memory: 256Mi
```

**Medium environment (staging):**
```yaml
resources:
  limits:
    cpu: 2000m
    memory: 2Gi
  requests:
    cpu: 500m
    memory: 512Mi
```

**Large environment (production):**
```yaml
resources:
  limits:
    cpu: 4000m
    memory: 4Gi
  requests:
    cpu: 1000m
    memory: 1Gi
```

### Auto-scaling

```yaml
autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70
  targetMemoryUtilizationPercentage: 80
```

### Persistent Storage

```yaml
persistence:
  enabled: true
  storageClass: "fast-ssd"
  size: 20Gi
  accessMode: ReadWriteOnce
```

### Ingress with TLS

```yaml
ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
    nginx.ingress.kubernetes.io/rate-limit: "100"
  hosts:
    - host: rmap.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: rmap-tls
      hosts:
        - rmap.example.com
```

---

## Monitoring Setup

### Prometheus Operator

```bash
# Install Prometheus Operator (if not already installed)
helm repo add prometheus-community \
  https://prometheus-community.github.io/helm-charts
helm repo update

helm install prometheus prometheus-community/kube-prometheus-stack \
  --namespace monitoring \
  --create-namespace
```

### ServiceMonitor

R-Map includes a ServiceMonitor for automatic metric scraping:

```yaml
# Already included in Helm chart
serviceMonitor:
  enabled: true
  interval: 30s
  scrapeTimeout: 10s
```

### Grafana Dashboard

```bash
# Port forward to Grafana
kubectl port-forward -n monitoring svc/prometheus-grafana 3000:80

# Login: admin / prom-operator (default)
# Import dashboard from /grafana-dashboards/rmap-overview.json
```

---

## Security Configuration

### Network Policy

```yaml
# Included in Helm chart
networkPolicy:
  enabled: true
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: ingress-nginx
      ports:
        - protocol: TCP
          port: 8080
```

### Pod Security Policy

```yaml
# Included in Helm chart
podSecurityContext:
  runAsNonRoot: true
  runAsUser: 65532
  fsGroup: 65532

securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop:
      - ALL
    add:
      - NET_RAW
      - NET_ADMIN
```

### RBAC

```yaml
# Service account with minimal permissions
serviceAccount:
  create: true
  name: rmap

rbac:
  create: true
  rules:
    - apiGroups: [""]
      resources: ["pods", "services"]
      verbs: ["get", "list", "watch"]
```

---

## High Availability

### Multi-Zone Deployment

```yaml
affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
      - weight: 100
        podAffinityTerm:
          labelSelector:
            matchExpressions:
              - key: app
                operator: In
                values:
                  - rmap
          topologyKey: topology.kubernetes.io/zone
```

### Pod Disruption Budget

```yaml
podDisruptionBudget:
  enabled: true
  minAvailable: 2
```

---

## Upgrade Guide

### Minor Version Upgrade

```bash
# Update Helm repo
helm repo update

# Check available versions
helm search repo rmap --versions

# Upgrade
helm upgrade rmap rmap/rmap \
  --namespace=rmap \
  --values=values.yaml \
  --wait
```

### Major Version Upgrade

```bash
# Backup database first
kubectl exec -n rmap deploy/rmap-api -- \
  sqlite3 /data/scans.db ".backup /tmp/backup.db"

kubectl cp rmap/rmap-api-xxx:/tmp/backup.db ./backup.db

# Upgrade
helm upgrade rmap rmap/rmap \
  --namespace=rmap \
  --values=values.yaml \
  --wait
```

---

## Backup & Recovery

### Database Backup CronJob

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: rmap-backup
  namespace: rmap
spec:
  schedule: "0 2 * * *"  # 2 AM daily
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: backup
              image: alpine:latest
              command:
                - /bin/sh
                - -c
                - |
                  apk add sqlite
                  sqlite3 /data/scans.db ".backup /backup/scan-$(date +%Y%m%d).db"
              volumeMounts:
                - name: data
                  mountPath: /data
                - name: backup
                  mountPath: /backup
          volumes:
            - name: data
              persistentVolumeClaim:
                claimName: rmap-data
            - name: backup
              persistentVolumeClaim:
                claimName: rmap-backup
          restartPolicy: OnFailure
```

---

## Troubleshooting

### Pods Not Starting

```bash
# Check pod status
kubectl describe pod -n rmap <pod-name>

# Check events
kubectl get events -n rmap --sort-by='.lastTimestamp'

# Check logs
kubectl logs -n rmap <pod-name>
```

### Service Not Reachable

```bash
# Check service endpoints
kubectl get endpoints -n rmap

# Test from within cluster
kubectl run -it --rm debug --image=alpine --restart=Never -- sh
apk add curl
curl http://rmap-api.rmap:8080/api/v1/health
```

### Performance Issues

```bash
# Check resource usage
kubectl top pods -n rmap
kubectl top nodes

# Scale up if needed
kubectl scale deployment rmap-api -n rmap --replicas=5
```

---

## Uninstall

```bash
# Uninstall Helm release
helm uninstall rmap -n rmap

# Delete namespace (includes all resources)
kubectl delete namespace rmap

# Delete PVCs (if desired)
kubectl delete pvc --all -n rmap
```

---

## Next Steps

- **Production Deployment:** See [/steering/DEPLOYMENT.md](../steering/DEPLOYMENT.md)
- **Performance Tuning:** See [/steering/PERFORMANCE.md](../steering/PERFORMANCE.md)
- **API Usage:** See [API_GUIDE.md](API_GUIDE.md)

---

**Happy deploying!** 🚀
