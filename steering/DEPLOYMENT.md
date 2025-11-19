# R-Map Production Deployment Guide

**Version:** 1.0.0
**Last Updated:** 2025-01-19

## Table of Contents

- [Overview](#overview)
- [Docker Best Practices](#docker-best-practices)
- [Kubernetes Production Configuration](#kubernetes-production-configuration)
- [Security Hardening](#security-hardening)
- [Monitoring Setup](#monitoring-setup)
- [High Availability](#high-availability)
- [Backup and Recovery](#backup-and-recovery)
- [Performance Tuning](#performance-tuning)
- [Production Checklist](#production-checklist)

---

## Overview

This guide covers production deployment of R-Map in enterprise environments with a focus on security, reliability, and scalability.

### Deployment Architectures

| Architecture | Use Case | Complexity | Scalability |
|--------------|----------|------------|-------------|
| **Single Container** | Development, small teams | Low | Limited |
| **Docker Compose** | Small production, testing | Medium | Moderate |
| **Kubernetes** | Enterprise, high-scale | High | Excellent |
| **Serverless** | Event-driven scanning | Medium | Auto-scale |

---

## Docker Best Practices

### Production Docker Configuration

**Dockerfile (Multi-stage build):**

```dockerfile
# Build stage
FROM rust:1.75-alpine AS builder

WORKDIR /build
COPY . .

RUN apk add --no-cache musl-dev && \
    cargo build --release --locked && \
    strip target/release/rmap

# Runtime stage
FROM gcr.io/distroless/cc-debian12:nonroot

COPY --from=builder /build/target/release/rmap /usr/local/bin/rmap

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/rmap"]
```

**Build optimized image:**

```bash
# Build with BuildKit caching
DOCKER_BUILDKIT=1 docker build \
  --tag rmap:1.0.0 \
  --tag rmap:latest \
  --build-arg RUST_VERSION=1.75 \
  .

# Multi-platform build
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --tag ghcr.io/ununp3ntium115/r-map:1.0.0 \
  --push \
  .
```

### Docker Compose Production Setup

**docker-compose.prod.yml:**

```yaml
version: '3.8'

services:
  rmap-api:
    image: ghcr.io/ununp3ntium115/r-map:1.0.0
    container_name: rmap-api
    restart: unless-stopped

    # Resource limits
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 2G
        reservations:
          cpus: '1.0'
          memory: 512M

    # Security
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp:noexec,nosuid,size=100m

    # Capabilities (for SYN scanning)
    cap_add:
      - NET_RAW
      - NET_ADMIN
    cap_drop:
      - ALL

    # Environment
    environment:
      - RUST_LOG=info
      - RMAP_MAX_CONNECTIONS=500
      - RMAP_DB_PATH=/data/scans.db

    # Volumes
    volumes:
      - rmap-data:/data:rw
      - /etc/localtime:/etc/localtime:ro

    # Network
    ports:
      - "127.0.0.1:8080:8080"  # API (localhost only)
      - "127.0.0.1:3001:3001"  # Metrics (internal)
    networks:
      - rmap-net

    # Health check
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/api/v1/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

    # Logging
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

  prometheus:
    image: prom/prometheus:latest
    container_name: rmap-prometheus
    restart: unless-stopped

    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus-data:/prometheus

    ports:
      - "127.0.0.1:9090:9090"
    networks:
      - rmap-net

    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--storage.tsdb.retention.time=30d'

  grafana:
    image: grafana/grafana:latest
    container_name: rmap-grafana
    restart: unless-stopped

    environment:
      - GF_SECURITY_ADMIN_PASSWORD=secure_password_here
      - GF_INSTALL_PLUGINS=grafana-piechart-panel

    volumes:
      - grafana-data:/var/lib/grafana
      - ./grafana/dashboards:/etc/grafana/provisioning/dashboards:ro

    ports:
      - "127.0.0.1:3000:3000"
    networks:
      - rmap-net

    depends_on:
      - prometheus

  nginx:
    image: nginx:alpine
    container_name: rmap-nginx
    restart: unless-stopped

    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/nginx/ssl:ro

    ports:
      - "80:80"
      - "443:443"
    networks:
      - rmap-net

    depends_on:
      - rmap-api

volumes:
  rmap-data:
    driver: local
  prometheus-data:
    driver: local
  grafana-data:
    driver: local

networks:
  rmap-net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.25.0.0/16
```

**Start production stack:**

```bash
# Pull latest images
docker-compose -f docker-compose.prod.yml pull

# Start services
docker-compose -f docker-compose.prod.yml up -d

# View logs
docker-compose -f docker-compose.prod.yml logs -f rmap-api

# Check health
docker-compose -f docker-compose.prod.yml ps
```

---

## Kubernetes Production Configuration

### Namespace and RBAC

**namespace.yaml:**

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: rmap-prod
  labels:
    name: rmap-prod
    environment: production
```

**serviceaccount.yaml:**

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: rmap
  namespace: rmap-prod
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: rmap-role
  namespace: rmap-prod
rules:
  - apiGroups: [""]
    resources: ["pods", "services", "configmaps"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: rmap-rolebinding
  namespace: rmap-prod
subjects:
  - kind: ServiceAccount
    name: rmap
    namespace: rmap-prod
roleRef:
  kind: Role
  name: rmap-role
  apiGroup: rbac.authorization.k8s.io
```

### ConfigMap and Secrets

**configmap.yaml:**

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: rmap-config
  namespace: rmap-prod
data:
  RUST_LOG: "info"
  RMAP_MAX_CONNECTIONS: "500"
  RMAP_TIMEOUT: "3"
  RMAP_API_PORT: "8080"
  RMAP_METRICS_PORT: "3001"
```

**secrets.yaml:**

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: rmap-secrets
  namespace: rmap-prod
type: Opaque
stringData:
  JWT_SECRET: "your-secure-jwt-secret-here"  # Generate with: openssl rand -base64 32
  DATABASE_PASSWORD: "your-db-password-here"
```

### Deployment

**deployment.yaml:**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: rmap-api
  namespace: rmap-prod
  labels:
    app: rmap
    component: api
spec:
  replicas: 3

  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 1
      maxSurge: 1

  selector:
    matchLabels:
      app: rmap
      component: api

  template:
    metadata:
      labels:
        app: rmap
        component: api
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "3001"
        prometheus.io/path: "/metrics"

    spec:
      serviceAccountName: rmap

      # Security context
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        fsGroup: 65532
        seccompProfile:
          type: RuntimeDefault

      containers:
        - name: rmap
          image: ghcr.io/ununp3ntium115/r-map:1.0.0
          imagePullPolicy: IfNotPresent

          # Security
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            runAsNonRoot: true
            runAsUser: 65532
            capabilities:
              drop:
                - ALL
              add:
                - NET_RAW      # For SYN scanning
                - NET_ADMIN    # For raw sockets

          # Ports
          ports:
            - name: http
              containerPort: 8080
              protocol: TCP
            - name: metrics
              containerPort: 3001
              protocol: TCP

          # Environment
          envFrom:
            - configMapRef:
                name: rmap-config
            - secretRef:
                name: rmap-secrets

          # Resources
          resources:
            requests:
              cpu: 500m
              memory: 512Mi
            limits:
              cpu: 2000m
              memory: 2Gi

          # Health checks
          livenessProbe:
            httpGet:
              path: /api/v1/health
              port: 8080
            initialDelaySeconds: 30
            periodSeconds: 10
            timeoutSeconds: 5
            failureThreshold: 3

          readinessProbe:
            httpGet:
              path: /api/v1/health
              port: 8080
            initialDelaySeconds: 10
            periodSeconds: 5
            timeoutSeconds: 3
            successThreshold: 1

          # Volumes
          volumeMounts:
            - name: tmp
              mountPath: /tmp
            - name: data
              mountPath: /data

      volumes:
        - name: tmp
          emptyDir:
            sizeLimit: 100Mi
        - name: data
          persistentVolumeClaim:
            claimName: rmap-data

      # Affinity (spread pods across nodes)
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
                topologyKey: kubernetes.io/hostname

      # Tolerations (if using tainted nodes)
      tolerations:
        - key: "workload"
          operator: "Equal"
          value: "scanning"
          effect: "NoSchedule"
```

### Service

**service.yaml:**

```yaml
apiVersion: v1
kind: Service
metadata:
  name: rmap-api
  namespace: rmap-prod
  labels:
    app: rmap
    component: api
spec:
  type: ClusterIP
  selector:
    app: rmap
    component: api
  ports:
    - name: http
      port: 8080
      targetPort: 8080
      protocol: TCP
    - name: metrics
      port: 3001
      targetPort: 3001
      protocol: TCP
  sessionAffinity: ClientIP  # Sticky sessions for WebSocket
```

### Ingress

**ingress.yaml:**

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: rmap-ingress
  namespace: rmap-prod
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/rate-limit: "100"
    nginx.ingress.kubernetes.io/limit-rps: "10"
    nginx.ingress.kubernetes.io/proxy-body-size: "10m"
spec:
  ingressClassName: nginx
  tls:
    - hosts:
        - rmap.example.com
      secretName: rmap-tls
  rules:
    - host: rmap.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: rmap-api
                port:
                  number: 8080
```

### Horizontal Pod Autoscaler

**hpa.yaml:**

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: rmap-api-hpa
  namespace: rmap-prod
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: rmap-api
  minReplicas: 3
  maxReplicas: 10
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: 80
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
        - type: Percent
          value: 50
          periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
        - type: Percent
          value: 100
          periodSeconds: 30
        - type: Pods
          value: 2
          periodSeconds: 30
      selectPolicy: Max
```

### Deploy to Kubernetes

```bash
# Create namespace
kubectl apply -f namespace.yaml

# Create secrets (do this first!)
kubectl apply -f secrets.yaml

# Deploy resources
kubectl apply -f serviceaccount.yaml
kubectl apply -f configmap.yaml
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml
kubectl apply -f ingress.yaml
kubectl apply -f hpa.yaml

# Verify deployment
kubectl get all -n rmap-prod

# Check pod status
kubectl get pods -n rmap-prod -w

# View logs
kubectl logs -n rmap-prod -l app=rmap -f

# Test API
kubectl port-forward -n rmap-prod svc/rmap-api 8080:8080
curl http://localhost:8080/api/v1/health
```

---

## Security Hardening

### Container Security

**Best practices:**

1. **Use minimal base images** (distroless, alpine)
2. **Run as non-root user** (UID 65532)
3. **Read-only root filesystem**
4. **Drop all capabilities**, add only required
5. **No privileged containers**
6. **Resource limits** (prevent DoS)
7. **Network policies** (restrict traffic)
8. **Security scanning** (Trivy, Snyk)

**Network Policy:**

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: rmap-network-policy
  namespace: rmap-prod
spec:
  podSelector:
    matchLabels:
      app: rmap
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
    - from:
        - namespaceSelector:
            matchLabels:
              name: monitoring
      ports:
        - protocol: TCP
          port: 3001
  egress:
    - to:
        - podSelector: {}
      ports:
        - protocol: TCP
          port: 53  # DNS
        - protocol: UDP
          port: 53
    - to:
        - namespaceSelector: {}
      ports:
        - protocol: TCP
          port: 443  # HTTPS for scanning
        - protocol: TCP
          port: 80   # HTTP for scanning
```

### TLS/SSL Configuration

**Generate certificates:**

```bash
# Self-signed (development)
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout tls.key -out tls.crt \
  -subj "/CN=rmap.example.com"

# Create Kubernetes secret
kubectl create secret tls rmap-tls \
  --cert=tls.crt --key=tls.key \
  -n rmap-prod

# Production: Use cert-manager + Let's Encrypt
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml
```

**cert-manager ClusterIssuer:**

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: admin@example.com
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
      - http01:
          ingress:
            class: nginx
```

---

## Monitoring Setup

### Prometheus Configuration

**prometheus.yml:**

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'rmap-api'
    kubernetes_sd_configs:
      - role: pod
        namespaces:
          names:
            - rmap-prod
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
        action: keep
        regex: true
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_path]
        action: replace
        target_label: __metrics_path__
        regex: (.+)
      - source_labels: [__address__, __meta_kubernetes_pod_annotation_prometheus_io_port]
        action: replace
        regex: ([^:]+)(?::\d+)?;(\d+)
        replacement: $1:$2
        target_label: __address__
```

### Grafana Dashboards

**Import dashboard JSON:**

1. Login to Grafana
2. Go to Dashboards → Import
3. Upload `/grafana-dashboards/rmap-overview.json`
4. Select Prometheus data source

**Key metrics to monitor:**

- **Request rate:** `rate(http_requests_total[5m])`
- **Error rate:** `rate(http_requests_total{status=~"5.."}[5m])`
- **Latency (p95):** `histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))`
- **Active scans:** `scans_in_progress`
- **Memory usage:** `container_memory_usage_bytes`
- **CPU usage:** `rate(container_cpu_usage_seconds_total[5m])`

### Alerting

**PrometheusRule:**

```yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: rmap-alerts
  namespace: rmap-prod
spec:
  groups:
    - name: rmap
      interval: 30s
      rules:
        - alert: RMapHighErrorRate
          expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.05
          for: 5m
          labels:
            severity: warning
          annotations:
            summary: "High error rate detected"
            description: "Error rate is {{ $value | humanizePercentage }}"

        - alert: RMapPodDown
          expr: up{job="rmap-api"} == 0
          for: 2m
          labels:
            severity: critical
          annotations:
            summary: "R-Map pod is down"

        - alert: RMapHighMemory
          expr: container_memory_usage_bytes{pod=~"rmap-.*"} / container_spec_memory_limit_bytes > 0.9
          for: 5m
          labels:
            severity: warning
          annotations:
            summary: "High memory usage"
```

---

## High Availability

### Requirements

- **Minimum 3 replicas** across different nodes
- **Pod anti-affinity** to spread pods
- **PodDisruptionBudget** to prevent all pods down
- **Health checks** (liveness + readiness)
- **Load balancing** via Service/Ingress

**PodDisruptionBudget:**

```yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: rmap-api-pdb
  namespace: rmap-prod
spec:
  minAvailable: 2
  selector:
    matchLabels:
      app: rmap
      component: api
```

---

## Backup and Recovery

### Database Backup

**Backup script:**

```bash
#!/bin/bash
# backup-rmap.sh

NAMESPACE="rmap-prod"
POD=$(kubectl get pods -n $NAMESPACE -l app=rmap -o jsonpath='{.items[0].metadata.name}')
DATE=$(date +%Y%m%d_%H%M%S)

# Backup SQLite database
kubectl exec -n $NAMESPACE $POD -- sqlite3 /data/scans.db ".backup /tmp/backup.db"
kubectl cp $NAMESPACE/$POD:/tmp/backup.db ./rmap-backup-$DATE.db

# Upload to S3
aws s3 cp ./rmap-backup-$DATE.db s3://my-backups/rmap/

# Cleanup old backups (keep last 30 days)
find ./rmap-backup-*.db -mtime +30 -delete
```

**Cron job:**

```bash
# Add to crontab
0 2 * * * /path/to/backup-rmap.sh
```

---

## Production Checklist

### Pre-Deployment

- [ ] Security audit completed
- [ ] Load testing passed (10K+ hosts)
- [ ] Resource limits configured
- [ ] Secrets management in place
- [ ] TLS certificates configured
- [ ] Monitoring and alerting setup
- [ ] Backup strategy defined
- [ ] Disaster recovery plan documented
- [ ] Runbook created for operations team

### Post-Deployment

- [ ] Health checks passing
- [ ] Logs flowing to central logging
- [ ] Metrics visible in Grafana
- [ ] Alerts configured and tested
- [ ] Backup job running successfully
- [ ] Performance baseline established
- [ ] Documentation updated
- [ ] Team trained on operations

---

**Document Version:** 1.0
**Last Updated:** 2025-01-19
**Support:** support@r-map.io
