# R-Map Kubernetes Deployment - Quick Start Guide

## Prerequisites Check

```bash
# Verify you have the required tools
kubectl version --client
helm version
kustomize version  # Optional - kubectl has it built-in

# Verify cluster access
kubectl cluster-info
kubectl get nodes
```

## Option 1: Deploy with Kustomize (Simple)

### Development (Single Pod, Debug Mode)

```bash
# Deploy
kubectl apply -k /home/user/R-map/k8s/overlays/dev/

# Verify
kubectl get pods -n rmap-dev -l app=rmap -w

# Access (port-forward)
kubectl port-forward -n rmap-dev svc/dev-rmap 8080:8080

# Test
curl http://localhost:8080/health
```

### Staging (2 Pods, Auto-scaling)

```bash
# Deploy
kubectl apply -k /home/user/R-map/k8s/overlays/staging/

# Verify
kubectl get all -n rmap-staging -l app=rmap

# Check HPA
kubectl get hpa -n rmap-staging -w
```

### Production (3+ Pods, Full Security)

```bash
# ⚠️ IMPORTANT: Update secrets FIRST!
# Edit k8s/overlays/production/kustomization.yaml
# OR use Sealed Secrets / External Secrets

# Deploy
kubectl apply -k /home/user/R-map/k8s/overlays/production/

# Verify rollout
kubectl rollout status deployment/prod-rmap -n rmap-prod

# Check status
kubectl get all -n rmap-prod -l app=rmap
```

## Option 2: Deploy with Helm (Flexible)

### Development

```bash
helm install rmap-dev /home/user/R-map/helm/rmap \
  --namespace rmap-dev \
  --create-namespace \
  --values /home/user/R-map/helm/rmap/values-dev.yaml

# Check status
helm status rmap-dev -n rmap-dev
```

### Staging

```bash
helm install rmap-staging /home/user/R-map/helm/rmap \
  --namespace rmap-staging \
  --create-namespace \
  --values /home/user/R-map/helm/rmap/values-staging.yaml \
  --set secrets.jwtSecret=$(openssl rand -base64 32)

# Watch deployment
kubectl get pods -n rmap-staging -w
```

### Production

```bash
# Generate secure secret
export JWT_SECRET=$(openssl rand -base64 32)

# Install with specific version
helm install rmap-prod /home/user/R-map/helm/rmap \
  --namespace rmap-prod \
  --create-namespace \
  --values /home/user/R-map/helm/rmap/values-production.yaml \
  --set image.tag=v0.2.0 \
  --set secrets.jwtSecret=$JWT_SECRET

# Verify
helm list -n rmap-prod
kubectl get all -n rmap-prod
```

## Testing the Deployment

```bash
# 1. Check pod status
kubectl get pods -n <namespace>

# 2. Check logs
kubectl logs -n <namespace> -l app.kubernetes.io/name=rmap -f

# 3. Port-forward and test
kubectl port-forward -n <namespace> svc/<service-name> 8080:8080 3001:3001

# 4. Test health endpoint
curl http://localhost:8080/health

# 5. Test metrics endpoint
curl http://localhost:3001/metrics

# 6. Test API (example)
curl http://localhost:8080/api/v1/scan
```

## Enable Monitoring (Optional)

```bash
# Apply ServiceMonitor (requires Prometheus Operator)
kubectl apply -f /home/user/R-map/k8s/monitoring/servicemonitor.yaml -n <namespace>

# Apply PrometheusRule (alert rules)
kubectl apply -f /home/user/R-map/k8s/monitoring/prometheusrule.yaml -n <namespace>

# Or enable in Helm
helm upgrade rmap-prod /home/user/R-map/helm/rmap \
  --namespace rmap-prod \
  --reuse-values \
  --set monitoring.serviceMonitor.enabled=true \
  --set monitoring.prometheusRule.enabled=true
```

## Common Operations

### View Logs

```bash
# All pods
kubectl logs -n <namespace> -l app=rmap -f

# Specific pod
kubectl logs -n <namespace> <pod-name> -f

# Previous crashed container
kubectl logs -n <namespace> <pod-name> --previous
```

### Scale Manually

```bash
# Kustomize deployment
kubectl scale deployment/<deployment-name> -n <namespace> --replicas=5

# Helm deployment
kubectl scale deployment/rmap-prod -n rmap-prod --replicas=5
```

### Update Configuration

```bash
# Kustomize: Edit ConfigMap, then
kubectl apply -k /home/user/R-map/k8s/overlays/production/

# Helm: Update values, then
helm upgrade rmap-prod /home/user/R-map/helm/rmap \
  --namespace rmap-prod \
  --values /home/user/R-map/helm/rmap/values-production.yaml
```

### Rollback Deployment

```bash
# Kustomize
kubectl rollout undo deployment/<deployment-name> -n <namespace>

# Helm
helm rollback rmap-prod -n rmap-prod
```

## Troubleshooting Quick Reference

### Pod not starting (ImagePullBackOff)

```bash
kubectl describe pod <pod-name> -n <namespace>
# Check: image name, tag, pull secrets
```

### Pod crashing (CrashLoopBackOff)

```bash
kubectl logs <pod-name> -n <namespace> --previous
# Check: application logs, environment variables
```

### HPA not scaling

```bash
kubectl describe hpa -n <namespace>
# Check: metrics-server is running, resource requests are set
```

### Can't access via ingress

```bash
kubectl get ingress -n <namespace>
kubectl describe ingress <ingress-name> -n <namespace>
# Check: ingress controller, DNS, TLS certificates
```

### Secrets missing

```bash
kubectl get secrets -n <namespace>
kubectl describe secret <secret-name> -n <namespace>
```

## Security Checklist Before Production

- [ ] Replace JWT_SECRET with strong random value
- [ ] Use Sealed Secrets or External Secrets Operator
- [ ] Update ingress domain names
- [ ] Configure TLS certificates (cert-manager)
- [ ] Review NetworkPolicy rules
- [ ] Set appropriate resource limits
- [ ] Enable monitoring (ServiceMonitor + PrometheusRule)
- [ ] Test disaster recovery (backup/restore)
- [ ] Review RBAC permissions
- [ ] Enable audit logging

## Clean Up

```bash
# Kustomize
kubectl delete -k /home/user/R-map/k8s/overlays/<env>/

# Helm
helm uninstall <release-name> -n <namespace>

# Delete namespace (removes everything)
kubectl delete namespace <namespace>
```

## Next Steps

1. **Test in Development** - Deploy to dev, verify functionality
2. **Secret Management** - Set up Sealed Secrets or External Secrets
3. **Monitoring** - Install Prometheus Operator, enable ServiceMonitor
4. **Ingress** - Configure domain, TLS certificates
5. **Load Testing** - Verify auto-scaling works
6. **GitOps** - Set up ArgoCD or Flux for automated deployments

## Documentation

- **Full K8s Guide**: `/home/user/R-map/k8s/README.md`
- **Helm Chart Docs**: `/home/user/R-map/helm/rmap/README.md`
- **Summary**: `/home/user/R-map/KUBERNETES_DEPLOYMENT_SUMMARY.md`

## Support

- GitHub Issues: https://github.com/Ununp3ntium115/R-map/issues
- Documentation: https://github.com/Ununp3ntium115/R-map/docs
