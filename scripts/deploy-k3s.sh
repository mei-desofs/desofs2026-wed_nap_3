#!/bin/bash
set -e

echo "🚀 EnderChest k3s Deployment Script"
echo "===================================="

# Configuration
DOMAIN=${1:-enderchest.local}
EMAIL=${2:-admin@enderchest.local}
NAMESPACE=enderchest

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}[1/5] Installing k3s...${NC}"
curl -sfL https://get.k3s.io | sh -
sudo chmod 644 /etc/rancher/k3s/k3s.yaml
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml

echo -e "${BLUE}[2/5] Waiting for k3s to be ready...${NC}"
kubectl wait --for=condition=Ready node --all --timeout=300s

echo -e "${BLUE}[3/5] Installing Cert-Manager for HTTPS...${NC}"
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml
kubectl wait --for=condition=ready pod -l app.kubernetes.io/instance=cert-manager -n cert-manager --timeout=300s

echo -e "${BLUE}[4/5] Creating ClusterIssuer for Let's Encrypt...${NC}"
cat <<EOF | kubectl apply -f -
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: ${EMAIL}
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
    - http01:
        ingress:
          class: traefik
EOF

echo -e "${BLUE}[5/5] Creating EnderChest namespace and deploying...${NC}"
kubectl create namespace ${NAMESPACE} || true

# Build and push image to local registry (or use pre-built)
echo -e "${BLUE}Building Docker image...${NC}"
docker build -t enderchest-app:latest .
docker tag enderchest-app:latest localhost:5000/enderchest-app:latest
docker push localhost:5000/enderchest-app:latest || echo "Note: Local registry not available, using local image"

# Deploy with Helm
helm repo add bitnami https://charts.bitnami.com/bitnami || true
helm repo update

helm upgrade --install enderchest ./helm-chart \
  --namespace ${NAMESPACE} \
  --values ./helm-chart/values.yaml \
  --set ingress.hosts[0].host=${DOMAIN} \
  --set ingress.tls[0].hosts[0]=${DOMAIN} \
  --wait

echo -e "${GREEN}✅ Deployment Complete!${NC}"
echo ""
echo "📊 Access Points:"
echo "  HTTPS API:    https://${DOMAIN}"
echo "  Swagger UI:   https://${DOMAIN}/swagger-ui.html"
echo "  OpenAPI Spec: https://${DOMAIN}/v3/api-docs"
echo ""
echo "📋 Useful commands:"
echo "  kubectl get pods -n ${NAMESPACE}"
echo "  kubectl logs -f deployment/enderchest -n ${NAMESPACE}"
echo "  kubectl port-forward svc/enderchest-app 8080:8080 -n ${NAMESPACE}"
echo ""
echo "🔐 Certificate Status:"
kubectl get certificate -n ${NAMESPACE}
