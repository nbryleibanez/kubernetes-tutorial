# Kubernetes Tutorial: EKS Platform Essentials

This guide teaches beginner-intermediate DevOps/Platform engineers how to build an EKS-based platform using Terraform, Karpenter, Prometheus, Grafana, and Fluent Bit. It focuses on WHY each tool is chosen and WHAT each resource does, with practical callouts you can practice as you go.

## Who This Is For

- You are new to Kubernetes platform engineering but comfortable with CLI tools.
- You want a realistic, production-aligned setup, not a toy demo.
- You want hands-on practice with the same resources you will run in real
  clusters.

## What You Will Build

- A Terraform-managed VPC and EKS cluster
- A minimal managed node group for system workloads
- Karpenter for dynamic, cost-aware compute
- Prometheus + Grafana for metrics and dashboards
- Fluent Bit for log shipping to CloudWatch
- Argo CD for GitOps-driven delivery and drift correction

## Why This Stack

- **Terraform**: declarative, repeatable, and reviewable infrastructure changes.
- **EKS**: managed control plane reduces operational burden.
- **Karpenter**: scales nodes based on pod scheduling pressure, not fixed groups.
- **Prometheus/Grafana**: standard OSS monitoring stack with flexible dashboards.
- **Fluent Bit**: lightweight, reliable log forwarder.
- **Argo CD**: GitOps engine that keeps the cluster aligned with Git.

## Prerequisites

- AWS account with permissions to create VPC, EKS, IAM, EC2, and S3 resources.
- Configured AWS credentials (`aws sts get-caller-identity` should work).
- CLI tools: Terraform >= 1.9, AWS CLI v2, kubectl, Helm, and Git.
- Optional tools: `envsubst` (for templates) and `jq` (handy for JSON output).

## Directory Layout (Create This Locally)

If you are not using a repository checkout, create the structure below:

```bash
mkdir -p terraform
mkdir -p gitops/platform/karpenter
mkdir -p gitops/apps/hello-nginx
mkdir -p gitops/apps/inflate
mkdir -p gitops/logging
mkdir -p gitops/observability
mkdir -p gitops/argocd/applications
```

## Environment Setup

Store environment-specific values in `.env` so you can reuse them across
Terraform, kubectl, and AWS CLI commands.
Keep secrets out of `.env`; only store non-sensitive identifiers and names.

Create `.env` at the repo root:

```bash
cat <<'EOF' > .env
# Project identity
PROJECT_NAME=example-platform
ENVIRONMENT=dev
AWS_REGION=us-east-2
EKS_CLUSTER_NAME=example-platform-dev-eks

# Terraform backend
TF_STATE_BUCKET=example-platform-tf-state
TF_STATE_KEY=${ENVIRONMENT}/terraform.tfstate

# Logging
LOG_GROUP_NAME=/eks/${EKS_CLUSTER_NAME}/${ENVIRONMENT}
LOGGING_NAMESPACE=logging
FLUENT_BIT_SERVICE_ACCOUNT=fluent-bit

# Karpenter
KARPENTER_NODE_ROLE_NAME=${PROJECT_NAME}-${ENVIRONMENT}-karpenter-node-role
KARPENTER_DISCOVERY_TAG=${PROJECT_NAME}

# Argo CD
# Replace before sourcing. Angle brackets break shell parsing.
REPO_URL=https://github.com/your-org/your-repo.git
REPO_REVISION=main

# Helm chart versions (update after `helm search repo ... --versions`)
KARPENTER_CHART_VERSION=1.1.1
PROMETHEUS_CHART_VERSION=25.8.0
GRAFANA_CHART_VERSION=8.0.0
FLUENT_BIT_CHART_VERSION=0.47.7

# Terraform variable passthrough
TF_VAR_project_name=${PROJECT_NAME}
TF_VAR_environment=${ENVIRONMENT}
TF_VAR_region=${AWS_REGION}
TF_VAR_logging_namespace=${LOGGING_NAMESPACE}
TF_VAR_fluent_bit_service_account=${FLUENT_BIT_SERVICE_ACCOUNT}
EOF
```

You can copy the template instead:

```bash
cp .env.example .env
```

Load it into your shell (this expands derived variables like `LOG_GROUP_NAME`):

```bash
set -a
source .env
set +a
```

Terraform reads `TF_VAR_*` automatically, so no extra `tfvars` file is needed.

Why this matters: pinning Helm chart versions reduces surprise upgrades. If a
version is not found, run `helm search repo <chart> --versions | head -n 5` and
update the version in `.env`.

## Terraform Configuration

These files define your AWS infrastructure. Use them as-is before you apply.

### terraform/terraform.tf

Why: pins Terraform and provider versions, and configures remote state.

```hcl
# terraform/terraform.tf

terraform {
  required_version = ">= 1.9.0"

  backend "s3" {
    encrypt      = true
    use_lockfile = true
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.1"
    }
  }
}
```

### terraform/locals.tf

Why: locals centralize naming and tagging so you do not repeat values.

```hcl
# terraform/locals.tf

locals {
  common = {
    project_name = var.project_name
    environment  = var.environment
    region       = var.region
  }

  tags = {
    Environment      = local.common.environment
    Project          = local.common.project_name
    TerraformManaged = true
}
}
```

### terraform/variables.tf

Why: define environment-driven values that can be passed via `.env`.

```hcl
# terraform/variables.tf

variable "project_name" {
  description = "Project name used for naming and tags."
  type        = string
}

variable "environment" {
  description = "Environment name (e.g., dev, staging, prod)."
  type        = string
}

variable "region" {
  description = "AWS region for all resources."
  type        = string
}

variable "logging_namespace" {
  description = "Namespace for Fluent Bit and log shipping."
  type        = string
}

variable "fluent_bit_service_account" {
  description = "Service account name for Fluent Bit."
  type        = string
}
```

### terraform/providers.tf

Why: sets the AWS region and applies default tags to all resources.

```hcl
# terraform/providers.tf

provider "aws" {
  region = local.common.region

  default_tags {
    tags = local.tags
  }
}
```

### terraform/main.tf

Why: provisions VPC, EKS, Karpenter, and logging IAM resources with tested
community modules.

```hcl
# terraform/main.tf

data "aws_availability_zones" "available" {}
data "aws_caller_identity" "current" {}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "6.5.1"

  name = "${local.common.project_name}-${local.common.environment}-vpc"
  cidr = "10.0.0.0/16"

  azs             = slice(data.aws_availability_zones.available.names, 0, 3)
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]

  enable_nat_gateway = true
  single_nat_gateway = true

  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = 1
    "karpenter.sh/discovery"          = local.common.project_name
  }

  tags = local.tags
}

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "21.10.1"

  name               = "${local.common.project_name}-${local.common.environment}-eks"
  kubernetes_version = "1.34"

  endpoint_public_access                   = true
  endpoint_private_access                  = true
  enable_cluster_creator_admin_permissions = true

  control_plane_scaling_config = {
    tier = "standard"
  }

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  eks_managed_node_groups = {
    karpenter = {
      ami_type       = "AL2023_ARM_64_STANDARD"
      instance_types = ["m6g.large", "m6g.xlarge"]
      capacity_type  = "ON_DEMAND"

      min_size     = 1
      max_size     = 3
      desired_size = 1

      labels = {
        "karpenter.sh/controller" = "true"
      }
    }
  }

  addons = {
    coredns    = {}
    kube-proxy = {}
    vpc-cni = {
      before_compute = true
    }
    eks-pod-identity-agent = {
      before_compute = true
    }
  }

  node_security_group_tags = merge(local.tags, {
    "karpenter.sh/discovery" = local.common.project_name
  })

  tags = local.tags
}

module "karpenter" {
  source = "terraform-aws-modules/eks/aws//modules/karpenter"

  cluster_name = module.eks.cluster_name

  node_iam_role_use_name_prefix   = false
  node_iam_role_name              = "${local.common.project_name}-${local.common.environment}-karpenter-node-role"
  create_pod_identity_association = true

  node_iam_role_additional_policies = {
    AmazonSSMManagedInstanceCore = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
  }

  tags = local.tags
}

resource "aws_iam_policy" "fluent_bit_cloudwatch" {
  name = "${local.common.project_name}-${local.common.environment}-fluent-bit-cloudwatch"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:DescribeLogStreams",
          "logs:PutLogEvents",
          "logs:PutRetentionPolicy"
        ]
        Resource = "arn:aws:logs:${local.common.region}:${data.aws_caller_identity.current.account_id}:log-group:/eks/${module.eks.cluster_name}/${local.common.environment}*"
      }
    ]
  })
}

resource "aws_iam_role" "fluent_bit_pod_identity" {
  name = "${local.common.project_name}-${local.common.environment}-fluent-bit-pod-identity"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "pods.eks.amazonaws.com"
        }
        Action = [
          "sts:AssumeRole",
          "sts:TagSession"
        ]
      }
    ]
  })

  tags = local.tags
}

resource "aws_iam_role_policy_attachment" "fluent_bit_cloudwatch" {
  role       = aws_iam_role.fluent_bit_pod_identity.name
  policy_arn = aws_iam_policy.fluent_bit_cloudwatch.arn
}

resource "aws_eks_pod_identity_association" "fluent_bit" {
  cluster_name    = module.eks.cluster_name
  namespace       = var.logging_namespace
  service_account = var.fluent_bit_service_account
  role_arn        = aws_iam_role.fluent_bit_pod_identity.arn
}
```

### Why This Terraform Layout Matters

- **VPC**: private subnets keep worker nodes off the public internet.
- **EKS**: a managed control plane means fewer operational tasks.
- **Managed node group**: hosts critical system pods so Karpenter does not need
  to create nodes for its own controller.
- **Karpenter module**: creates IAM and pod identity resources needed for node
  provisioning.
- **Fluent Bit IAM**: policy + pod identity association for CloudWatch logging.

> Practice note: understand how node networking, IAM roles, and cluster add-ons work.

## Initialize and Apply

```bash
terraform -chdir=terraform init \
  -backend-config="bucket=$TF_STATE_BUCKET" \
  -backend-config="key=$TF_STATE_KEY" \
  -backend-config="region=$AWS_REGION"
terraform -chdir=terraform fmt -recursive
terraform -chdir=terraform validate
terraform -chdir=terraform plan
terraform -chdir=terraform apply
```

Expected: Terraform ends with `Apply complete` and no errors.

## Configure kubectl

```bash
aws eks update-kubeconfig --region "$AWS_REGION" --name "$EKS_CLUSTER_NAME"
kubectl get nodes
```

Expected: nodes are in `Ready` state.

Why this matters: confirms your kubeconfig points at the new cluster.

## Karpenter Configuration (Manifests)

Create `gitops/platform/karpenter/karpenter.yaml.tmpl`:

```yaml
# gitops/platform/karpenter/karpenter.yaml.tmpl
---
apiVersion: karpenter.k8s.aws/v1
kind: EC2NodeClass
metadata:
  name: default
spec:
  amiSelectorTerms:
    - alias: "al2023@v20260107"
  role: ${KARPENTER_NODE_ROLE_NAME}
  subnetSelectorTerms:
    - tags:
        karpenter.sh/discovery: ${KARPENTER_DISCOVERY_TAG}
  securityGroupSelectorTerms:
    - tags:
        karpenter.sh/discovery: ${KARPENTER_DISCOVERY_TAG}
  tags:
    karpenter.sh/discovery: ${KARPENTER_DISCOVERY_TAG}
---
apiVersion: karpenter.sh/v1
kind: NodePool
metadata:
  name: default
spec:
  template:
    spec:
      nodeClassRef:
        group: karpenter.k8s.aws
        kind: EC2NodeClass
        name: default
      requirements:
        - key: kubernetes.io/arch
          operator: In
          values: ["arm64"]
        - key: kubernetes.io/os
          operator: In
          values: ["linux"]
        - key: karpenter.sh/capacity-type
          operator: In
          values: ["spot", "on-demand"]
        - key: karpenter.k8s.aws/instance-category
          operator: In
          values: ["m", "c", "r"]
  limits:
    cpu: 8
  disruption:
    consolidationPolicy: WhenEmpty
    consolidateAfter: 30s
```

What it does:

- **EC2NodeClass**: picks AMIs, IAM role, and networking for EC2 nodes.
- **NodePool**: describes scheduling constraints and scaling limits.

Apply and verify:

```bash
envsubst < gitops/platform/karpenter/karpenter.yaml.tmpl > gitops/platform/karpenter/karpenter.yaml
kubectl apply -f gitops/platform/karpenter/karpenter.yaml
kubectl get ec2nodeclasses
kubectl get nodepools
```

Expected: you should see a `default` EC2NodeClass and NodePool.

> Practice note: Karpenter works because pods have resource requests. Without
> requests, the scheduler has no signal to trigger capacity.

## Install Karpenter (Helm)

Why: installs the controller that watches pending pods and creates nodes.

```bash
helm repo add karpenter https://charts.karpenter.sh
helm repo update

helm upgrade --install karpenter karpenter/karpenter \
  --version "$KARPENTER_CHART_VERSION" \
  --namespace karpenter \
  --create-namespace \
  --set clusterName="$EKS_CLUSTER_NAME" \
  --set clusterEndpoint=$(aws eks describe-cluster \
    --name "$EKS_CLUSTER_NAME" \
    --region "$AWS_REGION" \
    --query "cluster.endpoint" --output text)
```

Expected: `kubectl -n karpenter get pods` shows the controller running.

Important: the original command contained a typo (`$CLUSTERz` and a stray
backtick). Use the corrected version above.

## Scaling Demo (Workload Pressure)

Create `gitops/apps/inflate/inflate.yaml`:

```yaml
# gitops/apps/inflate/inflate.yaml

apiVersion: apps/v1
kind: Deployment
metadata:
  name: inflate
spec:
  replicas: 0
  selector:
    matchLabels:
      app: inflate
  template:
    metadata:
      labels:
        app: inflate
    spec:
      terminationGracePeriodSeconds: 0
      securityContext:
        runAsUser: 1000
        runAsGroup: 3000
        fsGroup: 2000
      containers:
        - name: inflate
          image: public.ecr.aws/eks-distro/kubernetes/pause:3.7
          resources:
            requests:
              cpu: 1
          securityContext:
            allowPrivilegeEscalation: false
```

Apply and scale:

```bash
kubectl apply -f gitops/apps/inflate/inflate.yaml
kubectl scale deployment inflate --replicas 5
kubectl get nodes -w
```

Expected: new nodes appear as Karpenter provisions capacity.

Why it works: the CPU request forces the scheduler to place pods, which
triggers Karpenter to create new nodes to satisfy demand.

> Practice note: labels and selectors tie Deployments to Pods.

## Monitoring: Prometheus and Grafana

Create `gitops/observability/prometheus-values.yaml`:

```yaml
alertmanager:
  persistentVolume:
    enabled: false

server:
  fullnameOverride: prometheus-server
  persistentVolume:
    enabled: false

extraScrapeConfigs: |
  - job_name: karpenter
    kubernetes_sd_configs:
      - role: endpoints
        namespaces:
          names:
            - kube-system
    relabel_configs:
      - source_labels:
          - __meta_kubernetes_endpoints_name
          - __meta_kubernetes_endpoint_port_name
        action: keep
        regex: karpenter;http-metrics
```

Create `gitops/observability/grafana-values.yaml`:

```yaml
datasources:
  datasources.yaml:
    apiVersion: 1
    datasources:
      - name: Prometheus
        type: prometheus
        version: 1
        url: http://prometheus-server:80
        access: proxy
dashboardProviders:
  dashboardproviders.yaml:
    apiVersion: 1
    providers:
      - name: "default"
        orgId: 1
        folder: ""
        type: file
        disableDeletion: false
        editable: true
        options:
          path: /var/lib/grafana/dashboards/default
dashboards:
  default:
    capacity-dashboard:
      url: https://karpenter.sh/preview/getting-started/getting-started-with-karpenter/karpenter-capacity-dashboard.json
    performance-dashboard:
      url: https://karpenter.sh/preview/getting-started/getting-started-with-karpenter/karpenter-performance-dashboard.json
```

Install charts:

```bash
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo add grafana https://grafana.github.io/helm-charts
helm repo update

kubectl create namespace monitoring
helm install prometheus prometheus-community/prometheus \
  --namespace monitoring \
  --version "$PROMETHEUS_CHART_VERSION" \
  --values gitops/observability/prometheus-values.yaml

helm install grafana grafana/grafana \
  --namespace monitoring \
  --version "$GRAFANA_CHART_VERSION" \
  --values gitops/observability/grafana-values.yaml
```

Expected: `kubectl -n monitoring get pods` shows Prometheus and Grafana pods
running.

Grafana access:

```bash
export POD_NAME=$(kubectl get pods -n monitoring -l "app.kubernetes.io/name=grafana,app.kubernetes.io/instance=grafana" -o jsonpath="{.items[0].metadata.name}")
kubectl -n monitoring port-forward "$POD_NAME" 3000
```

Why this matters: you can observe node churn, pod scheduling latency, and
capacity saturation, which are core operational signals for Karpenter.

## Logging: Fluent Bit to CloudWatch (Complete Pipeline)

Installing Fluent Bit alone does nothing. CloudWatch Logs is the destination,
and Fluent Bit is the pipeline that collects, enriches, and routes logs.

### Step 1: Provision IAM via Terraform

Fluent Bit needs rights to create log groups/streams and put log events. Those
IAM resources are defined in `terraform/main.tf`:

- `aws_iam_policy.fluent_bit_cloudwatch`
- `aws_iam_role.fluent_bit_pod_identity`
- `aws_eks_pod_identity_association.fluent_bit`

Apply (or re-apply) Terraform after adding them:

```bash
terraform -chdir=terraform apply
```

Important: the association expects `namespace=$LOGGING_NAMESPACE` and
`service_account=$FLUENT_BIT_SERVICE_ACCOUNT`. Keep those values aligned with
the Helm chart and your `.env` settings.

### Step 2: Configure Fluent Bit values

Create `gitops/logging/fluent-bit-values.yaml.tmpl`:

```yaml
serviceAccount:
  create: true
  name: ${FLUENT_BIT_SERVICE_ACCOUNT}

config:
  service: |
    [SERVICE]
        Flush        1
        Log_Level    info
        HTTP_Server  On
        HTTP_Listen  0.0.0.0
        HTTP_Port    2020
  inputs: |
    [INPUT]
        Name              tail
        Path              /var/log/containers/*.log
        Tag               kube.*
        Parser            docker
        Mem_Buf_Limit     5MB
        Skip_Long_Lines   On
  filters: |
    [FILTER]
        Name                kubernetes
        Match               kube.*
        Kube_Tag_Prefix      kube.var.log.containers.
        Merge_Log           On
        Keep_Log            Off
        K8S-Logging.Parser  On
        K8S-Logging.Exclude Off
  outputs: |
    [OUTPUT]
        Name              cloudwatch_logs
        Match             kube.*
        region            ${AWS_REGION}
        log_group_name    ${LOG_GROUP_NAME}
        log_stream_prefix fluent-bit-
        auto_create_group true
```

Render the values file:

```bash
envsubst < gitops/logging/fluent-bit-values.yaml.tmpl > gitops/logging/fluent-bit-values.yaml
```

Install Fluent Bit:

```bash
helm repo add fluent https://fluent.github.io/helm-charts
helm repo update
kubectl create namespace "$LOGGING_NAMESPACE"
helm upgrade --install fluent-bit fluent/fluent-bit \
  --namespace "$LOGGING_NAMESPACE" \
  --version "$FLUENT_BIT_CHART_VERSION" \
  --values gitops/logging/fluent-bit-values.yaml
```

Expected: `kubectl get pods -n "$LOGGING_NAMESPACE"` shows fluent-bit pods
running.

### Step 3: Set log retention

```bash
aws logs put-retention-policy \
  --log-group-name "$LOG_GROUP_NAME" \
  --retention-in-days 30 \
  --region "$AWS_REGION"
```

Why this matters: log retention controls cost and incident forensics depth.

### Validation

```bash
kubectl get pods -n "$LOGGING_NAMESPACE"
kubectl logs -n "$LOGGING_NAMESPACE" -l app.kubernetes.io/name=fluent-bit --tail=20

aws logs describe-log-groups \
  --log-group-name-prefix "$LOG_GROUP_NAME" \
  --region "$AWS_REGION"
```

CloudWatch console check:

- Open **CloudWatch -> Logs -> Log groups**.
- Select `$LOG_GROUP_NAME` and confirm new log streams with the
  `fluent-bit-` prefix.
- Open **Logs Insights** and set a time range like "Last 15 minutes".

Logs Insights query (console or CLI):

```
fields @timestamp, @message, kubernetes.namespace_name, kubernetes.pod_name
| sort @timestamp desc
| limit 20
```

CLI example (Logs Insights):

```bash
# Build the query and target log group/region.
QUERY='fields @timestamp, @message, kubernetes.namespace_name, kubernetes.pod_name | sort @timestamp desc | limit 20'
GROUP="$LOG_GROUP_NAME"
REGION="$AWS_REGION"

# macOS (BSD date)
START_TIME=$(date -u -v-15M +%s)
END_TIME=$(date -u +%s)

# Linux (GNU date) alternative:
# START_TIME=$(date -u -d '15 minutes ago' +%s)
# END_TIME=$(date -u +%s)

# Start the query for the last 15 minutes and capture the query ID.
QUERY_ID=$(aws logs start-query \
  --log-group-name "$GROUP" \
  --start-time "$START_TIME" \
  --end-time "$END_TIME" \
  --query-string "$QUERY" \
  --region "$REGION" \
  --query 'queryId' --output text)

# Poll for completion, then fetch results once the status is Complete.
for i in {1..30}; do
  STATUS=$(aws logs get-query-results \
    --query-id "$QUERY_ID" \
    --region "$REGION" \
    --query 'status' --output text)

  if [ "$STATUS" = "Complete" ]; then
    aws logs get-query-results \
      --query-id "$QUERY_ID" \
      --region "$REGION"
    break
  fi

  if [ "$STATUS" = "Failed" ] || [ "$STATUS" = "Cancelled" ]; then
    echo "Query status: $STATUS" >&2
    break
  fi

  sleep 2
done
```

Expected: results include `@message` entries from recent pods.

Filter examples:

```
fields @timestamp, @message, kubernetes.namespace_name, kubernetes.pod_name
| filter kubernetes.namespace_name = "logging"
| sort @timestamp desc
| limit 50
```

```
fields @timestamp, @message, kubernetes.namespace_name, kubernetes.pod_name
| filter kubernetes.pod_name like /fluent-bit/
| sort @timestamp desc
| limit 50
```

## GitOps: Argo CD

Why: GitOps makes Git the source of truth and continuously reconciles drift.
Argo CD is installed manually because it bootstraps itself.
Goal: install Argo CD, register a sample app, then validate and debug with
`kubectl` so you can practice day-to-day ops skills.

### Step 1: Install Argo CD

This installs Argo CD into its own namespace and waits for the API server to
be ready.

```bash
kubectl create namespace argocd --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -n argocd \
  -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml
kubectl -n argocd rollout status deployment/argocd-server --timeout=5m
```

### Step 2: Access the UI locally

Grab the initial admin password first so you can paste it right after the UI
loads. The port-forward stays open, so run it last and keep it running in the
current terminal.

```bash
kubectl -n argocd get secret argocd-initial-admin-secret \
  -o jsonpath="{.data.password}" | base64 --decode; echo
kubectl -n argocd port-forward svc/argocd-server 8080:443
```

Login at `https://localhost:8080` with user `admin` and the password from the
command above. Leave the port-forward running and use a second terminal for
the next steps. If something changes later, refresh the Argo CD UI to see live
sync status and events.

Why this step matters:

- The secret is a one-time bootstrap password; capture it before you start the
  port-forward so you can log in right away.
- Port-forwarding keeps the Argo CD API local to your machine (safer than
  exposing it publicly while you are learning).

Checkpoint: Argo CD health (use anytime)

```bash
kubectl -n argocd get pods -o wide
kubectl -n argocd describe deployment argocd-server
kubectl -n argocd get events --sort-by=.lastTimestamp | tail -n 20
```

### Step 3: Add a public-image app (Nginx)

These manifests define a small Nginx deployment and service that Argo CD can
sync from Git.

`gitops/apps/hello-nginx/serviceaccount.yaml`:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: hello-nginx
  namespace: apps
```

`gitops/apps/hello-nginx/deployment.yaml`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: hello-nginx
  namespace: apps
  labels:
    app: hello-nginx
spec:
  replicas: 1
  selector:
    matchLabels:
      app: hello-nginx
  template:
    metadata:
      labels:
        app: hello-nginx
    spec:
      serviceAccountName: hello-nginx
      containers:
        - name: nginx
          image: nginx:1.27-alpine
          ports:
            - containerPort: 80
          resources:
            requests:
              cpu: 50m
              memory: 64Mi
            limits:
              cpu: 200m
              memory: 128Mi
```

`gitops/apps/hello-nginx/service.yaml`:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: hello-nginx
  namespace: apps
  labels:
    app: hello-nginx
spec:
  type: ClusterIP
  selector:
    app: hello-nginx
  ports:
    - name: http
      port: 80
      targetPort: 80
```

### Step 4: Register the Application in Argo CD

This points Argo CD at the Git repo and auto-syncs the app into the cluster.
The `CreateNamespace` option ensures the `apps` namespace exists.

Save as `gitops/argocd/applications/hello-nginx.yaml.tmpl`:

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: hello-nginx
  namespace: argocd
spec:
  project: default
  source:
    repoURL: ${REPO_URL}
    targetRevision: ${REPO_REVISION}
    path: gitops/apps/hello-nginx
  destination:
    server: https://kubernetes.default.svc
    namespace: apps
  ignoreDifferences:
    - group: apps
      kind: Deployment
      name: hello-nginx
      namespace: apps
      jsonPointers:
        - /spec/replicas
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
      - CreateNamespace=true
```

Apply it:

```bash
envsubst < gitops/argocd/applications/hello-nginx.yaml.tmpl > gitops/argocd/applications/hello-nginx.yaml
kubectl apply -f gitops/argocd/applications/hello-nginx.yaml
```

Note: `ignoreDifferences` keeps Argo CD from fighting HPA-managed replica
counts later.

If the app goes `OutOfSync` or `Progressing`, check the Argo CD UI in your
browser to watch the live sync and resource status.

Expected: the application reaches `Synced` and `Healthy`.

Why this step matters:

- The `Application` resource is the GitOps contract: it tells Argo CD what
  repo, which revision, and what path to reconcile.
- `CreateNamespace=true` keeps the workflow hands-off by creating `apps`
  automatically.

Checkpoint: Application status (after registration)

```bash
kubectl -n argocd describe application hello-nginx
kubectl -n apps get deploy,rs,po,svc
kubectl -n apps rollout status deployment/hello-nginx --timeout=2m
kubectl -n apps describe pod -l app=hello-nginx
kubectl -n apps get endpoints hello-nginx -o wide
```

### Step 5: Validate the sync

The `port-forward` stays open, so run it in a new terminal while you keep using
your main one for checks.

```bash
kubectl -n argocd get applications
kubectl get pods -n apps

kubectl -n apps port-forward svc/hello-nginx 8081:80
curl -I http://localhost:8081
```

Confirm the app is reachable in your browser at `http://localhost:8081` or by
checking the `curl` response headers in the terminal.

Expected: `curl` returns `HTTP/1.1 200 OK`.

### Step 6: Demo GitOps auto-sync

This shows the CD loop in action: a Git change triggers Argo CD to reconcile
the cluster automatically.

1. Update `gitops/apps/hello-nginx/deployment.yaml` and change the image tag
   (for example, `nginx:1.27-alpine` -> `nginx:1.28-alpine`).

2. Commit and push the change:

```bash
git add gitops/apps/hello-nginx/deployment.yaml
git commit -m "Bump hello-nginx image"
git push
```

3. Watch the Argo CD UI for `Syncing` → `Healthy`, then confirm in the cluster:

```bash
kubectl -n apps get deploy hello-nginx
kubectl -n apps rollout status deployment/hello-nginx --timeout=2m
```

Expected: the Deployment shows a new replica set and the rollout completes.

### Step 7: Add scaling, safety, and policy controls

Now that Argo CD is syncing from Git, add guardrails and autoscaling so the
cluster enforces good defaults.

Prereqs:

- HPA requires `metrics-server` (`kubectl top pods` should work).
- NetworkPolicy requires a policy-capable CNI (EKS VPC CNI alone does not
  enforce policies; Calico/Cilium does).

Check metrics-server:

```bash
kubectl get apiservices v1beta1.metrics.k8s.io
kubectl top pods -n apps
```

Expected: `kubectl top pods -n apps` returns CPU/Memory values. If it errors or
shows no metrics, install metrics-server:

```bash
METRICS_SERVER_VERSION=v0.7.2
kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/download/$METRICS_SERVER_VERSION/components.yaml
```

Expected: metrics API becomes available and `kubectl top pods -n apps` returns
data. If the URL 404s, update `METRICS_SERVER_VERSION`.

Add namespace guardrails:

`gitops/apps/hello-nginx/resourcequota.yaml`:

```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: apps-quota
  namespace: apps
spec:
  hard:
    pods: "10"
    requests.cpu: "2"
    requests.memory: 2Gi
    limits.cpu: "4"
    limits.memory: 4Gi
```

`gitops/apps/hello-nginx/limitrange.yaml`:

```yaml
apiVersion: v1
kind: LimitRange
metadata:
  name: apps-defaults
  namespace: apps
spec:
  limits:
    - type: Container
      defaultRequest:
        cpu: 100m
        memory: 128Mi
      default:
        cpu: 500m
        memory: 512Mi
      min:
        cpu: 50m
        memory: 64Mi
      max:
        cpu: "1"
        memory: 1Gi
```

Add RBAC for the service account:

`gitops/apps/hello-nginx/role.yaml`:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: hello-nginx-read
  namespace: apps
rules:
  - apiGroups: [""]
    resources: ["pods", "services", "endpoints"]
    verbs: ["get", "list", "watch"]
```

`gitops/apps/hello-nginx/rolebinding.yaml`:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: hello-nginx-read
  namespace: apps
subjects:
  - kind: ServiceAccount
    name: hello-nginx
    namespace: apps
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: hello-nginx-read
```

Confirm the deployment already references `serviceAccountName: hello-nginx`
(set in Step 3). The validation commands below check it.

Add autoscaling and disruption protection:

`gitops/apps/hello-nginx/hpa.yaml`:

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: hello-nginx
  namespace: apps
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: hello-nginx
  minReplicas: 2
  maxReplicas: 5
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 60
```

`gitops/apps/hello-nginx/pdb.yaml`:

```yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: hello-nginx
  namespace: apps
spec:
  minAvailable: 1
  selector:
    matchLabels:
      app: hello-nginx
```

Add a network policy:

`gitops/apps/hello-nginx/networkpolicy.yaml`:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: hello-nginx
  namespace: apps
spec:
  podSelector:
    matchLabels:
      app: hello-nginx
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: apps
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
```

Commit and push so Argo CD syncs:

```bash
git add gitops/apps/hello-nginx
git commit -m "Add HPA, PDB, RBAC, quotas, and network policy"
git push
```

Validate and explore:

```bash
kubectl get hpa,pdb,netpol -n apps
kubectl get resourcequota,limitrange -n apps
kubectl describe hpa hello-nginx
kubectl top pods -n apps

kubectl -n apps get pod -l app=hello-nginx \
  -o jsonpath='{.items[0].spec.serviceAccountName}{"\n"}'
```

Expected: `kubectl get hpa -n apps` shows `TARGETS` with CPU percentages. If it
shows `<unknown>`, wait a minute or recheck metrics-server.

Optional: run a pod as the service account and check API access (works even
without impersonation rights):

```bash
kubectl -n apps run rbac-test --rm -it --image=curlimages/curl \
  --serviceaccount=hello-nginx -- sh
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -sSk -H "Authorization: Bearer $TOKEN" \
  https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT/api
```

If you have impersonation rights, you can also test RBAC directly:

```bash
kubectl auth can-i get pods -n apps \
  --as=system:serviceaccount:apps:hello-nginx
kubectl auth can-i get secrets -n apps \
  --as=system:serviceaccount:apps:hello-nginx
kubectl auth can-i get pods -n kube-system \
  --as=system:serviceaccount:apps:hello-nginx
```

Why this matters:

- **HPA + Karpenter**: HPA scales pods; Karpenter scales nodes to fit them.
- **PDB**: protects availability during voluntary disruptions.
- **ResourceQuota + LimitRange**: enforce defaults and prevent noisy neighbors.
- **RBAC + ServiceAccount**: least privilege limits blast radius.
- **NetworkPolicy**: blocks unexpected traffic paths when enforced by the CNI.

Notes:

- Set `REPO_URL` and `REPO_REVISION` in `.env` before rendering the template.
- Argo CD polls Git on a timer (default is a few minutes). If you want near
  real-time syncs, add a Git webhook later.
- If you prefer manual sync, remove the `automated` block and run
  `argocd app sync hello-nginx` when ready.

Auto-sync vs manual sync:

- Use auto-sync in dev or for low-risk apps so drift is fixed automatically.
- Use manual sync for prod or sensitive changes so humans review before apply.

Best practices (beginner-friendly):

- Use pull requests so Git history explains every change Argo CD applies.
- Keep `main` for dev/demo; promote to `release` or tags for production.
- Avoid committing rendered templates; keep only the source and render at deploy
  time.

Quick glossary:

- `Application`: the Argo CD custom resource that points to your Git repo.
- `repoURL`: the Git URL Argo CD reads from.
- `targetRevision`: the branch, tag, or commit to sync.

## Cleanup

Run cleanup while the cluster still exists so controllers can delete any cloud
resources they created.

Why this order matters:

- Remove apps first so Argo CD can prune them cleanly.
- Uninstall controllers before destroying the cluster to avoid dangling AWS
  resources (load balancers, ENIs, volumes).
- Destroy infrastructure last to avoid orphaned cloud resources.

If you are in a new shell, reload `.env` so the cleanup commands use the same
names and regions:

```bash
set -a
source .env
set +a
```

### Step 1: Remove GitOps apps and sample workloads

```bash
kubectl -n argocd delete application hello-nginx
kubectl delete -f gitops/apps/inflate/inflate.yaml

# Optional: delete the namespace if it only contains the demo app.
kubectl delete namespace apps
```

### Step 2: Uninstall Helm add-ons

```bash
helm uninstall karpenter -n karpenter
helm uninstall prometheus -n monitoring
helm uninstall grafana -n monitoring
helm uninstall fluent-bit -n "$LOGGING_NAMESPACE"

kubectl delete namespace karpenter
kubectl delete namespace monitoring
kubectl delete namespace "$LOGGING_NAMESPACE"
```

### Step 3: Remove Argo CD

```bash
kubectl delete namespace argocd
```

### Step 4: Delete CloudWatch logs (optional)

```bash
aws logs delete-log-group \
  --log-group-name "$LOG_GROUP_NAME" \
  --region "$AWS_REGION"
```

### Step 5: Destroy AWS infrastructure

This deletes the EKS cluster, VPC, and IAM roles created by Terraform. Double
check your AWS account and region before running it.

```bash
terraform -chdir=terraform destroy
```

Local cleanup (optional):

- Remove generated files: `gitops/platform/karpenter/karpenter.yaml`,
  `gitops/logging/fluent-bit-values.yaml`,
  `gitops/argocd/applications/hello-nginx.yaml`.
- Remove local Terraform cache: `rm -rf terraform/.terraform`.
- If you no longer need remote state, delete the S3 bucket used by
  `TF_STATE_BUCKET` after confirming it contains only this state file.

## Common Pitfalls (Call These Out Early)

- **EKS version**: confirm the configured version is supported in your region.
- **Karpenter AMI alias**: verify the alias exists in your account/region.
- **Missing discovery tags**: Karpenter will not find subnets/SGs without the
  `karpenter.sh/discovery` tag used above.
- **No resource requests**: autoscaling will not trigger without them.
- **Logging IAM**: missing CloudWatch permissions prevents log delivery.
- **Pod Identity mismatch**: `logging` namespace or `fluent-bit` service account
  mismatch breaks log delivery.
- **GitOps sync noise**: ensure Argo CD excludes `*-values.yaml`.

## Skill Practice Ideas

- Add memory requests/limits in `inflate.yaml` and observe scheduling changes.
- Use `kubectl describe pod` to interpret scheduling decisions.
- Practice rollout debugging with `kubectl rollout status` and `kubectl events`.
- Lower the HPA target and watch replica counts change.
- Tighten the `apps` ResourceQuota and observe admission errors.

## Next Steps

- Add GitOps promotion strategies once you have multiple environments.
- Introduce Loki for queryable logs and lower storage costs.
- Add real workloads and enforce PodDisruptionBudgets and NetworkPolicies.
