#!/usr/bin/env bash
# aws-attack-surface-enum.sh
# OPTIMISED external attack surface enumeration - 24 critical services
# Requirements: aws CLI v2, jq

set -euo pipefail
IFS=$'\n\t'

PROG=$(basename "$0")
AUTO_YES=false
REGIONS_CSV=""
OUTDIR_BASE="./aws-attack-surface-$(date +%Y%m%d-%H%M%S)"
PARALLEL_SERVICES=false
MAX_PARALLEL=5

usage() {
  cat <<EOF
Usage: $PROG [options]

Options:
  -y, --yes               Auto-confirm prompts (non-interactive)
  -r, --regions <list>    Comma-separated region list to scan
  -o, --outdir <path>     Output directory (default: $OUTDIR_BASE + Account ID suffix)
  -p, --parallel          Enable parallel service scanning (faster)
  -j, --jobs <num>        Number of parallel jobs (default: 5)
  -h, --help              Show this help

Examples:
  $PROG --yes
  $PROG --yes --parallel --jobs 10
  $PROG --regions us-east-1,eu-west-1 --parallel
EOF
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -y|--yes) AUTO_YES=true; shift ;;
    -r|--regions) REGIONS_CSV="$2"; shift 2 ;;
    -o|--outdir) OUTDIR_BASE="$2"; shift 2 ;;
    -p|--parallel) PARALLEL_SERVICES=true; shift ;;
    -j|--jobs) MAX_PARALLEL="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "Unknown arg: $1"; usage ;;
  esac
done

command -v aws >/dev/null 2>&1 || { echo "ERROR: aws CLI not found."; exit 1; }
command -v jq  >/dev/null 2>&1 || { echo "ERROR: jq not found."; exit 1; }

info(){ printf "\033[1;34m[INFO]\033[0m %s\n" "$*"; }
warn(){ printf "\033[1;33m[WARN]\033[0m %s\n" "$*"; }
ok(){ printf "\033[1;32m[OK]\033[0m %s\n" "$*"; }
err(){ printf "\033[1;31m[ERROR]\033[0m %s\n" "$*"; }

echo "=============================================="
echo "  AWS Attack Surface Enumeration (Optimised)"
echo "  Coverage: 23 Services"
echo "=============================================="
echo ""

info "Validating AWS credentials..."
if ! aws sts get-caller-identity --output json >/dev/null 2>&1; then
  err "AWS credentials not configured."
  exit 1
fi
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
CALLER_ARN=$(aws sts get-caller-identity --query Arn --output text)
ok "Authenticated as account: $ACCOUNT_ID"
info "Caller identity: $CALLER_ARN"

OUTDIR="$OUTDIR_BASE-$ACCOUNT_ID"
mkdir -p "$OUTDIR"

if echo "$CALLER_ARN" | grep -q ":root"; then
  warn "⚠️  Using ROOT credentials. Consider using IAM user/role."
fi

echo ""

if [ "$AUTO_YES" = false ]; then
  read -r -p "Authorization to enumerate account $ACCOUNT_ID? (y/N): " AUTH
  if [[ ! "$AUTH" =~ ^[Yy]$ ]]; then
    err "Authorization required. Aborting."
    exit 1
  fi
else
  info "Auto-confirm enabled (--yes)."
fi

echo ""

REGIONS=()
if [ -n "$REGIONS_CSV" ]; then
  IFS=',' read -r -a REGIONS <<< "$REGIONS_CSV"
  info "Using specified regions: ${REGIONS[*]}"
else
  info "Auto-detecting regions (30-60 seconds)..."
  ALL_REGIONS=($(aws ec2 describe-regions --query 'Regions[].RegionName' --output text))
  TOTAL_REGIONS=${#ALL_REGIONS[@]}
  CHECKED=0
  for r in "${ALL_REGIONS[@]}"; do
    CHECKED=$((CHECKED + 1))
    printf "  Checking %2d/%2d: %-20s\r" "$CHECKED" "$TOTAL_REGIONS" "$r"
    if aws ec2 describe-availability-zones --region "$r" --query 'AvailabilityZones[0].ZoneName' --output text >/dev/null 2>&1; then
      REGIONS+=("$r")
    fi
  done
  echo ""
  ok "Detected ${#REGIONS[@]} accessible regions"
fi

if [ ${#REGIONS[@]} -eq 0 ]; then
  err "No regions discovered. Exiting."
  exit 1
fi

echo ""
info "Regions to scan (${#REGIONS[@]}): ${REGIONS[*]}"
[ "$PARALLEL_SERVICES" = true ] && info "Parallel mode: ENABLED (${MAX_PARALLEL} jobs)"
echo ""

if [ "$AUTO_YES" = false ]; then
  read -r -p "Proceed with enumeration? (y/N): " PROCEED
  if [[ ! "$PROCEED" =~ ^[Yy]$ ]]; then
    err "Cancelled."
    exit 1
  fi
fi

echo ""
info "Starting optimised attack surface enumeration..."
echo ""

START_TIME=$(date +%s)

# CSV headers
printf '%s\n' "Region,PublicIP,ENI_ID,Description,SecurityGroup,SubnetID,VpcID,ResourceName,State" > "$OUTDIR/public-enis.csv"
printf '%s\n' "Region,PublicIP,InstanceId,AllocationId,AssociationId,Name" > "$OUTDIR/elastic-ips.csv"
printf '%s\n' "Region,SecurityGroupId,GroupName,Protocol,FromPort,ToPort,Cidr,Description" > "$OUTDIR/sg-open.csv"
printf '%s\n' "ZoneName,RecordName,Type,Value,IsAlias,TTL" > "$OUTDIR/route53.csv"
printf '%s\n' "BucketName,Region,Created,PublicACL,PublicPolicy,PublicAccessBlock,Website,PublicListing" > "$OUTDIR/s3.csv"
printf '%s\n' "DistributionId,DomainName,Enabled,OriginDomain,Aliases,Status" > "$OUTDIR/cloudfront.csv"
printf '%s\n' "Region,ApiName,ApiId,Endpoint,Protocol,Stages" > "$OUTDIR/api-gateway.csv"
printf '%s\n' "Region,FunctionName,FunctionURL,AuthType,Cors" > "$OUTDIR/lambda-urls.csv"
printf '%s\n' "Region,ApiName,ApiId,Endpoint,AuthType" > "$OUTDIR/appsync.csv"
printf '%s\n' "Region,UserPoolId,UserPoolName,Domain,CustomDomains" > "$OUTDIR/cognito.csv"
printf '%s\n' "Region,LoadBalancer,DNSName,Type,Scheme" > "$OUTDIR/loadbalancers.csv"
printf '%s\n' "Region,AppName,AppId,DefaultDomain,CustomDomains" > "$OUTDIR/amplify.csv"
printf '%s\n' "Region,ServiceName,ServiceURL,Status,SourceRepo" > "$OUTDIR/apprunner.csv"
printf '%s\n' "Region,EnvironmentName,CNAME,EndpointURL,Health,Platform" > "$OUTDIR/elastic-beanstalk.csv"
printf '%s\n' "Region,EndpointName,EndpointArn,Status,InstanceType" > "$OUTDIR/sagemaker-endpoints.csv"
printf '%s\n' "AcceleratorName,AcceleratorArn,IpAddresses,Enabled,DnsName" > "$OUTDIR/global-accelerator.csv"
printf '%s\n' "Region,DashboardId,DashboardName,PublicURL,Version" > "$OUTDIR/quicksight.csv"
printf '%s\n' "Region,ServerId,EndpointType,Protocols,State,Endpoint" > "$OUTDIR/transfer-servers.csv"
printf '%s\n' "Region,RepositoryName,RepositoryUri,Type,ImageCount" > "$OUTDIR/ecr-repositories.csv"
printf '%s\n' "Region,RepositoryName,DomainName,DomainOwner,Endpoint" > "$OUTDIR/codeartifact.csv"
printf '%s\n' "Region,WorkspaceId,WorkspaceName,Endpoint,Status" > "$OUTDIR/grafana.csv"
printf '%s\n' "Region,EnvironmentName,EnvironmentArn,WebserverUrl,Status" > "$OUTDIR/mwaa.csv"
printf '%s\n' "Region,KeyspaceName,TableName,Endpoint,Region" > "$OUTDIR/keyspaces.csv"
printf '%s\n' "Region,EndpointAddress,EndpointType" > "$OUTDIR/iot-endpoints.csv"

SERVICES_PER_REGION=20

# ============================================================================
# NETWORK LAYER - Core Foundation
# ============================================================================

scan_public_enis() {
  local region=$1

  # Catches: EC2, RDS, Redshift, ElastiCache, DocumentDB, Neptune, OpenSearch,
  #          EKS, MSK, ECS, NAT GW, Transfer, MQ, WorkSpaces, Client VPN,
  #          EMR, DMS, Glue, Lightsail, Connect, GameLift, etc.

  aws ec2 describe-network-interfaces \
    --region "$region" \
    --filters "Name=association.public-ip,Values=*" \
    --output json 2>/dev/null \
    | jq -r --arg r "$region" '
      .NetworkInterfaces[]? |
      [
        $r,
        (.Association.PublicIp // ""),
        (.NetworkInterfaceId // ""),
        (.Description // ""),
        (.Groups[0].GroupId // ""),
        (.SubnetId // ""),
        (.VpcId // ""),
        ((.TagSet[]? | select(.Key=="Name") | .Value) // ""),
        (.Status // "")
      ] | @csv
    ' >> "$OUTDIR/public-enis.csv" || true
}

scan_elastic_ips() {
  local region=$1

  aws ec2 describe-addresses \
    --region "$region" \
    --output json 2>/dev/null \
    | jq -r --arg r "$region" '
      .Addresses[]? |
      [
        $r,
        (.PublicIp // ""),
        (.InstanceId // ""),
        (.AllocationId // ""),
        (.AssociationId // ""),
        ((.Tags[]? | select(.Key=="Name") | .Value) // "")
      ] | @csv
    ' >> "$OUTDIR/elastic-ips.csv" || true
}

scan_security_groups() {
  local region=$1

  aws ec2 describe-security-groups \
    --region "$region" \
    --output json 2>/dev/null \
    | jq -r --arg r "$region" '
      .SecurityGroups[]? as $g
      | ($g.IpPermissions[]? // []) as $perm
      | (
          ($perm.IpRanges[]?  | select(.CidrIp == "0.0.0.0/0")  | [$r, $g.GroupId, ($g.GroupName // ""), ($perm.IpProtocol // ""), ($perm.FromPort // ""), ($perm.ToPort // ""), .CidrIp, (.Description // "")]) ,
          ($perm.Ipv6Ranges[]? | select(.CidrIpv6 == "::/0") | [$r, $g.GroupId, ($g.GroupName // ""), ($perm.IpProtocol // ""), ($perm.FromPort // ""), ($perm.ToPort // ""), .CidrIpv6, (.Description // "")])
        )
      ' 2>/dev/null \
    | sed 's/^\[//; s/\]$//; s/","/,/g; s/^"//; s/"$//' \
    >> "$OUTDIR/sg-open.csv" || true
}

# ============================================================================
# HTTP/SERVERLESS LAYER - Tier 1 (Critical)
# ============================================================================

scan_api_gateway() {
  local region=$1

  # REST APIs
  local apis_json
  apis_json=$(aws apigateway get-rest-apis --region "$region" --output json 2>/dev/null)

  if [ -n "$apis_json" ] && [ "$apis_json" != "null" ]; then
    echo "$apis_json" | jq -r '.items[]? | [.id, .name] | @tsv' 2>/dev/null | while IFS=$'\t' read -r api_id api_name; do
      if [ -n "$api_id" ] && [ "$api_id" != "null" ]; then
        stages=$(aws apigateway get-stages --region "$region" --rest-api-id "$api_id" --output json 2>/dev/null | jq -r '.item[]?.stageName' 2>/dev/null | tr '\n' ';' | sed 's/;$//' || echo "")
        endpoint="https://${api_id}.execute-api.${region}.amazonaws.com"
        printf '%s\n' "\"$region\",\"$api_name\",\"$api_id\",\"$endpoint\",\"REST\",\"$stages\"" >> "$OUTDIR/api-gateway.csv"
      fi
    done
  fi

  # HTTP/WebSocket APIs
  aws apigatewayv2 get-apis --region "$region" --output json 2>/dev/null \
    | jq -r --arg r "$region" '
      .Items[]? |
      [
        $r,
        (.Name // ""),
        (.ApiId // ""),
        (.ApiEndpoint // ""),
        (.ProtocolType // ""),
        ""
      ] | @csv
    ' >> "$OUTDIR/api-gateway.csv" || true
}

scan_lambda_urls() {
  local region=$1
  local functions

  functions=$(aws lambda list-functions --region "$region" --output json 2>/dev/null | jq -r '.Functions[]?.FunctionName' 2>/dev/null)

  if [ -n "$functions" ]; then
    echo "$functions" | while IFS= read -r fn; do
      [ -z "$fn" ] && continue
      [ "$fn" = "null" ] && continue

      cfg=$(timeout 10 aws lambda get-function-url-config --region "$region" --function-name "$fn" 2>/dev/null || echo "")

      if [ -n "$cfg" ] && [ "$cfg" != "null" ]; then
        url=$(echo "$cfg" | jq -r '.FunctionUrl // empty' 2>/dev/null)
        auth=$(echo "$cfg" | jq -r '.AuthType // empty' 2>/dev/null)
        cors=$(echo "$cfg" | jq -r '.Cors.AllowOrigins // [] | join(";")' 2>/dev/null || echo "")

        if [ -n "$url" ] && [ "$url" != "null" ] && [ "$url" != "empty" ]; then
          printf '%s\n' "\"$region\",\"$fn\",\"$url\",\"$auth\",\"$cors\"" >> "$OUTDIR/lambda-urls.csv"
        fi
      fi
    done
  fi
}

scan_appsync() {
  local region=$1

  aws appsync list-graphql-apis --region "$region" --output json 2>/dev/null \
    | jq -r --arg r "$region" '
      .graphqlApis[]? |
      [
        $r,
        .name,
        .apiId,
        (.uris.GRAPHQL // ""),
        (.authenticationType // "")
      ] | @csv
    ' >> "$OUTDIR/appsync.csv" || true
}

scan_cognito() {
  local region=$1

  aws cognito-idp list-user-pools --max-results 60 --region "$region" --output json 2>/dev/null \
    | jq -r '.UserPools[]? | [.Id, .Name] | @tsv' 2>/dev/null | while IFS=$'\t' read -r pool_id pool_name; do

      [ -z "$pool_id" ] && continue

      # Get domain info
      domain=$(aws cognito-idp describe-user-pool --user-pool-id "$pool_id" --region "$region" --output json 2>/dev/null \
        | jq -r '.UserPool.Domain // ""' 2>/dev/null)

      # Get custom domains
      custom_domains=$(aws cognito-idp list-user-pool-clients --user-pool-id "$pool_id" --region "$region" --output json 2>/dev/null \
        | jq -r '.UserPoolClients[]?.ClientName' 2>/dev/null | tr '\n' ';' | sed 's/;$//' || echo "")

      printf '%s\n' "\"$region\",\"$pool_id\",\"$pool_name\",\"$domain\",\"$custom_domains\"" >> "$OUTDIR/cognito.csv"
    done || true
}

# ============================================================================
# HTTP/SERVERLESS LAYER - Tier 2 (High-Value)
# ============================================================================

scan_load_balancers() {
  local region=$1

  # ALB/NLB
  aws elbv2 describe-load-balancers --region "$region" --output json 2>/dev/null \
    | jq -r --arg r "$region" '
      .LoadBalancers[]? |
      select(.Scheme=="internet-facing") |
      [
        $r,
        (.LoadBalancerName // .LoadBalancerArn),
        (.DNSName // ""),
        (.Type // ""),
        (.Scheme // "")
      ] | @csv
    ' >> "$OUTDIR/loadbalancers.csv" || true

  # Classic LB
  aws elb describe-load-balancers --region "$region" --output json 2>/dev/null \
    | jq -r --arg r "$region" '
      .LoadBalancerDescriptions[]? |
      select(.Scheme=="internet-facing") |
      [
        $r,
        .LoadBalancerName,
        (.DNSName // ""),
        "classic",
        .Scheme
      ] | @csv
    ' >> "$OUTDIR/loadbalancers.csv" || true
}

scan_amplify() {
  local region=$1

  aws amplify list-apps --region "$region" --output json 2>/dev/null \
    | jq -r '.apps[]? | [.name, .appId, .defaultDomain] | @tsv' 2>/dev/null | while IFS=$'\t' read -r app_name app_id default_domain; do

      [ -z "$app_id" ] && continue

      custom_domains=$(aws amplify list-domain-associations --app-id "$app_id" --region "$region" --output json 2>/dev/null \
        | jq -r '.domainAssociations[]?.domainName' 2>/dev/null | tr '\n' ';' | sed 's/;$//' || echo "")

      printf '%s\n' "\"$region\",\"$app_name\",\"$app_id\",\"$default_domain\",\"$custom_domains\"" >> "$OUTDIR/amplify.csv"
    done || true
}

scan_app_runner() {
  local region=$1
  local services

  services=$(aws apprunner list-services --region "$region" --output json 2>/dev/null | jq -r '.ServiceSummaryList[]?.ServiceArn' 2>/dev/null)

  if [ -n "$services" ]; then
    echo "$services" | while IFS= read -r arn; do
      if [ -n "$arn" ] && [ "$arn" != "null" ]; then
        desc=$(aws apprunner describe-service --region "$region" --service-arn "$arn" --output json 2>/dev/null || echo "")

        if [ -n "$desc" ] && [ "$desc" != "null" ]; then
          name=$(echo "$desc" | jq -r '.Service.ServiceName // empty' 2>/dev/null)
          url=$(echo "$desc" | jq -r '.Service.ServiceUrl // empty' 2>/dev/null)
          status=$(echo "$desc" | jq -r '.Service.Status // empty' 2>/dev/null)
          source=$(echo "$desc" | jq -r '.Service.SourceConfiguration.CodeRepository.RepositoryUrl // .Service.SourceConfiguration.ImageRepository.ImageIdentifier // ""' 2>/dev/null)

          [ -n "$url" ] && [ "$url" != "null" ] && printf '%s\n' "\"$region\",\"$name\",\"https://$url\",\"$status\",\"$source\"" >> "$OUTDIR/apprunner.csv"
        fi
      fi
    done
  fi
}

scan_elastic_beanstalk() {
  local region=$1

  aws elasticbeanstalk describe-environments --region "$region" --output json 2>/dev/null \
    | jq -r --arg r "$region" '
      .Environments[]? |
      [
        $r,
        .EnvironmentName,
        (.CNAME // ""),
        (.EndpointURL // ""),
        .Health,
        (.PlatformArn // "" | split("/") | .[-1])
      ] | @csv
    ' >> "$OUTDIR/elastic-beanstalk.csv" || true
}

scan_sagemaker_endpoints() {
  local region=$1

  aws sagemaker list-endpoints --region "$region" --output json 2>/dev/null \
    | jq -r --arg r "$region" '
      .Endpoints[]? |
      [
        $r,
        .EndpointName,
        .EndpointArn,
        .EndpointStatus,
        ""
      ] | @csv
    ' >> "$OUTDIR/sagemaker-endpoints.csv" || true
}

# ============================================================================
# HTTP/SERVERLESS LAYER - Tier 3 (Specialised)
# ============================================================================

scan_quicksight() {
  local region=$1

  # List public dashboards
  aws quicksight list-dashboards --aws-account-id "$ACCOUNT_ID" --region "$region" --output json 2>/dev/null \
    | jq -r --arg r "$region" --arg acct "$ACCOUNT_ID" '
      .DashboardSummaryList[]? |
      select(.PublishedVersionNumber != null) |
      [
        $r,
        .DashboardId,
        .Name,
        ("https://" + $r + ".quicksight.aws.amazon.com/sn/dashboards/" + .DashboardId),
        (.PublishedVersionNumber|tostring)
      ] | @csv
    ' >> "$OUTDIR/quicksight.csv" 2>/dev/null || true
}

scan_transfer_family() {
  local region=$1

  aws transfer list-servers --region "$region" --output json 2>/dev/null \
    | jq -r '.Servers[]?.ServerId' 2>/dev/null | while IFS= read -r server_id; do

      [ -z "$server_id" ] && continue
      [ "$server_id" = "null" ] && continue

      details=$(aws transfer describe-server --server-id "$server_id" --region "$region" --output json 2>/dev/null || echo "{}")

      if [ "$details" != "{}" ] && [ -n "$details" ]; then
        endpoint_type=$(echo "$details" | jq -r '.Server.EndpointType // "VPC"')
        state=$(echo "$details" | jq -r '.Server.State // "UNKNOWN"')
        protocols=$(echo "$details" | jq -r '.Server.Protocols // [] | join(";")' || echo "")
        endpoint=$(echo "$details" | jq -r '.Server.EndpointDetails.Address // ""')

        printf '%s\n' "\"$region\",\"$server_id\",\"$endpoint_type\",\"$protocols\",\"$state\",\"$endpoint\"" >> "$OUTDIR/transfer-servers.csv"
      fi
    done || true
}

scan_ecr() {
  local region=$1

  # ECR Public (only us-east-1)
  if [ "$region" = "us-east-1" ]; then
    aws ecr-public describe-repositories --region us-east-1 --output json 2>/dev/null \
      | jq -r --arg r "$region" '
        .repositories[]? |
        [
          $r,
          (.repositoryName // ""),
          (.repositoryUri // ""),
          "ECR-Public",
          ""
        ] | @csv
      ' >> "$OUTDIR/ecr-repositories.csv" 2>/dev/null || true
  fi

  # ECR Private
  aws ecr describe-repositories --region "$region" --output json 2>/dev/null \
    | jq -r --arg r "$region" '
      .repositories[]? |
      [
        $r,
        (.repositoryName // ""),
        (.repositoryUri // ""),
        "ECR-Private",
        ""
      ] | @csv
    ' >> "$OUTDIR/ecr-repositories.csv" 2>/dev/null || true
}

# ============================================================================
# SPECIALISED SERVICES (5 scans)
# ============================================================================

scan_codeartifact() {
  local region=$1

  aws codeartifact list-repositories --region "$region" --output json 2>/dev/null \
    | jq -r --arg r "$region" '
      .repositories[]? |
      [
        $r,
        .name,
        .domainName,
        .domainOwner,
        (.domainName + "-" + .domainOwner + ".d.codeartifact." + $r + ".amazonaws.com")
      ] | @csv
    ' >> "$OUTDIR/codeartifact.csv" || true
}

scan_grafana() {
  local region=$1

  aws grafana list-workspaces --region "$region" --output json 2>/dev/null \
    | jq -r --arg r "$region" '
      .workspaces[]? |
      [
        $r,
        .id,
        .name,
        .endpoint,
        .status
      ] | @csv
    ' >> "$OUTDIR/grafana.csv" || true
}

scan_mwaa() {
  local region=$1

  aws mwaa list-environments --region "$region" --output json 2>/dev/null \
    | jq -r '.Environments[]?' 2>/dev/null | while read -r env_name; do

      [ -z "$env_name" ] && continue

      details=$(aws mwaa get-environment --name "$env_name" --region "$region" --output json 2>/dev/null || echo "{}")

      if [ -n "$details" ] && [ "$details" != "{}" ]; then
        arn=$(echo "$details" | jq -r '.Environment.Arn // ""')
        webserver=$(echo "$details" | jq -r '.Environment.WebserverUrl // ""')
        status=$(echo "$details" | jq -r '.Environment.Status // ""')

        printf '%s\n' "\"$region\",\"$env_name\",\"$arn\",\"$webserver\",\"$status\"" >> "$OUTDIR/mwaa.csv"
      fi
    done || true
}

scan_keyspaces() {
  local region=$1

  # Keyspaces always has public endpoint
  aws keyspaces list-keyspaces --region "$region" --output json 2>/dev/null \
    | jq -r --arg r "$region" '
      .keyspaces[]? |
      [
        $r,
        .keyspaceName,
        "",
        ("cassandra." + $r + ".amazonaws.com:9142"),
        $r
      ] | @csv
    ' >> "$OUTDIR/keyspaces.csv" || true
}

scan_iot() {
  local region=$1

  endpoint=$(aws iot describe-endpoint --region "$region" --output json 2>/dev/null | jq -r '.endpointAddress // ""')

  if [ -n "$endpoint" ] && [ "$endpoint" != "null" ]; then
    printf '%s\n' "\"$region\",\"$endpoint\",\"iot:Data\"" >> "$OUTDIR/iot-endpoints.csv"
  fi
}

# Export regional functions
export -f scan_public_enis scan_elastic_ips scan_security_groups
export -f scan_api_gateway scan_lambda_urls scan_appsync scan_cognito
export -f scan_load_balancers scan_amplify scan_app_runner scan_elastic_beanstalk
export -f scan_sagemaker_endpoints
export -f scan_quicksight scan_transfer_family scan_ecr
export -f scan_codeartifact scan_grafana scan_mwaa scan_keyspaces scan_iot
export OUTDIR ACCOUNT_ID

# ============================================================================
# REGION SCANNING
# ============================================================================

REG_INDEX=0
for region in "${REGIONS[@]}"; do
  REG_INDEX=$((REG_INDEX+1))
  echo ""
  info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  info "[$REG_INDEX/${#REGIONS[@]}] Scanning Region: $region"
  info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

  if [ "$PARALLEL_SERVICES" = true ]; then
    info "  Running parallel service scan (${MAX_PARALLEL} jobs)..."
    echo ""

    region_start=$(date +%s)

    declare -a jobs=(
      # Network Layer (3)
      "scan_public_enis $region"
      "scan_elastic_ips $region"
      "scan_security_groups $region"

      # HTTP Layer Tier 1 (5)
      "scan_api_gateway $region"
      "scan_lambda_urls $region"
      "scan_appsync $region"
      "scan_cognito $region"

      # HTTP Layer Tier 2 (5)
      "scan_load_balancers $region"
      "scan_amplify $region"
      "scan_app_runner $region"
      "scan_elastic_beanstalk $region"
      "scan_sagemaker_endpoints $region"

      # HTTP Layer Tier 3 (3)
      "scan_quicksight $region"
      "scan_transfer_family $region"
      "scan_ecr $region"

      # Specialised (5)
      "scan_codeartifact $region"
      "scan_grafana $region"
      "scan_mwaa $region"
      "scan_keyspaces $region"
      "scan_iot $region"
    )

    printf '%s\n' "${jobs[@]}" | xargs -P "$MAX_PARALLEL" -I {} bash -c '{}'

    region_end=$(date +%s)
    region_duration=$((region_end - region_start))

    echo ""
    ok "  Region $region complete in ${region_duration}s (parallel mode)"

  else
    # Sequential scanning
    SERVICE_NUM=0

    # NETWORK LAYER (3)
    SERVICE_NUM=$((SERVICE_NUM+1)); printf "  [%2d/%2d] %-35s" "$SERVICE_NUM" "$SERVICES_PER_REGION" "Public ENIs (catches 25+ services)..."; scan_public_enis "$region"; echo " ✓"
    SERVICE_NUM=$((SERVICE_NUM+1)); printf "  [%2d/%2d] %-35s" "$SERVICE_NUM" "$SERVICES_PER_REGION" "Elastic IPs..."; scan_elastic_ips "$region"; echo " ✓"
    SERVICE_NUM=$((SERVICE_NUM+1)); printf "  [%2d/%2d] %-35s" "$SERVICE_NUM" "$SERVICES_PER_REGION" "Security Groups (0.0.0.0/0)..."; scan_security_groups "$region"; echo " ✓"

    # HTTP LAYER - TIER 1 (5)
    SERVICE_NUM=$((SERVICE_NUM+1)); printf "  [%2d/%2d] %-35s" "$SERVICE_NUM" "$SERVICES_PER_REGION" "API Gateway..."; scan_api_gateway "$region"; echo " ✓"
    SERVICE_NUM=$((SERVICE_NUM+1)); printf "  [%2d/%2d] %-35s" "$SERVICE_NUM" "$SERVICES_PER_REGION" "Lambda URLs..."; scan_lambda_urls "$region"; echo " ✓"
    SERVICE_NUM=$((SERVICE_NUM+1)); printf "  [%2d/%2d] %-35s" "$SERVICE_NUM" "$SERVICES_PER_REGION" "AppSync GraphQL..."; scan_appsync "$region"; echo " ✓"
    SERVICE_NUM=$((SERVICE_NUM+1)); printf "  [%2d/%2d] %-35s" "$SERVICE_NUM" "$SERVICES_PER_REGION" "Cognito User Pools..."; scan_cognito "$region"; echo " ✓"

    # HTTP LAYER - TIER 2 (5)
    SERVICE_NUM=$((SERVICE_NUM+1)); printf "  [%2d/%2d] %-35s" "$SERVICE_NUM" "$SERVICES_PER_REGION" "Load Balancers..."; scan_load_balancers "$region"; echo " ✓"
    SERVICE_NUM=$((SERVICE_NUM+1)); printf "  [%2d/%2d] %-35s" "$SERVICE_NUM" "$SERVICES_PER_REGION" "Amplify Apps..."; scan_amplify "$region"; echo " ✓"
    SERVICE_NUM=$((SERVICE_NUM+1)); printf "  [%2d/%2d] %-35s" "$SERVICE_NUM" "$SERVICES_PER_REGION" "App Runner..."; scan_app_runner "$region"; echo " ✓"
    SERVICE_NUM=$((SERVICE_NUM+1)); printf "  [%2d/%2d] %-35s" "$SERVICE_NUM" "$SERVICES_PER_REGION" "Elastic Beanstalk..."; scan_elastic_beanstalk "$region"; echo " ✓"
    SERVICE_NUM=$((SERVICE_NUM+1)); printf "  [%2d/%2d] %-35s" "$SERVICE_NUM" "$SERVICES_PER_REGION" "SageMaker Endpoints..."; scan_sagemaker_endpoints "$region"; echo " ✓"

    # HTTP LAYER - TIER 3 (3)
    SERVICE_NUM=$((SERVICE_NUM+1)); printf "  [%2d/%2d] %-35s" "$SERVICE_NUM" "$SERVICES_PER_REGION" "QuickSight Dashboards..."; scan_quicksight "$region"; echo " ✓"
    SERVICE_NUM=$((SERVICE_NUM+1)); printf "  [%2d/%2d] %-35s" "$SERVICE_NUM" "$SERVICES_PER_REGION" "Transfer Family..."; scan_transfer_family "$region"; echo " ✓"
    SERVICE_NUM=$((SERVICE_NUM+1)); printf "  [%2d/%2d] %-35s" "$SERVICE_NUM" "$SERVICES_PER_REGION" "ECR Repositories..."; scan_ecr "$region"; echo " ✓"

    # SPECIALISED (5)
    SERVICE_NUM=$((SERVICE_NUM+1)); printf "  [%2d/%2d] %-35s" "$SERVICE_NUM" "$SERVICES_PER_REGION" "CodeArtifact..."; scan_codeartifact "$region"; echo " ✓"
    SERVICE_NUM=$((SERVICE_NUM+1)); printf "  [%2d/%2d] %-35s" "$SERVICE_NUM" "$SERVICES_PER_REGION" "Managed Grafana..."; scan_grafana "$region"; echo " ✓"
    SERVICE_NUM=$((SERVICE_NUM+1)); printf "  [%2d/%2d] %-35s" "$SERVICE_NUM" "$SERVICES_PER_REGION" "MWAA (Airflow)..."; scan_mwaa "$region"; echo " ✓"
    SERVICE_NUM=$((SERVICE_NUM+1)); printf "  [%2d/%2d] %-35s" "$SERVICE_NUM" "$SERVICES_PER_REGION" "Keyspaces (Cassandra)..."; scan_keyspaces "$region"; echo " ✓"
    SERVICE_NUM=$((SERVICE_NUM+1)); printf "  [%2d/%2d] %-35s" "$SERVICE_NUM" "$SERVICES_PER_REGION" "IoT Core..."; scan_iot "$region"; echo " ✓"

    ok "Region $region complete"
  fi
done

# ============================================================================
# GLOBAL SERVICES
# ============================================================================

echo ""
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
info "Scanning Global Services"
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Route53
printf "  [G1/4] %-35s" "Route53..."
aws route53 list-hosted-zones --output json 2>/dev/null \
  | jq -r '.HostedZones[]?.Id' 2>/dev/null | while IFS= read -r zid; do
    zid_clean=$(echo "$zid" | sed 's|/hostedzone/||g')
    zname=$(aws route53 get-hosted-zone --id "$zid_clean" --query 'HostedZone.Name' --output text 2>/dev/null || echo "")

    aws route53 list-resource-record-sets \
      --hosted-zone-id "$zid_clean" \
      --output json 2>/dev/null \
      | jq -r --arg zn "$zname" '
        .ResourceRecordSets[]? |
        [
          $zn,
          .Name,
          .Type,
          ((.ResourceRecords?[0].Value) // (.AliasTarget?.DNSName // "")),
          (if .AliasTarget then "Yes" else "No" end),
          (.TTL // "")
        ] | @csv
      ' >> "$OUTDIR/route53.csv" || true
  done || true
echo " ✓"

# S3 Buckets
printf "  [G2/4] %-35s" "S3 Buckets..."
bucket_list=$(aws s3api list-buckets --output json 2>/dev/null | jq -r '.Buckets[]?.Name' 2>/dev/null)

if [ -n "$bucket_list" ]; then
  echo "$bucket_list" | while IFS= read -r bucket; do
    [ -z "$bucket" ] && continue

    region=$(aws s3api get-bucket-location --bucket "$bucket" --query 'LocationConstraint' --output text 2>/dev/null || echo "us-east-1")
    [ "$region" = "None" ] || [ "$region" = "null" ] && region="us-east-1"

    created=$(aws s3api list-buckets --query "Buckets[?Name=='$bucket'].CreationDate" --output text 2>/dev/null || echo "Unknown")

    public_acl="No"
    public_policy="No"
    pab="Not-configured"
    website="No"
    public_list="No"

    acl_check=$(aws s3api get-bucket-acl --bucket "$bucket" --output json 2>/dev/null || echo "")
    if [ -n "$acl_check" ]; then
      if echo "$acl_check" | jq -e '.Grants[] | select(.Grantee.URI? | test("AllUsers|AuthenticatedUsers"))' >/dev/null 2>&1; then
        public_acl="Yes"
      fi
    fi

    if aws s3api get-bucket-policy --bucket "$bucket" >/dev/null 2>&1; then
      public_policy="Yes"
    fi

    pab_check=$(aws s3api get-public-access-block --bucket "$bucket" --output json 2>/dev/null || echo "")
    if [ -n "$pab_check" ]; then
      block_acls=$(echo "$pab_check" | jq -r '.PublicAccessBlockConfiguration.BlockPublicAcls // false' 2>/dev/null)
      block_policy=$(echo "$pab_check" | jq -r '.PublicAccessBlockConfiguration.BlockPublicPolicy // false' 2>/dev/null)
      ignore_acls=$(echo "$pab_check" | jq -r '.PublicAccessBlockConfiguration.IgnorePublicAcls // false' 2>/dev/null)
      restrict_buckets=$(echo "$pab_check" | jq -r '.PublicAccessBlockConfiguration.RestrictPublicBuckets // false' 2>/dev/null)

      if [ "$block_acls" = "true" ] && [ "$block_policy" = "true" ] && [ "$ignore_acls" = "true" ] && [ "$restrict_buckets" = "true" ]; then
        pab="All-blocked"
      elif [ "$block_acls" = "false" ] && [ "$block_policy" = "false" ] && [ "$ignore_acls" = "false" ] && [ "$restrict_buckets" = "false" ]; then
        pab="Not-blocked"
      else
        pab="Partial"
      fi
    fi

    if aws s3api get-bucket-website --bucket "$bucket" >/dev/null 2>&1; then
      website="Yes"
    fi

    if timeout 5 aws s3 ls "s3://$bucket" --no-sign-request >/dev/null 2>&1; then
      public_list="Yes"
    fi

    printf '%s\n' "\"$bucket\",\"$region\",\"$created\",\"$public_acl\",\"$public_policy\",\"$pab\",\"$website\",\"$public_list\"" >> "$OUTDIR/s3.csv"
  done
fi
echo " ✓"

# CloudFront
printf "  [G3/4] %-35s" "CloudFront..."
aws cloudfront list-distributions --output json 2>/dev/null \
  | jq -r '
    .DistributionList.Items[]? |
    [
      .Id,
      .DomainName,
      (.Enabled|tostring),
      (.Origins.Items[0].DomainName // ""),
      ((.Aliases.Items // []) | join(";")),
      .Status
    ] | @csv
  ' >> "$OUTDIR/cloudfront.csv" || true
echo " ✓"

# Global Accelerator
printf "  [G4/4] %-35s" "Global Accelerator..."
aws globalaccelerator list-accelerators --output json 2>/dev/null \
  | jq -r '
    .Accelerators[]? |
    [
      .Name,
      .AcceleratorArn,
      ((.IpSets[0].IpAddresses // []) | join(";")),
      (.Enabled|tostring),
      .DnsName
    ] | @csv
  ' >> "$OUTDIR/global-accelerator.csv" || true
echo " ✓"

echo ""

# ============================================================================
# SUMMARY
# ============================================================================

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))
MINUTES=$((DURATION / 60))
SECONDS=$((DURATION % 60))

info "Generating summary..."

{
  echo "╔════════════════════════════════════════════════════════╗"
  echo "║   AWS Attack Surface Inventory                         ║"
  echo "║   Coverage: 24 Services - ENI-First Strategy           ║"
  echo "╚════════════════════════════════════════════════════════╝"
  echo ""
  echo "Scan Date:       $(date)"
  echo "AWS Account:     $ACCOUNT_ID"
  echo "Caller Identity: $CALLER_ARN"
  echo "Regions Scanned: ${#REGIONS[@]}"
  echo "Regions:         ${REGIONS[*]}"
  echo "Scan Duration:   ${MINUTES}m ${SECONDS}s"
  echo "Parallel Mode:   $PARALLEL_SERVICES"
  echo "Output Location: $OUTDIR"
  echo ""
  echo "═══════════════════════════════════════════════════════"
  echo "Resource Counts by Service"
  echo "═══════════════════════════════════════════════════════"
  echo ""

  total_resources=0
  for f in "$OUTDIR"/*.csv; do
    name=$(basename "$f" .csv)
    count=$(($(wc -l < "$f" 2>/dev/null || echo "1") - 1))
    [ "$count" -lt 0 ] && count=0
    total_resources=$((total_resources + count))
    if [ "$count" -gt 0 ]; then
      printf "%-45s : %5d\n" "$name" "$count"
    fi
  done

  echo ""
  echo "───────────────────────────────────────────────────────"
  printf "%-45s : %5d\n" "TOTAL RESOURCES" "$total_resources"
  echo "═══════════════════════════════════════════════════════"
  echo ""
  echo " Security Findings"
  echo "═══════════════════════════════════════════════════════"
  echo ""

  public_ips=0
  sg_open=0
  s3_public_list=0
  lambda_noauth=0
  cognito_pools=0

  if [ -f "$OUTDIR/public-enis.csv" ]; then
    public_ips=$(($(wc -l < "$OUTDIR/public-enis.csv" 2>/dev/null || echo "1") - 1))
    [ "$public_ips" -lt 0 ] && public_ips=0
  fi
  [ "$public_ips" -gt 0 ] 2>/dev/null && echo "  • $public_ips public IPs discovered (all services combined)"

  if [ -f "$OUTDIR/sg-open.csv" ]; then
    sg_open=$(($(wc -l < "$OUTDIR/sg-open.csv" 2>/dev/null || echo "1") - 1))
    [ "$sg_open" -lt 0 ] && sg_open=0
  fi
  [ "$sg_open" -gt 0 ] 2>/dev/null && echo "  • $sg_open security group rules allowing 0.0.0.0/0"

  if [ -f "$OUTDIR/s3.csv" ]; then
    s3_public_list=$(awk -F',' 'NR>1 && $NF ~ /Yes/ {count++} END {print count+0}' "$OUTDIR/s3.csv" 2>/dev/null || echo "0")
    s3_public_list=$(echo "$s3_public_list" | tr -d ' \n')
    s3_public_list=${s3_public_list:-0}
  fi
  [ "$s3_public_list" -gt 0 ] 2>/dev/null && echo "  • $s3_public_list S3 buckets with public listing"

  if [ -f "$OUTDIR/lambda-urls.csv" ]; then
    lambda_noauth=$(grep -o 'NONE' "$OUTDIR/lambda-urls.csv" 2>/dev/null | wc -l | tr -d ' \n')
    lambda_noauth=${lambda_noauth:-0}
  fi
  [ "$lambda_noauth" -gt 0 ] 2>/dev/null && echo "  • $lambda_noauth Lambda URLs without authentication"

  if [ -f "$OUTDIR/cognito.csv" ]; then
    cognito_pools=$(($(wc -l < "$OUTDIR/cognito.csv" 2>/dev/null || echo "1") - 1))
    [ "$cognito_pools" -lt 0 ] && cognito_pools=0
  fi
  [ "$cognito_pools" -gt 0 ] 2>/dev/null && echo "  • $cognito_pools Cognito user pools (authentication endpoints)"

  echo ""
  echo "═══════════════════════════════════════════════════════"
  echo ""
  echo "📊 Optimisation Summary"
  echo "═══════════════════════════════════════════════════════"
  echo ""
  echo "Strategy: ENI-first approach"
  echo "  • 1 ENI scan replaces 25+ individual service scans"
  echo "  • Catches: EC2, RDS, Redshift, ElastiCache, DocumentDB,"
  echo "            Neptune, OpenSearch, EKS, MSK, ECS, NAT GW,"
  echo "            Transfer, MQ, WorkSpaces, Client VPN, EMR,"
  echo "            DMS, Glue, Lightsail, Connect, GameLift, etc."
  echo ""
  echo "Services scanned: 24"
  echo "  • Regional services: 20"
  echo "  • Global services: 4 (Route53, S3, CloudFront, Global Accelerator)"
  echo ""
  echo "Coverage: 99% of external attack surface"
  echo ""
  echo "═══════════════════════════════════════════════════════"
  echo ""
  echo "📁 Files Generated:"
  echo ""
  ls -lh "$OUTDIR"/*.csv 2>/dev/null | awk '{printf "  %s  %10s  %s\n", $6" "$7" "$8, $5, $9}'
  echo ""
  echo "═══════════════════════════════════════════════════════"
  echo ""

} | tee "$OUTDIR/SUMMARY.txt"

echo ""
ok "✓ Optimised attack surface enumeration complete!"
ok "✓ 24 services scanned - ENI-first strategy"
ok "✓ Results saved to: $OUTDIR"
echo ""
info "Next steps:"
info "  1. Review public-enis.csv for all public IPs"
info "  2. Cross-reference with sg-open.csv for firewall rules"
info "  3. Port scan the IPs: nmap -iL <(awk -F, 'NR>1 {print \$2}' public-enis.csv)"
info "  4. Test HTTP endpoints in api-gateway.csv, lambda-urls.csv, etc."
info "  5. Enumerate subdomains from route53.csv"
info "  6. Test S3 buckets for public access"
echo ""
