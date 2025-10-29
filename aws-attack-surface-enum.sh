#!/usr/bin/env bash
# aws-attack-surface-enum.sh
# Improved AWS external attack surface enumeration
# - Safer parallel writes (tmp files + merge)
# - AWS retry/backoff wrapper + timeouts
# - --profile and --assume-role-arn support
# Requirements: aws CLI v2, jq, timeout (coreutils), md5sum (or shasum), xargs

set -euo pipefail
IFS=$'\n\t'

PROG=$(basename "$0")
AUTO_YES=false
REGIONS_CSV=""
OUTDIR_BASE="./aws-attack-surface-$(date +%Y%m%d-%H%M%S)"
PARALLEL_SERVICES=false
MAX_PARALLEL=5
AWS_PROFILE=""
ASSUME_ROLE_ARN=""
TMPDIR=""
AWS_TIMEOUT=25
AWS_CALL_MAX_ATTEMPTS=3

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
  --profile <name>        AWS profile to use (sets AWS_PROFILE)
  --assume-role <arn>     Assume role ARN (STS assume-role used; exports temp creds)

Examples:
  $PROG --yes
  $PROG --yes --parallel --jobs 10
  $PROG --regions us-east-1,eu-west-1 --parallel
  $PROG --yes --profile production --assume-role arn:aws:iam::123456789012:role/SecurityAuditRole
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
    --profile) AWS_PROFILE="$2"; shift 2 ;;
    --assume-role) ASSUME_ROLE_ARN="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "Unknown arg: $1"; usage ;;
  esac
done

command -v aws >/dev/null 2>&1 || { echo "ERROR: aws CLI not found."; exit 1; }
command -v jq  >/dev/null 2>&1 || { echo "ERROR: jq not found."; exit 1; }
command -v timeout >/dev/null 2>&1 || { echo "ERROR: timeout not found (install coreutils)."; exit 1; }
command -v md5sum >/dev/null 2>&1 || { command -v shasum >/dev/null 2>&1 || echo "WARNING: md5sum/shasum not found; tmp filenames may collide."; }

# Helpers for colored output
info(){ printf "\033[1;34m[INFO]\033[0m %s\n" "$*"; }
warn(){ printf "\033[1;33m[WARN]\033[0m %s\n" "$*"; }
ok(){ printf "\033[1;32m[OK]\033[0m %s\n" "$*"; }
err(){ printf "\033[1;31m[ERROR]\033[0m %s\n" "$*"; }

# Disable AWS CLI pager which can hang scripts
export AWS_PAGER=""
# If profile provided, set AWS_PROFILE env var (aws cli will use it)
[ -n "$AWS_PROFILE" ] && export AWS_PROFILE="$AWS_PROFILE"

# Temporary directory for parallel outputs
TMPDIR=$(mktemp -d -t aws-ase-XXXX) || TMPDIR="/tmp/aws-ase-$$"
trap 'rc=$?; rm -rf "$TMPDIR"; exit $rc' EXIT INT TERM

# aws_call: wrapper to execute aws CLI with retries/backoff and timeout
# Usage: aws_call aws ec2 describe-instances --region us-east-1 --output json
aws_call() {
  local attempts=0
  local max=$AWS_CALL_MAX_ATTEMPTS
  local delay=1
  # Build the command array
  local -a cmd=( "$@" )
  while true; do
    # Use timeout to avoid hanging; allow caller to pipe output
    if timeout "$AWS_TIMEOUT" "${cmd[@]}"; then
      return 0
    else
      attempts=$((attempts+1))
      if [ "$attempts" -ge "$max" ]; then
        warn "aws_call: giving up after $attempts attempts: ${cmd[*]}"
        return 1
      fi
      warn "aws_call: attempt $attempts failed; retrying in ${delay}s..."
      sleep "$delay"
      delay=$((delay * 2))
    fi
  done
}

# assume_role: if ASSUME_ROLE_ARN provided, assume role and export temporary creds
assume_role_if_requested() {
  if [ -z "$ASSUME_ROLE_ARN" ]; then
    return 0
  fi
  info "Assuming role: $ASSUME_ROLE_ARN"
  creds_json=$(aws_call aws sts assume-role --role-arn "$ASSUME_ROLE_ARN" --role-session-name "aws-ase-session-$$" --output json 2>/dev/null) || {
    err "Failed to assume role $ASSUME_ROLE_ARN"
    return 1
  }
  export AWS_ACCESS_KEY_ID=$(echo "$creds_json" | jq -r '.Credentials.AccessKeyId')
  export AWS_SECRET_ACCESS_KEY=$(echo "$creds_json" | jq -r '.Credentials.SecretAccessKey')
  export AWS_SESSION_TOKEN=$(echo "$creds_json" | jq -r '.Credentials.SessionToken')
  ok "Assumed role and exported temporary credentials"
}

echo "=============================================="
echo "  AWS Attack Surface Enumeration (v2)"
echo "  Coverage: 33 Services"
echo "=============================================="
echo ""

# Validate AWS credentials
info "Validating AWS credentials..."
if ! aws_call aws sts get-caller-identity --output json >/dev/null 2>&1; then
  err "AWS credentials not configured or not valid."
  exit 1
fi

# If user requested assume role, perform it (after initial validation)
if [ -n "$ASSUME_ROLE_ARN" ]; then
  assume_role_if_requested || exit 1
fi

# Re-check identity after assume-role (if used)
if ! caller_json=$(aws_call aws sts get-caller-identity --output json 2>/dev/null); then
  err "Failed to get caller identity after assume/validation"
  exit 1
fi
ACCOUNT_ID=$(echo "$caller_json" | jq -r '.Account')
CALLER_ARN=$(echo "$caller_json" | jq -r '.Arn')

ok "Authenticated as account: $ACCOUNT_ID"
info "Caller identity: $CALLER_ARN"

OUTDIR="$OUTDIR_BASE-$ACCOUNT_ID"
mkdir -p "$OUTDIR"
mkdir -p "$OUTDIR/raw"

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

# Regions detection
REGIONS=()
if [ -n "$REGIONS_CSV" ]; then
  IFS=',' read -r -a REGIONS <<< "$REGIONS_CSV"
  info "Using specified regions: ${REGIONS[*]}"
else
  info "Auto-detecting regions (30-60s)..."
  mapfile -t ALL_REGIONS < <(aws_call aws ec2 describe-regions --query 'Regions[].RegionName' --output text 2>/dev/null | tr '\t' '\n' || true)
  TOTAL_REGIONS=${#ALL_REGIONS[@]}
  CHECKED=0
  for r in "${ALL_REGIONS[@]}"; do
    CHECKED=$((CHECKED + 1))
    printf "  Checking %2d/%2d: %-20s\r" "$CHECKED" "$TOTAL_REGIONS" "$r"
    if aws_call aws ec2 describe-availability-zones --region "$r" --query 'AvailabilityZones[0].ZoneName' --output text >/dev/null 2>&1; then
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

# CSV filenames and headers (list all we will produce)
declare -A CSV_HEADERS
CSV_HEADERS=(
  ["public-enis.csv"]="Region,PublicIP,ENI_ID,Description,SecurityGroup,SubnetID,VpcID,ResourceName,State"
  ["elastic-ips.csv"]="Region,PublicIP,InstanceId,AllocationId,AssociationId,Name"
  ["sg-open.csv"]="Region,SecurityGroupId,GroupName,Protocol,FromPort,ToPort,Cidr,Description"
  ["route53.csv"]="ZoneName,RecordName,Type,Value,IsAlias,TTL"
  ["s3.csv"]="BucketName,Region,Created,PublicACL,PublicPolicy,PublicAccessBlock,Website,PublicListing"
  ["cloudfront.csv"]="DistributionId,DomainName,Enabled,OriginDomain,Aliases,Status"
  ["api-gateway.csv"]="Region,ApiName,ApiId,Endpoint,Protocol,Stages"
  ["lambda-urls.csv"]="Region,FunctionName,FunctionURL,AuthType,Cors"
  ["appsync.csv"]="Region,ApiName,ApiId,Endpoint,AuthType"
  ["cognito.csv"]="Region,UserPoolId,UserPoolName,Domain,CustomDomains"
  ["loadbalancers.csv"]="Region,LoadBalancer,DNSName,Type,Scheme"
  ["amplify.csv"]="Region,AppName,AppId,DefaultDomain,CustomDomains"
  ["apprunner.csv"]="Region,ServiceName,ServiceURL,Status,SourceRepo"
  ["elastic-beanstalk.csv"]="Region,EnvironmentName,CNAME,EndpointURL,Health,Platform"
  ["sagemaker-endpoints.csv"]="Region,EndpointName,EndpointArn,EndpointStatus,InstanceType"
  ["global-accelerator.csv"]="AcceleratorName,AcceleratorArn,IpAddresses,Enabled,DnsName"
  ["quicksight.csv"]="Region,DashboardId,DashboardName,PublicURL,Version"
  ["transfer-servers.csv"]="Region,ServerId,EndpointType,Protocols,State,Endpoint"
  ["ecr-repositories.csv"]="Region,RepositoryName,RepositoryUri,Type,ImageCount"
  ["codeartifact.csv"]="Region,RepositoryName,DomainName,DomainOwner,Endpoint"
  ["grafana.csv"]="Region,WorkspaceId,WorkspaceName,Endpoint,Status"
  ["mwaa.csv"]="Region,EnvironmentName,EnvironmentArn,WebserverUrl,Status"
  ["keyspaces.csv"]="Region,KeyspaceName,TableName,Endpoint,Region"
  ["iot-endpoints.csv"]="Region,EndpointAddress,EndpointType"
  ["rds.csv"]="Region,DBInstanceIdentifier,Endpoint,PubliclyAccessible,Status"
  ["redshift.csv"]="Region,ClusterIdentifier,Endpoint,PubliclyAccessible,Status"
  ["opensearch.csv"]="Region,DomainName,Endpoint,Status"
  ["msk.csv"]="Region,ClusterName,ClusterArn,Status,Brokers"
  ["elasticache.csv"]="Region,CacheClusterId,PrimaryEndpoint,Engine,Status"
  ["docdb.csv"]="Region,DBInstanceIdentifier,Endpoint,PubliclyAccessible,Status"
  ["neptune.csv"]="Region,DBInstanceIdentifier,Endpoint,PubliclyAccessible,Status"
  ["memorydb.csv"]="Region,ClusterName,Endpoint,Status,Engine"
  ["timestream.csv"]="Region,DatabaseName,Arn,IngestEndpoint,QueryEndpoint"
)

# Create CSV files with headers
for f in "${!CSV_HEADERS[@]}"; do
  printf '%s\n' "${CSV_HEADERS[$f]}" > "$OUTDIR/$f"
done

# Utility: write CSV row safely into a tmp file for service-region
write_tmp_csv() {
  local csvfile="$1"
  local row="$2"
  local marker="$3"
  local idpart
  if command -v md5sum >/dev/null 2>&1; then
    idpart=$(printf "%s" "${csvfile}-${marker}-${RANDOM}-$$" | md5sum | awk '{print $1}')
  else
    idpart=$(printf "%s" "${csvfile}-${marker}-${RANDOM}-$$" | shasum | awk '{print $1}')
  fi
  printf '%s\n' "$row" >> "$TMPDIR/${csvfile}.${idpart}.tmp"
}

# Deduplicate & merge tmp files into final csv (safe)
merge_tmp_csv() {
  local csvfile="$1"
  local final="$OUTDIR/$csvfile"
  if compgen -G "$TMPDIR/${csvfile}.*.tmp" >/dev/null 2>&1; then
    awk 'BEGIN{FS=OFS=","} {gsub("\r",""); print}' "$TMPDIR/${csvfile}."*.tmp | sort -u >> "$final"
    rm -f "$TMPDIR/${csvfile}."*.tmp || true
  fi
}

# ============================================================================
# Scanners
# ============================================================================

scan_public_enis() {
  local region=$1
  if ! data=$(aws_call aws ec2 describe-network-interfaces --region "$region" --filters "Name=association.public-ip,Values=*" --output json 2>/dev/null); then
    return 1
  fi
  printf '%s\n' "$data" > "$OUTDIR/raw/public-enis-${region}.json"
  echo "$data" | jq -r --arg r "$region" '
    .NetworkInterfaces[]? |
    [
      $r,
      (.Association.PublicIp // ""),
      (.NetworkInterfaceId // ""),
      (.Description // ""),
      ((.Groups[]? | .GroupId) // ""),
      (.SubnetId // ""),
      (.VpcId // ""),
      ((.TagSet[]? | select(.Key=="Name") | .Value) // ""),
      (.Status // "")
    ] | @csv
  ' 2>/dev/null | while IFS= read -r row; do
    [ -n "$row" ] && write_tmp_csv "public-enis.csv" "$row" "$region"
  done
}

scan_elastic_ips() {
  local region=$1
  if ! data=$(aws_call aws ec2 describe-addresses --region "$region" --output json 2>/dev/null); then
    return 1
  fi
  printf '%s\n' "$data" > "$OUTDIR/raw/elastic-ips-${region}.json"
  echo "$data" | jq -r --arg r "$region" '
    .Addresses[]? |
    [
      $r,
      (.PublicIp // ""),
      (.InstanceId // ""),
      (.AllocationId // ""),
      (.AssociationId // ""),
      ((.Tags[]? | select(.Key=="Name") | .Value) // "")
    ] | @csv
  ' 2>/dev/null | while IFS= read -r row; do
    [ -n "$row" ] && write_tmp_csv "elastic-ips.csv" "$row" "$region"
  done
}

scan_security_groups() {
  local region=$1
  if ! data=$(aws_call aws ec2 describe-security-groups --region "$region" --output json 2>/dev/null); then
    return 1
  fi
  printf '%s\n' "$data" > "$OUTDIR/raw/sg-${region}.json"

  # IPv4 open rules
  echo "$data" | jq -r --arg r "$region" '
    .SecurityGroups[]? as $g |
    $g.IpPermissions[]? as $perm |
    $perm.IpRanges[]? |
    select(.CidrIp == "0.0.0.0/0") |
    [
      $r,
      $g.GroupId,
      ($g.GroupName // ""),
      ($perm.IpProtocol // ""),
      (($perm.FromPort|tostring) // ""),
      (($perm.ToPort|tostring) // ""),
      .CidrIp,
      (.Description // "")
    ] | @csv
  ' 2>/dev/null | while IFS= read -r row; do
    [ -n "$row" ] && write_tmp_csv "sg-open.csv" "$row" "$region"
  done

  # IPv6 open rules
  echo "$data" | jq -r --arg r "$region" '
    .SecurityGroups[]? as $g |
    $g.IpPermissions[]? as $perm |
    $perm.Ipv6Ranges[]? |
    select(.CidrIpv6 == "::/0") |
    [
      $r,
      $g.GroupId,
      ($g.GroupName // ""),
      ($perm.IpProtocol // ""),
      (($perm.FromPort|tostring) // ""),
      (($perm.ToPort|tostring) // ""),
      .CidrIpv6,
      (.Description // "")
    ] | @csv
  ' 2>/dev/null | while IFS= read -r row; do
    [ -n "$row" ] && write_tmp_csv "sg-open.csv" "$row" "$region"
  done
}

scan_api_gateway() {
  local region=$1
  if rest=$(aws_call aws apigateway get-rest-apis --region "$region" --output json 2>/dev/null); then
    printf '%s\n' "$rest" > "$OUTDIR/raw/apigateway-rest-${region}.json"
    echo "$rest" | jq -r '.items[]? | [.name, .id] | @tsv' 2>/dev/null | while IFS=$'\t' read -r name id; do
      [ -z "$id" ] && continue
      stages=$(aws_call aws apigateway get-stages --region "$region" --rest-api-id "$id" --output json 2>/dev/null | jq -r '.item[]?.stageName' 2>/dev/null | tr '\n' ';' | sed 's/;$//' || echo "")
      endpoint="https://${id}.execute-api.${region}.amazonaws.com"
      row=$(jq -nr --arg r "$region" --arg n "$name" --arg id "$id" --arg ep "$endpoint" --arg prot "REST" --arg st "$stages" '[$r,$n,$id,$ep,$prot,$st] | @csv')
      write_tmp_csv "api-gateway.csv" "$row" "$region"
    done
  fi

  if apiv2=$(aws_call aws apigatewayv2 get-apis --region "$region" --output json 2>/dev/null); then
    printf '%s\n' "$apiv2" > "$OUTDIR/raw/apigateway-v2-${region}.json"
    echo "$apiv2" | jq -r --arg r "$region" '.Items[]? | [$r, (.Name // ""), (.ApiId // ""), (.ApiEndpoint // ""), (.ProtocolType // ""), ""] | @csv' 2>/dev/null | while IFS= read -r row; do
      [ -n "$row" ] && write_tmp_csv "api-gateway.csv" "$row" "$region"
    done
  fi
}

scan_lambda_urls() {
  local region=$1
  token=""
  while :; do
    if [ -z "$token" ]; then
      out=$(aws_call aws lambda list-functions --region "$region" --output json 2>/dev/null) || break
    else
      out=$(aws_call aws lambda list-functions --region "$region" --starting-token "$token" --output json 2>/dev/null) || break
    fi
    printf '%s\n' "$out" > "$OUTDIR/raw/lambda-list-${region}-${token:-first}.json"
    echo "$out" | jq -r '.Functions[]?.FunctionName' 2>/dev/null | while IFS= read -r fn; do
      [ -z "$fn" ] && continue
      cfg=$(timeout 10 aws lambda get-function-url-config --region "$region" --function-name "$fn" 2>/dev/null || echo "")
      if [ -n "$cfg" ]; then
        url=$(echo "$cfg" | jq -r '.FunctionUrl // empty' 2>/dev/null)
        auth=$(echo "$cfg" | jq -r '.AuthType // empty' 2>/dev/null)
        cors=$(echo "$cfg" | jq -r '.Cors.AllowOrigins // [] | join(";")' 2>/dev/null || echo "")
        if [ -n "$url" ]; then
          row=$(jq -nr --arg r "$region" --arg fn "$fn" --arg url "$url" --arg auth "$auth" --arg cors "$cors" '[$r,$fn,$url,$auth,$cors] | @csv')
          write_tmp_csv "lambda-urls.csv" "$row" "$region"
        fi
      fi
    done
    token=$(echo "$out" | jq -r '.NextMarker // empty' 2>/dev/null || echo "")
    [ -z "$token" ] && break
  done
}

scan_appsync() {
  local region=$1
  if data=$(aws_call aws appsync list-graphql-apis --region "$region" --output json 2>/dev/null); then
    printf '%s\n' "$data" > "$OUTDIR/raw/appsync-${region}.json"
    echo "$data" | jq -r --arg r "$region" '.graphqlApis[]? | [$r, .name, .apiId, (.uris.GRAPHQL // ""), (.authenticationType // "")] | @csv' 2>/dev/null | while IFS= read -r row; do
      [ -n "$row" ] && write_tmp_csv "appsync.csv" "$row" "$region"
    done
  fi
}

scan_cognito() {
  local region=$1
  if pools=$(aws_call aws cognito-idp list-user-pools --max-results 60 --region "$region" --output json 2>/dev/null); then
    printf '%s\n' "$pools" > "$OUTDIR/raw/cognito-list-${region}.json"
    echo "$pools" | jq -r '.UserPools[]? | [.Id, .Name] | @tsv' 2>/dev/null | while IFS=$'\t' read -r pool_id pool_name; do
      [ -z "$pool_id" ] && continue
      domain=$(aws_call aws cognito-idp describe-user-pool --user-pool-id "$pool_id" --region "$region" --output json 2>/dev/null | jq -r '.UserPool.Domain // ""' 2>/dev/null || echo "")
      custom_domains=$(aws_call aws cognito-idp list-user-pool-clients --user-pool-id "$pool_id" --region "$region" --output json 2>/dev/null | jq -r '.UserPoolClients[]?.ClientName' 2>/dev/null | tr '\n' ';' | sed 's/;$//' || echo "")
      row=$(jq -nr --arg r "$region" --arg id "$pool_id" --arg name "$pool_name" --arg dom "$domain" --arg cd "$custom_domains" '[$r,$id,$name,$dom,$cd] | @csv')
      write_tmp_csv "cognito.csv" "$row" "$region"
    done
  fi
}

scan_load_balancers() {
  local region=$1
  if lbs=$(aws_call aws elbv2 describe-load-balancers --region "$region" --output json 2>/dev/null); then
    printf '%s\n' "$lbs" > "$OUTDIR/raw/elbv2-${region}.json"
    echo "$lbs" | jq -r --arg r "$region" '.LoadBalancers[]? | select(.Scheme=="internet-facing") | [$r, (.LoadBalancerName // .LoadBalancerArn), (.DNSName // ""), (.Type // ""), (.Scheme // "")] | @csv' 2>/dev/null | while IFS= read -r row; do
      [ -n "$row" ] && write_tmp_csv "loadbalancers.csv" "$row" "$region"
    done
  fi

  if cl=$(aws_call aws elb describe-load-balancers --region "$region" --output json 2>/dev/null); then
    printf '%s\n' "$cl" > "$OUTDIR/raw/elb-classic-${region}.json"
    echo "$cl" | jq -r --arg r "$region" '.LoadBalancerDescriptions[]? | select(.Scheme=="internet-facing") | [$r, .LoadBalancerName, (.DNSName // ""), "classic", .Scheme] | @csv' 2>/dev/null | while IFS= read -r row; do
      [ -n "$row" ] && write_tmp_csv "loadbalancers.csv" "$row" "$region"
    done
  fi
}

scan_amplify() {
  local region=$1
  if data=$(aws_call aws amplify list-apps --region "$region" --output json 2>/dev/null); then
    printf '%s\n' "$data" > "$OUTDIR/raw/amplify-${region}.json"
    echo "$data" | jq -r '.apps[]? | [.name, .appId, .defaultDomain] | @tsv' 2>/dev/null | while IFS=$'\t' read -r app_name app_id default_domain; do
      [ -z "$app_id" ] && continue
      custom_domains=$(aws_call aws amplify list-domain-associations --app-id "$app_id" --region "$region" --output json 2>/dev/null | jq -r '.domainAssociations[]?.domainName' 2>/dev/null | tr '\n' ';' | sed 's/;$//' || echo "")
      row=$(jq -nr --arg r "$region" --arg app "$app_name" --arg id "$app_id" --arg def "$default_domain" --arg cd "$custom_domains" '[$r,$app,$id,$def,$cd] | @csv')
      write_tmp_csv "amplify.csv" "$row" "$region"
    done
  fi
}

scan_app_runner() {
  local region=$1
  if services=$(aws_call aws apprunner list-services --region "$region" --output json 2>/dev/null | jq -r '.ServiceSummaryList[]?.ServiceArn' 2>/dev/null); then
    printf '%s\n' "$services" > "$OUTDIR/raw/apprunner-list-${region}.txt"
    echo "$services" | while IFS= read -r arn; do
      [ -z "$arn" ] && continue
      desc=$(aws_call aws apprunner describe-service --region "$region" --service-arn "$arn" --output json 2>/dev/null || echo "")
      name=$(echo "$desc" | jq -r '.Service.ServiceName // empty' 2>/dev/null)
      url=$(echo "$desc" | jq -r '.Service.ServiceUrl // empty' 2>/dev/null)
      status=$(echo "$desc" | jq -r '.Service.Status // empty' 2>/dev/null)
      source=$(echo "$desc" | jq -r '.Service.SourceConfiguration.CodeRepository.RepositoryUrl // .Service.SourceConfiguration.ImageRepository.ImageIdentifier // ""' 2>/dev/null)
      if [ -n "$url" ]; then
        row=$(jq -nr --arg r "$region" --arg n "$name" --arg u "https://$url" --arg s "$status" --arg src "$source" '[$r,$n,$u,$s,$src] | @csv')
        write_tmp_csv "apprunner.csv" "$row" "$region"
      fi
    done
  fi
}

scan_elastic_beanstalk() {
  local region=$1
  if envs=$(aws_call aws elasticbeanstalk describe-environments --region "$region" --output json 2>/dev/null); then
    printf '%s\n' "$envs" > "$OUTDIR/raw/eb-${region}.json"
    echo "$envs" | jq -r --arg r "$region" '.Environments[]? | [$r, .EnvironmentName, (.CNAME // ""), (.EndpointURL // ""), .Health, (.PlatformArn // "" | split("/") | .[-1])] | @csv' 2>/dev/null | while IFS= read -r row; do
      [ -n "$row" ] && write_tmp_csv "elastic-beanstalk.csv" "$row" "$region"
    done
  fi
}

scan_sagemaker_endpoints() {
  local region=$1
  if data=$(aws_call aws sagemaker list-endpoints --region "$region" --output json 2>/dev/null); then
    printf '%s\n' "$data" > "$OUTDIR/raw/sagemaker-${region}.json"
    echo "$data" | jq -r --arg r "$region" '.Endpoints[]? | [$r, .EndpointName, .EndpointArn, .EndpointStatus, ""] | @csv' 2>/dev/null | while IFS= read -r row; do
      [ -n "$row" ] && write_tmp_csv "sagemaker-endpoints.csv" "$row" "$region"
    done
  fi
}

scan_quicksight() {
  local region=$1
  if data=$(aws_call aws quicksight list-dashboards --aws-account-id "$ACCOUNT_ID" --region "$region" --output json 2>/dev/null); then
    printf '%s\n' "$data" > "$OUTDIR/raw/quicksight-${region}.json"
    echo "$data" | jq -r --arg r "$region" --arg acct "$ACCOUNT_ID" '.DashboardSummaryList[]? | select(.PublishedVersionNumber != null) | [$r, .DashboardId, .Name, ("https://" + $r + ".quicksight.aws.amazon.com/sn/dashboards/" + .DashboardId), (.PublishedVersionNumber|tostring)] | @csv' 2>/dev/null | while IFS= read -r row; do
      [ -n "$row" ] && write_tmp_csv "quicksight.csv" "$row" "$region"
    done
  fi
}

scan_transfer_family() {
  local region=$1
  if servers=$(aws_call aws transfer list-servers --region "$region" --output json 2>/dev/null | jq -r '.Servers[]?.ServerId' 2>/dev/null); then
    printf '%s\n' "$servers" > "$OUTDIR/raw/transfer-${region}.txt"
    echo "$servers" | while IFS= read -r server_id; do
      [ -z "$server_id" ] && continue
      details=$(aws_call aws transfer describe-server --server-id "$server_id" --region "$region" --output json 2>/dev/null || echo "{}")
      endpoint_type=$(echo "$details" | jq -r '.Server.EndpointType // "VPC"' 2>/dev/null)
      state=$(echo "$details" | jq -r '.Server.State // "UNKNOWN"' 2>/dev/null)
      protocols=$(echo "$details" | jq -r '.Server.Protocols // [] | join(";")' 2>/dev/null || echo "")
      endpoint=$(echo "$details" | jq -r '.Server.EndpointDetails.Address // ""' 2>/dev/null)
      row=$(jq -nr --arg r "$region" --arg id "$server_id" --arg et "$endpoint_type" --arg pr "$protocols" --arg st "$state" --arg ep "$endpoint" '[$r,$id,$et,$pr,$st,$ep] | @csv')
      write_tmp_csv "transfer-servers.csv" "$row" "$region"
    done
  fi
}

scan_ecr() {
  local region=$1
  if [ "$region" = "us-east-1" ]; then
    if data=$(aws_call aws ecr-public describe-repositories --region us-east-1 --output json 2>/dev/null); then
      printf '%s\n' "$data" > "$OUTDIR/raw/ecr-pub-${region}.json"
      echo "$data" | jq -r --arg r "$region" '.repositories[]? | [$r, (.repositoryName // ""), (.repositoryUri // ""), "ECR-Public", ""] | @csv' 2>/dev/null | while IFS= read -r row; do
        [ -n "$row" ] && write_tmp_csv "ecr-repositories.csv" "$row" "$region"
      done
    fi
  fi

  if data2=$(aws_call aws ecr describe-repositories --region "$region" --output json 2>/dev/null); then
    printf '%s\n' "$data2" > "$OUTDIR/raw/ecr-${region}.json"
    echo "$data2" | jq -r --arg r "$region" '.repositories[]? | [$r, (.repositoryName // ""), (.repositoryUri // ""), "ECR-Private", ""] | @csv' 2>/dev/null | while IFS= read -r row; do
      [ -n "$row" ] && write_tmp_csv "ecr-repositories.csv" "$row" "$region"
    done
  fi
}

scan_codeartifact() {
  local region=$1
  if data=$(aws_call aws codeartifact list-repositories --region "$region" --output json 2>/dev/null); then
    printf '%s\n' "$data" > "$OUTDIR/raw/codeartifact-${region}.json"
    echo "$data" | jq -r --arg r "$region" '.repositories[]? | [$r, .name, .domainName, .domainOwner, (.domainName + "-" + (.domainOwner|tostring) + ".d.codeartifact." + $r + ".amazonaws.com")] | @csv' 2>/dev/null | while IFS= read -r row; do
      [ -n "$row" ] && write_tmp_csv "codeartifact.csv" "$row" "$region"
    done
  fi
}

scan_grafana() {
  local region=$1
  if data=$(aws_call aws grafana list-workspaces --region "$region" --output json 2>/dev/null); then
    printf '%s\n' "$data" > "$OUTDIR/raw/grafana-${region}.json"
    echo "$data" | jq -r --arg r "$region" '.workspaces[]? | [$r, .id, .name, .endpoint, .status] | @csv' 2>/dev/null | while IFS= read -r row; do
      [ -n "$row" ] && write_tmp_csv "grafana.csv" "$row" "$region"
    done
  fi
}

scan_mwaa() {
  local region=$1
  if envs=$(aws_call aws mwaa list-environments --region "$region" --output json 2>/dev/null | jq -r '.Environments[]?' 2>/dev/null); then
    printf '%s\n' "$envs" > "$OUTDIR/raw/mwaa-list-${region}.txt"
    echo "$envs" | while IFS= read -r env_name; do
      [ -z "$env_name" ] && continue
      details=$(aws_call aws mwaa get-environment --name "$env_name" --region "$region" --output json 2>/dev/null || echo "{}")
      arn=$(echo "$details" | jq -r '.Environment.Arn // ""' 2>/dev/null)
      webserver=$(echo "$details" | jq -r '.Environment.WebserverUrl // ""' 2>/dev/null)
      status=$(echo "$details" | jq -r '.Environment.Status // ""' 2>/dev/null)
      row=$(jq -nr --arg r "$region" --arg n "$env_name" --arg arn "$arn" --arg web "$webserver" --arg st "$status" '[$r,$n,$arn,$web,$st] | @csv')
      write_tmp_csv "mwaa.csv" "$row" "$region"
    done
  fi
}

scan_keyspaces() {
  local region=$1
  if data=$(aws_call aws keyspaces list-keyspaces --region "$region" --output json 2>/dev/null); then
    printf '%s\n' "$data" > "$OUTDIR/raw/keyspaces-${region}.json"
    echo "$data" | jq -r --arg r "$region" '.keyspaces[]? | [$r, .keyspaceName, "", ("cassandra." + $r + ".amazonaws.com:9142"), $r] | @csv' 2>/dev/null | while IFS= read -r row; do
      [ -n "$row" ] && write_tmp_csv "keyspaces.csv" "$row" "$region"
    done
  fi
}

scan_iot() {
  local region=$1
  if ep=$(aws_call aws iot describe-endpoint --region "$region" --output json 2>/dev/null | jq -r '.endpointAddress // ""' 2>/dev/null); then
    if [ -n "$ep" ]; then
      row=$(jq -nr --arg r "$region" --arg ep "$ep" '[$r,$ep,"iot:Data"] | @csv')
      write_tmp_csv "iot-endpoints.csv" "$row" "$region"
    fi
  fi
}

scan_rds() {
  local region=$1
  if data=$(aws_call aws rds describe-db-instances --region "$region" --output json 2>/dev/null); then
    printf '%s\n' "$data" > "$OUTDIR/raw/rds-${region}.json"
    echo "$data" | jq -r --arg r "$region" '.DBInstances[]? | [$r, .DBInstanceIdentifier, (.Endpoint.Address // ""), (.PubliclyAccessible|tostring), (.DBInstanceStatus // "")] | @csv' 2>/dev/null | while IFS= read -r row; do
      [ -n "$row" ] && write_tmp_csv "rds.csv" "$row" "$region"
    done
  fi
}

scan_redshift() {
  local region=$1
  if data=$(aws_call aws redshift describe-clusters --region "$region" --output json 2>/dev/null); then
    printf '%s\n' "$data" > "$OUTDIR/raw/redshift-${region}.json"
    echo "$data" | jq -r --arg r "$region" '.Clusters[]? | [$r, .ClusterIdentifier, (.Endpoint.Address // ""), (.PubliclyAccessible|tostring), (.ClusterStatus // "")] | @csv' 2>/dev/null | while IFS= read -r row; do
      [ -n "$row" ] && write_tmp_csv "redshift.csv" "$row" "$region"
    done
  fi
}

scan_opensearch() {
  local region=$1
  if domains=$(aws_call aws opensearch list-domain-names --region "$region" --output json 2>/dev/null); then
    printf '%s\n' "$domains" > "$OUTDIR/raw/opensearch-list-${region}.json"
    echo "$domains" | jq -r '.DomainNames[]?.DomainName' 2>/dev/null | while IFS= read -r dn; do
      [ -z "$dn" ] && continue
      details=$(aws_call aws opensearch describe-domain --domain-name "$dn" --region "$region" --output json 2>/dev/null || echo "{}")
      endpoint=$(echo "$details" | jq -r '.DomainStatus.Endpoint // ""' 2>/dev/null)
      status=$(echo "$details" | jq -r '.DomainStatus.Processing // ""' 2>/dev/null)
      row=$(jq -nr --arg r "$region" --arg dn "$dn" --arg ep "$endpoint" --arg st "$status" '[$r,$dn,$ep,$st] | @csv')
      write_tmp_csv "opensearch.csv" "$row" "$region"
    done
  fi
}

scan_msk() {
  local region=$1
  if data=$(aws_call aws kafka list-clusters --region "$region" --output json 2>/dev/null); then
    printf '%s\n' "$data" > "$OUTDIR/raw/msk-list-${region}.json"
    echo "$data" | jq -r '.ClusterInfoList[]? | [.ClusterName, .ClusterArn] | @tsv' 2>/dev/null | while IFS=$'\t' read -r name arn; do
      [ -z "$arn" ] && continue
      desc=$(aws_call aws kafka describe-cluster --cluster-arn "$arn" --region "$region" --output json 2>/dev/null || echo "{}")
      status=$(echo "$desc" | jq -r '.ClusterInfo.State // ""' 2>/dev/null)
      brokers=$(echo "$desc" | jq -r '.ClusterInfo.BrokerNodeGroupInfo.ZookeeperConnectString // ""' 2>/dev/null)
      row=$(jq -nr --arg r "$region" --arg name "$name" --arg arn "$arn" --arg st "$status" --arg br "$brokers" '[$r,$name,$arn,$st,$br] | @csv')
      write_tmp_csv "msk.csv" "$row" "$region"
    done
  fi
}

scan_elasticache() {
  local region=$1
  if data=$(aws_call aws elasticache describe-cache-clusters --region "$region" --show-cache-node-info --output json 2>/dev/null); then
    printf '%s\n' "$data" > "$OUTDIR/raw/elasticache-${region}.json"
    echo "$data" | jq -r --arg r "$region" '.CacheClusters[]? | [$r, .CacheClusterId, (.ConfigurationEndpoint.Address // ""), (.Engine // ""), (.CacheClusterStatus // "")] | @csv' 2>/dev/null | while IFS= read -r row; do
      [ -n "$row" ] && write_tmp_csv "elasticache.csv" "$row" "$region"
    done
  fi
}

scan_docdb() {
  local region=$1
  if data=$(aws_call aws docdb describe-db-instances --region "$region" --output json 2>/dev/null); then
    printf '%s\n' "$data" > "$OUTDIR/raw/docdb-${region}.json"
    echo "$data" | jq -r --arg r "$region" '.DBInstances[]? | [$r, .DBInstanceIdentifier, (.Endpoint.Address // ""), (.PubliclyAccessible|tostring), (.DBInstanceStatus // "")] | @csv' 2>/dev/null | while IFS= read -r row; do
      [ -n "$row" ] && write_tmp_csv "docdb.csv" "$row" "$region"
    done
  fi
}

scan_neptune() {
  local region=$1
  if data=$(aws_call aws neptune describe-db-instances --region "$region" --output json 2>/dev/null); then
    printf '%s\n' "$data" > "$OUTDIR/raw/neptune-${region}.json"
    echo "$data" | jq -r --arg r "$region" '.DBInstances[]? | [$r, .DBInstanceIdentifier, (.Endpoint.Address // ""), (.PubliclyAccessible|tostring), (.DBInstanceStatus // "")] | @csv' 2>/dev/null | while IFS= read -r row; do
      [ -n "$row" ] && write_tmp_csv "neptune.csv" "$row" "$region"
    done
  fi
}

scan_memorydb() {
  local region=$1
  if data=$(aws_call aws memorydb describe-clusters --region "$region" --output json 2>/dev/null); then
    printf '%s\n' "$data" > "$OUTDIR/raw/memorydb-${region}.json"
    echo "$data" | jq -r --arg r "$region" '.Clusters[]? | [$r, .Name, (.ClusterEndpoint.Address // ""), (.Status // ""), (.Engine // "redis")] | @csv' 2>/dev/null | while IFS= read -r row; do
      [ -n "$row" ] && write_tmp_csv "memorydb.csv" "$row" "$region"
    done
  fi
}

scan_timestream() {
  local region=$1
  if data=$(aws_call aws timestream-write list-databases --region "$region" --output json 2>/dev/null); then
    printf '%s\n' "$data" > "$OUTDIR/raw/timestream-${region}.json"
    echo "$data" | jq -r --arg r "$region" '.Databases[]? | [$r, .DatabaseName, .Arn, ("ingest-cell1.timestream." + $r + ".amazonaws.com"), ("query-cell1.timestream." + $r + ".amazonaws.com")] | @csv' 2>/dev/null | while IFS= read -r row; do
      [ -n "$row" ] && write_tmp_csv "timestream.csv" "$row" "$region"
    done
  fi
}

# Export functions
export -f aws_call write_tmp_csv merge_tmp_csv
export -f scan_public_enis scan_elastic_ips scan_security_groups scan_api_gateway scan_lambda_urls scan_appsync scan_cognito
export -f scan_load_balancers scan_amplify scan_app_runner scan_elastic_beanstalk scan_sagemaker_endpoints
export -f scan_quicksight scan_transfer_family scan_ecr scan_codeartifact scan_grafana scan_mwaa scan_keyspaces scan_iot
export -f scan_rds scan_redshift scan_opensearch scan_msk scan_elasticache scan_docdb
export -f scan_neptune scan_memorydb scan_timestream
export OUTDIR TMPDIR ACCOUNT_ID AWS_TIMEOUT AWS_CALL_MAX_ATTEMPTS

# ============================================================================
# Region scanning
# ============================================================================
SERVICES_PER_REGION=29

REG_INDEX=0
for region in "${REGIONS[@]}"; do
  REG_INDEX=$((REG_INDEX+1))
  echo ""
  info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  info "[$REG_INDEX/${#REGIONS[@]}] Scanning Region: $region"
  info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

  jobs=(
    "scan_public_enis $region"
    "scan_elastic_ips $region"
    "scan_security_groups $region"
    "scan_api_gateway $region"
    "scan_lambda_urls $region"
    "scan_appsync $region"
    "scan_cognito $region"
    "scan_load_balancers $region"
    "scan_amplify $region"
    "scan_app_runner $region"
    "scan_elastic_beanstalk $region"
    "scan_sagemaker_endpoints $region"
    "scan_quicksight $region"
    "scan_transfer_family $region"
    "scan_ecr $region"
    "scan_codeartifact $region"
    "scan_grafana $region"
    "scan_mwaa $region"
    "scan_keyspaces $region"
    "scan_iot $region"
    "scan_rds $region"
    "scan_redshift $region"
    "scan_opensearch $region"
    "scan_msk $region"
    "scan_elasticache $region"
    "scan_docdb $region"
    "scan_neptune $region"
    "scan_memorydb $region"
    "scan_timestream $region"
  )

  if [ "$PARALLEL_SERVICES" = true ]; then
    info "  Running parallel service scan (${MAX_PARALLEL} jobs)..."
    printf '%s\n' "${jobs[@]}" | xargs -P "$MAX_PARALLEL" -I {} bash -c '{}'
    ok "  Region $region complete (parallel)"
  else
    SERVICE_NUM=0
    for j in "${jobs[@]}"; do
      SERVICE_NUM=$((SERVICE_NUM+1))
      printf "  [%2d/%2d] %-45s" "$SERVICE_NUM" "$SERVICES_PER_REGION" "$j"
      bash -c "$j" 2>/dev/null || true
      echo " ✓"
    done
    ok "  Region $region complete (sequential)"
  fi

  for f in "${!CSV_HEADERS[@]}"; do
    merge_tmp_csv "$f"
  done

  sleep 1
done

# ============================================================================
# Global services
# ============================================================================
echo ""
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
info "Scanning Global Services"
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Route53
printf "  [G1/4] %-35s" "Route53..."
if zones=$(aws_call aws route53 list-hosted-zones --output json 2>/dev/null); then
  printf '%s\n' "$zones" > "$OUTDIR/raw/route53-zones.json"
  echo "$zones" | jq -r '.HostedZones[]?.Id' 2>/dev/null | while IFS= read -r zid; do
    [ -z "$zid" ] && continue
    zid_clean=$(echo "$zid" | sed 's|/hostedzone/||g')
    zname=$(aws_call aws route53 get-hosted-zone --id "$zid_clean" --query 'HostedZone.Name' --output text 2>/dev/null || echo "")
    rrsets=$(aws_call aws route53 list-resource-record-sets --hosted-zone-id "$zid_clean" --output json 2>/dev/null || echo "{}")
    printf '%s\n' "$rrsets" > "$OUTDIR/raw/route53-${zid_clean}.json"
    echo "$rrsets" | jq -r --arg zn "$zname" '.ResourceRecordSets[]? | [$zn, .Name, .Type, ((.ResourceRecords?[0].Value) // (.AliasTarget?.DNSName // "")), (if .AliasTarget then "Yes" else "No" end), (.TTL // "")] | @csv' 2>/dev/null | while IFS= read -r row; do
      [ -n "$row" ] && write_tmp_csv "route53.csv" "$row" "$zid_clean"
    done
  done
fi
merge_tmp_csv "route53.csv"
echo " ✓"

# S3
printf "  [G2/4] %-35s" "S3 Buckets..."
if bucket_json=$(aws_call aws s3api list-buckets --output json 2>/dev/null); then
  printf '%s\n' "$bucket_json" > "$OUTDIR/raw/s3-buckets-list.json"
  mapfile -t bucket_array < <(echo "$bucket_json" | jq -r '.Buckets[]?.Name' 2>/dev/null)

  for bucket in "${bucket_array[@]}"; do
    [ -z "$bucket" ] && continue
    if [[ "$bucket" =~ [^a-zA-Z0-9._-] ]]; then
      warn "Skipping bucket with special characters: $bucket"
      continue
    fi

    (
      region=$(timeout 10 aws s3api get-bucket-location --bucket "$bucket" --query 'LocationConstraint' --output text 2>/dev/null || echo "us-east-1")
      [ "$region" = "None" ] || [ "$region" = "null" ] && region="us-east-1"
      created=$(echo "$bucket_json" | jq -r ".Buckets[] | select(.Name==\"$bucket\") | .CreationDate" 2>/dev/null || echo "Unknown")

      public_acl="No"
      public_policy="No"
      pab="Not-configured"
      website="No"
      public_list="No"

      if acl_check=$(timeout 10 aws s3api get-bucket-acl --bucket "$bucket" --output json 2>/dev/null); then
        if echo "$acl_check" | jq -e '.Grants[] | select(.Grantee.URI? | test("AllUsers|AuthenticatedUsers"))' >/dev/null 2>&1; then
          public_acl="Yes"
        fi
      fi

      if timeout 10 aws s3api get-bucket-policy --bucket "$bucket" >/dev/null 2>&1; then
        public_policy="Yes"
      fi

      if pab_check=$(timeout 10 aws s3api get-public-access-block --bucket "$bucket" --output json 2>/dev/null); then
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

      if timeout 10 aws s3api get-bucket-website --bucket "$bucket" >/dev/null 2>&1; then
        website="Yes"
      fi

      if timeout 10 aws s3 ls "s3://$bucket" --no-sign-request >/dev/null 2>&1; then
        public_list="Yes"
      fi

      row=$(jq -nr --arg b "$bucket" --arg reg "$region" --arg created "$created" --arg acl "$public_acl" --arg pol "$public_policy" --arg pab "$pab" --arg web "$website" --arg pl "$public_list" '[$b,$reg,$created,$acl,$pol,$pab,$web,$pl] | @csv')
      write_tmp_csv "s3.csv" "$row" "$bucket"
    ) || warn "Failed to scan bucket: $bucket"
  done
fi
merge_tmp_csv "s3.csv"
echo " ✓"

# CloudFront
printf "  [G3/4] %-35s" "CloudFront..."
if cf=$(aws_call aws cloudfront list-distributions --output json 2>/dev/null); then
  printf '%s\n' "$cf" > "$OUTDIR/raw/cloudfront-list.json"
  echo "$cf" | jq -r '.DistributionList.Items[]? | [.Id, .DomainName, (.Enabled|tostring), (.Origins.Items[0].DomainName // ""), ((.Aliases.Items // []) | join(";")), .Status] | @csv' 2>/dev/null | while IFS= read -r row; do
    [ -n "$row" ] && write_tmp_csv "cloudfront.csv" "$row" "global"
  done
fi
merge_tmp_csv "cloudfront.csv"
echo " ✓"

# Global Accelerator
printf "  [G4/4] %-35s" "Global Accelerator..."
if ga=$(aws_call aws globalaccelerator list-accelerators --output json 2>/dev/null); then
  printf '%s\n' "$ga" > "$OUTDIR/raw/globalaccelerator.json"
  echo "$ga" | jq -r '.Accelerators[]? | [.Name, .AcceleratorArn, ((.IpSets[0].IpAddresses // []) | join(";")), (.Enabled|tostring), .DnsName] | @csv' 2>/dev/null | while IFS= read -r row; do
    [ -n "$row" ] && write_tmp_csv "global-accelerator.csv" "$row" "global"
  done
fi
merge_tmp_csv "global-accelerator.csv"
echo " ✓"

echo ""

# Final merge
for f in "${!CSV_HEADERS[@]}"; do
  merge_tmp_csv "$f"
done

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
  echo "║   AWS Attack Surface Inventory (v2)                    ║"
  echo "║   Coverage: 33 Services - ENI-First Strategy           ║"
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
  echo " Security Findings (quick counts)"
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
  [ "$sg_open" -gt 0 ] 2>/dev/null && echo "  • $sg_open security group rules allowing 0.0.0.0/0 or ::/0"

  if [ -f "$OUTDIR/s3.csv" ]; then
    s3_public_list=$(awk -F',' 'NR>1 && $NF ~ /Yes/ {count++} END {print count+0}' "$OUTDIR/s3.csv" 2>/dev/null || echo "0")
  fi
  [ "${s3_public_list:-0}" -gt 0 ] 2>/dev/null && echo "  • $s3_public_list S3 buckets with public listing"

  if [ -f "$OUTDIR/lambda-urls.csv" ]; then
    lambda_noauth=$(grep -c 'NONE' "$OUTDIR/lambda-urls.csv" 2>/dev/null || echo "0")
  fi
  [ "${lambda_noauth:-0}" -gt 0 ] 2>/dev/null && echo "  • $lambda_noauth Lambda URLs without authentication (AuthType=NONE)"

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
  echo "Strategy: ENI-first approach + explicit database enumerators"
  echo "  • ENI scan catches many managed resources"
  echo "  • Added 9 explicit database enumerators for complete coverage"
  echo "  • Services scanned: 33 (29 regional + 4 global)"
  echo ""
  echo "═══════════════════════════════════════════════════════"
  echo ""

} | tee "$OUTDIR/SUMMARY.txt"

ok "✓ Attack surface enumeration complete!"
ok "✓ Results saved to: $OUTDIR"
echo ""
info "Next steps:"
info "  1. Review: $OUTDIR/SUMMARY.txt"
info "  2. Check public IPs: $OUTDIR/public-enis.csv"
info "  3. Review security groups: $OUTDIR/sg-open.csv"
info "  4. Audit S3 buckets: $OUTDIR/s3.csv"
echo ""
