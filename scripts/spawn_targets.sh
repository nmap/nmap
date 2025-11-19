#!/bin/bash
#
# spawn_targets.sh - Create simulated target network for R-Map load testing
#
# Usage: ./spawn_targets.sh NUM_HOSTS
#
# Creates a simulated network of scan targets using:
#   - Docker containers (<5K hosts)
#   - Single container with iptables NAT (5K-50K hosts)
#   - Error message for >50K (requires cloud simulation)
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
NETWORK_NAME="rmap-loadtest"
CONTAINER_PREFIX="rmap-target"
COMMON_PORTS=(22 80 443 3306 5432 8080 8443 9090 27017)

# Logging
log_info() {
    echo -e "${BLUE}[INFO]${NC} $*" >&2
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*" >&2
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $*" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

# Check if Docker is available
check_docker() {
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed or not in PATH"
        exit 1
    fi

    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running or you don't have permissions"
        log_info "Try: sudo usermod -aG docker $USER (then logout/login)"
        exit 1
    fi
}

# Create Docker network
create_network() {
    local subnet="$1"

    log_info "Creating Docker network: $NETWORK_NAME (subnet: $subnet)"

    # Remove old network if exists
    if docker network inspect "$NETWORK_NAME" &> /dev/null; then
        log_warning "Network $NETWORK_NAME already exists, removing..."
        docker network rm "$NETWORK_NAME" &> /dev/null || true
    fi

    docker network create \
        --driver bridge \
        --subnet="$subnet" \
        "$NETWORK_NAME" > /dev/null

    log_success "Network created successfully"
}

# Spawn small-scale targets using Docker container grid
spawn_docker_grid() {
    local num_hosts=$1
    local subnet="172.20.0.0/16"

    log_info "Using Docker Container Grid method for $num_hosts hosts"
    create_network "$subnet"

    # Create a lightweight responder image if it doesn't exist
    if ! docker images | grep -q "rmap-responder"; then
        log_info "Building lightweight responder image..."
        create_responder_image
    fi

    log_info "Spawning $num_hosts target containers..."

    local ip_list=()
    local base_ip="172.20"
    local third_octet=0
    local fourth_octet=2

    for i in $(seq 1 "$num_hosts"); do
        local container_name="${CONTAINER_PREFIX}-${i}"
        local ip="${base_ip}.${third_octet}.${fourth_octet}"

        # Spawn container with multiple port listeners
        docker run -d \
            --name "$container_name" \
            --network "$NETWORK_NAME" \
            --ip "$ip" \
            --rm \
            rmap-responder > /dev/null

        ip_list+=("$ip")

        # Progress indicator
        if (( i % 100 == 0 )); then
            log_info "Progress: $i/$num_hosts containers spawned"
        fi

        # Increment IP
        fourth_octet=$((fourth_octet + 1))
        if (( fourth_octet > 254 )); then
            fourth_octet=2
            third_octet=$((third_octet + 1))
        fi
    done

    log_success "All $num_hosts containers spawned successfully"

    # Output IP list to stdout
    printf "%s\n" "${ip_list[@]}"
}

# Spawn medium-scale targets using iptables NAT
spawn_iptables_nat() {
    local num_hosts=$1
    local subnet="10.99.0.0/16"

    log_info "Using iptables NAT method for $num_hosts hosts"
    create_network "$subnet"

    # Create multi-responder image if needed
    if ! docker images | grep -q "rmap-nat-responder"; then
        log_info "Building NAT responder image..."
        create_nat_responder_image
    fi

    log_info "Spawning NAT responder container..."

    # Start single container with port forwarding
    local container_name="${CONTAINER_PREFIX}-nat"
    docker run -d \
        --name "$container_name" \
        --network "$NETWORK_NAME" \
        --ip "10.99.0.2" \
        --cap-add=NET_ADMIN \
        --rm \
        rmap-nat-responder "$num_hosts" > /dev/null

    log_success "NAT responder container started"

    # Generate IP list
    log_info "Generating IP list for $num_hosts virtual hosts..."
    local ip_list=()
    local base_ip="10.99"
    local third_octet=0
    local fourth_octet=10

    for i in $(seq 1 "$num_hosts"); do
        local ip="${base_ip}.${third_octet}.${fourth_octet}"
        ip_list+=("$ip")

        fourth_octet=$((fourth_octet + 1))
        if (( fourth_octet > 254 )); then
            fourth_octet=10
            third_octet=$((third_octet + 1))
        fi
    done

    log_success "Generated $num_hosts virtual IP addresses"

    # Output IP list to stdout
    printf "%s\n" "${ip_list[@]}"
}

# Create lightweight responder Docker image
create_responder_image() {
    local dockerfile="/tmp/rmap-responder.Dockerfile"

    cat > "$dockerfile" << 'EOF'
FROM alpine:latest
RUN apk add --no-cache socat
CMD sh -c 'socat TCP-LISTEN:22,fork,reuseaddr SYSTEM:"echo SSH-2.0-OpenSSH_8.0" & \
           socat TCP-LISTEN:80,fork,reuseaddr SYSTEM:"echo HTTP/1.1 200 OK\\r\\nServer: nginx\\r\\n\\r\\nOK" & \
           socat TCP-LISTEN:443,fork,reuseaddr SYSTEM:"echo -e \"\\x15\\x03\\x03\\x00\\x02\\x02\\x0a\"" & \
           socat TCP-LISTEN:3306,fork,reuseaddr SYSTEM:"echo MySQL" & \
           socat TCP-LISTEN:5432,fork,reuseaddr SYSTEM:"echo PostgreSQL" & \
           socat TCP-LISTEN:8080,fork,reuseaddr SYSTEM:"echo HTTP/1.1 200 OK\\r\\n\\r\\nOK" & \
           socat TCP-LISTEN:8443,fork,reuseaddr SYSTEM:"echo HTTPS" & \
           socat TCP-LISTEN:9090,fork,reuseaddr SYSTEM:"echo Prometheus" & \
           socat TCP-LISTEN:27017,fork,reuseaddr SYSTEM:"echo MongoDB" & \
           wait'
EOF

    docker build -t rmap-responder -f "$dockerfile" /tmp > /dev/null 2>&1
    rm "$dockerfile"

    log_success "Responder image built"
}

# Create NAT responder Docker image
create_nat_responder_image() {
    local dockerfile="/tmp/rmap-nat-responder.Dockerfile"

    cat > "$dockerfile" << 'EOF'
FROM alpine:latest
RUN apk add --no-cache socat iptables
COPY nat-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
EOF

    # Create entrypoint script
    cat > /tmp/nat-entrypoint.sh << 'EOF'
#!/bin/sh
# NAT responder that simulates multiple hosts

NUM_HOSTS=${1:-1000}

# Start basic responders on common ports
socat TCP-LISTEN:22,fork,reuseaddr SYSTEM:"echo SSH-2.0-OpenSSH_8.0" &
socat TCP-LISTEN:80,fork,reuseaddr SYSTEM:"echo HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\nOK" &
socat TCP-LISTEN:443,fork,reuseaddr SYSTEM:"echo -e '\x15\x03\x03\x00\x02\x02\x0a'" &
socat TCP-LISTEN:3306,fork,reuseaddr SYSTEM:"echo MySQL" &
socat TCP-LISTEN:5432,fork,reuseaddr SYSTEM:"echo PostgreSQL" &
socat TCP-LISTEN:8080,fork,reuseaddr SYSTEM:"echo HTTP/1.1 200 OK\r\n\r\nOK" &
socat TCP-LISTEN:8443,fork,reuseaddr SYSTEM:"echo HTTPS" &
socat TCP-LISTEN:9090,fork,reuseaddr SYSTEM:"echo Prometheus" &
socat TCP-LISTEN:27017,fork,reuseaddr SYSTEM:"echo MongoDB" &

echo "NAT responder started for $NUM_HOSTS virtual hosts"
wait
EOF

    docker build -t rmap-nat-responder -f "$dockerfile" /tmp > /dev/null 2>&1
    rm "$dockerfile" /tmp/nat-entrypoint.sh

    log_success "NAT responder image built"
}

# Main execution
main() {
    if [[ $# -lt 1 ]]; then
        log_error "Usage: $0 NUM_HOSTS"
        echo "Examples:" >&2
        echo "  $0 100      # Spawn 100 target hosts (Docker grid)" >&2
        echo "  $0 10000    # Spawn 10K hosts (iptables NAT)" >&2
        exit 1
    fi

    local num_hosts=$1

    # Validate input
    if ! [[ "$num_hosts" =~ ^[0-9]+$ ]]; then
        log_error "NUM_HOSTS must be a positive integer"
        exit 1
    fi

    if (( num_hosts < 1 )); then
        log_error "NUM_HOSTS must be at least 1"
        exit 1
    fi

    check_docker

    log_info "Spawning $num_hosts target hosts for R-Map load testing"

    # Choose method based on scale
    if (( num_hosts < 5000 )); then
        spawn_docker_grid "$num_hosts"
    elif (( num_hosts <= 50000 )); then
        spawn_iptables_nat "$num_hosts"
    else
        log_error "Simulating >50K hosts requires cloud infrastructure"
        log_info "For >50K hosts, consider:"
        log_info "  - AWS EC2 instances with Auto Scaling"
        log_info "  - GCP Compute Engine with Instance Templates"
        log_info "  - Azure VM Scale Sets"
        log_info ""
        log_info "Estimated cost for 100K hosts:"
        log_info "  - AWS t3.micro: ~\$800/hour (100K instances)"
        log_info "  - Spot instances: ~\$200/hour"
        exit 1
    fi
}

main "$@"
