#!/bin/bash
#
# cleanup_targets.sh - Clean up R-Map load testing infrastructure
#
# Usage: ./cleanup_targets.sh
#
# Removes all Docker containers, networks, and temporary files
# created by spawn_targets.sh
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

# Logging
log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

# Stop and remove all target containers
cleanup_containers() {
    log_info "Searching for R-Map target containers..."

    # Find all containers with our prefix
    local containers=$(docker ps -a --filter "name=${CONTAINER_PREFIX}" --format "{{.Names}}" 2>/dev/null || echo "")

    if [[ -z "$containers" ]]; then
        log_info "No target containers found"
        return 0
    fi

    local count=$(echo "$containers" | wc -l)
    log_info "Found $count target container(s), removing..."

    # Stop containers first
    echo "$containers" | xargs -r docker stop > /dev/null 2>&1 || true

    # Remove containers
    echo "$containers" | xargs -r docker rm -f > /dev/null 2>&1 || true

    log_success "Removed $count container(s)"
}

# Remove Docker network
cleanup_network() {
    log_info "Checking for R-Map test network..."

    if docker network inspect "$NETWORK_NAME" &> /dev/null; then
        log_info "Removing network: $NETWORK_NAME"
        docker network rm "$NETWORK_NAME" > /dev/null 2>&1 || {
            log_warning "Failed to remove network (may have active endpoints)"
            log_info "Forcing network cleanup..."
            docker network rm -f "$NETWORK_NAME" > /dev/null 2>&1 || true
        }
        log_success "Network removed"
    else
        log_info "Network not found (already cleaned up)"
    fi
}

# Clean up temporary files
cleanup_temp_files() {
    log_info "Cleaning up temporary files..."

    # Remove temporary Dockerfiles
    rm -f /tmp/rmap-responder.Dockerfile
    rm -f /tmp/rmap-nat-responder.Dockerfile
    rm -f /tmp/nat-entrypoint.sh

    # Remove any IP list files
    rm -f /tmp/rmap-targets-*.txt

    log_success "Temporary files cleaned up"
}

# Optional: Remove Docker images
cleanup_images() {
    if [[ "${1:-}" == "--with-images" ]]; then
        log_info "Removing R-Map responder Docker images..."

        docker rmi -f rmap-responder > /dev/null 2>&1 || log_info "  rmap-responder image not found"
        docker rmi -f rmap-nat-responder > /dev/null 2>&1 || log_info "  rmap-nat-responder image not found"

        log_success "Docker images removed"
    fi
}

# Display cleanup summary
show_summary() {
    log_info "Cleanup complete!"
    echo ""
    echo "Remaining Docker resources:"
    echo "  Containers: $(docker ps -a --filter "name=${CONTAINER_PREFIX}" 2>/dev/null | wc -l) (should be 1 = header only)"
    echo "  Networks: $(docker network ls --filter "name=${NETWORK_NAME}" 2>/dev/null | wc -l) (should be 1 = header only)"
    echo ""

    # Check if cleanup was successful
    local remaining_containers=$(docker ps -a --filter "name=${CONTAINER_PREFIX}" --format "{{.Names}}" 2>/dev/null | wc -l)
    local remaining_networks=$(docker network ls --filter "name=${NETWORK_NAME}" --format "{{.Name}}" 2>/dev/null | wc -l)

    if [[ $remaining_containers -eq 0 ]] && [[ $remaining_networks -eq 0 ]]; then
        log_success "All R-Map load test resources cleaned up successfully!"
    else
        log_warning "Some resources may still exist. Run 'docker ps -a' to check."
    fi
}

# Main execution
main() {
    echo "=========================================="
    echo "  R-Map Load Test Cleanup"
    echo "=========================================="
    echo ""

    # Check if Docker is available
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed or not in PATH"
        exit 1
    fi

    # Perform cleanup steps
    cleanup_containers
    cleanup_network
    cleanup_temp_files
    cleanup_images "$@"

    echo ""
    show_summary
}

# Handle help flag
if [[ "${1:-}" == "-h" ]] || [[ "${1:-}" == "--help" ]]; then
    echo "Usage: $0 [--with-images]"
    echo ""
    echo "Cleans up R-Map load testing infrastructure"
    echo ""
    echo "Options:"
    echo "  --with-images    Also remove Docker images (rmap-responder, rmap-nat-responder)"
    echo "  -h, --help       Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                  # Clean up containers and networks only"
    echo "  $0 --with-images    # Clean up everything including Docker images"
    exit 0
fi

main "$@"
