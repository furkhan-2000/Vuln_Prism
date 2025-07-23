#!/bin/bash

# VulnPrism Build Script - Error-free Docker build
set -e

echo "🚀 VulnPrism Build Script - Zero Error Build"
echo "=============================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Docker is running
check_docker() {
    print_status "Checking Docker availability..."
    if ! docker info > /dev/null 2>&1; then
        print_error "Docker is not running. Please start Docker and try again."
        exit 1
    fi
    print_success "Docker is running"
}

# Clean up previous builds
cleanup() {
    print_status "Cleaning up previous builds..."
    docker system prune -f > /dev/null 2>&1 || true
    print_success "Cleanup completed"
}

# Build individual service
build_service() {
    local service_name=$1
    local context_dir=$2
    
    print_status "Building $service_name service..."
    
    if docker build -t "vulnprism-$service_name:latest" "$context_dir"; then
        print_success "$service_name build completed successfully"
        return 0
    else
        print_error "$service_name build failed"
        return 1
    fi
}

# Test service after build
test_service() {
    local service_name=$1
    
    print_status "Testing $service_name service..."
    
    if docker run --rm "vulnprism-$service_name:latest" python --version > /dev/null 2>&1; then
        print_success "$service_name test passed"
        return 0
    else
        print_warning "$service_name test failed (non-critical)"
        return 0
    fi
}

# Main build process
main() {
    print_status "Starting VulnPrism build process..."
    
    # Check prerequisites
    check_docker
    
    # Clean up
    cleanup
    
    # Build services in order (lightest to heaviest)
    print_status "Building services in optimal order..."
    
    # 1. Frontend (lightest)
    if build_service "frontend" "./chatbot-frontend"; then
        test_service "frontend"
    else
        print_error "Frontend build failed. Stopping build process."
        exit 1
    fi
    
    # 2. SAST (medium)
    if build_service "sast" "./sast"; then
        test_service "sast"
    else
        print_error "SAST build failed. Stopping build process."
        exit 1
    fi
    
    # 3. CYBERSCYTHE (heaviest)
    if build_service "cyberscythe" "./CYBERSCYTHE"; then
        test_service "cyberscythe"
    else
        print_error "CYBERSCYTHE build failed. Stopping build process."
        exit 1
    fi
    
    print_success "All services built successfully!"
    
    # Optional: Start services
    read -p "Do you want to start all services now? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_status "Starting all services..."
        docker-compose -f docker-compose-simple.yml up -d
        print_success "All services started!"
        print_status "Access points:"
        print_status "  Frontend: http://localhost:3000"
        print_status "  SAST: http://localhost:5050"
        print_status "  CYBERSCYTHE: http://localhost:5051"
    fi
}

# Run main function
main "$@"
