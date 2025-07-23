#!/bin/bash

# VulnPrism Comprehensive Fix Deployment Script
# This script builds and deploys the fixed CYBERSCYTHE and SAST services

set -e  # Exit on any error

echo "🚀 Starting VulnPrism Comprehensive Fix Deployment"
echo "=================================================="

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

# Check if we're in the right directory
if [ ! -d "CYBERSCYTHE" ] || [ ! -d "sast" ]; then
    print_error "Please run this script from the VulnPrism root directory"
    exit 1
fi

print_status "Building CYBERSCYTHE image with comprehensive fixes..."
docker build -t furkhan2000/shark:cyber-v5 ./CYBERSCYTHE
if [ $? -eq 0 ]; then
    print_success "CYBERSCYTHE image built successfully"
else
    print_error "Failed to build CYBERSCYTHE image"
    exit 1
fi

print_status "Building SAST image with enhanced logging..."
docker build -t furkhan2000/shark:sast-v4 ./sast
if [ $? -eq 0 ]; then
    print_success "SAST image built successfully"
else
    print_error "Failed to build SAST image"
    exit 1
fi

print_status "Pushing CYBERSCYTHE image to registry..."
docker push furkhan2000/shark:cyber-v5
if [ $? -eq 0 ]; then
    print_success "CYBERSCYTHE image pushed successfully"
else
    print_error "Failed to push CYBERSCYTHE image"
    exit 1
fi

print_status "Pushing SAST image to registry..."
docker push furkhan2000/shark:sast-v4
if [ $? -eq 0 ]; then
    print_success "SAST image pushed successfully"
else
    print_error "Failed to push SAST image"
    exit 1
fi

print_status "Updating CYBERSCYTHE deployment..."
kubectl patch deployment cyber-dep -n mustang -p '{"spec":{"template":{"spec":{"containers":[{"name":"cyber-con","image":"furkhan2000/shark:cyber-v5"}]}}}}'
if [ $? -eq 0 ]; then
    print_success "CYBERSCYTHE deployment updated"
else
    print_error "Failed to update CYBERSCYTHE deployment"
    exit 1
fi

print_status "Updating SAST deployment..."
kubectl patch deployment sast-dep -n mustang -p '{"spec":{"template":{"spec":{"containers":[{"name":"sast-con","image":"furkhan2000/shark:sast-v4"}]}}}}'
if [ $? -eq 0 ]; then
    print_success "SAST deployment updated"
else
    print_error "Failed to update SAST deployment"
    exit 1
fi

print_status "Waiting for CYBERSCYTHE rollout to complete..."
kubectl rollout status deployment/cyber-dep -n mustang --timeout=300s
if [ $? -eq 0 ]; then
    print_success "CYBERSCYTHE rollout completed"
else
    print_warning "CYBERSCYTHE rollout may have timed out, checking status..."
fi

print_status "Waiting for SAST rollout to complete..."
kubectl rollout status deployment/sast-dep -n mustang --timeout=300s
if [ $? -eq 0 ]; then
    print_success "SAST rollout completed"
else
    print_warning "SAST rollout may have timed out, checking status..."
fi

print_status "Checking pod status..."
kubectl get pods -n mustang

print_status "Checking CYBERSCYTHE logs..."
kubectl logs -n mustang -l tier=versace --tail=10

print_status "Checking SAST logs..."
kubectl logs -n mustang -l tier=porsche --tail=10

print_success "🎉 Deployment completed successfully!"
echo ""
echo "✅ FIXES APPLIED:"
echo "  - CYBERSCYTHE: Fixed KeyError 'signature' and add_error method"
echo "  - CYBERSCYTHE: Added comprehensive error handling and logging"
echo "  - SAST: Enhanced logging with timestamps and performance metrics"
echo "  - Both: Zero-tolerance error handling with graceful degradation"
echo ""
echo "🧪 TEST YOUR SERVICES:"
echo "  1. Access CYBERSCYTHE and run a scan"
echo "  2. Access SAST and upload a repository"
echo "  3. Check logs for detailed debugging information"
echo ""
echo "📊 MONITORING:"
echo "  - kubectl logs -n mustang -l tier=versace -f  # CYBERSCYTHE logs"
echo "  - kubectl logs -n mustang -l tier=porsche -f  # SAST logs"
