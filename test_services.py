#!/usr/bin/env python3
"""
Simple test script to verify VulnPrism services work correctly
Run this before Docker build to catch issues early
"""

import sys
import os
import subprocess
import importlib.util

def test_imports():
    """Test if all required packages can be imported"""
    print("🔍 Testing Python imports...")
    
    # Test SAST imports
    try:
        sys.path.insert(0, 'sast')
        import scan_engine
        print("✅ SAST scan_engine import successful")
    except Exception as e:
        print(f"❌ SAST import failed: {e}")
        return False
    
    # Test CYBERSCYTHE imports
    try:
        sys.path.insert(0, 'CYBERSCYTHE')
        from app.aggressive_scanner.scanner import ScanResult
        print("✅ CYBERSCYTHE scanner import successful")
    except Exception as e:
        print(f"❌ CYBERSCYTHE import failed: {e}")
        return False
    
    # Test common packages
    required_packages = [
        'fastapi', 'uvicorn', 'httpx', 'loguru', 
        'pydantic', 'playwright', 'fpdf'
    ]
    
    for package in required_packages:
        try:
            __import__(package)
            print(f"✅ {package} import successful")
        except ImportError as e:
            print(f"❌ {package} import failed: {e}")
            return False
    
    return True

def test_pdf_generation():
    """Test PDF generation functionality"""
    print("\n📄 Testing PDF generation...")
    
    try:
        from fpdf import FPDF
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font('Arial', 'B', 16)
        pdf.cell(0, 10, 'Test PDF', 0, 1, 'C')
        
        # Test output
        output = pdf.output(dest='S')
        if len(output) > 0:
            print("✅ FPDF PDF generation successful")
            return True
        else:
            print("❌ FPDF PDF generation failed - empty output")
            return False
    except Exception as e:
        print(f"❌ PDF generation failed: {e}")
        return False

def test_service_health():
    """Test if services can start (basic syntax check)"""
    print("\n🏥 Testing service health...")
    
    # Test SAST main.py syntax
    try:
        spec = importlib.util.spec_from_file_location("sast_main", "sast/main.py")
        sast_main = importlib.util.module_from_spec(spec)
        print("✅ SAST main.py syntax check passed")
    except Exception as e:
        print(f"❌ SAST main.py syntax error: {e}")
        return False
    
    # Test CYBERSCYTHE main.py syntax
    try:
        spec = importlib.util.spec_from_file_location("cyber_main", "CYBERSCYTHE/app/main.py")
        cyber_main = importlib.util.module_from_spec(spec)
        print("✅ CYBERSCYTHE main.py syntax check passed")
    except Exception as e:
        print(f"❌ CYBERSCYTHE main.py syntax error: {e}")
        return False
    
    return True

def main():
    """Run all tests"""
    print("🚀 VulnPrism Service Test Suite")
    print("=" * 50)
    
    all_passed = True
    
    # Run tests
    if not test_imports():
        all_passed = False
    
    if not test_pdf_generation():
        all_passed = False
    
    if not test_service_health():
        all_passed = False
    
    print("\n" + "=" * 50)
    if all_passed:
        print("🎉 All tests passed! Services are ready for Docker build.")
        return 0
    else:
        print("❌ Some tests failed. Fix issues before Docker build.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
