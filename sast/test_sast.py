#!/usr/bin/env python3
"""
Quick test script to verify SAST service functionality
"""
import os
import tempfile
import shutil
from pathlib import Path

# Test imports
try:
    import scan_engine
    import pdf_report
    print("✅ All imports successful")
except ImportError as e:
    print(f"❌ Import error: {e}")
    exit(1)

def test_basic_functionality():
    """Test basic SAST functionality"""
    print("🔍 Testing SAST basic functionality...")
    
    # Create a temporary directory with test code
    with tempfile.TemporaryDirectory() as temp_dir:
        test_file = os.path.join(temp_dir, "test.py")
        with open(test_file, "w") as f:
            f.write("""
# Test Python file with potential security issues
import os
password = "hardcoded_password_123"  # Security issue
user_input = input("Enter command: ")
os.system(user_input)  # Command injection vulnerability
""")
        
        print(f"📁 Created test file: {test_file}")
        
        # Test directory validation
        try:
            analysis = scan_engine.validate_source_directory(temp_dir)
            print(f"✅ Directory validation: {analysis}")
        except Exception as e:
            print(f"❌ Directory validation failed: {e}")
            return False
        
        # Test scan engine
        try:
            temp_id = "test_123"
            report_path = scan_engine.run_full_scan_and_report(temp_dir, temp_id)
            if report_path and os.path.exists(report_path):
                print(f"✅ Scan completed, report: {report_path}")
                print(f"📄 Report size: {os.path.getsize(report_path)} bytes")
                return True
            else:
                print("❌ Scan failed - no report generated")
                return False
        except Exception as e:
            print(f"❌ Scan failed: {e}")
            return False

if __name__ == "__main__":
    print("🚀 SAST Service Test Starting...")
    success = test_basic_functionality()
    if success:
        print("🎉 All tests passed!")
        exit(0)
    else:
        print("💥 Tests failed!")
        exit(1)
