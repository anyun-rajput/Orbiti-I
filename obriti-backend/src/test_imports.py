#!/usr/bin/env python3
"""
Test script to verify all imports are working correctly
"""

def test_imports():
    try:
        print("Testing imports...")
        
        # Test the main problematic import
        from utils.auth_utils import create_access_token
        print("✅ utils.auth_utils import successful")
        
        # Test microsoft callback import
        from api.microsoft_callback import router as microsoft_callback_router
        print("✅ api.microsoft_callback import successful")
        
        # Test microsoft sso service import
        from services.microsoft_sso_service import microsoft_sso_service
        print("✅ services.microsoft_sso_service import successful")
        
        # Test main app import
        from main import app
        print("✅ main app import successful")
        
        print("\n🎉 All imports successful! The server should start without import errors.")
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

if __name__ == "__main__":
    test_imports()
