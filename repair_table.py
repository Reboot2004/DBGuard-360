#!/usr/bin/env python3
"""
DBGuard 360 - MySQL general_log Table Repair Utility

Fixes the "Table 'general_log' is marked as crashed" error
Run this if you encounter database errors in the monitor.
"""

import mysql.connector
import sys


def repair_general_log():
    """Repair the mysql.general_log table"""
    
    print("🔧 DBGuard 360 - Table Repair Utility")
    print("=" * 60)
    
    # Get credentials
    user = input("MySQL username [superuser]: ").strip() or "superuser"
    password = input("MySQL password: ").strip()
    
    if not password:
        print("❌ Password is required")
        sys.exit(1)
    
    try:
        print("\n🔌 Connecting to MySQL...")
        conn = mysql.connector.connect(
            host='localhost',
            user=user,
            password=password
        )
        
        cursor = conn.cursor()
        
        print("✅ Connected successfully")
        print()
        
        # Check table status
        print("📊 Checking mysql.general_log table status...")
        cursor.execute("CHECK TABLE mysql.general_log")
        result = cursor.fetchall()
        
        for row in result:
            table, op, msg_type, msg_text = row
            print(f"   {msg_type}: {msg_text}")
        
        print()
        
        # Repair table
        print("🔧 Repairing mysql.general_log table...")
        cursor.execute("REPAIR TABLE mysql.general_log")
        result = cursor.fetchall()
        
        for row in result:
            table, op, msg_type, msg_text = row
            status_emoji = "✅" if msg_type == "status" and "OK" in msg_text else "⚠️"
            print(f"   {status_emoji} {msg_type}: {msg_text}")
        
        print()
        
        # Optimize table (optional but recommended)
        print("⚡ Optimizing table (this may take a moment)...")
        cursor.execute("OPTIMIZE TABLE mysql.general_log")
        result = cursor.fetchall()
        
        for row in result:
            table, op, msg_type, msg_text = row
            print(f"   {msg_type}: {msg_text}")
        
        cursor.close()
        conn.close()
        
        print()
        print("=" * 60)
        print("✅ Repair completed successfully!")
        print("=" * 60)
        print()
        print("💡 You can now run: python monitor_general_log.py")
        
    except mysql.connector.Error as e:
        print(f"\n❌ MySQL Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    repair_general_log()
