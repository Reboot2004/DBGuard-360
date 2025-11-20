"""
DBGuard360 - Continuous Monitoring Mode
Run this to continuously monitor and log MySQL queries
Use your regular MySQL client for actual work
"""

import sys
import time
from src.core.interceptor import DBGuardConnection
from src.logger.memory_buffer import MemoryBufferedLogger
from src.recovery.analyzer import ProcessAndArchiveAnalyzer


def monitor_database(database_name):
    """
    Continuously monitor database queries
    Keeps connection alive and logs all activity
    """
    
    # Initialize protection components (WITHOUT first_commit - no IBD backups)
    print("🛡️  Initializing DBGuard360 monitoring...")
    logger = MemoryBufferedLogger()
    analyzer = ProcessAndArchiveAnalyzer()
    
    # MySQL configuration
    mysql_config = {
        'host': 'localhost',
        'user': 'superuser',
        'password': 'Collector#123',
        'database': database_name
    }
    
    print(f"📡 Starting monitoring for database '{database_name}'...")
    print(f"👤 User: {mysql_config['user']}")
    print()
    
    try:
        # Create connection WITHOUT first_commit_handler (no IBD backups)
        conn = DBGuardConnection(mysql_config, logger, analyzer, first_commit_handler=None)
        
        print("✅ DBGuard360 monitoring active!")
        print()
        print("=" * 60)
        print("📊 MONITORING STATUS")
        print("=" * 60)
        print("✓ Query logging: ENABLED (memory buffered)")
        print("✓ Malicious detection: ENABLED")
        print("✓ Auto-archive: ENABLED")
        print("✗ IBD backups: DISABLED (manual only)")
        print("=" * 60)
        print()
        print("💡 How to use:")
        print("   1. Leave this script running")
        print("   2. Open another terminal: mysql -u superuser -p testdb")
        print("   3. Execute your queries normally")
        print("   4. On COMMIT, queries will be logged here")
        print("   5. Use the GUI to view logs: python view_logs_gui.py")
        print()
        print("📁 Logs will be saved to:")
        print(f"   • Clean queries → logs/archive/")
        print(f"   • Malicious queries → logs/malicious/")
        print()
        print("🛑 Press Ctrl+C to stop monitoring")
        print("=" * 60)
        print()
        
        # Keep connection alive and monitor
        counter = 0
        while True:
            time.sleep(5)  # Check every 5 seconds
            counter += 1
            
            # Process any pending logs
            if counter % 6 == 0:  # Every 30 seconds
                pending_count = len(list(analyzer.pending_dir.glob("*.raw")))
                if pending_count > 0:
                    print(f"📋 Processing {pending_count} pending log file(s)...")
                    malicious = analyzer.process_all_pending()
                    if malicious:
                        print(f"⚠️  Found {len(malicious)} malicious queries!")
            
    except KeyboardInterrupt:
        print("\n\n🛑 Monitoring stopped by user")
        print("📊 Final statistics:")
        print(f"   • Clean logs: {analyzer.get_archive_count()}")
        print(f"   • Malicious logs: {analyzer.get_malicious_count()}")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        print("\nTroubleshooting:")
        print("1. Verify MySQL is running")
        print(f"2. Check database '{database_name}' exists")
        print("3. Ensure user 'superuser' has proper permissions")
        
    finally:
        try:
            conn.close()
            print("\n🔒 Connection closed")
        except:
            pass


def main():
    """Main entry point"""
    
    # Get database name
    if len(sys.argv) > 1:
        database_name = sys.argv[1]
    else:
        database_name = input("Enter database name to monitor: ").strip()
        if not database_name:
            print("❌ Database name is required!")
            return
    
    monitor_database(database_name)


if __name__ == '__main__':
    main()
