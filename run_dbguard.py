"""
DBGuard360 - Main Entry Point
Run this file to start using DBGuard protection
"""

import sys
from src.core.interceptor import DBGuardConnection
from src.logger.memory_buffer import MemoryBufferedLogger
from src.recovery.analyzer import ProcessAndArchiveAnalyzer
from src.snapshot.first_commit import FirstCommitHandler


def main():
    """
    Main entry point for DBGuard360 protection
    """
    
    # Get database name from command line or prompt user
    if len(sys.argv) > 1:
        database_name = sys.argv[1]
    else:
        database_name = input("Enter database name: ").strip()
        if not database_name:
            print("❌ Database name is required!")
            return
    
    # Initialize protection components (NO IBD backups)
    print("🛡️  Initializing DBGuard360 protection...")
    logger = MemoryBufferedLogger()
    analyzer = ProcessAndArchiveAnalyzer()
    first_commit = None  # Disabled - no IBD backups
    
    # MySQL configuration with your credentials
    mysql_config = {
        'host': 'localhost',
        'user': 'superuser',
        'password': 'Collector#123',
        'database': database_name
    }
    
    print(f"📡 Connecting to MySQL database '{database_name}' as {mysql_config['user']}...")
    
    try:
        # Create protected connection with interceptor enabled
        conn = DBGuardConnection(mysql_config, logger, analyzer, first_commit)
        print("✅ DBGuard360 interceptor enabled!\n")
        
        # Now you can use conn.execute() for all your queries
        # All queries will be logged, analyzed for malicious patterns, and can be recovered
        
        # Get list of tables in database
        cursor = conn.cursor()
        cursor.execute("SHOW TABLES")
        tables = cursor.fetchall()
        cursor.close()  # Close cursor after fetching results
        
        if tables:
            print(f"📊 Found {len(tables)} tables in database '{database_name}':")
            for table in tables:
                print(f"   • {table[0]}")
            
            # Example usage with first table
            first_table = tables[0][0]
            print(f"\n--- Example: Protected Transaction on '{first_table}' ---")
            conn.execute("START TRANSACTION")
            result_cursor = conn.execute(f"SELECT * FROM {first_table} LIMIT 5")
            result_cursor.fetchall()  # Consume the results
            result_cursor.close()  # Close the cursor
            conn.execute("COMMIT")
            
            print("\n✅ Transaction completed and logged")
            print("📁 Check logs/archive/ for clean queries")
            print("⚠️  Check logs/malicious/ for suspicious queries")
        else:
            print(f"⚠️  No tables found in database '{database_name}'")
            print("   Create some tables first to see DBGuard360 in action!")
        
        # Close connection when done
        conn.close()
        print("\n🔒 Connection closed safely")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        print("\nTroubleshooting:")
        print("1. Verify MySQL is running: mysql -u superuser -p")
        print(f"2. Check database '{database_name}' exists")
        print("3. Ensure user 'superuser' has proper permissions")
        print("\n💡 Usage:")
        print("   python run_dbguard.py <database_name>")
        print("   python run_dbguard.py mydatabase")


if __name__ == '__main__':
    main()

