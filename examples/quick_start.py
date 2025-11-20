"""
Quick Start Guide - DBGuard360 with Interceptor
This example shows how to use the interceptor in your application
"""

from src.core.interceptor import DBGuardConnection
from src.logger.memory_buffer import MemoryBufferedLogger
from src.recovery.analyzer import ProcessAndArchiveAnalyzer
from src.snapshot.first_commit import FirstCommitHandler


def example_with_interceptor():
    """
    Complete example showing interceptor usage
    """
    
    # Step 1: Initialize DBGuard components
    logger = MemoryBufferedLogger()
    analyzer = ProcessAndArchiveAnalyzer()
    first_commit = FirstCommitHandler()
    
    # Step 2: Configure MySQL connection
    mysql_config = {
        'host': 'localhost',
        'user': 'superuser',
        'password': 'Collector#123',
        'database': 'test_db'  # Change to your database
    }
    
    # Step 3: Create protected connection (interceptor is now active!)
    print("🛡️  Creating protected connection with interceptor...")
    conn = DBGuardConnection(mysql_config, logger, analyzer, first_commit)
    print("✅ Interceptor enabled - all queries will be monitored\n")
    
    try:
        # ===== EXAMPLE 1: Safe Transaction =====
        print("--- Example 1: Safe Transaction ---")
        conn.execute("START TRANSACTION")
        conn.execute("SELECT * FROM users WHERE id = 1")
        conn.execute("UPDATE users SET last_login = NOW() WHERE id = 1")
        conn.execute("COMMIT")  # Logs flushed, analyzed, archived
        print()
        
        # ===== EXAMPLE 2: Suspicious Query Detection =====
        print("--- Example 2: Malicious Query Detection ---")
        conn.execute("START TRANSACTION")
        conn.execute("DELETE FROM temp_logs")  # No WHERE - will be flagged!
        conn.execute("COMMIT")  # Will show warning about malicious query
        print()
        
        # ===== EXAMPLE 3: Rollback (no logs created) =====
        print("--- Example 3: Rollback ---")
        conn.execute("START TRANSACTION")
        conn.execute("UPDATE accounts SET balance = 0")
        conn.execute("ROLLBACK")  # Buffer cleared
        print()
        
        # ===== EXAMPLE 4: Context Manager (auto-commit) =====
        print("--- Example 4: Using Context Manager ---")
        with DBGuardConnection(mysql_config, logger, analyzer, first_commit) as conn2:
            conn2.execute("START TRANSACTION")
            conn2.execute("INSERT INTO audit_log (action) VALUES ('test')")
            # Auto-commits and logs when context exits
        print()
        
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        conn.close()
        print("🔒 Connection closed\n")
        
    # Check results
    print("📊 Results:")
    print("   • Clean queries → logs/archive/")
    print("   • Malicious queries → logs/malicious/")
    print("   • Table snapshots → snapshots/tables/")
    print("\n💡 Use CLI to analyze: python -m src.cli.commands status")


def example_in_your_app():
    """
    How to integrate interceptor in your actual application
    """
    
    print("\n" + "="*60)
    print("HOW TO USE IN YOUR APPLICATION:")
    print("="*60)
    
    print("""
1. Import the components:
   from src.core.interceptor import DBGuardConnection
   from src.logger.memory_buffer import MemoryBufferedLogger
   from src.recovery.analyzer import ProcessAndArchiveAnalyzer
   from src.snapshot.first_commit import FirstCommitHandler

2. Initialize once (at app startup):
   logger = MemoryBufferedLogger()
   analyzer = ProcessAndArchiveAnalyzer()
   first_commit = FirstCommitHandler()
   
   mysql_config = {
       'host': 'localhost',
       'user': 'superuser',
       'password': 'Collector#123',
       'database': 'your_database'
   }

3. Replace mysql.connector.connect() with DBGuardConnection():
   # Old way:
   # conn = mysql.connector.connect(**mysql_config)
   
   # New way (with protection):
   conn = DBGuardConnection(mysql_config, logger, analyzer, first_commit)

4. Use normally:
   conn.execute("SELECT * FROM users")
   conn.execute("COMMIT")
   
5. That's it! Protection is automatic:
   ✓ Queries logged in memory (zero overhead)
   ✓ Flushed to disk on COMMIT
   ✓ Analyzed for malicious patterns
   ✓ Tables backed up on first commit
   ✓ Ready for instant recovery
""")


if __name__ == '__main__':
    print("🚀 DBGuard360 Quick Start\n")
    example_with_interceptor()
    example_in_your_app()

