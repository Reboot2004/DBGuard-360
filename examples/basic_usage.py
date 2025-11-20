"""
Basic usage example for DBGuard360
"""

from src.core import DBGuardConnection
from src.logger import MemoryBufferedLogger
from src.recovery import ProcessAndArchiveAnalyzer
from src.snapshot import FirstCommitHandler


def main():
    """
    Demonstrates basic DBGuard360 usage
    """
    
    # Initialize components
    logger = MemoryBufferedLogger()
    analyzer = ProcessAndArchiveAnalyzer()
    first_commit = FirstCommitHandler()
    
    # MySQL configuration
    mysql_config = {
        'host': 'localhost',
        'user': 'root',
        'password': 'your_password',
        'database': 'test_db'
    }
    
    # Create protected connection
    print("Connecting to MySQL with DBGuard360 protection...")
    conn = DBGuardConnection(mysql_config, logger, analyzer, first_commit)
    
    try:
        # Example 1: Normal transaction
        print("\n--- Example 1: Normal Transaction ---")
        conn.execute("START TRANSACTION")
        conn.execute("INSERT INTO users (id, name) VALUES (1, 'Alice')")
        conn.execute("INSERT INTO users (id, name) VALUES (2, 'Bob')")
        conn.execute("COMMIT")  # Logs are flushed, analyzed, archived
        
        # Example 2: Query with potential issue
        print("\n--- Example 2: Potentially Dangerous Query ---")
        conn.execute("START TRANSACTION")
        conn.execute("DELETE FROM temp_table")  # No WHERE - will be flagged
        conn.execute("COMMIT")
        
        # Example 3: Rollback (discards buffer)
        print("\n--- Example 3: Transaction Rollback ---")
        conn.execute("START TRANSACTION")
        conn.execute("UPDATE users SET balance = 0")
        conn.execute("ROLLBACK")  # Buffer cleared, no log file created
        
    finally:
        conn.close()
        print("\nConnection closed.")


if __name__ == '__main__':
    main()
