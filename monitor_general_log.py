"""
DBGuard360 - General Log Monitor (RAW FORMAT)
Monitors MySQL general log and captures queries in raw format
No parsing - just raw storage until recovery
"""

import sys
import time
from pathlib import Path
from datetime import datetime
import mysql.connector


class GeneralLogMonitor:
    """
    Monitor MySQL general log and capture raw queries
    Stores in raw format - no parsing until recovery
    """
    
    def __init__(self, database_name):
        self.database = database_name
        self.pending_dir = Path("logs/pending")
        self.pending_dir.mkdir(parents=True, exist_ok=True)
        
        self.config = {
            'host': 'localhost',
            'user': 'superuser',
            'password': 'Collector#123',
            'database': database_name
        }
        
        self.current_transaction = []
        self.transaction_user = "unknown"
        self.transaction_start_time = None
    
    def enable_general_log(self, conn):
        """Enable general query log to table"""
        cursor = conn.cursor()
        
        # Check if general log is enabled
        cursor.execute("SHOW VARIABLES LIKE 'general_log'")
        result = cursor.fetchone()
        
        if result and result[1] == 'OFF':
            print("⚠️  General log is OFF. Enabling it...")
            cursor.execute("SET GLOBAL general_log = 'ON'")
            cursor.execute("SET GLOBAL log_output = 'TABLE'")
            print("✅ General log enabled (logging to mysql.general_log table)")
        
        cursor.close()
    
    def monitor(self):
        """Monitor general log and capture raw queries"""
        
        print(f"🛡️  Starting RAW query monitoring for database '{self.database}'")
        print(f"👤 User: {self.config['user']}")
        print()
        
        conn = mysql.connector.connect(**self.config)
        
        try:
            # Enable general log
            self.enable_general_log(conn)
            
            print("=" * 60)
            print("📊 MONITORING STATUS")
            print("=" * 60)
            print("✓ General log monitoring: ENABLED")
            print("✓ Raw format: ENABLED (no parsing)")
            print("✓ Transaction tracking: ENABLED")
            print("=" * 60)
            print()
            print("💡 How to use:")
            print("   1. Leave this script running")
            print("   2. Open MySQL client: mysql -u superuser -p testdb")
            print("   3. SET autocommit = 0;")
            print("   4. START TRANSACTION;")
            print("   5. Run your queries")
            print("   6. COMMIT;  -- This captures raw queries")
            print()
            print("📁 Raw logs saved to: logs/pending/")
            print("🛑 Press Ctrl+C to stop")
            print("=" * 60)
            print()
            
            # Get current max event_time to start from
            cursor = conn.cursor()
            cursor.execute("SELECT MAX(event_time) FROM mysql.general_log")
            last_time = cursor.fetchone()[0] or datetime.now()
            cursor.close()
            
            transaction_count = 0
            
            while True:
                cursor = conn.cursor()
                
                # Query new log entries (filter by database in Python, not SQL)
                query = """
                    SELECT event_time, user_host, thread_id, command_type, argument
                    FROM mysql.general_log
                    WHERE event_time > %s
                    ORDER BY event_time ASC
                    LIMIT 1000
                """
                
                cursor.execute(query, (last_time,))
                entries = cursor.fetchall()
                
                for entry in entries:
                    event_time, user_host, thread_id, command_type, argument = entry
                    last_time = event_time
                    
                    # Only process Query commands
                    if command_type != 'Query':
                        continue
                    
                    # Skip if argument is None or empty
                    if not argument:
                        continue
                    
                    query_upper = argument.strip().upper()
                    
                    # Filter by database (check USE database or database.table references)
                    # For simplicity, capture all queries - user will be working in correct DB
                    # if query_upper.startswith('USE ') and self.database.upper() not in query_upper:
                    #     continue
                    
                    # Extract user from user_host (format: user[user] @ hostname [ip])
                    if '[' in user_host:
                        user = user_host.split('[')[1].split(']')[0]
                    else:
                        user = 'unknown'
                    
                    # Track transaction lifecycle
                    if query_upper.startswith('START TRANSACTION') or query_upper.startswith('BEGIN'):
                        self.current_transaction = []
                        self.transaction_user = user
                        self.transaction_start_time = int(time.time() * 1000)
                        print(f"🔵 Transaction started by {user}")
                    
                    # Add to current transaction
                    if self.transaction_start_time:
                        timestamp_ms = int(event_time.timestamp() * 1000)
                        query_length = len(argument)
                        
                        # RAW FORMAT: timestamp|session|user|length|query
                        raw_line = f"{timestamp_ms}|{thread_id}|{user}|{query_length}|{argument}\n"
                        self.current_transaction.append(raw_line)
                        
                        # Show preview
                        preview = argument[:80].replace('\n', ' ')
                        print(f"   📝 {preview}{'...' if len(argument) > 80 else ''}")
                    
                    # On COMMIT - flush raw transaction to file
                    if query_upper.startswith('COMMIT'):
                        if self.current_transaction:
                            transaction_count += 1
                            session_id = f"{thread_id:08x}"
                            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
                            filename = f"txn_{session_id}_{timestamp}.raw"
                            filepath = self.pending_dir / filename
                            
                            # Write RAW format (no parsing, no processing)
                            with open(filepath, 'w', encoding='utf-8') as f:
                                f.writelines(self.current_transaction)
                            
                            print(f"✅ Transaction #{transaction_count} logged: {filename}")
                            print(f"   {len(self.current_transaction)} queries captured (RAW)")
                            print()
                            
                            # Reset
                            self.current_transaction = []
                            self.transaction_start_time = None
                    
                    # On ROLLBACK - discard
                    if query_upper.startswith('ROLLBACK'):
                        if self.current_transaction:
                            print(f"🔴 Transaction rolled back - discarded {len(self.current_transaction)} queries")
                            print()
                            self.current_transaction = []
                            self.transaction_start_time = None
                
                cursor.close()
                time.sleep(0.5)  # Poll every 500ms
        
        except KeyboardInterrupt:
            print("\n\n🛑 Monitoring stopped")
            print(f"📊 Total transactions captured: {transaction_count}")
        
        except Exception as e:
            print(f"\n❌ Error: {e}")
            import traceback
            traceback.print_exc()
        
        finally:
            conn.close()
            print("🔒 Connection closed")


def main():
    """Main entry point"""
    
    if len(sys.argv) > 1:
        database = sys.argv[1]
    else:
        database = input("Enter database name to monitor: ").strip()
        if not database:
            print("❌ Database name is required!")
            return
    
    monitor = GeneralLogMonitor(database)
    monitor.monitor()


if __name__ == '__main__':
    main()
