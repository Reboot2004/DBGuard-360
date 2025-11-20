"""
Table-specific recovery functionality
"""

import mysql.connector
from .display import RecoveryDisplay
from ..snapshot.ibd_manager import IBDRestorer


class TableRecovery:
    """
    Recover specific table(s) from IBD backup and replay safe queries
    """
    
    def __init__(self, mysql_config=None):
        """
        Initialize table recovery
        
        Args:
            mysql_config: MySQL connection config (optional, can provide later)
        """
        self.mysql_config = mysql_config
        self.display = RecoveryDisplay()
        self.ibd_restorer = IBDRestorer()
    
    def recover_table(self, table_name: str, mysql_config=None, confirm=True):
        """
        Recover a specific table from backup
        
        Args:
            table_name: Name of table to recover
            mysql_config: MySQL connection config
            confirm: Whether to ask for confirmation
            
        Returns:
            dict: Recovery results
        """
        if mysql_config is None:
            mysql_config = self.mysql_config
        
        if mysql_config is None:
            raise ValueError("MySQL config required for recovery")
        
        print(f"\n🔄 Starting recovery for table: {table_name}\n")
        
        # Step 1: Show recovery plan (parses queries)
        plan = self.display.get_recovery_plan(table_name)
        
        if confirm:
            response = input(f"\nProceed with recovery? (yes/no): ")
            if response.lower() != 'yes':
                print("Recovery cancelled.")
                return {'status': 'cancelled'}
        
        # Connect to MySQL
        conn = mysql.connector.connect(**mysql_config)
        cursor = conn.cursor()
        
        try:
            # Step 2: Restore IBD file (back to initial state)
            print(f"\n📦 Restoring {table_name} from IBD backup...")
            self.ibd_restorer.restore_table(table_name, cursor)
            conn.commit()
            
            # Step 3: Replay safe queries (parsed on demand)
            print(f"\n▶️  Replaying {len(plan['safe_queries'])} safe queries...")
            
            replayed = 0
            failed = 0
            
            for query_info in sorted(plan['safe_queries'], key=lambda x: x['timestamp']):
                try:
                    cursor.execute(query_info['query'])
                    conn.commit()
                    replayed += 1
                except Exception as e:
                    print(f"⚠️  Failed to replay: {query_info['query'][:50]}... Error: {e}")
                    failed += 1
            
            print(f"\n✅ Recovery complete!")
            print(f"   Restored: {table_name}")
            print(f"   Replayed: {replayed} queries")
            print(f"   Failed: {failed} queries")
            print(f"   Skipped: {len(plan['malicious_queries'])} malicious queries")
            
            return {
                'status': 'success',
                'table': table_name,
                'replayed': replayed,
                'failed': failed,
                'skipped': len(plan['malicious_queries'])
            }
            
        except Exception as e:
            print(f"\n❌ Recovery failed: {e}")
            conn.rollback()
            return {'status': 'failed', 'error': str(e)}
        
        finally:
            cursor.close()
            conn.close()
    
    def recover_multiple_tables(self, table_names: list, mysql_config=None, confirm=True):
        """
        Recover multiple tables
        
        Args:
            table_names: List of table names
            mysql_config: MySQL connection config
            confirm: Whether to ask for confirmation
            
        Returns:
            list: Recovery results for each table
        """
        results = []
        
        for table_name in table_names:
            result = self.recover_table(table_name, mysql_config, confirm)
            results.append(result)
        
        return results
    
    def verify_backup_exists(self, table_name: str) -> bool:
        """
        Check if backup exists for a table
        
        Args:
            table_name: Name of table
            
        Returns:
            bool: True if backup exists
        """
        from pathlib import Path
        backup_path = Path(__file__).parent.parent.parent / "snapshots" / "tables" / f"{table_name}.ibd.backup"
        return backup_path.exists()
