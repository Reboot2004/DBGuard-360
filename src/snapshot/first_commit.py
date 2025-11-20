"""
First commit handler that triggers IBD file backup
"""

import sqlite3
from pathlib import Path
from .ibd_manager import IBDBackup


class FirstCommitHandler:
    """
    Detects first commit per table and triggers one-time IBD backup
    """
    
    def __init__(self, snapshot_dir=None):
        """
        Initialize first commit handler
        
        Args:
            snapshot_dir: Directory for snapshots. Defaults to snapshots/
        """
        if snapshot_dir is None:
            snapshot_dir = Path(__file__).parent.parent.parent / "snapshots"
        
        self.snapshot_dir = Path(snapshot_dir)
        self.snapshot_dir.mkdir(parents=True, exist_ok=True)
        
        self.metadata_db_path = self.snapshot_dir / "metadata.db"
        self.metadata_db = sqlite3.connect(str(self.metadata_db_path), check_same_thread=False)
        self._init_metadata_table()
        
        self.ibd_backup = IBDBackup(snapshot_dir)
    
    def _init_metadata_table(self):
        """Create metadata table if not exists"""
        self.metadata_db.execute("""
            CREATE TABLE IF NOT EXISTS table_snapshots (
                table_name TEXT PRIMARY KEY,
                snapshot_path TEXT NOT NULL,
                snapshot_date INTEGER NOT NULL,
                snapshot_size INTEGER,
                is_backed_up INTEGER DEFAULT 1
            )
        """)
        self.metadata_db.commit()
    
    def handle_commit(self, cursor, session_id: str):
        """
        Handle commit - backup tables that haven't been backed up yet
        
        Args:
            cursor: MySQL cursor for querying metadata
            session_id: Current session ID
        """
        # Get tables accessed in this transaction
        accessed_tables = self._get_accessed_tables_from_mysql(cursor)
        
        if not accessed_tables:
            # Fallback: try to get from information_schema
            accessed_tables = self._get_all_tables(cursor)
        
        for table in accessed_tables:
            if not self._is_backed_up(table):
                print(f"📸 First commit backup for table: {table}")
                try:
                    self.ibd_backup.backup_table(table, cursor)
                    self._mark_backed_up(table, self.snapshot_dir / "tables" / f"{table}.ibd.backup")
                    print(f"✓ Successfully backed up {table}")
                except Exception as e:
                    print(f"⚠️  Failed to backup {table}: {e}")
    
    def _get_accessed_tables_from_mysql(self, cursor):
        """
        Get tables accessed in current transaction using performance schema
        
        Args:
            cursor: MySQL cursor
            
        Returns:
            list: Table names accessed
        """
        try:
            query = """
                SELECT DISTINCT object_name 
                FROM performance_schema.events_statements_history 
                WHERE thread_id = CONNECTION_ID()
                AND object_schema = DATABASE()
                AND object_name IS NOT NULL
                AND object_type = 'TABLE'
            """
            cursor.execute(query)
            return [row[0] for row in cursor.fetchall()]
        except Exception as e:
            print(f"⚠️  Could not query performance_schema: {e}")
            return []
    
    def _get_all_tables(self, cursor):
        """
        Fallback: Get all tables in current database
        
        Args:
            cursor: MySQL cursor
            
        Returns:
            list: All table names in database
        """
        try:
            cursor.execute("SHOW TABLES")
            return [row[0] for row in cursor.fetchall()]
        except Exception as e:
            print(f"⚠️  Could not list tables: {e}")
            return []
    
    def _is_backed_up(self, table_name: str) -> bool:
        """
        Check if table already has IBD backup
        
        Args:
            table_name: Name of table
            
        Returns:
            bool: True if backed up, False otherwise
        """
        result = self.metadata_db.execute(
            "SELECT is_backed_up FROM table_snapshots WHERE table_name = ?",
            (table_name,)
        ).fetchone()
        return result and result[0] == 1
    
    def _mark_backed_up(self, table_name: str, snapshot_path: Path):
        """
        Mark table as backed up in metadata
        
        Args:
            table_name: Name of table
            snapshot_path: Path to backup file
        """
        import time
        import os
        
        snapshot_size = os.path.getsize(snapshot_path) if snapshot_path.exists() else 0
        
        self.metadata_db.execute("""
            INSERT OR REPLACE INTO table_snapshots 
            (table_name, snapshot_path, snapshot_date, snapshot_size, is_backed_up)
            VALUES (?, ?, ?, ?, 1)
        """, (table_name, str(snapshot_path), int(time.time()), snapshot_size))
        self.metadata_db.commit()
    
    def get_backed_up_tables(self) -> list:
        """
        Get list of all backed up tables
        
        Returns:
            list: Table names that have backups
        """
        result = self.metadata_db.execute(
            "SELECT table_name FROM table_snapshots WHERE is_backed_up = 1"
        ).fetchall()
        return [row[0] for row in result]
    
    def close(self):
        """Close database connection"""
        self.metadata_db.close()
