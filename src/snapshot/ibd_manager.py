"""
IBD file backup and restoration manager
"""

import shutil
import os
from pathlib import Path


class IBDBackup:
    """
    Handles one-time IBD file backup for tables
    """
    
    def __init__(self, snapshot_dir=None):
        """
        Initialize IBD backup manager
        
        Args:
            snapshot_dir: Directory for snapshots
        """
        if snapshot_dir is None:
            snapshot_dir = Path(__file__).parent.parent.parent / "snapshots"
        
        self.snapshot_dir = Path(snapshot_dir)
        self.tables_dir = self.snapshot_dir / "tables"
        self.tables_dir.mkdir(parents=True, exist_ok=True)
    
    def backup_table(self, table_name: str, cursor):
        """
        Copy IBD file for table (one-time only)
        
        Args:
            table_name: Name of table to backup
            cursor: MySQL cursor for executing commands
        """
        # 1. Get MySQL data directory
        data_dir = self._get_mysql_data_dir(cursor)
        database = self._get_current_database(cursor)
        
        # 2. Flush table to disk
        try:
            cursor.execute(f"FLUSH TABLES `{table_name}` FOR EXPORT")
        except Exception as e:
            print(f"⚠️  Note: FLUSH TABLES FOR EXPORT failed (may not be needed): {e}")
        
        # 3. Find and copy IBD file
        ibd_path = Path(data_dir) / database / f"{table_name}.ibd"
        
        if not ibd_path.exists():
            raise FileNotFoundError(f"IBD file not found: {ibd_path}")
        
        backup_path = self.tables_dir / f"{table_name}.ibd.backup"
        shutil.copy2(ibd_path, backup_path)
        
        # 4. Copy CFG file if exists (for transportable tablespaces)
        cfg_path = Path(data_dir) / database / f"{table_name}.cfg"
        if cfg_path.exists():
            cfg_backup_path = self.tables_dir / f"{table_name}.cfg.backup"
            shutil.copy2(cfg_path, cfg_backup_path)
        
        # 5. Unlock tables
        try:
            cursor.execute("UNLOCK TABLES")
        except Exception as e:
            print(f"⚠️  Note: UNLOCK TABLES failed: {e}")
    
    def _get_mysql_data_dir(self, cursor) -> str:
        """
        Get MySQL data directory path
        
        Args:
            cursor: MySQL cursor
            
        Returns:
            str: Data directory path
        """
        cursor.execute("SELECT @@datadir")
        result = cursor.fetchone()
        if result:
            return result[0]
        raise RuntimeError("Could not determine MySQL data directory")
    
    def _get_current_database(self, cursor) -> str:
        """
        Get current database name
        
        Args:
            cursor: MySQL cursor
            
        Returns:
            str: Database name
        """
        cursor.execute("SELECT DATABASE()")
        result = cursor.fetchone()
        if result and result[0]:
            return result[0]
        raise RuntimeError("No database selected")


class IBDRestorer:
    """
    Restores tables from IBD backup files
    """
    
    def __init__(self, snapshot_dir=None):
        """
        Initialize IBD restorer
        
        Args:
            snapshot_dir: Directory containing snapshots
        """
        if snapshot_dir is None:
            snapshot_dir = Path(__file__).parent.parent.parent / "snapshots"
        
        self.snapshot_dir = Path(snapshot_dir)
        self.tables_dir = self.snapshot_dir / "tables"
    
    def restore_table(self, table_name: str, cursor):
        """
        Restore table from IBD backup (instant recovery)
        
        Args:
            table_name: Name of table to restore
            cursor: MySQL cursor for executing commands
        """
        backup_path = self.tables_dir / f"{table_name}.ibd.backup"
        
        if not backup_path.exists():
            raise FileNotFoundError(f"No backup found for table: {table_name}")
        
        # Get paths
        data_dir = self._get_mysql_data_dir(cursor)
        database = self._get_current_database(cursor)
        target_path = Path(data_dir) / database / f"{table_name}.ibd"
        
        # 1. Discard current tablespace
        cursor.execute(f"ALTER TABLE `{table_name}` DISCARD TABLESPACE")
        
        # 2. Copy backup IBD to data directory
        shutil.copy2(backup_path, target_path)
        
        # 3. Copy CFG file if exists
        cfg_backup = self.tables_dir / f"{table_name}.cfg.backup"
        if cfg_backup.exists():
            cfg_target = Path(data_dir) / database / f"{table_name}.cfg"
            shutil.copy2(cfg_backup, cfg_target)
        
        # 4. Import tablespace
        cursor.execute(f"ALTER TABLE `{table_name}` IMPORT TABLESPACE")
        
        print(f"✓ Table {table_name} restored from IBD backup")
    
    def _get_mysql_data_dir(self, cursor) -> str:
        """Get MySQL data directory path"""
        cursor.execute("SELECT @@datadir")
        result = cursor.fetchone()
        if result:
            return result[0]
        raise RuntimeError("Could not determine MySQL data directory")
    
    def _get_current_database(self, cursor) -> str:
        """Get current database name"""
        cursor.execute("SELECT DATABASE()")
        result = cursor.fetchone()
        if result and result[0]:
            return result[0]
        raise RuntimeError("No database selected")
