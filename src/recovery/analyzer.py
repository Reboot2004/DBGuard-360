"""
Query analyzer that detects malicious patterns and archives log files
"""

import shutil
import os
import re
from pathlib import Path


class ProcessAndArchiveAnalyzer:
    """
    Process log files for malicious queries, then move to archive (Solution 4)
    No re-processing - each file processed once, then moved
    """
    
    def __init__(self, 
                 pending_dir=None,
                 archive_dir=None,
                 malicious_dir=None):
        """
        Initialize analyzer with directory paths
        
        Args:
            pending_dir: Directory with pending log files
            archive_dir: Directory for clean transaction logs
            malicious_dir: Directory for logs with malicious queries
        """
        if pending_dir is None:
            pending_dir = Path(__file__).parent.parent.parent / "logs" / "pending"
        if archive_dir is None:
            archive_dir = Path(__file__).parent.parent.parent / "logs" / "archive"
        if malicious_dir is None:
            malicious_dir = Path(__file__).parent.parent.parent / "logs" / "malicious"
        
        self.pending_dir = Path(pending_dir)
        self.archive_dir = Path(archive_dir)
        self.malicious_dir = Path(malicious_dir)
        
        # Create directories
        self.archive_dir.mkdir(parents=True, exist_ok=True)
        self.malicious_dir.mkdir(parents=True, exist_ok=True)
    
    def process_and_archive(self, log_file_path: str):
        """
        Process a single log file for malicious queries, then archive it
        
        Args:
            log_file_path: Path to log file to process
            
        Returns:
            list: Malicious queries found
        """
        malicious_queries = []
        
        # Read and analyze the file
        with open(log_file_path, 'r', encoding='utf-8') as f:
            for line in f:
                parts = line.strip().split('|', 4)
                if len(parts) != 5:
                    continue
                    
                timestamp, session, user, length, query = parts
                
                # Detect malicious patterns
                if self._is_malicious(query):
                    malicious_queries.append({
                        'timestamp': int(timestamp),
                        'session': session,
                        'user': user,
                        'query': query
                    })
        
        # Move to appropriate archive
        if malicious_queries:
            # Move to malicious archive
            dest = self.malicious_dir / os.path.basename(log_file_path)
            shutil.move(log_file_path, dest)
            print(f"⚠️  Moved to malicious archive: {os.path.basename(log_file_path)}")
        else:
            # Move to regular archive
            dest = self.archive_dir / os.path.basename(log_file_path)
            shutil.move(log_file_path, dest)
            print(f"✓ Archived: {os.path.basename(log_file_path)}")
        
        return malicious_queries
    
    def _is_malicious(self, query: str) -> bool:
        """
        Detect malicious query patterns
        
        Args:
            query: SQL query string
            
        Returns:
            bool: True if malicious, False otherwise
        """
        query_upper = query.strip().upper()
        
        # High-risk patterns
        dangerous_patterns = [
            # Drops without WHERE
            (r'DROP\s+TABLE\s+\w+\s*;', 'DROP TABLE without WHERE'),
            (r'DROP\s+DATABASE', 'DROP DATABASE'),
            (r'TRUNCATE\s+TABLE', 'TRUNCATE TABLE'),
            
            # Mass deletion/updates without WHERE
            (r'DELETE\s+FROM\s+\w+\s*;', 'DELETE without WHERE'),
            (r'UPDATE\s+\w+\s+SET\s+.*\s*;', 'UPDATE without WHERE'),
            (r'WHERE\s+1\s*=\s*1', 'WHERE 1=1 (mass operation)'),
            
            # Privilege escalation
            (r'GRANT\s+ALL', 'GRANT ALL PRIVILEGES'),
            (r'CREATE\s+USER.*IDENTIFIED\s+BY', 'Creating new user'),
            
            # Data exfiltration
            (r'SELECT\s+.*\s+INTO\s+OUTFILE', 'SELECT INTO OUTFILE'),
            (r'LOAD\s+DATA\s+INFILE', 'LOAD DATA INFILE'),
            
            # Suspicious comments
            (r'--.*DROP', 'Commented DROP statement'),
            (r'/\*.*DROP.*\*/', 'Comment-obfuscated DROP'),
        ]
        
        for pattern, description in dangerous_patterns:
            if re.search(pattern, query_upper, re.IGNORECASE):
                return True
        
        return False
    
    def process_all_pending(self):
        """
        Batch process all pending log files
        Useful for startup recovery or scheduled checks
        
        Returns:
            list: All malicious queries found
        """
        all_malicious = []
        
        # Get all unprocessed files
        pending_files = list(self.pending_dir.glob("*.raw"))
        
        for log_file in pending_files:
            malicious = self.process_and_archive(str(log_file))
            all_malicious.extend(malicious)
        
        return all_malicious
    
    def get_malicious_count(self) -> int:
        """
        Get count of malicious log files
        
        Returns:
            int: Number of malicious log files
        """
        return len(list(self.malicious_dir.glob("*.raw")))
    
    def get_archive_count(self) -> int:
        """
        Get count of archived log files
        
        Returns:
            int: Number of clean archived log files
        """
        return len(list(self.archive_dir.glob("*.raw")))
