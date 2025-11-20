"""
Memory-buffered query logger that flushes to file on COMMIT
"""

import time
import threading
from datetime import datetime
from pathlib import Path


class MemoryBufferedLogger:
    """
    Keep queries in memory, flush to file on COMMIT
    Zero overhead during normal operations - no parsing, no disk I/O
    """
    
    def __init__(self, log_dir=None):
        """
        Initialize the memory-buffered logger
        
        Args:
            log_dir: Directory for pending log files. Defaults to logs/pending/
        """
        if log_dir is None:
            log_dir = Path(__file__).parent.parent.parent / "logs" / "pending"
        
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Memory buffer per session: {session_id: [raw_lines]}
        self.session_buffers = {}
        self.lock = threading.Lock()
        
    def log_query(self, query: str, session_id: str, user: str):
        """
        Add query to memory buffer (no disk write, no parsing)
        
        Args:
            query: SQL query string
            session_id: Unique session identifier
            user: Database user executing the query
        """
        timestamp_ms = int(time.time() * 1000)
        query_length = len(query)
        
        # Raw format: timestamp|session|user|length|query
        raw_line = f"{timestamp_ms}|{session_id}|{user}|{query_length}|{query}\n"
        
        with self.lock:
            if session_id not in self.session_buffers:
                self.session_buffers[session_id] = []
            
            self.session_buffers[session_id].append(raw_line)
    
    def flush_on_commit(self, session_id: str):
        """
        COMMIT detected - flush memory buffer to file
        
        Args:
            session_id: Session ID to flush
            
        Returns:
            str: Path to created log file, or None if buffer empty
        """
        with self.lock:
            if session_id not in self.session_buffers:
                return None
            
            buffer = self.session_buffers[session_id]
            
            if not buffer:
                return None
            
            # Create unique filename for this transaction
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            filename = f"txn_{session_id}_{timestamp}.raw"
            filepath = self.log_dir / filename
            
            # Write all buffered queries to file
            with open(filepath, 'w', encoding='utf-8') as f:
                f.writelines(buffer)
            
            # Clear buffer
            self.session_buffers[session_id] = []
            
            return str(filepath)
    
    def clear_session(self, session_id: str):
        """
        Clear buffer without flushing (e.g., on ROLLBACK)
        
        Args:
            session_id: Session ID to clear
        """
        with self.lock:
            if session_id in self.session_buffers:
                del self.session_buffers[session_id]
    
    def get_buffer_size(self, session_id: str) -> int:
        """
        Get number of queries in buffer for a session
        
        Args:
            session_id: Session ID to check
            
        Returns:
            int: Number of buffered queries
        """
        with self.lock:
            if session_id in self.session_buffers:
                return len(self.session_buffers[session_id])
            return 0
