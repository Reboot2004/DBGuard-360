"""
MySQL connection interceptor that wraps queries and triggers protection mechanisms
"""

import uuid
import mysql.connector
from mysql.connector import Error as MySQLError


class DBGuardConnection:
    """
    Wraps MySQL connection to intercept queries and provide protection
    Buffers queries in memory and flushes on COMMIT
    """
    
    def __init__(self, mysql_config, logger, analyzer=None, first_commit_handler=None):
        """
        Initialize protected MySQL connection
        
        Args:
            mysql_config: Dict with MySQL connection parameters (host, user, password, database)
            logger: MemoryBufferedLogger instance
            analyzer: ProcessAndArchiveAnalyzer instance (optional)
            first_commit_handler: FirstCommitHandler instance (optional)
        """
        self.conn = mysql.connector.connect(**mysql_config)
        self.logger = logger
        self.analyzer = analyzer
        self.first_commit_handler = first_commit_handler
        self.session_id = self._generate_session_id()
        self.user = mysql_config.get('user', 'unknown')
        
    def _generate_session_id(self):
        """Generate unique session ID"""
        return str(uuid.uuid4())[:8]
    
    def execute(self, query: str, params=None):
        """
        Execute query with interception and logging
        
        Args:
            query: SQL query string
            params: Query parameters (optional)
            
        Returns:
            Cursor with query results
        """
        # Buffer query in memory (no disk write, no parsing)
        self.logger.log_query(query, self.session_id, self.user)
        
        # Execute normally
        cursor = self.conn.cursor()
        
        if params:
            result = cursor.execute(query, params)
        else:
            result = cursor.execute(query)
        
        # Check for transaction control statements
        query_upper = query.strip().upper()
        
        if query_upper.startswith('COMMIT'):
            self._handle_commit(cursor)
        elif query_upper.startswith('ROLLBACK'):
            self._handle_rollback()
        
        return cursor
    
    def _handle_commit(self, cursor):
        """
        COMMIT detected - flush buffer and process
        
        Args:
            cursor: MySQL cursor for accessing table metadata
        """
        # 1. Flush memory buffer to file
        log_file = self.logger.flush_on_commit(self.session_id)
        
        if not log_file:
            return
        
        print(f"✓ Transaction committed - logged to {log_file}")
        
        # 2. Handle first commit (IBD backup) if handler provided
        if self.first_commit_handler:
            try:
                self.first_commit_handler.handle_commit(cursor, self.session_id)
            except Exception as e:
                print(f"⚠️  Warning: First commit handler failed: {e}")
        
        # 3. Process the file immediately (detect malicious) if analyzer provided
        if self.analyzer:
            try:
                malicious = self.analyzer.process_and_archive(log_file)
                
                if malicious:
                    print(f"⚠️  WARNING: Detected {len(malicious)} malicious queries!")
                    for m in malicious:
                        print(f"  - {m['query'][:100]}{'...' if len(m['query']) > 100 else ''}")
            except Exception as e:
                print(f"⚠️  Warning: Analyzer failed: {e}")
    
    def _handle_rollback(self):
        """
        ROLLBACK detected - discard buffer
        """
        self.logger.clear_session(self.session_id)
        print(f"✓ Transaction rolled back - buffer cleared")
    
    def cursor(self):
        """Get underlying MySQL cursor"""
        return self.conn.cursor()
    
    def commit(self):
        """Commit transaction"""
        cursor = self.conn.cursor()
        cursor.execute("COMMIT")
        self._handle_commit(cursor)
    
    def rollback(self):
        """Rollback transaction"""
        self.conn.rollback()
        self._handle_rollback()
    
    def close(self):
        """Close connection"""
        self.conn.close()
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        if exc_type is None:
            self.commit()
        else:
            self.rollback()
        self.close()
