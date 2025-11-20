"""
Recovery display for showing queries grouped by table (lazy parsing)
"""

import re
from pathlib import Path
from datetime import datetime


class RecoveryDisplay:
    """
    Display and analyze queries - parse tables ONLY when needed (lazy parsing)
    Zero overhead during logging - parsing happens only during recovery
    """
    
    def __init__(self, archive_dir=None, malicious_dir=None):
        """
        Initialize recovery display
        
        Args:
            archive_dir: Directory with archived logs
            malicious_dir: Directory with malicious logs
        """
        if archive_dir is None:
            archive_dir = Path(__file__).parent.parent.parent / "logs" / "archive"
        if malicious_dir is None:
            malicious_dir = Path(__file__).parent.parent.parent / "logs" / "malicious"
        
        self.archive_dir = Path(archive_dir)
        self.malicious_dir = Path(malicious_dir)
    
    def display_queries_by_table(self, table_name: str = None):
        """
        Show queries grouped by table - parse tables NOW (lazy)
        
        Args:
            table_name: Filter by specific table, or None for all tables
        """
        all_files = list(self.archive_dir.glob("*.raw")) + \
                   list(self.malicious_dir.glob("*.raw"))
        
        if not all_files:
            print("No log files found.")
            return
        
        # Group queries by table (parse lazily)
        queries_by_table = {}
        
        for log_file in all_files:
            with open(log_file, 'r', encoding='utf-8') as f:
                for line in f:
                    parts = line.strip().split('|', 4)
                    if len(parts) != 5:
                        continue
                    
                    timestamp, session, user, length, query = parts
                    
                    # Parse tables NOW (only when displaying)
                    affected_tables = self._extract_tables(query)
                    
                    for table in affected_tables:
                        if table not in queries_by_table:
                            queries_by_table[table] = []
                        
                        queries_by_table[table].append({
                            'timestamp': int(timestamp),
                            'session': session,
                            'user': user,
                            'query': query,
                            'file': log_file.name
                        })
        
        # Display filtered by table
        if table_name:
            if table_name in queries_by_table:
                self._print_table_queries(table_name, queries_by_table[table_name])
            else:
                print(f"No queries found for table: {table_name}")
        else:
            # Show all tables
            for table, queries in sorted(queries_by_table.items()):
                self._print_table_queries(table, queries)
    
    def _print_table_queries(self, table_name: str, queries: list):
        """
        Pretty print queries for a table
        
        Args:
            table_name: Name of table
            queries: List of query dictionaries
        """
        print(f"\n{'='*80}")
        print(f"📊 Table: {table_name}")
        print(f"   Total Queries: {len(queries)}")
        print(f"{'='*80}\n")
        
        for q in sorted(queries, key=lambda x: x['timestamp']):
            timestamp_str = datetime.fromtimestamp(q['timestamp']/1000).strftime('%Y-%m-%d %H:%M:%S')
            print(f"⏰ {timestamp_str} | 👤 {q['user']} | 📝 Session: {q['session'][:8]}")
            print(f"   {q['query'][:100]}{'...' if len(q['query']) > 100 else ''}")
            print(f"   📁 File: {q['file']}\n")
    
    def _extract_tables(self, query: str) -> list:
        """
        Simple table extraction (only called during recovery)
        
        Args:
            query: SQL query string
            
        Returns:
            list: Table names found in query
        """
        tables = set()
        query_upper = query.upper()
        
        # Quick regex patterns for common SQL operations
        patterns = [
            r'FROM\s+([a-zA-Z0-9_]+)',
            r'JOIN\s+([a-zA-Z0-9_]+)',
            r'INTO\s+([a-zA-Z0-9_]+)',
            r'UPDATE\s+([a-zA-Z0-9_]+)',
            r'TABLE\s+([a-zA-Z0-9_]+)',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, query_upper)
            tables.update(matches)
        
        # Filter out SQL keywords
        sql_keywords = {'SELECT', 'WHERE', 'ORDER', 'GROUP', 'HAVING', 'LIMIT', 'OFFSET', 
                       'INNER', 'LEFT', 'RIGHT', 'OUTER', 'CROSS', 'ON', 'USING'}
        tables = {t for t in tables if t not in sql_keywords}
        
        return list(tables)
    
    def get_recovery_plan(self, corrupted_table: str):
        """
        Show what needs to be recovered for a specific table
        
        Args:
            corrupted_table: Name of table to analyze
            
        Returns:
            dict: Recovery plan with safe and malicious queries
        """
        print(f"\n🔍 Analyzing recovery plan for table: {corrupted_table}\n")
        
        # Find all queries affecting this table
        table_queries = []
        malicious_queries = []
        
        all_files = list(self.archive_dir.glob("*.raw")) + \
                   list(self.malicious_dir.glob("*.raw"))
        
        for log_file in all_files:
            is_malicious = log_file.parent == self.malicious_dir
            
            with open(log_file, 'r', encoding='utf-8') as f:
                for line in f:
                    parts = line.strip().split('|', 4)
                    if len(parts) != 5:
                        continue
                    
                    timestamp, session, user, length, query = parts
                    
                    # Parse table (lazy)
                    affected_tables = self._extract_tables(query)
                    
                    if corrupted_table in affected_tables:
                        query_info = {
                            'timestamp': int(timestamp),
                            'query': query,
                            'file': log_file.name
                        }
                        
                        if is_malicious:
                            malicious_queries.append(query_info)
                        else:
                            table_queries.append(query_info)
        
        # Display recovery plan
        print(f"📋 Recovery Plan:")
        print(f"   ✅ Safe queries to replay: {len(table_queries)}")
        print(f"   ⚠️  Malicious queries to skip: {len(malicious_queries)}")
        
        if malicious_queries:
            print(f"\n❌ Malicious Queries Found:")
            for mq in malicious_queries:
                print(f"   - {mq['query'][:80]}{'...' if len(mq['query']) > 80 else ''}")
        
        return {
            'safe_queries': table_queries,
            'malicious_queries': malicious_queries
        }
    
    def list_all_tables(self) -> list:
        """
        List all tables with logged queries
        
        Returns:
            list: Table names found in logs
        """
        all_files = list(self.archive_dir.glob("*.raw")) + \
                   list(self.malicious_dir.glob("*.raw"))
        
        tables = set()
        
        for log_file in all_files:
            with open(log_file, 'r', encoding='utf-8') as f:
                for line in f:
                    parts = line.strip().split('|', 4)
                    if len(parts) == 5:
                        query = parts[4]
                        tables.update(self._extract_tables(query))
        
        return sorted(list(tables))
