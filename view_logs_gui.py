"""
DBGuard360 - Log Viewer GUI
Browse logged queries by database and table
Highlights malicious/suspicious queries
"""

import tkinter as tk
from tkinter import ttk, scrolledtext
from pathlib import Path
import re
from datetime import datetime


class LogViewerGUI:
    """GUI for viewing logged queries"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("DBGuard360 - Log Viewer")
        self.root.geometry("1200x800")
        
        # Paths
        self.pending_dir = Path("logs/pending")
        self.archive_dir = Path("logs/archive")
        self.malicious_dir = Path("logs/malicious")
        
        # Data
        self.all_queries = []
        self.filtered_queries = []
        
        # Colors
        self.color_clean = "#d4edda"
        self.color_malicious = "#f8d7da"
        self.color_suspicious = "#fff3cd"
        
        self.setup_ui()
        self.load_logs()
    
    def setup_ui(self):
        """Setup UI components"""
        
        # Title
        title_frame = tk.Frame(self.root, bg="#2c3e50", height=60)
        title_frame.pack(fill=tk.X)
        title_label = tk.Label(title_frame, text="🛡️ DBGuard360 Log Viewer", 
                               font=("Arial", 20, "bold"), 
                               bg="#2c3e50", fg="white")
        title_label.pack(pady=15)
        
        # Stats bar
        stats_frame = tk.Frame(self.root, bg="#ecf0f1", height=50)
        stats_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.stats_label = tk.Label(stats_frame, text="Loading...", 
                                     font=("Arial", 10), bg="#ecf0f1")
        self.stats_label.pack(pady=10)
        
        # Filter frame
        filter_frame = tk.Frame(self.root, bg="#ecf0f1")
        filter_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(filter_frame, text="Filter by Table:", bg="#ecf0f1").pack(side=tk.LEFT, padx=5)
        self.table_filter = ttk.Combobox(filter_frame, width=30)
        self.table_filter.pack(side=tk.LEFT, padx=5)
        self.table_filter.bind("<<ComboboxSelected>>", lambda e: self.apply_filters())
        
        tk.Label(filter_frame, text="Query Type:", bg="#ecf0f1").pack(side=tk.LEFT, padx=5)
        self.type_filter = ttk.Combobox(filter_frame, width=20, 
                                        values=["All", "Pending", "Clean", "Malicious", "Suspicious"])
        self.type_filter.set("All")
        self.type_filter.pack(side=tk.LEFT, padx=5)
        self.type_filter.bind("<<ComboboxSelected>>", lambda e: self.apply_filters())
        
        tk.Button(filter_frame, text="🔄 Refresh", command=self.load_logs).pack(side=tk.LEFT, padx=5)
        
        # Main content - Treeview for queries
        main_frame = tk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Treeview
        columns = ("Time", "Table", "Type", "Confidence", "Query Preview")
        self.tree = ttk.Treeview(main_frame, columns=columns, show="tree headings", height=15)
        
        self.tree.heading("#0", text="Status")
        self.tree.heading("Time", text="Time")
        self.tree.heading("Table", text="Table")
        self.tree.heading("Type", text="Type")
        self.tree.heading("Confidence", text="Confidence")
        self.tree.heading("Query Preview", text="Query Preview")
        
        self.tree.column("#0", width=80)
        self.tree.column("Time", width=150)
        self.tree.column("Table", width=120)
        self.tree.column("Type", width=100)
        self.tree.column("Confidence", width=90)
        self.tree.column("Query Preview", width=500)
        
        # Scrollbar for treeview
        tree_scroll = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=tree_scroll.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind selection
        self.tree.bind("<<TreeviewSelect>>", self.show_query_detail)
        
        # Detail panel
        detail_frame = tk.LabelFrame(self.root, text="Query Details", bg="white")
        detail_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.detail_text = scrolledtext.ScrolledText(detail_frame, height=10, 
                                                      font=("Courier", 10), wrap=tk.WORD)
        self.detail_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def load_logs(self):
        """Load all log files"""
        self.all_queries = []
        
        # Load pending queries (not yet processed) - raw format without classification
        for log_file in self.pending_dir.glob("*.log"):
            self.parse_log_file(log_file, is_pending=True)
        
        # Load classified queries from archive - contains CLEAN and SUSPICIOUS
        for log_file in self.archive_dir.glob("*.log"):
            self.parse_log_file(log_file, is_pending=False)
        
        # Load malicious queries - contains MALICIOUS
        for log_file in self.malicious_dir.glob("*.log"):
            self.parse_log_file(log_file, is_pending=False)
        
        # Update UI
        self.update_stats()
        self.populate_table_filter()
        self.apply_filters()
    
    def parse_log_file(self, log_file, is_pending=False):
        """Parse a log file and extract queries"""
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                for line in f:
                    parts = line.strip().split('|')
                    
                    # Handle both formats: raw (5 parts) and classified (7 parts)
                    if is_pending and len(parts) >= 5:
                        # Pending queries: timestamp|session|user|length|query
                        timestamp, session, user, length, query = parts[0], parts[1], parts[2], parts[3], parts[4]
                        classification = "Pending"
                        confidence = 0
                    elif not is_pending and len(parts) >= 7:
                        # Classified queries: timestamp|session|user|length|query|classification|confidence
                        timestamp, session, user, length = parts[0], parts[1], parts[2], parts[3]
                        query = parts[4]
                        classification = parts[5]
                        try:
                            confidence = int(parts[6])
                        except (ValueError, IndexError):
                            confidence = 0
                    else:
                        continue
                    
                    # Convert timestamp from milliseconds to seconds
                    try:
                        timestamp_sec = int(timestamp) / 1000.0
                    except (ValueError, TypeError):
                        timestamp_sec = 0
                    
                    # Extract table name from query
                    table = self.extract_table_name(query)
                    
                    self.all_queries.append({
                        'timestamp': timestamp_sec,
                        'session': session,
                        'user': user,
                        'query': query,
                        'table': table,
                        'type': classification,
                        'confidence': confidence
                    })
        except Exception as e:
            print(f"Error parsing {log_file}: {e}")
    
    def extract_table_name(self, query):
        """Extract table name from SQL query"""
        query_upper = query.upper()
        
        # Try to find table name after FROM, INTO, UPDATE, DELETE FROM, etc.
        patterns = [
            r'FROM\s+([`\w]+)',
            r'INTO\s+([`\w]+)',
            r'UPDATE\s+([`\w]+)',
            r'JOIN\s+([`\w]+)',
            r'TABLE\s+([`\w]+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, query_upper)
            if match:
                table = match.group(1).strip('`')
                return table
        
        return "Unknown"
    
    def is_suspicious(self, query):
        """Check if query is suspicious"""
        query_upper = query.upper()
        
        suspicious_patterns = [
            r'WHERE\s+1\s*=\s*1',
            r'DELETE.*FROM',
            r'DROP',
            r'TRUNCATE',
            r'GRANT',
            r'ALTER.*USER',
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, query_upper):
                return True
        
        return False
    
    def update_stats(self):
        """Update statistics bar"""
        total = len(self.all_queries)
        pending = sum(1 for q in self.all_queries if q['type'] == 'Pending')
        clean = sum(1 for q in self.all_queries if q['type'] == 'Clean')
        suspicious = sum(1 for q in self.all_queries if q['type'] == 'Suspicious')
        malicious = sum(1 for q in self.all_queries if q['type'] == 'Malicious')
        
        stats_text = f"Total: {total} | 🔵 Pending: {pending} | ✅ Clean: {clean} | ⚠️ Suspicious: {suspicious} | 🚨 Malicious: {malicious}"
        self.stats_label.config(text=stats_text)
    
    def populate_table_filter(self):
        """Populate table filter dropdown"""
        tables = set(q['table'] for q in self.all_queries)
        self.table_filter['values'] = ["All"] + sorted(list(tables))
        self.table_filter.set("All")
    
    def apply_filters(self):
        """Apply filters and update treeview"""
        # Clear treeview
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Get filter values
        table_filter = self.table_filter.get()
        type_filter = self.type_filter.get()
        
        # Filter queries
        self.filtered_queries = []
        for query in self.all_queries:
            # Table filter
            if table_filter != "All" and query['table'] != table_filter:
                continue
            
            # Type filter
            if type_filter != "All" and query['type'] != type_filter:
                continue
            
            self.filtered_queries.append(query)
        
        # Sort by timestamp (newest first)
        self.filtered_queries.sort(key=lambda q: q['timestamp'], reverse=True)
        
        # Populate treeview
        for query in self.filtered_queries:
            # Status icon and tag based on classification
            classification = query['type'].upper()
            if classification == 'MALICIOUS':
                icon = "🚨"
                tag = "malicious"
            elif classification == 'SUSPICIOUS':
                icon = "⚠️"
                tag = "suspicious"
            elif classification == 'PENDING':
                icon = "🔵"
                tag = "pending"
            else:  # CLEAN
                icon = "✅"
                tag = "clean"
            
            # Format time
            time_str = datetime.fromtimestamp(query['timestamp']).strftime("%Y-%m-%d %H:%M:%S")
            
            # Format confidence
            confidence_str = f"{query['confidence']}%" if query['confidence'] > 0 else "-"
            
            # Query preview (first 80 chars)
            preview = query['query'][:80] + ("..." if len(query['query']) > 80 else "")
            
            item = self.tree.insert("", tk.END, text=icon,
                                   values=(time_str, query['table'], query['type'], confidence_str, preview),
                                   tags=(tag,))
        
        # Configure tags for coloring
        self.tree.tag_configure("pending", background="#e3f2fd")
        self.tree.tag_configure("clean", background=self.color_clean)
        self.tree.tag_configure("suspicious", background=self.color_suspicious)
        self.tree.tag_configure("malicious", background=self.color_malicious)
    
    def show_query_detail(self, event):
        """Show full query details when selected"""
        selection = self.tree.selection()
        if not selection:
            return
        
        item = selection[0]
        index = self.tree.index(item)
        
        if index >= len(self.filtered_queries):
            return
        
        query = self.filtered_queries[index]
        
        # Format detail text
        time_str = datetime.fromtimestamp(query['timestamp']).strftime("%Y-%m-%d %H:%M:%S")
        confidence_str = f"{query['confidence']}%" if query['confidence'] > 0 else "Not classified"
        
        detail = f"""
╔══════════════════════════════════════════════════════════════════════════════════
║ QUERY DETAILS
╚══════════════════════════════════════════════════════════════════════════════════

⏰ Time:       {time_str}
👤 User:       {query['user']}
🔖 Session:    {query['session']}
📊 Table:      {query['table']}
🏷️  Type:       {query['type']}
🎯 Confidence: {confidence_str}

╔══════════════════════════════════════════════════════════════════════════════════
║ SQL QUERY
╚══════════════════════════════════════════════════════════════════════════════════

{query['query']}

"""
        
        classification = query['type'].upper()
        if classification == 'MALICIOUS':
            detail += "\n⚠️  WARNING: This query has been flagged as MALICIOUS!\n"
        elif classification == 'SUSPICIOUS':
            detail += "\n⚠️  CAUTION: This query shows suspicious patterns.\n"
        elif classification == 'CLEAN':
            detail += f"\n✅ This query appears safe (confidence: {confidence_str}).\n"
        
        self.detail_text.delete(1.0, tk.END)
        self.detail_text.insert(1.0, detail)


def main():
    """Main entry point"""
    root = tk.Tk()
    app = LogViewerGUI(root)
    root.mainloop()


if __name__ == '__main__':
    main()
