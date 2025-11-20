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
                                        values=["All", "Clean", "Malicious", "Suspicious"])
        self.type_filter.set("All")
        self.type_filter.pack(side=tk.LEFT, padx=5)
        self.type_filter.bind("<<ComboboxSelected>>", lambda e: self.apply_filters())
        
        tk.Button(filter_frame, text="🔄 Refresh", command=self.load_logs).pack(side=tk.LEFT, padx=5)
        
        # Main content - Treeview for queries
        main_frame = tk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Treeview
        columns = ("Time", "Table", "Type", "Query Preview")
        self.tree = ttk.Treeview(main_frame, columns=columns, show="tree headings", height=15)
        
        self.tree.heading("#0", text="Status")
        self.tree.heading("Time", text="Time")
        self.tree.heading("Table", text="Table")
        self.tree.heading("Type", text="Type")
        self.tree.heading("Query Preview", text="Query Preview")
        
        self.tree.column("#0", width=80)
        self.tree.column("Time", width=150)
        self.tree.column("Table", width=150)
        self.tree.column("Type", width=100)
        self.tree.column("Query Preview", width=600)
        
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
        
        # Load clean queries
        for log_file in self.archive_dir.glob("*.raw"):
            self.parse_log_file(log_file, is_malicious=False)
        
        # Load malicious queries
        for log_file in self.malicious_dir.glob("*.raw"):
            self.parse_log_file(log_file, is_malicious=True)
        
        # Update UI
        self.update_stats()
        self.populate_table_filter()
        self.apply_filters()
    
    def parse_log_file(self, log_file, is_malicious):
        """Parse a log file and extract queries"""
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                for line in f:
                    parts = line.strip().split('|', 4)
                    if len(parts) != 5:
                        continue
                    
                    timestamp, session, user, length, query = parts
                    
                    # Convert timestamp from milliseconds to seconds
                    timestamp_sec = int(timestamp) / 1000.0
                    
                    # Extract table name from query
                    table = self.extract_table_name(query)
                    
                    # Determine if suspicious (even in clean logs)
                    suspicious = self.is_suspicious(query) if not is_malicious else False
                    
                    query_type = "Malicious" if is_malicious else ("Suspicious" if suspicious else "Clean")
                    
                    self.all_queries.append({
                        'timestamp': timestamp_sec,
                        'session': session,
                        'user': user,
                        'query': query,
                        'table': table,
                        'type': query_type,
                        'is_malicious': is_malicious
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
        clean = sum(1 for q in self.all_queries if q['type'] == 'Clean')
        suspicious = sum(1 for q in self.all_queries if q['type'] == 'Suspicious')
        malicious = sum(1 for q in self.all_queries if q['type'] == 'Malicious')
        
        stats_text = f"Total: {total} | ✅ Clean: {clean} | ⚠️ Suspicious: {suspicious} | 🚨 Malicious: {malicious}"
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
            # Status icon
            if query['type'] == 'Malicious':
                icon = "🚨"
                tag = "malicious"
            elif query['type'] == 'Suspicious':
                icon = "⚠️"
                tag = "suspicious"
            else:
                icon = "✅"
                tag = "clean"
            
            # Format time
            time_str = datetime.fromtimestamp(query['timestamp']).strftime("%Y-%m-%d %H:%M:%S")
            
            # Query preview (first 80 chars)
            preview = query['query'][:80] + ("..." if len(query['query']) > 80 else "")
            
            item = self.tree.insert("", tk.END, text=icon,
                                   values=(time_str, query['table'], query['type'], preview),
                                   tags=(tag,))
        
        # Configure tags for coloring
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
        
        detail = f"""
╔══════════════════════════════════════════════════════════════════════════════════
║ QUERY DETAILS
╚══════════════════════════════════════════════════════════════════════════════════

⏰ Time:     {time_str}
👤 User:     {query['user']}
🔖 Session:  {query['session']}
📊 Table:    {query['table']}
🏷️  Type:     {query['type']}

╔══════════════════════════════════════════════════════════════════════════════════
║ SQL QUERY
╚══════════════════════════════════════════════════════════════════════════════════

{query['query']}

"""
        
        if query['type'] == 'Malicious':
            detail += "\n⚠️  WARNING: This query has been flagged as MALICIOUS!\n"
        elif query['type'] == 'Suspicious':
            detail += "\n⚠️  CAUTION: This query shows suspicious patterns.\n"
        
        self.detail_text.delete(1.0, tk.END)
        self.detail_text.insert(1.0, detail)


def main():
    """Main entry point"""
    root = tk.Tk()
    app = LogViewerGUI(root)
    root.mainloop()


if __name__ == '__main__':
    main()
