"""
DBGuard360 - Log Viewer GUI
Browse logged queries by database and table
Highlights malicious/suspicious queries
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
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
        
        # Colors (binary classification)
        self.color_clean = "#d4edda"
        self.color_malicious = "#f8d7da"
        
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
        self.table_filter = ttk.Combobox(filter_frame, width=30, state="readonly")
        self.table_filter.pack(side=tk.LEFT, padx=5)
        self.table_filter.bind("<<ComboboxSelected>>", self.on_filter_changed)
        
        tk.Label(filter_frame, text="Query Type:", bg="#ecf0f1").pack(side=tk.LEFT, padx=5)
        self.type_filter = ttk.Combobox(filter_frame, width=20, 
                                        values=["All", "Pending", "Clean", "Malicious"], state="readonly")
        self.type_filter.set("All")
        self.type_filter.pack(side=tk.LEFT, padx=5)
        self.type_filter.bind("<<ComboboxSelected>>", self.on_filter_changed)
        
        tk.Button(filter_frame, text="🔄 Refresh", command=self.load_logs).pack(side=tk.LEFT, padx=5)
        
        # Main content - Treeview for queries
        main_frame = tk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Treeview with checkboxes (selectmode extended for multi-select)
        columns = ("Time", "Table", "Type", "Query Preview")
        self.tree = ttk.Treeview(main_frame, columns=columns, show="tree headings", height=15, selectmode="extended")
        
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
        self.tree.bind("<<TreeviewSelect>>", self.on_selection_changed)
        self.tree.bind("<Button-1>", self.on_tree_click)
        
        # Action buttons frame
        action_frame = tk.Frame(self.root, bg="#ecf0f1")
        action_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Button(action_frame, text="🔄 Run Selected Queries", 
                 command=self.run_selected_queries, 
                 font=("Arial", 10, "bold"),
                 bg="#3498db", fg="white", padx=10, pady=5).pack(side=tk.LEFT, padx=5)
        
        self.selection_label = tk.Label(action_frame, text="No queries selected", 
                                       font=("Arial", 9), bg="#ecf0f1")
        self.selection_label.pack(side=tk.LEFT, padx=10)
        
        # Detail panel
        detail_frame = tk.LabelFrame(self.root, text="Query Details", bg="white")
        detail_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.detail_text = scrolledtext.ScrolledText(detail_frame, height=10, 
                                                      font=("Courier", 10), wrap=tk.WORD)
        self.detail_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def load_logs(self):
        """Load all log files"""
        self.all_queries = []
        
        # Load pending queries (not yet processed) - .raw format without classification
        for log_file in self.pending_dir.glob("*.raw"):
            self.parse_log_file(log_file, is_pending=True)
        
        # Load classified clean queries from archive
        for log_file in self.archive_dir.glob("*.raw"):
            self.parse_log_file(log_file, is_pending=False)
        
        # Load malicious queries
        for log_file in self.malicious_dir.glob("*.raw"):
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
                    
                    # Handle both formats: raw (5 parts) and classified (6 parts)
                    if is_pending and len(parts) >= 5:
                        # Pending queries: timestamp|session|user|length|query
                        timestamp, session, user, length, query = parts[0], parts[1], parts[2], parts[3], parts[4]
                        classification = "Pending"
                    elif not is_pending and len(parts) >= 6:
                        # Classified queries: timestamp|session|user|length|query|classification
                        timestamp, session, user, length = parts[0], parts[1], parts[2], parts[3]
                        query = parts[4]
                        classification = parts[5]
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
                        'type': classification
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
        pending = sum(1 for q in self.all_queries if q['type'].upper() == 'PENDING')
        clean = sum(1 for q in self.all_queries if q['type'].upper() == 'CLEAN')
        malicious = sum(1 for q in self.all_queries if q['type'].upper() == 'MALICIOUS')
        
        stats_text = f"Total: {total} | 🔵 Pending: {pending} | ✅ Clean: {clean} | 🚨 Malicious: {malicious}"
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
            elif classification == 'PENDING':
                icon = "🔵"
                tag = "pending"
            else:  # CLEAN
                icon = "✅"
                tag = "clean"
            
            # Format time
            time_str = datetime.fromtimestamp(query['timestamp']).strftime("%Y-%m-%d %H:%M:%S")
            
            # Query preview (first 80 chars)
            preview = query['query'][:80] + ("..." if len(query['query']) > 80 else "")
            
            item = self.tree.insert("", tk.END, text=icon,
                                   values=(time_str, query['table'], query['type'], preview),
                                   tags=(tag,))
        
        # Configure tags for coloring (binary: pending, clean, malicious)
        self.tree.tag_configure("pending", background="#e3f2fd")
        self.tree.tag_configure("clean", background=self.color_clean)
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
        
        classification = query['type'].upper()
        if classification == 'MALICIOUS':
            detail += "\n🚨 WARNING: This query has been flagged as MALICIOUS!\n"
        elif classification == 'CLEAN':
            detail += "\n✅ This query appears safe.\n"
        elif classification == 'PENDING':
            detail += "\n🔵 This query is awaiting classification.\n"
        
        self.detail_text.delete(1.0, tk.END)
        self.detail_text.insert(1.0, detail)
    
    def on_filter_changed(self, event):
        """Handle filter changes without resetting dropdown"""
        self.apply_filters()
    
    def on_tree_click(self, event):
        """Handle tree click to show details without affecting selection"""
        region = self.tree.identify_region(event.x, event.y)
        if region == "cell" or region == "tree":
            item = self.tree.identify_row(event.y)
            if item:
                # Only update detail view, don't affect multi-selection
                self.show_single_query_detail(item)
    
    def on_selection_changed(self, event):
        """Handle selection changes to update selection count"""
        selected_items = self.tree.selection()
        if not selected_items:
            self.selection_label.config(text="No queries selected")
            return
        
        # Get tables for all selected queries
        selected_tables = set()
        for item in selected_items:
            index = self.tree.index(item)
            if index < len(self.filtered_queries):
                selected_tables.add(self.filtered_queries[index]['table'])
        
        count = len(selected_items)
        if len(selected_tables) == 1:
            table = list(selected_tables)[0]
            self.selection_label.config(
                text=f"✅ {count} query(ies) selected from table '{table}'",
                fg="green"
            )
        else:
            self.selection_label.config(
                text=f"⚠️ {count} queries selected from DIFFERENT tables (not allowed!)",
                fg="red"
            )
    
    def show_single_query_detail(self, item):
        """Show details for a single query item"""
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
        
        classification = query['type'].upper()
        if classification == 'MALICIOUS':
            detail += "\n🚨 WARNING: This query has been flagged as MALICIOUS!\n"
        elif classification == 'CLEAN':
            detail += "\n✅ This query appears safe.\n"
        elif classification == 'PENDING':
            detail += "\n🔵 This query is awaiting classification.\n"
        
        self.detail_text.delete(1.0, tk.END)
        self.detail_text.insert(1.0, detail)
    
    def run_selected_queries(self):
        """Run selected queries on a new table"""
        selected_items = self.tree.selection()
        
        if not selected_items:
            tk.messagebox.showwarning("No Selection", "Please select at least one query to run.")
            return
        
        # Get all selected queries and their tables
        selected_queries = []
        selected_tables = set()
        
        for item in selected_items:
            index = self.tree.index(item)
            if index < len(self.filtered_queries):
                query_data = self.filtered_queries[index]
                selected_queries.append(query_data)
                selected_tables.add(query_data['table'])
        
        # Validate: all queries must be from the same table
        if len(selected_tables) != 1:
            tk.messagebox.showerror(
                "Invalid Selection",
                f"All selected queries must be from the SAME table.\n\n"
                f"You selected queries from {len(selected_tables)} different tables:\n"
                + "\n".join(f"  • {table}" for table in sorted(selected_tables))
            )
            return
        
        original_table = list(selected_tables)[0]
        
        # Open dialog to get new table info
        self.show_table_schema_dialog(original_table, selected_queries)
    
    def show_table_schema_dialog(self, original_table, selected_queries):
        """Show dialog to input new table name and schema"""
        dialog = tk.Toplevel(self.root)
        dialog.title(f"Run Queries on New Table")
        dialog.geometry("700x500")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Header
        header = tk.Frame(dialog, bg="#2c3e50", height=60)
        header.pack(fill=tk.X)
        tk.Label(header, 
                text=f"🔄 Run {len(selected_queries)} Query(ies) on New Table",
                font=("Arial", 14, "bold"),
                bg="#2c3e50", fg="white").pack(pady=15)
        
        # Content frame
        content = tk.Frame(dialog, padx=20, pady=20)
        content.pack(fill=tk.BOTH, expand=True)
        
        # Original table info
        info_frame = tk.LabelFrame(content, text="Original Table", font=("Arial", 10, "bold"))
        info_frame.pack(fill=tk.X, pady=(0, 10))
        tk.Label(info_frame, text=f"Table: {original_table}", 
                font=("Arial", 10)).pack(anchor=tk.W, padx=10, pady=5)
        tk.Label(info_frame, text=f"Selected Queries: {len(selected_queries)}", 
                font=("Arial", 10)).pack(anchor=tk.W, padx=10, pady=5)
        
        # New table name
        name_frame = tk.LabelFrame(content, text="New Table Name", font=("Arial", 10, "bold"))
        name_frame.pack(fill=tk.X, pady=(0, 10))
        tk.Label(name_frame, text="Enter the name of the table to run these queries on:", 
                font=("Arial", 9)).pack(anchor=tk.W, padx=10, pady=(5, 0))
        table_name_entry = tk.Entry(name_frame, font=("Arial", 10), width=40)
        table_name_entry.pack(padx=10, pady=5, fill=tk.X)
        table_name_entry.insert(0, original_table + "_new")
        
        # Table schema
        schema_frame = tk.LabelFrame(content, text="Table Schema (CREATE TABLE statement)", 
                                    font=("Arial", 10, "bold"))
        schema_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        tk.Label(schema_frame, 
                text="Paste the CREATE TABLE statement or describe the table structure:",
                font=("Arial", 9)).pack(anchor=tk.W, padx=10, pady=(5, 0))
        
        schema_text = scrolledtext.ScrolledText(schema_frame, height=10, 
                                                font=("Courier", 9), wrap=tk.WORD)
        schema_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        schema_text.insert(1.0, f"CREATE TABLE {original_table}_new (\n    id INT PRIMARY KEY,\n    -- Add columns here\n);")
        
        # Buttons
        button_frame = tk.Frame(content)
        button_frame.pack(fill=tk.X)
        
        def on_execute():
            new_table = table_name_entry.get().strip()
            schema = schema_text.get(1.0, tk.END).strip()
            
            if not new_table:
                tk.messagebox.showwarning("Missing Info", "Please enter a table name.")
                return
            
            if not schema:
                tk.messagebox.showwarning("Missing Info", "Please enter the table schema.")
                return
            
            dialog.destroy()
            self.execute_queries_on_new_table(new_table, schema, original_table, selected_queries)
        
        tk.Button(button_frame, text="✅ Execute Queries", command=on_execute,
                 bg="#27ae60", fg="white", font=("Arial", 10, "bold"),
                 padx=20, pady=8).pack(side=tk.LEFT, padx=5)
        
        tk.Button(button_frame, text="❌ Cancel", command=dialog.destroy,
                 bg="#e74c3c", fg="white", font=("Arial", 10),
                 padx=20, pady=8).pack(side=tk.LEFT, padx=5)
    
    def execute_queries_on_new_table(self, new_table, schema, original_table, selected_queries):
        """Execute the selected queries on the new table"""
        import mysql.connector
        
        try:
            # Connect to MySQL
            conn = mysql.connector.connect(
                host='localhost',
                user='superuser',
                password='Collector#123',
                database='testdb'
            )
            cursor = conn.cursor()
            
            # Drop table if exists (for re-execution)
            try:
                cursor.execute(f"DROP TABLE IF EXISTS {new_table}")
                conn.commit()
            except:
                pass
            
            # Create the new table
            cursor.execute(schema)
            conn.commit()
            
            # Replace table names in queries and execute
            results = []
            errors = []
            
            for query_data in selected_queries:
                original_query = query_data['query'].strip()
                
                # Skip transaction control statements
                query_upper = original_query.upper()
                if any(keyword in query_upper for keyword in ['START TRANSACTION', 'BEGIN', 'COMMIT', 'ROLLBACK']):
                    continue
                
                # Replace table name (handle with/without backticks)
                modified_query = original_query
                
                # Try different replacement patterns
                replacements = [
                    (f"`{original_table}`", f"`{new_table}`"),
                    (f" {original_table} ", f" {new_table} "),
                    (f" {original_table};", f" {new_table};"),
                    (f" {original_table}\n", f" {new_table}\n"),
                    (f"INTO {original_table}", f"INTO {new_table}"),
                    (f"FROM {original_table}", f"FROM {new_table}"),
                    (f"UPDATE {original_table}", f"UPDATE {new_table}"),
                    (f"TABLE {original_table}", f"TABLE {new_table}"),
                ]
                
                for old, new in replacements:
                    modified_query = modified_query.replace(old, new)
                
                # Case-insensitive replacement for common patterns
                modified_query = re.sub(
                    rf'\b{re.escape(original_table)}\b',
                    new_table,
                    modified_query,
                    flags=re.IGNORECASE
                )
                
                try:
                    # Execute the modified query
                    cursor.execute(modified_query)
                    
                    # Get affected rows
                    affected = cursor.rowcount if cursor.rowcount >= 0 else 0
                    
                    conn.commit()
                    results.append(f"✅ {modified_query[:80]}... ({affected} rows affected)")
                except Exception as e:
                    errors.append(f"❌ {modified_query[:60]}...\n   Error: {str(e)}")
            
            cursor.close()
            conn.close()
            
            # Show results
            self.show_execution_results(new_table, len(selected_queries), results, errors)
            
        except Exception as e:
            tk.messagebox.showerror("Execution Error", f"Failed to execute queries:\n\n{str(e)}")
    
    def show_execution_results(self, table_name, total_queries, results, errors):
        """Show execution results in a dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Execution Results")
        dialog.geometry("900x700")
        dialog.transient(self.root)
        
        # Header
        header = tk.Frame(dialog, bg="#27ae60" if not errors else "#e67e22", height=60)
        header.pack(fill=tk.X)
        
        success_count = len(results)
        status_text = f"✅ Successfully executed {success_count}/{total_queries} queries" if not errors else \
                     f"⚠️ {success_count} succeeded, {len(errors)} failed"
        
        tk.Label(header, text=status_text,
                font=("Arial", 14, "bold"),
                bg="#27ae60" if not errors else "#e67e22", 
                fg="white").pack(pady=15)
        
        # Content
        content = tk.Frame(dialog, padx=20, pady=20)
        content.pack(fill=tk.BOTH, expand=True)
        
        tk.Label(content, text=f"Table: {table_name} | Total Queries Attempted: {total_queries}",
                font=("Arial", 10, "bold")).pack(anchor=tk.W)
        
        # Add verify button
        verify_frame = tk.Frame(content)
        verify_frame.pack(fill=tk.X, pady=5)
        
        tk.Button(verify_frame, text="🔍 Verify Table Data", 
                 command=lambda: self.verify_table_data(table_name, dialog),
                 bg="#3498db", fg="white", font=("Arial", 9),
                 padx=10, pady=5).pack(side=tk.LEFT, padx=5)
        
        # Results text
        results_text = scrolledtext.ScrolledText(content, height=25, 
                                                 font=("Courier", 9), wrap=tk.WORD)
        results_text.pack(fill=tk.BOTH, expand=True, pady=10)
        
        output = f"Execution Summary\n{'=' * 80}\n\n"
        
        if results:
            output += f"✅ Successful Queries ({len(results)}):\n{'-' * 80}\n"
            for i, result in enumerate(results, 1):
                output += f"{i}. {result}\n"
            output += "\n"
        
        if errors:
            output += f"❌ Failed Queries ({len(errors)}):\n{'-' * 80}\n"
            for i, error in enumerate(errors, 1):
                output += f"{i}. {error}\n"
            output += "\n"
        
        output += f"\n{'=' * 80}\n"
        output += f"💡 Tip: Click 'Verify Table Data' to check what was actually inserted/updated\n"
        
        results_text.insert(1.0, output)
        results_text.config(state=tk.DISABLED)
        
        # Close button
        tk.Button(content, text="Close", command=dialog.destroy,
                 bg="#95a5a6", fg="white", font=("Arial", 10),
                 padx=20, pady=8).pack()
    
    def verify_table_data(self, table_name, parent_dialog):
        """Query the table to verify data was inserted"""
        import mysql.connector
        
        try:
            conn = mysql.connector.connect(
                host='localhost',
                user='superuser',
                password='Collector#123',
                database='testdb'
            )
            cursor = conn.cursor()
            
            # Get table structure
            cursor.execute(f"DESCRIBE {table_name}")
            columns = cursor.fetchall()
            
            # Get table data
            cursor.execute(f"SELECT * FROM {table_name} LIMIT 100")
            rows = cursor.fetchall()
            
            cursor.close()
            conn.close()
            
            # Show in new dialog
            verify_dialog = tk.Toplevel(parent_dialog)
            verify_dialog.title(f"Table Data: {table_name}")
            verify_dialog.geometry("900x600")
            verify_dialog.transient(parent_dialog)
            
            # Header
            header = tk.Frame(verify_dialog, bg="#3498db", height=50)
            header.pack(fill=tk.X)
            tk.Label(header, text=f"📊 Table: {table_name} ({len(rows)} rows)",
                    font=("Arial", 12, "bold"),
                    bg="#3498db", fg="white").pack(pady=10)
            
            # Content
            content = tk.Frame(verify_dialog, padx=20, pady=20)
            content.pack(fill=tk.BOTH, expand=True)
            
            # Data text
            data_text = scrolledtext.ScrolledText(content, height=30, 
                                                   font=("Courier", 9), wrap=tk.NONE)
            data_text.pack(fill=tk.BOTH, expand=True)
            
            # Format output
            output = f"Table Structure:\n{'=' * 80}\n"
            for col in columns:
                output += f"  {col[0]:20} {col[1]:20} {col[2]:5} {col[3]:5}\n"
            
            output += f"\nTable Data ({len(rows)} rows):\n{'=' * 80}\n"
            
            if rows:
                # Column headers
                col_names = [col[0] for col in columns]
                output += " | ".join(f"{name:20}" for name in col_names) + "\n"
                output += "-" * 80 + "\n"
                
                # Data rows
                for row in rows:
                    output += " | ".join(f"{str(val)[:20]:20}" for val in row) + "\n"
            else:
                output += "⚠️ No data found in table!\n"
                output += "\nPossible reasons:\n"
                output += "  1. Queries were not actually executed\n"
                output += "  2. Table name mismatch in queries\n"
                output += "  3. Queries failed silently\n"
            
            data_text.insert(1.0, output)
            data_text.config(state=tk.DISABLED)
            
            # Close button
            tk.Button(content, text="Close", command=verify_dialog.destroy,
                     bg="#95a5a6", fg="white", font=("Arial", 10),
                     padx=20, pady=5).pack(pady=10)
            
        except Exception as e:
            tk.messagebox.showerror("Verification Error", 
                                   f"Failed to verify table data:\n\n{str(e)}",
                                   parent=parent_dialog)


def main():
    """Main entry point"""
    root = tk.Tk()
    app = LogViewerGUI(root)
    root.mainloop()


if __name__ == '__main__':
    main()
