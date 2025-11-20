# DBGuard360 - Quick Start Guide

## 🚀 Complete Monitoring Workflow

### Step 1: Start Monitoring
Run the monitoring script in one terminal:
```bash
python monitor_general_log.py
```

This will:
- ✅ Start continuous monitoring of MySQL general_log
- ✅ Capture queries from ANY MySQL client (CLI, GUI, apps)
- ✅ Log raw queries to `logs/pending/`
- ✅ Filter out ghost queries from monitoring itself

### Step 2: Setup MySQL Client
Open another terminal and use MySQL CLI:
```bash
mysql -u superuser -p testdb
```

**IMPORTANT: Disable autocommit first!**
```sql
-- Check current setting
SELECT @@autocommit;

-- Disable autocommit (REQUIRED!)
SET autocommit = 0;

-- Verify it's off (should show 0)
SELECT @@autocommit;
```

### Step 3: Execute Queries with Explicit Transactions
```sql
START TRANSACTION;
INSERT INTO users VALUES (1, 'Alice');
UPDATE users SET status = 'active' WHERE id = 1;
COMMIT;  -- This triggers logging
```

The monitoring script will automatically log and analyze the queries!

### Step 4: Classify Queries
Run the classification script to analyze pending logs:
```bash
python classify_queries.py
```

This will:
- ✅ Analyze all queries in `logs/pending/`
- ✅ Detect SQL injection, malicious patterns, suspicious behavior
- ✅ Move clean queries to `logs/archive/`
- ✅ Move malicious queries to `logs/malicious/`
- ✅ Add classification tags to each query

### Step 5: View Logs in GUI
Run the GUI to browse logged queries:
```bash
python view_logs_gui.py
```

Features:
- 📊 View all logged queries organized by database/table
- 🎨 Color-coded: Blue (pending), Green (clean), Yellow (suspicious), Red (malicious)
- 🔍 Filter by table name
- 🔍 Filter by query type (Pending/Clean/Suspicious/Malicious)
- 📝 Click any query to see full details
- 🔄 Refresh to see new logs

---

## 📂 File Structure

```
DBGuard360/
├── monitor_general_log.py     # Main monitoring script (leave running)
├── classify_queries.py        # Expert rule-based classifier
├── view_logs_gui.py           # GUI to view logs
├── run_dbguard.py             # Single-use test script (deprecated)
├── logs/
│   ├── pending/               # Raw queries waiting classification
│   ├── archive/               # Clean queries ✅
│   └── malicious/             # Malicious/suspicious queries 🚨
```

---

## 🎯 Usage Examples

### Complete Workflow
```bash
# Terminal 1: Start monitoring
python monitor_general_log.py

# Terminal 2: Use MySQL normally
mysql -u superuser -p testdb

# Terminal 3: Classify when ready
python classify_queries.py

# Terminal 4: View results
python view_logs_gui.py
```

### CLI Commands (Alternative)
```bash
# List all tables with logs
python -m src.cli.commands list-tables

# Show queries for specific table
python -m src.cli.commands show-queries --table users

# Check system status
python -m src.cli.commands status
```

---

## 🛡️ What Gets Detected?

### 🚨 Malicious (High Priority)
- ❌ **SQL Injection**: `OR 1=1`, `OR 'a'='a'`, `UNION SELECT`
- ❌ **File Access**: `LOAD_FILE()`, `INTO OUTFILE`, `INTO DUMPFILE`
- ❌ **Command Execution**: `EXEC()`, stacked queries
- ❌ **Time-based Attacks**: `SLEEP()`, `BENCHMARK()`
- ❌ **Schema Enumeration**: `information_schema` access

### ⚠️ Suspicious (Medium Priority)
- ⚠️ Excessive OR conditions (> 3)
- ⚠️ SQL comments (possible obfuscation)
- ⚠️ String encoding (CHAR, HEX, Base64)
- ⚠️ String concatenation tricks

### ✅ Clean
- ✅ Normal INSERT, UPDATE, DELETE with WHERE clause
- ✅ Standard SELECT queries
- ✅ Regular DDL operations

---

## 📝 Configuration

Edit `config/dbgurd.yaml`:
```yaml
mysql:
  host: localhost
  user: superuser
  password: Collector#123
  database: your_database

detection:
  enabled: true
```

---

## 🔧 Requirements

```bash
pip install -r requirements.txt
```

Requirements:
- Python 3.8+
- MySQL 5.7+
- mysql-connector-python
- click
- tkinter (for GUI)

---

## 💡 Pro Tips

1. **Keep monitoring script running** - It needs to be active to process commits
2. **Use the GUI** - Much easier than reading raw log files
3. **Filter by table** - Quickly find queries affecting specific tables
4. **Watch for red entries** - Malicious queries need immediate attention
5. **Regular refresh** - Click refresh in GUI to see latest logs

---

## 🐛 Troubleshooting

### Permission Denied for IBD Files
✅ **Fixed!** IBD backups are now disabled. The system only does query logging.

### Queries Not Showing Up
**Most common issue: Autocommit is ON!**

Solution:
```sql
SET autocommit = 0;
```

Then use explicit transactions:
```sql
START TRANSACTION;
-- your queries here
COMMIT;
```

Other checks:
- Make sure monitoring script is running
- Execute `COMMIT` after your queries
- Check `logs/pending/` for new files

### GUI Not Opening
Install tkinter:
```bash
# Ubuntu/Debian
sudo apt-get install python3-tk

# Already installed on Windows/Mac
```

---

## 🎓 How It Works

1. **Monitoring script** polls MySQL `general_log` table
2. **You use MySQL normally** from ANY client (CLI, GUI, app)
3. **Queries are captured** and written to `logs/pending/` in raw format
4. **Classification script** analyzes queries using expert rule-based system
5. **Feature extraction** detects SQL injection, malicious patterns, obfuscation
6. **Threat scoring** assigns confidence level (0-100%)
7. **Logs are moved** to `archive/` (clean) or `malicious/` (threats)
8. **GUI displays** all logs with color coding and filtering

**No code changes required** - works with existing MySQL applications!

---

## 📧 Support

For issues: Open a GitHub issue
