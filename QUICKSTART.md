# DBGuard360 - Quick Start Guide

## 🚀 New Workflow (Without IBD Backups)

### Step 1: Start Monitoring
Run the monitoring script in one terminal:
```bash
python monitor_dbguard.py testdb
```

This will:
- ✅ Start continuous monitoring
- ✅ Log all queries to `logs/pending/`
- ✅ Auto-process and detect malicious queries
- ✅ Move logs to `logs/archive/` (clean) or `logs/malicious/` (suspicious)
- ❌ NO IBD backups (removed due to permission issues)

### Step 2: Use MySQL Normally
Open another terminal and use MySQL CLI:
```bash
mysql -u superuser -p testdb
```

Execute your queries:
```sql
START TRANSACTION;
INSERT INTO users VALUES (1, 'Alice');
UPDATE users SET status = 'active' WHERE id = 1;
COMMIT;  -- This triggers logging
```

The monitoring script will automatically log and analyze the queries!

### Step 3: View Logs in GUI
Run the GUI to browse logged queries:
```bash
python view_logs_gui.py
```

Features:
- 📊 View all logged queries organized by database/table
- 🎨 Color-coded: Green (clean), Yellow (suspicious), Red (malicious)
- 🔍 Filter by table name
- 🔍 Filter by query type (Clean/Suspicious/Malicious)
- 📝 Click any query to see full details
- 🔄 Refresh to see new logs

---

## 📂 File Structure

```
DBGuard360/
├── monitor_dbguard.py        # Main monitoring script (leave running)
├── view_logs_gui.py           # GUI to view logs
├── run_dbguard.py             # Single-use test script
├── logs/
│   ├── pending/               # Queries waiting to be processed
│   ├── archive/               # Clean queries ✅
│   └── malicious/             # Malicious queries 🚨
```

---

## 🎯 Usage Examples

### Monitor a Database
```bash
python monitor_dbguard.py mydb
```

### View Logs
```bash
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

## 🛡️ What Gets Detected as Malicious?

- ❌ `DROP TABLE` / `DROP DATABASE`
- ❌ `DELETE FROM table;` (no WHERE clause)
- ❌ `UPDATE table SET ...;` (no WHERE clause)
- ❌ `WHERE 1=1` (mass operations)
- ❌ `TRUNCATE TABLE`
- ❌ `GRANT ALL PRIVILEGES`
- ❌ `SELECT ... INTO OUTFILE` (data exfiltration)

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

1. **Monitoring script** connects to MySQL with protection enabled
2. **You use MySQL normally** in another terminal/client
3. **On COMMIT**, queries are flushed from memory to `logs/pending/`
4. **Analyzer processes** the log file and detects malicious patterns
5. **Logs are moved** to `archive/` (clean) or `malicious/` (suspicious)
6. **GUI displays** all logs with color coding and filtering

**Zero overhead** during query execution - everything happens on COMMIT!

---

## 📧 Support

For issues: Open a GitHub issue
