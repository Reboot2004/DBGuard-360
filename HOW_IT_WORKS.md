# 🛡️ DBGuard 360 - How It Works

## 📖 Complete System Architecture

### Overview
DBGuard 360 captures and analyzes SQL queries **without modifying your application code**. It monitors MySQL's built-in logging system and uses expert rules to detect malicious patterns.

---

## 🔍 How We Capture Queries

### Step 1: MySQL General Log
MySQL has a built-in feature called **general_log** that records EVERY query executed on the server.

```sql
-- Check if general_log is enabled
SHOW VARIABLES LIKE 'general_log';

-- Enable it (DBGuard does this automatically)
SET GLOBAL general_log = 'ON';
SET GLOBAL log_output = 'TABLE';  -- Store in mysql.general_log table
```

**What gets logged:**
- ✅ Queries from MySQL CLI (`mysql -u user -p`)
- ✅ Queries from applications (Python, Java, PHP, etc.)
- ✅ Queries from GUI tools (MySQL Workbench, phpMyAdmin, etc.)
- ✅ **Everything** - including SELECT, INSERT, UPDATE, DELETE, DDL, etc.

### Step 2: Polling mysql.general_log Table
`monitor_general_log.py` continuously polls the `mysql.general_log` table:

```python
# Pseudocode showing how monitoring works
while True:
    # Get new log entries since last check
    cursor.execute("""
        SELECT event_time, user_host, thread_id, command_type, argument
        FROM mysql.general_log
        WHERE event_time > last_check_time
        ORDER BY event_time
    """)
    
    new_entries = cursor.fetchall()
    
    # Process each query
    for entry in new_entries:
        timestamp, user, session, cmd, query = entry
        
        # Filter out noise (Connect, Quit, etc.)
        if cmd == 'Query':
            # Track transactions
            if 'START TRANSACTION' in query:
                start_new_transaction()
            elif 'COMMIT' in query:
                save_transaction_to_file()
            else:
                add_query_to_current_transaction()
    
    time.sleep(1)  # Check every second
```

### Step 3: Transaction Tracking
DBGuard tracks complete transactions (not individual queries):

```
User executes in MySQL CLI:
┌─────────────────────────────────┐
│ START TRANSACTION;              │  ← Monitor sees this, starts tracking
│ INSERT INTO t1 VALUES (10);     │  ← Added to transaction buffer
│ UPDATE t1 SET x=20 WHERE id=5;  │  ← Added to transaction buffer
│ COMMIT;                         │  ← Flush entire transaction to file
└─────────────────────────────────┘
```

**Result:** One `.raw` file in `logs/pending/` containing all 3 queries.

---

## 📁 File Format

### Raw Log Format (logs/pending/*.raw)
```
timestamp_ms|session_id|user|length|query
1732147200000|12345|superuser@localhost|25|insert into t1 values (10)
1732147201000|12345|superuser@localhost|30|update t1 set x=20 where id=5
```

**Fields:**
- `timestamp_ms`: Unix timestamp in milliseconds
- `session_id`: MySQL thread/connection ID
- `user`: MySQL user who executed the query
- `length`: Query length in characters
- `query`: The actual SQL query

### Classified Log Format (logs/archive/*.raw, logs/malicious/*.raw)
```
timestamp_ms|session_id|user|length|query|CLASSIFICATION
1732147200000|12345|superuser@localhost|25|insert into t1 values (10)|CLEAN
1732147201000|12345|superuser@localhost|45|select * from t1 where id=1 or 1=1|MALICIOUS
```

**Added field:**
- `CLASSIFICATION`: Either `CLEAN` or `MALICIOUS`

---

## 🧠 Classification Engine

### How `classify_queries.py` Works

#### 1. Feature Extraction
The classifier analyzes each query for 20+ security features:

```python
class QueryFeatures:
    # SQL Injection patterns
    has_union: bool           # UNION SELECT attacks
    has_or_condition: bool    # OR in WHERE clause
    has_tautology: bool       # OR 1=1, OR 'a'='a'
    
    # Dangerous operations
    has_load_file: bool       # LOAD_FILE() - read server files
    has_outfile: bool         # INTO OUTFILE - write files
    has_exec: bool            # EXEC() - command execution
    
    # Time-based attacks
    has_sleep: bool           # SLEEP() - blind SQL injection
    has_benchmark: bool       # BENCHMARK() - DoS attacks
    
    # Obfuscation techniques
    has_comment: bool         # --, /*, # to hide code
    has_base64: bool          # Base64 encoding
    has_char_function: bool   # CHAR() to bypass filters
    has_hex: bool             # 0x4141 hex encoding
    
    # ... 10+ more features
```

#### 2. Threat Scoring
Each feature contributes points to a threat score (0-100):

| Feature | Points | Example |
|---------|--------|---------|
| SQL Injection (OR 1=1) | 20 | `WHERE id=1 OR 1=1` |
| UNION-based injection | 20 | `UNION SELECT password FROM users` |
| File access | 20 | `LOAD_FILE('/etc/passwd')` |
| Time-based injection | 10 | `SLEEP(5)` |
| Schema enumeration | 10 | `SELECT * FROM information_schema.tables` |
| Obfuscation | 5 | `0x41646d696e` (hex encoded 'Admin') |

#### 3. Binary Classification
```
Threat Score >= 10  →  🚨 MALICIOUS
Threat Score < 10   →  ✅ CLEAN
```

**Why threshold = 10?**
- Simple queries (INSERT, SELECT) score 0-5 points
- Suspicious patterns (multiple ORs, comments) score 5-10 points
- Clear attacks (SQL injection, file access) score 20+ points

### Example Classifications

#### ✅ CLEAN Queries (Score < 10)
```sql
INSERT INTO users VALUES (1, 'Alice');              -- Score: 0
SELECT * FROM orders WHERE user_id = 123;           -- Score: 0
UPDATE products SET price = 99.99 WHERE id = 5;     -- Score: 0
DELETE FROM logs WHERE created_at < '2024-01-01';   -- Score: 0
```

#### 🚨 MALICIOUS Queries (Score >= 10)
```sql
-- SQL Injection (Score: 20)
SELECT * FROM users WHERE id = 1 OR 1=1;

-- UNION-based injection (Score: 20)
SELECT name FROM products UNION SELECT password FROM admin;

-- File exfiltration (Score: 20)
SELECT * FROM users INTO OUTFILE '/tmp/stolen.csv';

-- Time-based blind injection (Score: 10)
SELECT * FROM users WHERE id = 1 AND SLEEP(5);

-- Schema enumeration (Score: 10)
SELECT table_name FROM information_schema.tables;

-- Obfuscation + OR injection (Score: 25)
SELECT * FROM users WHERE name = 0x41646d696e OR 1=1;
```

---

## 🖥️ GUI Viewer

### What `view_logs_gui.py` Does

1. **Loads all log files**
   - Pending: `.raw` files without classification
   - Archive: Classified CLEAN queries
   - Malicious: Classified MALICIOUS queries

2. **Parses log format**
   ```
   timestamp|session|user|length|query|CLASSIFICATION
   ```

3. **Displays in color-coded table**
   - 🔵 Blue: Pending (not yet classified)
   - ✅ Green: Clean (safe queries)
   - 🚨 Red: Malicious (threats)

4. **Filtering**
   - By table name (e.g., only show queries for `users` table)
   - By type (Pending/Clean/Malicious)

5. **Multi-select execution**
   - Select multiple queries from **same table**
   - Run them on a **new table** (for testing/recovery)
   - Replaces table names automatically

---

## 🔧 Common Issues

### Issue 1: Table Crashed Error
```
ERROR 1194 (HY000): Table 'general_log' is marked as crashed
```

**Cause:** MySQL's general_log table can become corrupted under heavy load.

**Solution:** DBGuard now auto-repairs the table:
```sql
REPAIR TABLE mysql.general_log;
```

**Manual fix if needed:**
```bash
# Stop MySQL
sudo systemctl stop mysql

# Run MySQL repair tool
sudo myisamchk -r /var/lib/mysql/mysql/general_log.MYI

# Start MySQL
sudo systemctl start mysql
```

### Issue 2: Queries Not Appearing
**Cause:** Autocommit is ON, so queries execute immediately without transactions.

**Solution:**
```sql
-- In your MySQL client
SET autocommit = 0;

-- Then use explicit transactions
START TRANSACTION;
-- your queries here
COMMIT;  -- This triggers capture
```

### Issue 3: Too Many Logs
**Cause:** general_log captures **everything**, including DBGuard's own monitoring queries.

**Solution:** DBGuard filters out its own queries:
```python
# Queries matching these patterns are ignored
IGNORED_PATTERNS = [
    'SELECT.*FROM mysql.general_log',  # Monitor's own queries
    'SHOW VARIABLES',
    'SET GLOBAL general_log'
]
```

---

## 📊 Performance Impact

### MySQL Server Load
- **general_log overhead:** ~1-5% CPU, ~10MB/hour disk I/O
- **Minimal** for most applications
- Can be disabled when not monitoring: `SET GLOBAL general_log = 'OFF';`

### DBGuard Monitor
- **Polling frequency:** 1 query/second
- **Memory:** ~50MB
- **CPU:** <1%
- **Disk:** 1KB per transaction

### Classification
- **Speed:** ~1000 queries/second (Python regex matching)
- **Memory:** <100MB for 10,000 queries
- **No ML models:** Fast, lightweight, no GPU needed

---

## 🎯 Usage Summary

### Workflow
```
1. START monitoring     →  python monitor_general_log.py
2. USE MySQL normally   →  mysql -u user -p database
3. CLASSIFY queries     →  python classify_queries.py
4. VIEW in GUI          →  python view_logs_gui.py
5. INVESTIGATE threats  →  Review malicious queries
6. RUN recovery         →  Select queries, execute on new table
```

### Key Files
| File | Purpose |
|------|---------|
| `monitor_general_log.py` | Captures queries from mysql.general_log |
| `classify_queries.py` | Expert rule-based classifier |
| `view_logs_gui.py` | Tkinter GUI for browsing logs |
| `logs/pending/*.raw` | Raw captured queries (not yet classified) |
| `logs/archive/*.raw` | Clean queries (safe) |
| `logs/malicious/*.raw` | Malicious queries (threats) |

---

## 🔒 Security Considerations

### What DBGuard Detects
✅ SQL injection attacks  
✅ File access attempts (LOAD_FILE, INTO OUTFILE)  
✅ Command execution (EXEC, stacked queries)  
✅ Schema enumeration (information_schema)  
✅ Time-based attacks (SLEEP, BENCHMARK)  
✅ Obfuscation techniques (hex, base64, comments)  

### What DBGuard Doesn't Detect
❌ Application-level logic flaws  
❌ Privilege escalation (if attacker has valid credentials)  
❌ Zero-day exploits in MySQL itself  
❌ Network-level attacks (DDoS, man-in-the-middle)  

### Best Practices
1. **Monitor continuously** - Leave `monitor_general_log.py` running
2. **Classify regularly** - Run `classify_queries.py` hourly/daily
3. **Review malicious logs** - Investigate all red-flagged queries
4. **Rotate logs** - Archive old logs to prevent disk filling
5. **Secure credentials** - Never commit `superuser` password to Git

---

## 💡 Advanced: How MySQL general_log Works

### Internal MySQL Architecture
```
MySQL Server
├── Connection Handler (receives queries)
├── Query Parser
├── Query Executor
└── Logger
    ├── Error Log
    ├── Slow Query Log
    └── General Log  ← DBGuard taps into this
        ├── File: /var/log/mysql/general.log (if log_output='FILE')
        └── Table: mysql.general_log (if log_output='TABLE')
```

### General Log Table Structure
```sql
DESC mysql.general_log;
+----------------+---------------------+
| Field          | Type                |
+----------------+---------------------+
| event_time     | timestamp(6)        | -- When query executed
| user_host      | mediumtext          | -- user@host
| thread_id      | bigint unsigned     | -- Connection/session ID
| server_id      | int unsigned        | -- MySQL server instance ID
| command_type   | varchar(64)         | -- Query, Connect, Quit, etc.
| argument       | mediumblob          | -- The actual query text
+----------------+---------------------+
```

### Example Entries
```sql
SELECT * FROM mysql.general_log ORDER BY event_time DESC LIMIT 5;
```
| event_time | user_host | thread_id | command_type | argument |
|------------|-----------|-----------|--------------|----------|
| 2025-11-21 10:30:45 | superuser@localhost | 12345 | Query | INSERT INTO t1 VALUES (10) |
| 2025-11-21 10:30:44 | superuser@localhost | 12345 | Query | START TRANSACTION |
| 2025-11-21 10:30:40 | superuser@localhost | 12345 | Connect | testdb |

---

## 🚀 Future Enhancements

### Planned Features
- [ ] Real-time alerts (email/Slack when malicious query detected)
- [ ] Machine learning enhancement (learn from your classifications)
- [ ] Query replay (execute entire transaction on test database)
- [ ] Performance impact analysis (show slow queries)
- [ ] Multi-database monitoring (monitor all databases simultaneously)
- [ ] Web dashboard (replace Tkinter with Flask/React)

---

## 📞 Support

For issues or questions:
1. Check `logs/` directory for error messages
2. Review this document's troubleshooting section
3. Open GitHub issue with:
   - Error message
   - MySQL version (`SELECT VERSION();`)
   - Python version (`python --version`)
   - Steps to reproduce

---

**Last Updated:** November 21, 2025  
**DBGuard 360 Version:** 1.0.0
