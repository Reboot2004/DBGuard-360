-- DBGuard360 - MySQL Setup Script
-- Run this in your MySQL client before using DBGuard360

-- Check current autocommit status
SELECT @@autocommit;

-- Disable autocommit (REQUIRED for DBGuard360)
SET autocommit = 0;

-- Verify it's disabled (should show 0)
SELECT @@autocommit;

-- Now you can use explicit transactions
-- Example:
-- START TRANSACTION;
-- INSERT INTO users VALUES (1, 'Alice');
-- UPDATE users SET status = 'active' WHERE id = 1;
-- COMMIT;  -- This will trigger DBGuard360 logging

-- To make it permanent for your session, add to ~/.my.cnf:
-- [mysql]
-- init-command="SET autocommit=0"
