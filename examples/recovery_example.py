"""
Recovery example for DBGuard360
"""

from src.recovery import RecoveryDisplay, TableRecovery


def show_recovery_analysis():
    """
    Demonstrate recovery analysis
    """
    display = RecoveryDisplay()
    
    # List all tables with queries
    print("=== All Tables with Logged Queries ===")
    tables = display.list_all_tables()
    for table in tables:
        print(f"  • {table}")
    
    # Show queries for specific table
    print("\n=== Queries for 'users' table ===")
    display.display_queries_by_table('users')
    
    # Analyze recovery plan
    print("\n=== Recovery Plan Analysis ===")
    plan = display.get_recovery_plan('users')
    print(f"Safe queries: {len(plan['safe_queries'])}")
    print(f"Malicious queries: {len(plan['malicious_queries'])}")


def perform_recovery():
    """
    Demonstrate table recovery
    """
    mysql_config = {
        'host': 'localhost',
        'user': 'root',
        'password': 'your_password',
        'database': 'test_db'
    }
    
    recovery = TableRecovery(mysql_config)
    
    # Check if backup exists
    if recovery.verify_backup_exists('users'):
        print("✓ Backup exists for 'users' table")
        
        # Recover the table
        result = recovery.recover_table('users', confirm=False)
        
        if result['status'] == 'success':
            print(f"\n✅ Recovery successful!")
            print(f"   Replayed: {result['replayed']} queries")
            print(f"   Skipped: {result['skipped']} malicious queries")
        else:
            print(f"\n❌ Recovery failed: {result.get('error')}")
    else:
        print("❌ No backup found for 'users' table")


if __name__ == '__main__':
    # Show analysis
    show_recovery_analysis()
    
    # Uncomment to perform actual recovery
    # perform_recovery()
