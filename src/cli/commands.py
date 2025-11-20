"""
CLI commands for DBGurd recovery operations
"""

import click
from ..recovery import RecoveryDisplay, TableRecovery, ProcessAndArchiveAnalyzer


@click.group()
def cli():
    """DBGuard360 - MySQL Database Protection System"""
    pass


@cli.command()
@click.option('--table', '-t', help='Filter by table name')
def show_queries(table):
    """Display queries grouped by table"""
    display = RecoveryDisplay()
    display.display_queries_by_table(table)


@cli.command()
@click.argument('table_name')
def analyze(table_name):
    """Analyze recovery plan for a table"""
    display = RecoveryDisplay()
    display.get_recovery_plan(table_name)


@cli.command()
@click.argument('table_name')
@click.option('--host', default='localhost', help='MySQL host')
@click.option('--user', '-u', required=True, help='MySQL user')
@click.option('--password', '-p', prompt=True, hide_input=True, help='MySQL password')
@click.option('--database', '-d', required=True, help='MySQL database')
@click.option('--no-confirm', is_flag=True, help='Skip confirmation')
def recover(table_name, host, user, password, database, no_confirm):
    """Recover a specific table from backup"""
    mysql_config = {
        'host': host,
        'user': user,
        'password': password,
        'database': database
    }
    
    recovery = TableRecovery(mysql_config)
    recovery.recover_table(table_name, confirm=not no_confirm)


@cli.command()
def list_tables():
    """List all tables with logged queries"""
    display = RecoveryDisplay()
    tables = display.list_all_tables()
    
    if not tables:
        print("No tables found in logs.")
        return
    
    print("\n📊 Tables with logged queries:\n")
    for table in tables:
        print(f"   • {table}")
    print()


@cli.command()
def status():
    """Show DBGuard360 system status"""
    analyzer = ProcessAndArchiveAnalyzer()
    
    malicious_count = analyzer.get_malicious_count()
    archive_count = analyzer.get_archive_count()
    
    print("\n📊 DBGuard360 Status")
    print("=" * 50)
    print(f"✅ Clean transactions archived: {archive_count}")
    print(f"⚠️  Malicious transactions detected: {malicious_count}")
    print("=" * 50)
    print()


@cli.command()
def process_pending():
    """Process all pending log files"""
    analyzer = ProcessAndArchiveAnalyzer()
    
    print("Processing pending log files...")
    malicious = analyzer.process_all_pending()
    
    if malicious:
        print(f"\n⚠️  Found {len(malicious)} malicious queries!")
    else:
        print(f"\n✅ All pending logs processed - no threats detected")


if __name__ == '__main__':
    cli()
