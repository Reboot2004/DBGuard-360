"""
DBGuard360 - AI Query Classifier
Uses local LLM (Ollama) to classify queries as clean/suspicious/malicious
Processes pending logs and moves them to appropriate directories
"""

import sys
import json
import shutil
from pathlib import Path
from datetime import datetime
import subprocess
import re


class AIQueryClassifier:
    """
    Classify SQL queries using local LLM
    """
    
    def __init__(self):
        self.pending_dir = Path("logs/pending")
        self.archive_dir = Path("logs/archive")
        self.malicious_dir = Path("logs/malicious")
        
        # Create directories
        self.archive_dir.mkdir(parents=True, exist_ok=True)
        self.malicious_dir.mkdir(parents=True, exist_ok=True)
        
        # System prompt for classification
        self.system_prompt = """You are a SQL security expert analyzing database queries for malicious behavior.

Classify each query as one of:
- CLEAN: Normal, safe query
- SUSPICIOUS: Potentially dangerous but might be legitimate
- MALICIOUS: Clearly malicious or dangerous

Focus on patterns like:
- DROP, TRUNCATE without proper WHERE clauses
- DELETE/UPDATE without WHERE or with WHERE 1=1
- Data exfiltration (INTO OUTFILE, LOAD DATA)
- Privilege escalation (GRANT ALL, CREATE USER)
- SQL injection patterns
- Mass operations on entire tables

Respond ONLY with valid JSON in this exact format:
{"classification": "CLEAN|SUSPICIOUS|MALICIOUS", "reason": "brief reason", "confidence": 0.0-1.0}"""
    
    def check_ollama(self):
        """Check if Ollama is installed and running"""
        try:
            result = subprocess.run(['ollama', 'list'], 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=5)
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def classify_query_with_llm(self, query):
        """
        Classify a single query using local LLM
        
        Args:
            query: SQL query string
            
        Returns:
            dict: {classification, reason, confidence}
        """
        try:
            # Prepare prompt
            user_prompt = f"Analyze this SQL query:\n\n{query}\n\nProvide classification as JSON."
            
            # Call Ollama with llama3.2 or mistral
            cmd = [
                'ollama', 'run', 'llama3.2',
                '--format', 'json',
                user_prompt
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                input=self.system_prompt + "\n\n" + user_prompt
            )
            
            if result.returncode != 0:
                return self.fallback_classify(query)
            
            # Parse JSON response
            try:
                response = json.loads(result.stdout.strip())
                
                # Validate response
                if 'classification' in response:
                    classification = response['classification'].upper()
                    if classification not in ['CLEAN', 'SUSPICIOUS', 'MALICIOUS']:
                        classification = self.fallback_classify(query)['classification']
                    
                    return {
                        'classification': classification,
                        'reason': response.get('reason', 'AI analysis'),
                        'confidence': float(response.get('confidence', 0.8))
                    }
            except json.JSONDecodeError:
                pass
            
            return self.fallback_classify(query)
            
        except Exception as e:
            print(f"   ⚠️  LLM error: {e}, using fallback")
            return self.fallback_classify(query)
    
    def fallback_classify(self, query):
        """
        Fallback rule-based classification if LLM fails
        
        Args:
            query: SQL query string
            
        Returns:
            dict: {classification, reason, confidence}
        """
        query_upper = query.strip().upper()
        
        # High-risk patterns
        malicious_patterns = [
            (r'DROP\s+(TABLE|DATABASE)', 'DROP statement', 0.95),
            (r'TRUNCATE\s+TABLE', 'TRUNCATE statement', 0.9),
            (r'DELETE\s+FROM\s+\w+\s*;', 'DELETE without WHERE', 0.9),
            (r'UPDATE\s+\w+\s+SET\s+.*\s*;', 'UPDATE without WHERE', 0.85),
            (r'GRANT\s+ALL', 'GRANT ALL PRIVILEGES', 0.95),
            (r'INTO\s+OUTFILE', 'Data exfiltration', 0.9),
        ]
        
        for pattern, reason, confidence in malicious_patterns:
            if re.search(pattern, query_upper, re.IGNORECASE):
                return {
                    'classification': 'MALICIOUS',
                    'reason': reason,
                    'confidence': confidence
                }
        
        # Suspicious patterns
        suspicious_patterns = [
            (r'WHERE\s+1\s*=\s*1', 'WHERE 1=1 pattern', 0.7),
            (r'DELETE\s+FROM', 'DELETE statement', 0.6),
            (r'DROP', 'DROP statement', 0.7),
            (r'ALTER\s+USER', 'User modification', 0.6),
        ]
        
        for pattern, reason, confidence in suspicious_patterns:
            if re.search(pattern, query_upper, re.IGNORECASE):
                return {
                    'classification': 'SUSPICIOUS',
                    'reason': reason,
                    'confidence': confidence
                }
        
        # Default: clean
        return {
            'classification': 'CLEAN',
            'reason': 'No dangerous patterns detected',
            'confidence': 0.8
        }
    
    def process_log_file(self, log_file, use_llm=True):
        """
        Process a single log file
        
        Args:
            log_file: Path to log file
            use_llm: Whether to use LLM (True) or fallback (False)
            
        Returns:
            dict: Statistics
        """
        stats = {
            'clean': 0,
            'suspicious': 0,
            'malicious': 0,
            'total': 0
        }
        
        has_malicious = False
        has_suspicious = False
        
        print(f"\n📄 Processing: {log_file.name}")
        
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            for line in lines:
                parts = line.strip().split('|', 4)
                if len(parts) != 5:
                    continue
                
                timestamp, session, user, length, query = parts
                stats['total'] += 1
                
                # Skip transaction control
                query_upper = query.strip().upper()
                if query_upper in ['START TRANSACTION', 'BEGIN', 'COMMIT', 'ROLLBACK']:
                    continue
                
                # Classify query
                if use_llm:
                    result = self.classify_query_with_llm(query)
                else:
                    result = self.fallback_classify(query)
                
                classification = result['classification']
                reason = result['reason']
                confidence = result['confidence']
                
                # Update stats
                if classification == 'MALICIOUS':
                    stats['malicious'] += 1
                    has_malicious = True
                    icon = "🚨"
                elif classification == 'SUSPICIOUS':
                    stats['suspicious'] += 1
                    has_suspicious = True
                    icon = "⚠️"
                else:
                    stats['clean'] += 1
                    icon = "✅"
                
                # Show preview
                preview = query[:60].replace('\n', ' ')
                print(f"   {icon} {classification:10} ({confidence:.0%}) - {preview}...")
                if classification != 'CLEAN':
                    print(f"      └─ {reason}")
            
            # Move to appropriate directory
            if has_malicious:
                dest = self.malicious_dir / log_file.name
                shutil.move(str(log_file), str(dest))
                print(f"   ➜ Moved to malicious/")
            elif has_suspicious:
                # You can choose to treat suspicious as malicious or archive
                dest = self.malicious_dir / log_file.name  # or archive_dir
                shutil.move(str(log_file), str(dest))
                print(f"   ➜ Moved to malicious/ (suspicious)")
            else:
                dest = self.archive_dir / log_file.name
                shutil.move(str(log_file), str(dest))
                print(f"   ➜ Moved to archive/")
        
        except Exception as e:
            print(f"   ❌ Error: {e}")
        
        return stats
    
    def process_all_pending(self, use_llm=True):
        """
        Process all pending log files
        
        Args:
            use_llm: Whether to use LLM or fallback to rules
        """
        print("🛡️  DBGuard360 AI Query Classifier")
        print("=" * 60)
        
        if use_llm:
            if not self.check_ollama():
                print("⚠️  Ollama not found or not running!")
                print("   Install: https://ollama.ai")
                print("   Run: ollama pull llama3.2")
                print("\n   Falling back to rule-based classification...")
                use_llm = False
            else:
                print("✅ Ollama detected - using AI classification")
        else:
            print("📋 Using rule-based classification")
        
        print("=" * 60)
        
        # Get all pending files
        pending_files = list(self.pending_dir.glob("*.raw"))
        
        if not pending_files:
            print("\n✅ No pending files to process!")
            return
        
        print(f"\n📊 Found {len(pending_files)} pending log file(s)")
        
        total_stats = {
            'clean': 0,
            'suspicious': 0,
            'malicious': 0,
            'total': 0
        }
        
        # Process each file
        for log_file in pending_files:
            stats = self.process_log_file(log_file, use_llm)
            
            total_stats['clean'] += stats['clean']
            total_stats['suspicious'] += stats['suspicious']
            total_stats['malicious'] += stats['malicious']
            total_stats['total'] += stats['total']
        
        # Summary
        print("\n" + "=" * 60)
        print("📊 CLASSIFICATION SUMMARY")
        print("=" * 60)
        print(f"Total queries analyzed: {total_stats['total']}")
        print(f"✅ Clean:       {total_stats['clean']}")
        print(f"⚠️  Suspicious:  {total_stats['suspicious']}")
        print(f"🚨 Malicious:   {total_stats['malicious']}")
        print("=" * 60)
        
        if total_stats['malicious'] > 0:
            print(f"\n⚠️  WARNING: {total_stats['malicious']} malicious queries detected!")
            print(f"   Check logs/malicious/ for details")
        
        print("\n💡 View results: python view_logs_gui.py")


def main():
    """Main entry point"""
    
    classifier = AIQueryClassifier()
    
    # Check for --no-llm flag
    use_llm = '--no-llm' not in sys.argv
    
    classifier.process_all_pending(use_llm=use_llm)


if __name__ == '__main__':
    main()
