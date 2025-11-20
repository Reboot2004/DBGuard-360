"""
DBGuard360 - Local ML Query Classifier
Uses small transformer model from Hugging Face (no Ollama needed)
Runs directly in Python with transformers library
"""

import sys
import shutil
from pathlib import Path
import re
from transformers import pipeline
import torch


class LocalMLClassifier:
    """
    Classify SQL queries using local transformer model
    """
    
    def __init__(self):
        self.pending_dir = Path("logs/pending")
        self.archive_dir = Path("logs/archive")
        self.malicious_dir = Path("logs/malicious")
        
        # Create directories
        self.archive_dir.mkdir(parents=True, exist_ok=True)
        self.malicious_dir.mkdir(parents=True, exist_ok=True)
        
        self.classifier = None
        self.use_ml = False
    
    def load_model(self):
        """Load small text classification model from HuggingFace"""
        try:
            print("📥 Loading ML model (DistilBERT - 66MB)...")
            print("   First run will download model, subsequent runs are instant")
            
            # Use DistilBERT for zero-shot classification (small and fast)
            self.classifier = pipeline(
                "zero-shot-classification",
                model="typeform/distilbert-base-uncased-mnli",
                device=0 if torch.cuda.is_available() else -1  # GPU if available
            )
            
            self.use_ml = True
            print("✅ Model loaded successfully!")
            
            if torch.cuda.is_available():
                print("   🚀 Using GPU acceleration")
            else:
                print("   💻 Using CPU (slower but works)")
            
            return True
            
        except Exception as e:
            print(f"⚠️  Failed to load model: {e}")
            print("   Falling back to rule-based classification")
            return False
    
    def classify_with_ml(self, query):
        """
        Classify query using ML model
        
        Args:
            query: SQL query string
            
        Returns:
            dict: {classification, reason, confidence}
        """
        try:
            # Define candidate labels
            candidate_labels = [
                "safe database query",
                "suspicious database operation",
                "malicious or dangerous query"
            ]
            
            # Classify
            result = self.classifier(
                query,
                candidate_labels,
                multi_label=False
            )
            
            # Get top prediction
            top_label = result['labels'][0]
            confidence = result['scores'][0]
            
            # Map to classification
            if 'malicious' in top_label:
                classification = 'MALICIOUS'
            elif 'suspicious' in top_label:
                classification = 'SUSPICIOUS'
            else:
                classification = 'CLEAN'
            
            # If confidence is low, apply rules as well
            if confidence < 0.6:
                rule_result = self.rule_based_classify(query)
                if rule_result['classification'] != 'CLEAN':
                    return rule_result
            
            return {
                'classification': classification,
                'reason': f'ML prediction: {top_label}',
                'confidence': confidence
            }
            
        except Exception as e:
            print(f"   ⚠️  ML error: {e}, using rules")
            return self.rule_based_classify(query)
    
    def rule_based_classify(self, query):
        """
        Rule-based classification (fallback)
        
        Args:
            query: SQL query string
            
        Returns:
            dict: {classification, reason, confidence}
        """
        query_upper = query.strip().upper()
        
        # CRITICAL MALICIOUS patterns (high confidence)
        critical_patterns = [
            (r'DROP\s+(TABLE|DATABASE)\s+\w+\s*;', 'DROP without WHERE/CASCADE', 0.98),
            (r'TRUNCATE\s+TABLE', 'TRUNCATE TABLE (data loss)', 0.95),
            (r'DELETE\s+FROM\s+\w+\s*;', 'DELETE entire table (no WHERE)', 0.95),
            (r'UPDATE\s+\w+\s+SET\s+[^W]*;', 'UPDATE entire table (no WHERE)', 0.90),
            (r'GRANT\s+ALL\s+PRIVILEGES', 'Privilege escalation', 0.95),
            (r'INTO\s+OUTFILE', 'Data exfiltration attempt', 0.93),
            (r'LOAD\s+DATA\s+INFILE', 'File system access', 0.90),
        ]
        
        for pattern, reason, confidence in critical_patterns:
            if re.search(pattern, query_upper, re.IGNORECASE | re.DOTALL):
                return {
                    'classification': 'MALICIOUS',
                    'reason': reason,
                    'confidence': confidence
                }
        
        # SUSPICIOUS patterns (medium confidence)
        suspicious_patterns = [
            (r'WHERE\s+1\s*=\s*1', 'WHERE 1=1 (mass operation)', 0.75),
            (r'WHERE\s+TRUE', 'WHERE TRUE (mass operation)', 0.75),
            (r'DELETE\s+FROM', 'DELETE statement (check WHERE clause)', 0.65),
            (r'DROP\s+', 'DROP statement', 0.70),
            (r'ALTER\s+(USER|TABLE)', 'Schema/user modification', 0.65),
            (r'CREATE\s+USER', 'User creation', 0.60),
            (r'--\s*DROP|/\*.*DROP.*\*/', 'Commented DROP (obfuscation)', 0.80),
            (r'UNION\s+SELECT', 'UNION SELECT (possible injection)', 0.70),
            (r';\s*DROP', 'Stacked query with DROP', 0.85),
        ]
        
        for pattern, reason, confidence in suspicious_patterns:
            if re.search(pattern, query_upper, re.IGNORECASE | re.DOTALL):
                return {
                    'classification': 'SUSPICIOUS',
                    'reason': reason,
                    'confidence': confidence
                }
        
        # Check for proper WHERE clauses in DML
        if re.search(r'(DELETE|UPDATE)\s+', query_upper):
            if not re.search(r'WHERE\s+\w+', query_upper):
                return {
                    'classification': 'SUSPICIOUS',
                    'reason': 'DML without WHERE clause',
                    'confidence': 0.85
                }
        
        # Default: CLEAN
        return {
            'classification': 'CLEAN',
            'reason': 'No dangerous patterns detected',
            'confidence': 0.80
        }
    
    def process_log_file(self, log_file):
        """
        Process a single log file
        
        Args:
            log_file: Path to log file
            
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
        
        print(f"\n📄 {log_file.name}")
        
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
                if query_upper in ['START TRANSACTION', 'BEGIN', 'COMMIT', 'ROLLBACK', 'SET AUTOCOMMIT = 0']:
                    continue
                
                # Classify query
                if self.use_ml:
                    result = self.classify_with_ml(query)
                else:
                    result = self.rule_based_classify(query)
                
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
                preview = query[:50].replace('\n', ' ')
                print(f"  {icon} {classification:10} ({confidence:>4.0%}) {preview}...")
                if classification != 'CLEAN':
                    print(f"     └─ {reason}")
            
            # Move to appropriate directory
            if has_malicious:
                dest = self.malicious_dir / log_file.name
                shutil.move(str(log_file), str(dest))
                print(f"  ➜ malicious/")
            elif has_suspicious:
                dest = self.malicious_dir / log_file.name
                shutil.move(str(log_file), str(dest))
                print(f"  ➜ malicious/ (suspicious)")
            else:
                dest = self.archive_dir / log_file.name
                shutil.move(str(log_file), str(dest))
                print(f"  ➜ archive/")
        
        except Exception as e:
            print(f"  ❌ Error: {e}")
        
        return stats
    
    def process_all_pending(self, use_ml=True):
        """
        Process all pending log files
        
        Args:
            use_ml: Whether to use ML model
        """
        print("🛡️  DBGuard360 ML Query Classifier")
        print("=" * 60)
        
        if use_ml:
            if not self.load_model():
                print("📋 Using rule-based classification")
                use_ml = False
        else:
            print("📋 Using rule-based classification (fast mode)")
        
        print("=" * 60)
        
        # Get all pending files
        pending_files = sorted(list(self.pending_dir.glob("*.raw")))
        
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
        for i, log_file in enumerate(pending_files, 1):
            print(f"\n[{i}/{len(pending_files)}]", end=" ")
            stats = self.process_log_file(log_file)
            
            total_stats['clean'] += stats['clean']
            total_stats['suspicious'] += stats['suspicious']
            total_stats['malicious'] += stats['malicious']
            total_stats['total'] += stats['total']
        
        # Summary
        print("\n" + "=" * 60)
        print("📊 CLASSIFICATION SUMMARY")
        print("=" * 60)
        print(f"Total queries:  {total_stats['total']}")
        print(f"✅ Clean:       {total_stats['clean']:3d} ({total_stats['clean']/max(total_stats['total'],1)*100:5.1f}%)")
        print(f"⚠️  Suspicious:  {total_stats['suspicious']:3d} ({total_stats['suspicious']/max(total_stats['total'],1)*100:5.1f}%)")
        print(f"🚨 Malicious:   {total_stats['malicious']:3d} ({total_stats['malicious']/max(total_stats['total'],1)*100:5.1f}%)")
        print("=" * 60)
        
        if total_stats['malicious'] > 0 or total_stats['suspicious'] > 0:
            print(f"\n⚠️  WARNING: Found {total_stats['malicious'] + total_stats['suspicious']} potentially dangerous queries!")
            print(f"   Review: logs/malicious/")
        
        print("\n💡 View results in GUI: python view_logs_gui.py")


def main():
    """Main entry point"""
    
    classifier = LocalMLClassifier()
    
    # Check for flags
    use_ml = '--no-ml' not in sys.argv and '--rules-only' not in sys.argv
    
    if '--help' in sys.argv:
        print("""
DBGuard360 Query Classifier

Usage:
  python classify_queries_ml.py              # Use ML model (default)
  python classify_queries_ml.py --no-ml      # Use rules only (fast)
  python classify_queries_ml.py --rules-only # Same as --no-ml
  
First run will download a 66MB model from HuggingFace.
Subsequent runs use cached model (instant).
        """)
        return
    
    classifier.process_all_pending(use_ml=use_ml)


if __name__ == '__main__':
    main()
