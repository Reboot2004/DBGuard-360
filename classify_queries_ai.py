"""
DBGuard360 - Advanced ML Query Classifier
Uses proper ML techniques for SQL injection and malicious query detection
"""

import sys
import shutil
from pathlib import Path
import re
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification, pipeline
import numpy as np


class AdvancedMLClassifier:
    """
    Advanced ML classifier using multiple techniques:
    1. Pre-trained security models
    2. Feature extraction
    3. Ensemble methods
    """
    
    def __init__(self):
        self.pending_dir = Path("logs/pending")
        self.archive_dir = Path("logs/archive")
        self.malicious_dir = Path("logs/malicious")
        
        # Create directories
        self.archive_dir.mkdir(parents=True, exist_ok=True)
        self.malicious_dir.mkdir(parents=True, exist_ok=True)
        
        self.classifier = None
        self.zero_shot = None
        self.use_ml = False
    
    def load_models(self):
        """Load ML models"""
        try:
            print("📥 Loading ML models...")
            print("   Model 1: CodeBERT for code understanding")
            
            # Use CodeBERT - trained on code, better for SQL
            self.zero_shot = pipeline(
                "zero-shot-classification",
                model="microsoft/codebert-base",
                device=0 if torch.cuda.is_available() else -1
            )
            
            print("✅ Models loaded successfully!")
            
            if torch.cuda.is_available():
                print("   🚀 Using GPU acceleration")
            else:
                print("   💻 Using CPU")
            
            self.use_ml = True
            return True
            
        except Exception as e:
            print(f"⚠️  Failed to load models: {e}")
            print("   Trying lightweight alternative...")
            
            try:
                # Fallback to lighter model
                self.zero_shot = pipeline(
                    "zero-shot-classification",
                    model="facebook/bart-large-mnli",
                    device=-1
                )
                self.use_ml = True
                print("✅ Fallback model loaded (BART)")
                return True
            except:
                print("   Using enhanced rule-based classification")
                return False
    
    def extract_sql_features(self, query):
        """
        Extract features from SQL query for ML
        
        Returns:
            dict: Feature vector
        """
        query_upper = query.upper()
        
        features = {
            # Injection patterns
            'has_or_equals': bool(re.search(r'OR\s+[\'\"]?\d+[\'\"]?\s*=\s*[\'\"]?\d+[\'\"]?', query_upper)),
            'has_and_equals': bool(re.search(r'AND\s+[\'\"]?\d+[\'\"]?\s*=\s*[\'\"]?\d+[\'\"]?', query_upper)),
            'has_union': 'UNION' in query_upper,
            'has_comment': '--' in query or '/*' in query,
            'has_semicolon': ';' in query,
            'has_stacked': bool(re.search(r';\s*(DROP|DELETE|UPDATE|INSERT)', query_upper)),
            
            # Quote patterns
            'quote_mismatch': query.count("'") % 2 != 0,
            'double_quotes': "''" in query,
            'escaped_quotes': "\\'" in query or '\\"' in query,
            
            # Dangerous operations
            'has_drop': 'DROP' in query_upper,
            'has_delete': 'DELETE' in query_upper,
            'has_truncate': 'TRUNCATE' in query_upper,
            'has_grant': 'GRANT' in query_upper,
            'has_into_outfile': 'INTO OUTFILE' in query_upper or 'INTO DUMPFILE' in query_upper,
            
            # WHERE clause analysis
            'has_where': 'WHERE' in query_upper,
            'where_always_true': bool(re.search(r'WHERE\s+(1\s*=\s*1|TRUE)', query_upper)),
            
            # Length and complexity
            'query_length': len(query),
            'has_nested_select': query_upper.count('SELECT') > 1,
            'has_concat': 'CONCAT' in query_upper or '||' in query,
            
            # Encoding tricks
            'has_hex': bool(re.search(r'0x[0-9a-fA-F]+', query)),
            'has_char': 'CHAR(' in query_upper,
            'has_sleep': 'SLEEP' in query_upper or 'BENCHMARK' in query_upper or 'WAITFOR' in query_upper,
        }
        
        return features
    
    def feature_based_score(self, features):
        """
        Score query based on features
        
        Returns:
            float: Risk score 0-1
        """
        score = 0.0
        weights = {
            'has_or_equals': 0.25,
            'has_and_equals': 0.25,
            'has_union': 0.15,
            'has_stacked': 0.30,
            'quote_mismatch': 0.20,
            'double_quotes': 0.15,
            'has_drop': 0.20,
            'has_delete': 0.15,
            'has_into_outfile': 0.30,
            'where_always_true': 0.25,
            'has_nested_select': 0.10,
            'has_hex': 0.15,
            'has_sleep': 0.25,
        }
        
        for feature, value in features.items():
            if value and feature in weights:
                score += weights[feature]
        
        return min(score, 1.0)
    
    def classify_with_ml(self, query):
        """
        Classify using ML + features
        
        Args:
            query: SQL query
            
        Returns:
            dict: {classification, reason, confidence}
        """
        try:
            # Extract features
            features = self.extract_sql_features(query)
            feature_score = self.feature_based_score(features)
            
            # If feature score is very high, it's definitely malicious
            if feature_score > 0.7:
                return {
                    'classification': 'MALICIOUS',
                    'reason': f'High risk score: {feature_score:.2f} (multiple attack indicators)',
                    'confidence': min(0.95, 0.70 + feature_score * 0.3)
                }
            
            # Use ML for context understanding
            if self.use_ml and self.zero_shot:
                candidate_labels = [
                    "normal safe database query",
                    "SQL injection attack",
                    "dangerous database operation",
                    "data exfiltration attempt"
                ]
                
                result = self.zero_shot(
                    query[:512],  # Truncate for model
                    candidate_labels,
                    multi_label=False
                )
                
                top_label = result['labels'][0]
                ml_confidence = result['scores'][0]
                
                # Combine ML with feature score
                if 'injection' in top_label.lower():
                    combined_confidence = max(ml_confidence, feature_score)
                    return {
                        'classification': 'MALICIOUS',
                        'reason': f'ML detected: SQL injection (score: {feature_score:.2f})',
                        'confidence': combined_confidence
                    }
                
                elif 'dangerous' in top_label.lower() or 'exfiltration' in top_label.lower():
                    return {
                        'classification': 'MALICIOUS' if ml_confidence > 0.6 else 'SUSPICIOUS',
                        'reason': f'ML: {top_label}',
                        'confidence': ml_confidence
                    }
                
                # If ML says safe but features suspicious
                elif feature_score > 0.4:
                    return {
                        'classification': 'SUSPICIOUS',
                        'reason': f'Feature analysis flagged (score: {feature_score:.2f})',
                        'confidence': feature_score
                    }
                
                else:
                    return {
                        'classification': 'CLEAN',
                        'reason': f'ML: {top_label}',
                        'confidence': ml_confidence
                    }
            
            # Fallback to feature-based only
            if feature_score > 0.5:
                return {
                    'classification': 'MALICIOUS',
                    'reason': f'Feature-based detection (score: {feature_score:.2f})',
                    'confidence': feature_score
                }
            elif feature_score > 0.3:
                return {
                    'classification': 'SUSPICIOUS',
                    'reason': f'Some suspicious patterns (score: {feature_score:.2f})',
                    'confidence': feature_score
                }
            else:
                return {
                    'classification': 'CLEAN',
                    'reason': f'Low risk score: {feature_score:.2f}',
                    'confidence': 0.85
                }
                
        except Exception as e:
            print(f"   ⚠️  ML error: {e}")
            # Emergency fallback
            return self.simple_classify(query)
    
    def simple_classify(self, query):
        """Simple fallback"""
        query_upper = query.upper()
        
        # Critical patterns
        if any(p in query_upper for p in ['OR 1=1', 'OR 1 = 1', "OR '1'='1'", 'UNION SELECT']):
            return {'classification': 'MALICIOUS', 'reason': 'SQL injection pattern', 'confidence': 0.95}
        
        if re.search(r'(DROP|TRUNCATE|DELETE|UPDATE).*;\s*$', query_upper) and 'WHERE' not in query_upper:
            return {'classification': 'MALICIOUS', 'reason': 'Dangerous operation without WHERE', 'confidence': 0.90}
        
        if any(p in query_upper for p in ['INTO OUTFILE', 'LOAD DATA', 'GRANT ALL']):
            return {'classification': 'MALICIOUS', 'reason': 'Data exfiltration/privilege escalation', 'confidence': 0.92}
        
        return {'classification': 'CLEAN', 'reason': 'No obvious threats', 'confidence': 0.80}
    
    def process_log_file(self, log_file):
        """Process a single log file"""
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
                
                # Classify
                result = self.classify_with_ml(query)
                
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
        """Process all pending logs"""
        print("🛡️  DBGuard360 Advanced ML Classifier")
        print("=" * 60)
        
        if use_ml:
            self.load_models()
        else:
            print("📋 Using feature-based classification (fast mode)")
        
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
        
        print("\n💡 View results: python view_logs_gui.py")


def main():
    """Main entry point"""
    
    classifier = AdvancedMLClassifier()
    
    use_ml = '--no-ml' not in sys.argv and '--features-only' not in sys.argv
    
    if '--help' in sys.argv:
        print("""
DBGuard360 Advanced ML Classifier

Techniques used:
1. Feature extraction (injection patterns, quotes, operations)
2. ML models (CodeBERT/BART for context)
3. Risk scoring (weighted feature combination)
4. Ensemble decision (ML + features)

Usage:
  python classify_queries_ai.py              # Full ML + features
  python classify_queries_ai.py --no-ml      # Features only (fast)
  
First run downloads CodeBERT model (~500MB).
        """)
        return
    
    classifier.process_all_pending(use_ml=use_ml)


if __name__ == '__main__':
    main()
