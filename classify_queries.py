#!/usr/bin/env python3
"""
DBGuard 360 - Query Classification System
Expert rule-based classifier with feature extraction and threat scoring.

Usage:
    python classify_queries.py
"""

import os
import re
from datetime import datetime
from dataclasses import dataclass
from typing import List, Set, Tuple
from pathlib import Path


@dataclass
class QueryFeatures:
    """Extracted features from SQL query for classification."""
    has_union: bool = False
    has_or_condition: bool = False
    has_tautology: bool = False  # e.g., 1=1, 'a'='a'
    has_comment: bool = False
    has_stacked_query: bool = False
    has_sleep: bool = False
    has_benchmark: bool = False
    has_information_schema: bool = False
    has_load_file: bool = False
    has_outfile: bool = False
    has_into_dumpfile: bool = False
    has_exec: bool = False
    has_base64: bool = False
    has_char_function: bool = False
    has_concat: bool = False
    has_hex: bool = False
    suspicious_where_clause: bool = False
    excessive_or_conditions: bool = False  # > 3 OR conditions
    quotes_mismatch: bool = False
    
    def threat_score(self) -> int:
        """Calculate threat score based on features (0-100)."""
        score = 0
        
        # High risk indicators (20 points each)
        if self.has_tautology and self.has_or_condition:
            score += 20  # Classic SQL injection pattern
        if self.has_union:
            score += 20  # Union-based injection
        if self.has_stacked_query:
            score += 20  # Command stacking
        if self.has_load_file or self.has_outfile or self.has_into_dumpfile:
            score += 20  # File access attempts
        
        # Medium risk indicators (10 points each)
        if self.has_sleep or self.has_benchmark:
            score += 10  # Time-based injection
        if self.has_information_schema:
            score += 10  # Schema enumeration
        if self.has_exec:
            score += 10  # Command execution
        if self.excessive_or_conditions:
            score += 10  # Suspicious logic
        if self.has_comment:
            score += 5   # Comment obfuscation
        
        # Low risk indicators (5 points each)
        if self.has_base64 or self.has_char_function or self.has_hex:
            score += 5   # Encoding/obfuscation
        if self.has_concat:
            score += 5   # String concatenation tricks
        if self.quotes_mismatch:
            score += 5   # Malformed syntax
        
        return min(score, 100)  # Cap at 100


class QueryClassifier:
    """Expert rule-based classifier for SQL queries."""
    
    # SQL Injection patterns
    TAUTOLOGY_PATTERNS = [
        r"(?i)\bor\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?",  # or 'a'='a'
        r"(?i)\bor\s+\d+\s*=\s*\d+",  # or 1=1
        r"(?i)\band\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?",  # and 'a'='a'
        r"(?i)\band\s+\d+\s*=\s*\d+",  # and 1=1
    ]
    
    UNION_PATTERNS = [
        r"(?i)\bunion\s+(all\s+)?select\b",
    ]
    
    COMMENT_PATTERNS = [
        r"--",  # SQL comment
        r"/\*.*?\*/",  # Block comment
        r"#",  # MySQL comment
    ]
    
    TIME_BASED_PATTERNS = [
        r"(?i)\bsleep\s*\(",
        r"(?i)\bbenchmark\s*\(",
        r"(?i)\bwaitfor\s+delay\b",
    ]
    
    FILE_ACCESS_PATTERNS = [
        r"(?i)\bload_file\s*\(",
        r"(?i)\binto\s+outfile\b",
        r"(?i)\binto\s+dumpfile\b",
    ]
    
    OBFUSCATION_PATTERNS = [
        r"(?i)\bchar\s*\(",
        r"(?i)\bconcat\s*\(",
        r"(?i)\bhex\s*\(",
        r"(?i)\b0x[0-9a-f]+",  # Hex literals
        r"(?i)\bbase64\b",
    ]
    
    def __init__(self):
        self.stats = {
            'total': 0,
            'clean': 0,
            'suspicious': 0,
            'malicious': 0
        }
    
    def extract_features(self, query: str) -> QueryFeatures:
        """Extract security-relevant features from query."""
        features = QueryFeatures()
        query_lower = query.lower()
        
        # Check for SQL injection patterns
        for pattern in self.TAUTOLOGY_PATTERNS:
            if re.search(pattern, query):
                features.has_tautology = True
                break
        
        for pattern in self.UNION_PATTERNS:
            if re.search(pattern, query):
                features.has_union = True
                break
        
        for pattern in self.COMMENT_PATTERNS:
            if re.search(pattern, query):
                features.has_comment = True
                break
        
        for pattern in self.TIME_BASED_PATTERNS:
            if re.search(pattern, query):
                features.has_sleep = True
                features.has_benchmark = True
                break
        
        for pattern in self.FILE_ACCESS_PATTERNS:
            if re.search(pattern, query):
                if 'load_file' in query_lower:
                    features.has_load_file = True
                if 'outfile' in query_lower:
                    features.has_outfile = True
                if 'dumpfile' in query_lower:
                    features.has_into_dumpfile = True
                break
        
        for pattern in self.OBFUSCATION_PATTERNS:
            if re.search(pattern, query):
                if 'char(' in query_lower:
                    features.has_char_function = True
                if 'concat(' in query_lower:
                    features.has_concat = True
                if 'hex(' in query_lower or '0x' in query_lower:
                    features.has_hex = True
                if 'base64' in query_lower:
                    features.has_base64 = True
                break
        
        # Check for OR conditions
        or_count = len(re.findall(r'(?i)\bor\b', query))
        if or_count > 0:
            features.has_or_condition = True
        if or_count > 3:
            features.excessive_or_conditions = True
        
        # Check for stacked queries
        if ';' in query and query.strip().count(';') > 1:
            features.has_stacked_query = True
        
        # Check for information_schema access
        if 'information_schema' in query_lower:
            features.has_information_schema = True
        
        # Check for exec/execute
        if re.search(r'(?i)\bexec(ute)?\s*\(', query):
            features.has_exec = True
        
        # Check WHERE clause suspicion
        if re.search(r'(?i)\bwhere\b.*\bor\b.*[=<>]', query):
            features.suspicious_where_clause = True
        
        return features
    
    def classify(self, query: str) -> Tuple[str, int, List[str]]:
        """
        Classify query using expert rules.
        
        Returns:
            (classification, confidence, reasons)
            classification: "CLEAN", "SUSPICIOUS", "MALICIOUS"
            confidence: 0-100
            reasons: List of threat indicators found
        """
        features = self.extract_features(query)
        score = features.threat_score()
        reasons = []
        
        # Build reason list
        if features.has_tautology:
            reasons.append("SQL tautology detected (e.g., 1=1, 'a'='a')")
        if features.has_union:
            reasons.append("UNION-based injection pattern")
        if features.has_or_condition and features.has_tautology:
            reasons.append("Classic SQL injection: OR with always-true condition")
        if features.has_stacked_query:
            reasons.append("Stacked query attempt")
        if features.has_sleep or features.has_benchmark:
            reasons.append("Time-based injection pattern")
        if features.has_information_schema:
            reasons.append("Schema enumeration attempt")
        if features.has_load_file or features.has_outfile or features.has_into_dumpfile:
            reasons.append("File system access attempt")
        if features.has_exec:
            reasons.append("Command execution attempt")
        if features.excessive_or_conditions:
            reasons.append(f"Excessive OR conditions (bypass attempt)")
        if features.has_comment:
            reasons.append("SQL comments (possible obfuscation)")
        if features.has_base64 or features.has_char_function or features.has_hex:
            reasons.append("Encoding/obfuscation detected")
        if features.has_concat:
            reasons.append("String concatenation (evasion technique)")
        
        # Classify based on score
        if score >= 20:
            classification = "MALICIOUS"
            confidence = min(50 + score, 100)  # 50-100% confidence
        elif score >= 10:
            classification = "SUSPICIOUS"
            confidence = 40 + score  # 40-60% confidence
        else:
            classification = "CLEAN"
            confidence = max(95 - score * 5, 50)  # 50-95% confidence
        
        self.stats['total'] += 1
        self.stats[classification.lower()] += 1
        
        return classification, confidence, reasons
    
    def format_classification(self, query: str, classification: str, confidence: int, reasons: List[str]) -> str:
        """Format classification result for display."""
        emoji_map = {
            'CLEAN': '✅',
            'SUSPICIOUS': '⚠️',
            'MALICIOUS': '🚨'
        }
        
        result = f"{emoji_map[classification]} {classification} ({confidence}%) {query[:100]}"
        if reasons:
            for reason in reasons:
                result += f"\n   └─ {reason}"
        return result


def classify_pending_logs(pending_dir: str = "logs/pending", 
                         archive_dir: str = "logs/archive",
                         malicious_dir: str = "logs/malicious"):
    """Classify all pending log files and move to appropriate directories."""
    
    # Ensure directories exist
    os.makedirs(archive_dir, exist_ok=True)
    os.makedirs(malicious_dir, exist_ok=True)
    
    classifier = QueryClassifier()
    
    # Process all pending files
    pending_files = list(Path(pending_dir).glob("*.log"))
    
    if not pending_files:
        print(f"No pending log files found in {pending_dir}")
        return
    
    print(f"Processing {len(pending_files)} log files...\n")
    
    for log_file in sorted(pending_files):
        print(f"📄 Processing: {log_file.name}")
        
        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        
        classified_lines = []
        suspicious_count = 0
        malicious_count = 0
        
        for line in lines:
            parts = line.strip().split('|')
            if len(parts) < 5:
                continue
            
            query = parts[4]
            classification, confidence, reasons = classifier.classify(query)
            
            # Add classification tag to line
            classified_line = f"{line.rstrip()}|{classification}|{confidence}\n"
            classified_lines.append(classified_line)
            
            if classification == "SUSPICIOUS":
                suspicious_count += 1
                print(f"  {classifier.format_classification(query, classification, confidence, reasons)}")
            elif classification == "MALICIOUS":
                malicious_count += 1
                print(f"  {classifier.format_classification(query, classification, confidence, reasons)}")
        
        # Determine destination
        if malicious_count > 0:
            dest_dir = malicious_dir
            status = f"🚨 MALICIOUS ({malicious_count} threats)"
        elif suspicious_count > 0:
            dest_dir = archive_dir
            status = f"⚠️ SUSPICIOUS ({suspicious_count} warnings)"
        else:
            dest_dir = archive_dir
            status = "✅ CLEAN"
        
        # Move file to destination
        dest_path = Path(dest_dir) / log_file.name
        with open(dest_path, 'w', encoding='utf-8') as f:
            f.writelines(classified_lines)
        
        # Remove original pending file
        log_file.unlink()
        
        print(f"  → {status} → {dest_dir}/{log_file.name}\n")
    
    # Print summary
    print("=" * 60)
    print(f"Classification Summary:")
    print(f"  Total queries: {classifier.stats['total']}")
    print(f"  ✅ Clean: {classifier.stats['clean']}")
    print(f"  ⚠️ Suspicious: {classifier.stats['suspicious']}")
    print(f"  🚨 Malicious: {classifier.stats['malicious']}")
    print("=" * 60)


if __name__ == "__main__":
    classify_pending_logs()
