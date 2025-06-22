#!/usr/bin/env python3
"""
Enhanced Educational Antivirus - Academic Project
National Teachers College - Cybersecurity Exercise

Advanced antivirus tool specifically designed to detect and remove
the Odyssey Educational Virus and demonstrate cybersecurity principles.

Author: Academic Cybersecurity Project
Institution: National Teachers College
Date: June 2025
Target: Odyssey Educational Virus (ROT13 Implementation)

FEATURES:
- ROT13 decryption engine
- Comprehensive virus signature detection
- Advanced behavioral analysis
- Secure file recovery and restoration
- Real-time scanning with GUI
- Detailed forensic reporting
- Quarantine management system
"""

import os
import sys
import json
import time
import hashlib
import fnmatch
import threading
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import messagebox, scrolledtext, filedialog, ttk

class ROT13CryptographyEngine:
    """
    ROT13 Cryptographic Engine for Virus Decryption
    
    Implements the exact ROT13 algorithm used by the Odyssey virus
    to ensure proper decryption and file recovery.
    """
    
    @staticmethod
    def rot13_transform(text):
        """
        Apply ROT13 transformation (identical to virus implementation)
        
        Args:
            text (str): Input text to transform
            
        Returns:
            str: ROT13 transformed text
        """
        result = []
        
        for char in text:
            if char.isalpha():
                is_upper = char.isupper()
                char = char.upper()
                transformed_char = chr(((ord(char) - ord('A') + 13) % 26) + ord('A'))
                
                if not is_upper:
                    transformed_char = transformed_char.lower()
                    
                result.append(transformed_char)
            else:
                result.append(char)
        
        return ''.join(result)
    
    @staticmethod
    def rot13_decrypt(ciphertext):
        """
        Decrypt ROT13 ciphertext (ROT13 is self-inverse)
        
        Args:
            ciphertext (str): ROT13 encrypted text
            
        Returns:
            str: Decrypted plaintext
        """
        return ROT13CryptographyEngine.rot13_transform(ciphertext)
    
    @staticmethod
    def rot13_encrypt(plaintext):
        """
        Encrypt plaintext using ROT13 (for testing purposes)
        
        Args:
            plaintext (str): Text to encrypt
            
        Returns:
            str: ROT13 encrypted text
        """
        return ROT13CryptographyEngine.rot13_transform(plaintext)

class OdysseyVirusSignatureDatabase:
    """
    Comprehensive signature database for Odyssey Educational Virus
    
    Contains all known signatures, patterns, and behavioral indicators
    specific to the Odyssey virus implementation.
    """
    
    def __init__(self):
        self.virus_signatures = {
            "ODYSSEY_VIRUS_2025_NTC": {
                "name": "Odyssey Educational Virus",
                "version": "1.0_EDUCATIONAL_ROT13",
                "institution": "National Teachers College",
                "type": "Educational Malware Simulation",
                "risk_level": "Educational Only",
                "encryption_algorithm": "ROT13",
                "target_directory": "odyssey_test_environment",
                "description": "ROT13-based educational virus for cybersecurity learning"
            }
        }
        
        self.file_patterns = [
            "*ODYSSEY_ENCRYPTED*",           # Encrypted files
            "*ODYSSEY_LOCKED_*",             # Temporarily locked files
            "odyssey_activity.log",          # Activity log
            ".odyssey_infection_marker",     # Infection marker
            "odyssey_encrypted_payload.dat", # Encrypted payload
            "odyssey_encryption_manifest.json", # Encryption manifest
        ]
        
        self.content_signatures = [
            "ODYSSEY_VIRUS_2025_NTC",
            "<!-- ODYSSEY_VIRUS_2025_NTC -->",
            "<!-- Encryption: ROT13 -->",
            "National Teachers College",
            "Odyssey Educational Virus",
            "ROT13 Cryptographic Implementation"
        ]
        
        self.behavioral_indicators = [
            "File encryption with ODYSSEY_ENCRYPTED suffix",
            "ROT13 encrypted educational messages",
            "Infection marker placement",
            "Temporary file locking with ODYSSEY_LOCKED prefix",
            "Encrypted payload generation",
            "Educational popup message display",
            "Comprehensive activity logging"
        ]
        
        self.registry_entries = {
            # Potential registry modifications (for advanced detection)
            "educational_context": "National Teachers College Cybersecurity Exercise",
            "virus_purpose": "Academic Learning and Antivirus Development"
        }
    
    def get_virus_info(self, signature):
        """Get detailed information about virus signature"""
        return self.virus_signatures.get(signature, None)
    
    def is_odyssey_pattern(self, filename):
        """Check if filename matches Odyssey virus patterns"""
        for pattern in self.file_patterns:
            if fnmatch.fnmatch(filename, pattern):
                return True
        return False
    
    def get_all_signatures(self):
        """Get all known virus signatures"""
        return list(self.virus_signatures.keys())

class AdvancedVirusScanner:
    """
    Advanced virus scanning engine with comprehensive detection capabilities
    
    Implements multiple detection methods:
    - Signature-based detection
    - Heuristic analysis
    - Behavioral pattern recognition
    - File integrity verification
    """
    
    def __init__(self):
        self.crypto_engine = ROT13CryptographyEngine()
        self.signature_db = OdysseyVirusSignatureDatabase()
        self.scan_results = []
        self.quarantine_dir = "odyssey_antivirus_quarantine"
        self.scan_statistics = {
            'files_scanned': 0,
            'threats_detected': 0,
            'files_quarantined': 0,
            'files_cleaned': 0,
            'scan_duration': 0
        }
        
    def initialize_quarantine_system(self):
        """Initialize secure quarantine directory"""
        if not os.path.exists(self.quarantine_dir):
            os.makedirs(self.quarantine_dir)
            # Create quarantine metadata file
            quarantine_info = {
                "created": datetime.now().isoformat(),
                "purpose": "Odyssey Virus Quarantine",
                "antivirus": "Enhanced Educational Antivirus",
                "institution": "National Teachers College"
            }
            
            info_path = os.path.join(self.quarantine_dir, "quarantine_info.json")
            with open(info_path, 'w', encoding='utf-8') as f:
                json.dump(quarantine_info, f, indent=2)
                
            self.log_activity(f"✅ Quarantine system initialized: {self.quarantine_dir}")
        else:
            self.log_activity(f"📁 Using existing quarantine: {self.quarantine_dir}")
    
    def log_activity(self, message, level="INFO"):
        """Enhanced logging with different levels"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Level-specific prefixes
        level_prefixes = {
            "INFO": "📝",
            "WARNING": "⚠️",
            "ERROR": "❌",
            "SUCCESS": "✅",
            "DETECTION": "🚨",
            "CRYPTO": "🔐",
            "REMOVAL": "🧹"
        }
        
        prefix = level_prefixes.get(level, "📝")
        formatted_message = f"[{timestamp}] {prefix} {message}"
        print(formatted_message)
        
        # Also log to file if needed
        try:
            log_file = "antivirus_activity.log"
            with open(log_file, 'a', encoding='utf-8') as f:
                f.write(f"{formatted_message}\n")
        except:
            pass  # Don't let logging failures break the antivirus
    
    def calculate_file_hash(self, filepath):
        """Calculate SHA-256 hash of file for integrity verification"""
        try:
            hash_sha256 = hashlib.sha256()
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            self.log_activity(f"Failed to calculate hash for {filepath}: {str(e)}", "ERROR")
            return None
    
    def scan_file_signatures(self, filepath):
        """Advanced signature-based file scanning"""
        detections = []
        
        try:
            # Skip binary files and directories
            if not os.path.isfile(filepath) or self.quarantine_dir in filepath:
                return detections
            
            # Calculate file hash
            file_hash = self.calculate_file_hash(filepath)
            
            # Read file content with proper encoding
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Check for virus signatures
            for signature in self.signature_db.get_all_signatures():
                if signature in content:
                    virus_info = self.signature_db.get_virus_info(signature)
                    detection = {
                        'type': 'signature_match',
                        'signature': signature,
                        'file': filepath,
                        'file_hash': file_hash,
                        'virus_info': virus_info,
                        'detection_time': datetime.now().isoformat(),
                        'confidence': 'HIGH'
                    }
                    detections.append(detection)
                    self.log_activity(f"🚨 Virus signature detected: {signature} in {os.path.basename(filepath)}", "DETECTION")
            
            # Check for content signatures
            for content_sig in self.signature_db.content_signatures:
                if content_sig in content:
                    detection = {
                        'type': 'content_signature',
                        'pattern': content_sig,
                        'file': filepath,
                        'file_hash': file_hash,
                        'detection_time': datetime.now().isoformat(),
                        'confidence': 'MEDIUM'
                    }
                    detections.append(detection)
                    self.log_activity(f"🚨 Content signature detected: {content_sig[:30]}... in {os.path.basename(filepath)}", "DETECTION")
            
            # Check for ROT13 encrypted content (heuristic analysis)
            if self.is_rot13_encrypted(content):
                detection = {
                    'type': 'rot13_encrypted',
                    'file': filepath,
                    'file_hash': file_hash,
                    'detection_time': datetime.now().isoformat(),
                    'confidence': 'MEDIUM',
                    'description': 'File appears to contain ROT13 encrypted content'
                }
                detections.append(detection)
                self.log_activity(f"🔐 ROT13 encryption detected in {os.path.basename(filepath)}", "CRYPTO")
                
        except Exception as e:
            self.log_activity(f"Error scanning {filepath}: {str(e)}", "ERROR")
        
        return detections
    
    def is_rot13_encrypted(self, content):
        """
        Heuristic analysis to detect ROT13 encrypted content
        
        Uses statistical analysis to determine if content might be ROT13 encoded
        """
        if len(content) < 50:  # Too short for reliable analysis
            return False
        
        # Sample analysis on first 500 characters
        sample = content[:500].upper()
        
        # Count letter frequencies
        letter_counts = {}
        total_letters = 0
        
        for char in sample:
            if char.isalpha():
                letter_counts[char] = letter_counts.get(char, 0) + 1
                total_letters += 1
        
        if total_letters < 20:  # Not enough letters for analysis
            return False
        
        # Calculate frequency distribution
        frequencies = {char: count/total_letters for char, count in letter_counts.items()}
        
        # Check if frequency distribution is unusual (potential indicator of cipher)
        # Normal English text has certain expected frequency patterns
        expected_high_freq = ['E', 'T', 'A', 'O', 'I', 'N']
        
        # Count how many expected high-frequency letters have low frequency
        low_freq_count = 0
        for char in expected_high_freq:
            if frequencies.get(char, 0) < 0.02:  # Less than 2%
                low_freq_count += 1
        
        # If many expected high-frequency letters have low frequency, might be encrypted
        return low_freq_count >= 3
    
    def scan_filename_patterns(self, directory):
        """Scan directory for suspicious filename patterns"""
        detections = []
        
        try:
            for root, dirs, files in os.walk(directory):
                # Skip quarantine directory
                if self.quarantine_dir in root:
                    continue
                    
                for filename in files:
                    filepath = os.path.join(root, filename)
                    
                    if self.signature_db.is_odyssey_pattern(filename):
                        detection = {
                            'type': 'filename_pattern',
                            'pattern': filename,
                            'file': filepath,
                            'detection_time': datetime.now().isoformat(),
                            'confidence': 'HIGH',
                            'description': f'Filename matches Odyssey virus pattern'
                        }
                        detections.append(detection)
                        self.log_activity(f"🚨 Suspicious filename pattern: {filename}", "DETECTION")
                        
        except Exception as e:
            self.log_activity(f"Error scanning filename patterns in {directory}: {str(e)}", "ERROR")
        
        return detections
    
    def analyze_infection_marker(self, directory):
        """Analyze Odyssey virus infection marker"""
        marker_file = os.path.join(directory, ".odyssey_infection_marker")
        
        if not os.path.exists(marker_file):
            return None
        
        try:
            with open(marker_file, 'r', encoding='utf-8') as f:
                marker_data = json.load(f)
            
            self.log_activity("🎯 Odyssey infection marker found - analyzing...", "DETECTION")
            
            # Extract and display key information
            if 'infection_metadata' in marker_data:
                metadata = marker_data['infection_metadata']
                self.log_activity(f"   Virus Signature: {metadata.get('virus_signature', 'Unknown')}")
                self.log_activity(f"   Infection Time: {metadata.get('infection_timestamp', 'Unknown')}")
                self.log_activity(f"   Execution Duration: {metadata.get('execution_duration_seconds', 'Unknown')}s")
            
            if 'execution_statistics' in marker_data:
                stats = marker_data['execution_statistics']
                self.log_activity(f"   Files Processed: {stats.get('files_processed', 'Unknown')}")
                self.log_activity(f"   Encryption Operations: {stats.get('encryption_operations', 'Unknown')}")
            
            return marker_data
            
        except Exception as e:
            self.log_activity(f"Failed to analyze infection marker: {str(e)}", "ERROR")
            return None
    
    def analyze_encrypted_payload(self, directory):
        """Analyze and decrypt Odyssey virus payload"""
        payload_file = os.path.join(directory, "odyssey_encrypted_payload.dat")
        
        if not os.path.exists(payload_file):
            return None
        
        try:
            with open(payload_file, 'r', encoding='utf-8') as f:
                encrypted_content = f.read()
            
            self.log_activity("🔐 Analyzing encrypted payload...", "CRYPTO")
            
            # Remove virus signature comments if present
            lines = encrypted_content.split('\n')
            payload_content = []
            
            for line in lines:
                if not line.strip().startswith('<!--'):
                    payload_content.append(line)
            
            encrypted_payload = '\n'.join(payload_content).strip()
            
            # Decrypt using ROT13
            decrypted_payload = self.crypto_engine.rot13_decrypt(encrypted_payload)
            
            # Try to parse as JSON
            payload_data = json.loads(decrypted_payload)
            
            self.log_activity("✅ Successfully decrypted virus payload:", "SUCCESS")
            
            # Display key payload information
            if 'virus_identification' in payload_data:
                virus_id = payload_data['virus_identification']
                self.log_activity(f"   Virus Name: {virus_id.get('name', 'Unknown')}")
                self.log_activity(f"   Institution: {virus_id.get('institution', 'Unknown')}")
            
            if 'cryptographic_implementation' in payload_data:
                crypto_info = payload_data['cryptographic_implementation']
                self.log_activity(f"   Encryption: {crypto_info.get('primary_algorithm', 'Unknown')}")
            
            return payload_data
            
        except Exception as e:
            self.log_activity(f"Failed to decrypt payload: {str(e)}", "ERROR")
            return None
    
    def perform_comprehensive_scan(self, directories=None):
        """Perform comprehensive system scan"""
        if directories is None:
            directories = [".", "odyssey_test_environment"]
        
        self.log_activity("🔍 Starting comprehensive Odyssey virus scan...", "INFO")
        scan_start_time = time.time()
        
        all_detections = []
        
        for directory in directories:
            if not os.path.exists(directory):
                continue
                
            self.log_activity(f"📁 Scanning directory: {directory}")
            
            # Scan filename patterns
            pattern_detections = self.scan_filename_patterns(directory)
            all_detections.extend(pattern_detections)
            
            # Scan individual files
            try:
                for root, dirs, files in os.walk(directory):
                    if self.quarantine_dir in root:
                        continue
                        
                    for filename in files:
                        filepath = os.path.join(root, filename)
                        self.scan_statistics['files_scanned'] += 1
                        
                        file_detections = self.scan_file_signatures(filepath)
                        all_detections.extend(file_detections)
                        
            except Exception as e:
                self.log_activity(f"Error scanning files in {directory}: {str(e)}", "ERROR")
            
            # Analyze special files
            marker_data = self.analyze_infection_marker(directory)
            payload_data = self.analyze_encrypted_payload(directory)
        
        # Update statistics
        scan_duration = time.time() - scan_start_time
        self.scan_statistics['scan_duration'] = scan_duration
        self.scan_statistics['threats_detected'] = len(all_detections)
        
        self.log_activity(f"🔍 Scan completed in {scan_duration:.2f} seconds", "SUCCESS")
        self.log_activity(f"📊 Files scanned: {self.scan_statistics['files_scanned']}")
        self.log_activity(f"🚨 Threats detected: {self.scan_statistics['threats_detected']}")
        
        return all_detections

class OdysseyVirusRemover:
    """
    Advanced virus removal and file recovery system
    
    Provides comprehensive removal capabilities:
    - Safe file decryption and recovery
    - Secure quarantine management
    - Original file restoration
    - Artifact cleanup
    """
    
    def __init__(self, scanner):
        self.scanner = scanner
        self.crypto_engine = ROT13CryptographyEngine()
        self.removal_log = []
        self.recovery_statistics = {
            'files_decrypted': 0,
            'files_restored': 0,
            'artifacts_removed': 0,
            'files_quarantined': 0
        }
    
    def log_removal(self, message, level="INFO"):
        """Log removal activity"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        self.removal_log.append(log_entry)
        self.scanner.log_activity(message, level)
    
    def quarantine_file(self, filepath, reason="Virus detected"):
        """Safely quarantine infected file"""
        try:
            filename = os.path.basename(filepath)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            quarantine_name = f"{timestamp}_{filename}"
            quarantine_path = os.path.join(self.scanner.quarantine_dir, quarantine_name)
            
            # Create quarantine metadata
            metadata = {
                "original_path": filepath,
                "quarantine_time": datetime.now().isoformat(),
                "reason": reason,
                "file_hash": self.scanner.calculate_file_hash(filepath),
                "file_size": os.path.getsize(filepath)
            }
            
            # Move file to quarantine
            os.rename(filepath, quarantine_path)
            
            # Save metadata
            metadata_path = quarantine_path + ".metadata.json"
            with open(metadata_path, 'w', encoding='utf-8') as f:
                json.dump(metadata, f, indent=2)
            
            self.recovery_statistics['files_quarantined'] += 1
            self.log_removal(f"🔒 Quarantined: {filename} -> {quarantine_name}", "REMOVAL")
            return True
            
        except Exception as e:
            self.log_removal(f"❌ Failed to quarantine {filepath}: {str(e)}", "ERROR")
            return False
    
    def decrypt_odyssey_file(self, encrypted_file_path, output_path=None):
        """Decrypt Odyssey virus encrypted file"""
        try:
            # Determine output path
            if output_path is None:
                if "_ODYSSEY_ENCRYPTED" in encrypted_file_path:
                    output_path = encrypted_file_path.replace("_ODYSSEY_ENCRYPTED", "_RECOVERED")
                else:
                    name, ext = os.path.splitext(encrypted_file_path)
                    output_path = f"{name}_DECRYPTED{ext}"
            
            # Read encrypted file
            with open(encrypted_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                encrypted_content = f.read()
            
            # Remove virus signatures and comments
            lines = encrypted_content.split('\n')
            clean_content = []
            
            for line in lines:
                # Skip virus signature lines
                if not (line.strip().startswith('<!--') and 'ODYSSEY' in line):
                    clean_content.append(line)
            
            # Remove trailing virus signatures
            while clean_content and clean_content[-1].strip().startswith('<!--'):
                clean_content.pop()
            
            encrypted_text = '\n'.join(clean_content)
            
            # Decrypt using ROT13
            decrypted_content = self.crypto_engine.rot13_decrypt(encrypted_text)
            
            # Write decrypted file
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(decrypted_content)
            
            self.recovery_statistics['files_decrypted'] += 1
            self.log_removal(f"🔐 Decrypted: {os.path.basename(encrypted_file_path)} -> {os.path.basename(output_path)}", "CRYPTO")
            return True
            
        except Exception as e:
            self.log_removal(f"❌ Failed to decrypt {encrypted_file_path}: {str(e)}", "ERROR")
            return False
    
    def process_encryption_manifest(self, directory):
        """Process Odyssey virus encryption manifest"""
        manifest_path = os.path.join(directory, "odyssey_encryption_manifest.json")
        
        if not os.path.exists(manifest_path):
            self.log_removal("📋 No encryption manifest found")
            return 0
        
        try:
            with open(manifest_path, 'r', encoding='utf-8') as f:
                manifest_data = json.load(f)
            
            self.log_removal(f"📋 Processing encryption manifest: {len(manifest_data)} entries")
            
            decrypted_count = 0
            
            for encrypted_filename, file_info in manifest_data.items():
                encrypted_path = os.path.join(directory, encrypted_filename)
                
                if os.path.exists(encrypted_path):
                    # Determine original filename
                    original_filename = file_info.get('original_filename', 'unknown')
                    
                    # Create recovery filename
                    name, ext = os.path.splitext(original_filename)
                    recovery_filename = f"{name}_RECOVERED{ext}"
                    recovery_path = os.path.join(directory, recovery_filename)
                    
                    # Decrypt the file
                    if self.decrypt_odyssey_file(encrypted_path, recovery_path):
                        decrypted_count += 1
                        
                        # Remove the encrypted version
                        try:
                            os.remove(encrypted_path)
                            self.log_removal(f"🗑️ Removed encrypted file: {encrypted_filename}")
                        except Exception as e:
                            self.log_removal(f"⚠️ Could not remove encrypted file {encrypted_filename}: {str(e)}", "WARNING")
            
            # Remove the manifest file
            try:
                os.remove(manifest_path)
                self.log_removal("🗑️ Removed encryption manifest")
            except Exception as e:
                self.log_removal(f"⚠️ Could not remove manifest: {str(e)}", "WARNING")
            
            return decrypted_count
            
        except Exception as e:
            self.log_removal(f"❌ Error processing encryption manifest: {str(e)}", "ERROR")
            return 0
    
    def restore_locked_files(self, directory):
        """Restore files that were temporarily locked by virus"""
        restored_count = 0
        
        try:
            for root, dirs, files in os.walk(directory):
                if self.scanner.quarantine_dir in root:
                    continue
                    
                for filename in files:
                    if filename.startswith("ODYSSEY_LOCKED_"):
                        original_name = filename[15:]  # Remove "ODYSSEY_LOCKED_" prefix
                        original_path = os.path.join(root, original_name)
                        locked_path = os.path.join(root, filename)
                        
                        # Only restore if original doesn't exist
                        if not os.path.exists(original_path):
                            try:
                                os.rename(locked_path, original_path)
                                self.recovery_statistics['files_restored'] += 1
                                self.log_removal(f"🔄 Restored: {filename} -> {original_name}", "SUCCESS")
                                restored_count += 1
                            except Exception as e:
                                self.log_removal(f"❌ Failed to restore {filename}: {str(e)}", "ERROR")
                        else:
                            # Original exists, just remove the locked version
                            try:
                                os.remove(locked_path)
                                self.log_removal(f"🗑️ Removed duplicate locked file: {filename}")
                            except Exception as e:
                                self.log_removal(f"⚠️ Could not remove locked file {filename}: {str(e)}", "WARNING")
                                
        except Exception as e:
            self.log_removal(f"❌ Error during file restoration: {str(e)}", "ERROR")
        
        return restored_count
    
    def clean_virus_artifacts(self, directory):
        """Remove all Odyssey virus artifacts"""
        artifacts_removed = 0
        
        # Known Odyssey virus artifacts
        artifact_patterns = [
            "odyssey_activity.log",
            ".odyssey_infection_marker",
            "odyssey_encrypted_payload.dat",
            "odyssey_encryption_manifest.json",
            "*ODYSSEY_ENCRYPTED*",
            "*ODYSSEY_LOCKED_*"
        ]
        
        try:
            for root, dirs, files in os.walk(directory):
                if self.scanner.quarantine_dir in root:
                    continue
                    
                for filename in files:
                    filepath = os.path.join(root, filename)
                    
                    # Check if file matches virus artifact patterns
                    for pattern in artifact_patterns:
                        if fnmatch.fnmatch(filename, pattern):
                            try:
                                os.remove(filepath)
                                self.recovery_statistics['artifacts_removed'] += 1
                                self.log_removal(f"🗑️ Removed artifact: {filename}", "REMOVAL")
                                artifacts_removed += 1
                            except Exception as e:
                                self.log_removal(f"❌ Failed to remove {filename}: {str(e)}", "ERROR")
                            break
                            
        except Exception as e:
            self.log_removal(f"❌ Error during artifact cleanup: {str(e)}", "ERROR")
        
        return artifacts_removed
    
    def perform_complete_removal(self, target_directory="odyssey_test_environment"):
        """Perform complete Odyssey virus removal and recovery"""
        self.log_removal("🧹 Starting comprehensive Odyssey virus removal...", "REMOVAL")
        
        removal_start_time = time.time()
        
        if not os.path.exists(target_directory):
            self.log_removal(f"⚠️ Target directory not found: {target_directory}", "WARNING")
            return False
        
        # Step 1: Process encryption manifest and decrypt files
        self.log_removal("📋 Step 1: Processing encryption manifest...")
        decrypted_count = self.process_encryption_manifest(target_directory)
        
        # Step 2: Restore locked files
        self.log_removal("🔄 Step 2: Restoring locked files...")
        restored_count = self.restore_locked_files(target_directory)
        
        # Step 3: Clean up virus artifacts
        self.log_removal("🗑️ Step 3: Cleaning virus artifacts...")
        artifacts_removed = self.clean_virus_artifacts(target_directory)
        
        # Calculate removal duration
        removal_duration = time.time() - removal_start_time
        
        # Log summary
        self.log_removal(f"✅ Removal completed in {removal_duration:.2f} seconds", "SUCCESS")
        self.log_removal(f"📊 Files decrypted: {decrypted_count}")
        self.log_removal(f"📊 Files restored: {restored_count}")
        self.log_removal(f"📊 Artifacts removed: {artifacts_removed}")
        
        return True

class EnhancedAntivirusGUI:
    """
    Advanced GUI for the enhanced educational antivirus
    
    Features:
    - Real-time scanning progress
    - Detailed threat analysis
    - Interactive removal options
    - Comprehensive reporting
    """
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Enhanced Educational Antivirus - Odyssey Virus Hunter")
        self.root.geometry("1000x700")
        self.root.configure(bg='#f0f0f0')
        
        self.scanner = AdvancedVirusScanner()
        self.remover = OdysseyVirusRemover(self.scanner)
        self.detections = []
        self.scan_in_progress = False
        
        self.setup_enhanced_gui()
        
    def setup_enhanced_gui(self):
        """Setup enhanced GUI components"""
        # Create main notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Scanner tab
        self.scanner_frame = tk.Frame(self.notebook, bg='#f0f0f0')
        self.notebook.add(self.scanner_frame, text="Virus Scanner")
        self.setup_scanner_tab()
        
        # Results tab
        self.results_frame = tk.Frame(self.notebook, bg='#f0f0f0')
        self.notebook.add(self.results_frame, text="Scan Results")
        self.setup_results_tab()
        
        # Quarantine tab
        self.quarantine_frame = tk.Frame(self.notebook, bg='#f0f0f0')
        self.notebook.add(self.quarantine_frame, text="Quarantine")
        self.setup_quarantine_tab()
        
    def setup_scanner_tab(self):
        """Setup the main scanner interface"""
        # Title
        title_label = tk.Label(self.scanner_frame,
                             text="🛡️ Enhanced Educational Antivirus",
                             font=("Arial", 18, "bold"),
                             bg='#f0f0f0', fg='#333')
        title_label.pack(pady=15)
        
        subtitle_label = tk.Label(self.scanner_frame,
                                text="Odyssey Virus Detection & Removal System",
                                font=("Arial", 12),
                                bg='#f0f0f0', fg='#666')
        subtitle_label.pack(pady=5)
        
        # Control buttons frame
        control_frame = tk.Frame(self.scanner_frame, bg='#f0f0f0')
        control_frame.pack(pady=20)
        
        # Scan button
        self.scan_button = tk.Button(control_frame,
                                   text="🔍 Start Comprehensive Scan",
                                   command=self.start_scan_thread,
                                   bg="#4CAF50", fg="white",
                                   font=("Arial", 12, "bold"),
                                   padx=30, pady=15,
                                   cursor="hand2")
        self.scan_button.pack(side=tk.LEFT, padx=10)
        
        # Quick scan button
        quick_scan_button = tk.Button(control_frame,
                                    text="⚡ Quick Scan",
                                    command=self.quick_scan,
                                    bg="#2196F3", fg="white",
                                    font=("Arial", 10),
                                    padx=20, pady=10,
                                    cursor="hand2")
        quick_scan_button.pack(side=tk.LEFT, padx=10)
        
        # Progress frame
        progress_frame = tk.Frame(self.scanner_frame, bg='#f0f0f0')
        progress_frame.pack(fill=tk.X, padx=20, pady=10)
        
        tk.Label(progress_frame, text="Scan Progress:", bg='#f0f0f0', font=("Arial", 10)).pack(anchor=tk.W)
        
        self.progress_var = tk.StringVar(value="Ready to scan")
        self.progress_label = tk.Label(progress_frame, textvariable=self.progress_var,
                                     bg='#f0f0f0', fg='#666', font=("Arial", 9))
        self.progress_label.pack(anchor=tk.W, pady=5)
        
        self.progress_bar = ttk.Progressbar(progress_frame, mode='indeterminate')
        self.progress_bar.pack(fill=tk.X, pady=5)
        
        # Status frame
        status_frame = tk.Frame(self.scanner_frame, bg='#f0f0f0')
        status_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # Statistics display
        stats_frame = tk.LabelFrame(status_frame, text="Scan Statistics", bg='#f0f0f0', font=("Arial", 10, "bold"))
        stats_frame.pack(fill=tk.X, pady=10)
        
        self.stats_text = tk.Text(stats_frame, height=6, width=80, font=("Courier", 9), bg='#ffffff')
        self.stats_text.pack(padx=10, pady=10)
        
        # Console output
        console_frame = tk.LabelFrame(self.scanner_frame, text="Scanner Console", bg='#f0f0f0', font=("Arial", 10, "bold"))
        console_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        self.console_text = scrolledtext.ScrolledText(console_frame,
                                                    height=15,
                                                    font=("Courier", 9),
                                                    bg='#1e1e1e', fg='#00ff00',
                                                    insertbackground='#00ff00')
        self.console_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
    def setup_results_tab(self):
        """Setup the results analysis tab"""
        # Results header
        header_frame = tk.Frame(self.results_frame, bg='#f0f0f0')
        header_frame.pack(fill=tk.X, padx=20, pady=10)
        
        tk.Label(header_frame, text="🚨 Threat Detection Results",
                font=("Arial", 14, "bold"), bg='#f0f0f0').pack(anchor=tk.W)
        
        # Action buttons
        action_frame = tk.Frame(self.results_frame, bg='#f0f0f0')
        action_frame.pack(fill=tk.X, padx=20, pady=10)
        
        self.remove_button = tk.Button(action_frame,
                                     text="🧹 Remove All Threats",
                                     command=self.remove_threats,
                                     bg="#f44336", fg="white",
                                     font=("Arial", 11, "bold"),
                                     padx=20, pady=10,
                                     cursor="hand2")
        self.remove_button.pack(side=tk.LEFT, padx=5)
        
        self.quarantine_button = tk.Button(action_frame,
                                         text="🔒 Quarantine Threats",
                                         command=self.quarantine_threats,
                                         bg="#FF9800", fg="white",
                                         font=("Arial", 11),
                                         padx=20, pady=10,
                                         cursor="hand2")
        self.quarantine_button.pack(side=tk.LEFT, padx=5)
        
        # Results display
        self.results_text = scrolledtext.ScrolledText(self.results_frame,
                                                    height=25,
                                                    font=("Courier", 10),
                                                    bg='#ffffff')
        self.results_text.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
    def setup_quarantine_tab(self):
        """Setup the quarantine management tab"""
        # Quarantine header
        header_frame = tk.Frame(self.quarantine_frame, bg='#f0f0f0')
        header_frame.pack(fill=tk.X, padx=20, pady=10)
        
        tk.Label(header_frame, text="🔒 Quarantine Management",
                font=("Arial", 14, "bold"), bg='#f0f0f0').pack(anchor=tk.W)
        
        # Quarantine info
        self.quarantine_text = scrolledtext.ScrolledText(self.quarantine_frame,
                                                       height=20,
                                                       font=("Courier", 10),
                                                       bg='#ffffff')
        self.quarantine_text.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Update quarantine info
        self.update_quarantine_info()
        
    def log_to_console(self, message):
        """Log message to GUI console"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] {message}\n"
        
        self.console_text.insert(tk.END, formatted_message)
        self.console_text.see(tk.END)
        self.root.update()
        
    def update_progress(self, message):
        """Update progress display"""
        self.progress_var.set(message)
        self.root.update()
        
    def start_scan_thread(self):
        """Start scan in separate thread to prevent GUI freezing"""
        if self.scan_in_progress:
            return
            
        self.scan_in_progress = True
        self.scan_button.config(state=tk.DISABLED, text="🔍 Scanning...")
        self.progress_bar.start()
        
        # Start scan in separate thread
        scan_thread = threading.Thread(target=self.perform_scan)
        scan_thread.daemon = True
        scan_thread.start()
        
    def perform_scan(self):
        """Perform the actual scan"""
        try:
            self.console_text.delete(1.0, tk.END)
            self.log_to_console("🛡️ Enhanced Educational Antivirus Scanner Starting...")
            
            # Initialize quarantine
            self.update_progress("Initializing quarantine system...")
            self.scanner.initialize_quarantine_system()
            
            # Override scanner's log_activity to also log to GUI
            original_log = self.scanner.log_activity
            
            def gui_log(message, level="INFO"):
                original_log(message, level)
                self.log_to_console(message)
                
            self.scanner.log_activity = gui_log
            
            # Perform scan
            self.update_progress("Scanning for Odyssey virus...")
            self.detections = self.scanner.perform_comprehensive_scan()
            
            # Update results tab
            self.update_results_display()
            
            # Update statistics
            self.update_statistics_display()
            
            self.log_to_console(f"\n✅ Scan completed: {len(self.detections)} threats detected")
            
        except Exception as e:
            self.log_to_console(f"❌ Scan error: {str(e)}")
            
        finally:
            # Reset UI
            self.scan_in_progress = False
            self.scan_button.config(state=tk.NORMAL, text="🔍 Start Comprehensive Scan")
            self.progress_bar.stop()
            self.update_progress("Scan completed")
            
    def quick_scan(self):
        """Perform quick scan of current directory only"""
        self.log_to_console("⚡ Starting quick scan...")
        self.detections = self.scanner.perform_comprehensive_scan(["."])
        self.update_results_display()
        self.log_to_console(f"✅ Quick scan completed: {len(self.detections)} threats detected")
        
    def update_results_display(self):
        """Update the results tab with detection information"""
        self.results_text.delete(1.0, tk.END)
        
        if not self.detections:
            self.results_text.insert(tk.END, "✅ No threats detected. System appears clean.\n")
            return
            
        self.results_text.insert(tk.END, f"🚨 THREAT DETECTION REPORT\n")
        self.results_text.insert(tk.END, f"=" * 50 + "\n")
        self.results_text.insert(tk.END, f"Total threats detected: {len(self.detections)}\n")
        self.results_text.insert(tk.END, f"Scan time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        for i, detection in enumerate(self.detections, 1):
            self.results_text.insert(tk.END, f"--- THREAT #{i} ---\n")
            self.results_text.insert(tk.END, f"Type: {detection['type']}\n")
            self.results_text.insert(tk.END, f"File: {detection['file']}\n")
            self.results_text.insert(tk.END, f"Confidence: {detection.get('confidence', 'MEDIUM')}\n")
            
            if 'virus_info' in detection:
                info = detection['virus_info']
                self.results_text.insert(tk.END, f"Virus: {info['name']}\n")
                self.results_text.insert(tk.END, f"Risk Level: {info['risk_level']}\n")
                
            if 'description' in detection:
                self.results_text.insert(tk.END, f"Description: {detection['description']}\n")
                
            self.results_text.insert(tk.END, f"Detection Time: {detection.get('detection_time', 'Unknown')}\n")
            self.results_text.insert(tk.END, "\n")
            
    def update_statistics_display(self):
        """Update scan statistics display"""
        stats = self.scanner.scan_statistics
        
        stats_text = f"""
Files Scanned:      {stats['files_scanned']}
Threats Detected:   {stats['threats_detected']}
Scan Duration:      {stats['scan_duration']:.2f} seconds
Files Quarantined:  {stats.get('files_quarantined', 0)}
Files Cleaned:      {stats.get('files_cleaned', 0)}
Last Scan:          {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
        
        self.stats_text.delete(1.0, tk.END)
        self.stats_text.insert(tk.END, stats_text.strip())
        
    def remove_threats(self):
        """Remove all detected threats"""
        if not self.detections:
            messagebox.showinfo("No Threats", "No threats detected to remove.")
            return
            
        result = messagebox.askyesno("Confirm Removal",
                                   f"Remove {len(self.detections)} detected threats?\n\n"
                                   f"This will decrypt encrypted files and clean virus artifacts.")
        if not result:
            return
            
        # Switch to scanner tab to show progress
        self.notebook.select(0)
        
        self.log_to_console("\n🧹 Starting threat removal process...")
        
        # Override remover's log to also log to GUI
        original_log = self.remover.log_removal
        
        def gui_removal_log(message, level="INFO"):
            original_log(message, level)
            self.log_to_console(message)
            
        self.remover.log_removal = gui_removal_log
        
        # Perform removal
        success = self.remover.perform_complete_removal()
        
        if success:
            self.log_to_console("\n✅ Threat removal completed successfully!")
            
            # Update statistics
            recovery_stats = self.remover.recovery_statistics
            self.log_to_console(f"\n📊 Recovery Statistics:")
            self.log_to_console(f"   Files Decrypted: {recovery_stats['files_decrypted']}")
            self.log_to_console(f"   Files Restored: {recovery_stats['files_restored']}")
            self.log_to_console(f"   Artifacts Removed: {recovery_stats['artifacts_removed']}")
            
            # Clear detections
            self.detections = []
            self.update_results_display()
            
            messagebox.showinfo("Removal Complete",
                              "All threats have been successfully removed!\n\n"
                              f"Files decrypted: {recovery_stats['files_decrypted']}\n"
                              f"Files restored: {recovery_stats['files_restored']}\n"
                              f"Artifacts removed: {recovery_stats['artifacts_removed']}")
        else:
            messagebox.showerror("Removal Failed", "Threat removal process encountered errors.")
            
    def quarantine_threats(self):
        """Quarantine detected threats instead of removing them"""
        if not self.detections:
            messagebox.showinfo("No Threats", "No threats detected to quarantine.")
            return
            
        result = messagebox.askyesno("Confirm Quarantine",
                                   f"Quarantine {len(self.detections)} detected threats?")
        if not result:
            return
            
        quarantined_count = 0
        
        for detection in self.detections:
            filepath = detection['file']
            if os.path.exists(filepath):
                if self.remover.quarantine_file(filepath, f"Threat: {detection['type']}"):
                    quarantined_count += 1
                    
        self.log_to_console(f"🔒 Quarantined {quarantined_count} files")
        self.update_quarantine_info()
        
        messagebox.showinfo("Quarantine Complete",
                          f"Successfully quarantined {quarantined_count} threats.")
                          
    def update_quarantine_info(self):
        """Update quarantine information display"""
        self.quarantine_text.delete(1.0, tk.END)
        
        quarantine_dir = self.scanner.quarantine_dir
        
        if not os.path.exists(quarantine_dir):
            self.quarantine_text.insert(tk.END, "📁 Quarantine directory not initialized.\n")
            return
            
        self.quarantine_text.insert(tk.END, f"📁 Quarantine Directory: {quarantine_dir}\n")
        self.quarantine_text.insert(tk.END, "=" * 50 + "\n\n")
        
        try:
            files = os.listdir(quarantine_dir)
            quarantined_files = [f for f in files if not f.endswith('.metadata.json') and f != 'quarantine_info.json']
            
            self.quarantine_text.insert(tk.END, f"Total quarantined files: {len(quarantined_files)}\n\n")
            
            for filename in quarantined_files:
                filepath = os.path.join(quarantine_dir, filename)
                metadata_path = filepath + ".metadata.json"
                
                self.quarantine_text.insert(tk.END, f"File: {filename}\n")
                
                if os.path.exists(metadata_path):
                    try:
                        with open(metadata_path, 'r', encoding='utf-8') as f:
                            metadata = json.load(f)
                            
                        self.quarantine_text.insert(tk.END, f"  Original: {metadata.get('original_path', 'Unknown')}\n")
                        self.quarantine_text.insert(tk.END, f"  Quarantined: {metadata.get('quarantine_time', 'Unknown')}\n")
                        self.quarantine_text.insert(tk.END, f"  Reason: {metadata.get('reason', 'Unknown')}\n")
                        self.quarantine_text.insert(tk.END, f"  Size: {metadata.get('file_size', 'Unknown')} bytes\n")
                        
                    except Exception as e:
                        self.quarantine_text.insert(tk.END, f"  Error reading metadata: {str(e)}\n")
                        
                self.quarantine_text.insert(tk.END, "\n")
                
        except Exception as e:
            self.quarantine_text.insert(tk.END, f"Error reading quarantine directory: {str(e)}\n")
            
    def run(self):
        """Start the enhanced GUI"""
        self.root.mainloop()

class CommandLineInterface:
    """Enhanced command-line interface"""
    
    def __init__(self):
        self.scanner = AdvancedVirusScanner()
        self.remover = OdysseyVirusRemover(self.scanner)
        
    def display_banner(self):
        """Display application banner"""
        banner = """
🛡️  ENHANCED EDUCATIONAL ANTIVIRUS
═══════════════════════════════════════════════
    Odyssey Virus Detection & Removal System
    National Teachers College - Cybersecurity Project
═══════════════════════════════════════════════

🎯 Target: Odyssey Educational Virus (ROT13)
🔐 Encryption: ROT13 Decryption Engine
🧹 Features: Advanced Detection & Removal
📊 Reporting: Comprehensive Analysis

"""
        print(banner)
        
    def run_interactive_scan(self):
        """Run interactive command-line scan"""
        self.display_banner()
        
        print("🔍 Initializing Enhanced Antivirus Scanner...")
        
        # Initialize quarantine
        self.scanner.initialize_quarantine_system()
        
        while True:
            print("\n" + "="*50)
            print("Select an option:")
            print("1. 🔍 Comprehensive System Scan")
            print("2. ⚡ Quick Scan (Current Directory)")
            print("3. 🧹 Remove Detected Threats")
            print("4. 🔒 View Quarantine")
            print("5. 📊 View Statistics")
            print("6. 🚪 Exit")
            
            choice = input("\nEnter your choice (1-6): ").strip()
            
            if choice == '1':
                self.perform_comprehensive_scan()
            elif choice == '2':
                self.perform_quick_scan()
            elif choice == '3':
                self.perform_removal()
            elif choice == '4':
                self.view_quarantine()
            elif choice == '5':
                self.view_statistics()
            elif choice == '6':
                print("\n👋 Thank you for using Enhanced Educational Antivirus!")
                break
            else:
                print("❌ Invalid choice. Please try again.")
                
    def perform_comprehensive_scan(self):
        """Perform comprehensive scan"""
        print("\n🔍 Starting comprehensive Odyssey virus scan...")
        detections = self.scanner.perform_comprehensive_scan()
        self.display_scan_results(detections)
        
    def perform_quick_scan(self):
        """Perform quick scan"""
        print("\n⚡ Starting quick scan...")
        detections = self.scanner.perform_comprehensive_scan(["."])
        self.display_scan_results(detections)
        
    def display_scan_results(self, detections):
        """Display scan results"""
        print(f"\n📊 SCAN RESULTS")
        print("="*40)
        print(f"Threats detected: {len(detections)}")
        
        if detections:
            print("\n🚨 DETECTED THREATS:")
            for i, detection in enumerate(detections, 1):
                print(f"\n{i}. {detection['type'].upper()}")
                print(f"   File: {detection['file']}")
                print(f"   Confidence: {detection.get('confidence', 'MEDIUM')}")
                
                if 'virus_info' in detection:
                    info = detection['virus_info']
                    print(f"   Virus: {info['name']}")
                    print(f"   Risk: {info['risk_level']}")
        else:
            print("\n✅ No threats detected. System appears clean!")
            
    def perform_removal(self):
        """Perform threat removal"""
        print("\n🧹 Starting threat removal process...")
        
        target_dir = "odyssey_test_environment"
        if not os.path.exists(target_dir):
            print(f"⚠️ Target directory '{target_dir}' not found.")
            return
            
        success = self.remover.perform_complete_removal(target_dir)
        
        if success:
            print("\n✅ Threat removal completed successfully!")
            stats = self.remover.recovery_statistics
            print(f"\n📊 Recovery Statistics:")
            print(f"   Files Decrypted: {stats['files_decrypted']}")
            print(f"   Files Restored: {stats['files_restored']}")
            print(f"   Artifacts Removed: {stats['artifacts_removed']}")
        else:
            print("\n❌ Threat removal encountered errors.")
            
    def view_quarantine(self):
        """View quarantine information"""
        print(f"\n🔒 QUARANTINE INFORMATION")
        print("="*40)
        
        quarantine_dir = self.scanner.quarantine_dir
        
        if not os.path.exists(quarantine_dir):
            print("📁 Quarantine directory not initialized.")
            return
            
        try:
            files = os.listdir(quarantine_dir)
            quarantined_files = [f for f in files if not f.endswith('.metadata.json') and f != 'quarantine_info.json']
            
            print(f"Directory: {quarantine_dir}")
            print(f"Quarantined files: {len(quarantined_files)}")
            
            if quarantined_files:
                print("\nQuarantined Files:")
                for filename in quarantined_files[:10]:  # Show first 10
                    print(f"  📁 {filename}")
                    
                if len(quarantined_files) > 10:
                    print(f"  ... and {len(quarantined_files) - 10} more files")
                    
        except Exception as e:
            print(f"❌ Error reading quarantine: {str(e)}")
            
    def view_statistics(self):
        """View scan statistics"""
        print(f"\n📊 ANTIVIRUS STATISTICS")
        print("="*40)
        
        stats = self.scanner.scan_statistics
        recovery_stats = self.remover.recovery_statistics
        
        print(f"Scan Statistics:")
        print(f"  Files Scanned: {stats['files_scanned']}")
        print(f"  Threats Detected: {stats['threats_detected']}")
        print(f"  Last Scan Duration: {stats['scan_duration']:.2f} seconds")
        
        print(f"\nRecovery Statistics:")
        print(f"  Files Decrypted: {recovery_stats['files_decrypted']}")
        print(f"  Files Restored: {recovery_stats['files_restored']}")
        print(f"  Artifacts Removed: {recovery_stats['artifacts_removed']}")
        print(f"  Files Quarantined: {recovery_stats['files_quarantined']}")

def main():
    """Main entry point for Enhanced Educational Antivirus"""
    print("🎓 Enhanced Educational Antivirus - Initializing...")
    
    # Check for GUI availability
    try:
        # Test if GUI is available
        test_root = tk.Tk()
        test_root.withdraw()
        test_root.destroy()
        
        # GUI available - ask user preference
        print("\nGUI available. Choose interface:")
        print("1. 🖥️ Graphical Interface (Recommended)")
        print("2. 💻 Command Line Interface")
        
        while True:
            choice = input("\nEnter choice (1 or 2): ").strip()
            
            if choice == '1':
                print("🖥️ Starting GUI mode...")
                antivirus = EnhancedAntivirusGUI()
                antivirus.run()
                break
            elif choice == '2':
                print("💻 Starting CLI mode...")
                cli = CommandLineInterface()
                cli.run_interactive_scan()
                break
            else:
                print("❌ Invalid choice. Please enter 1 or 2.")
                
    except Exception as e:
        # GUI not available, use CLI
        print("🖥️ GUI not available, using command line interface...")
        cli = CommandLineInterface()
        cli.run_interactive_scan()

if __name__ == "__main__":
    main()