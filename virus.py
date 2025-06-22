#!/usr/bin/env python3
"""
Odyssey Educational Virus - Academic Cybersecurity Project
National Teachers College - ROT13 Cryptographic Implementation

DISCLAIMER: This code is for educational purposes only.
Must be executed in virtual machine or isolated sandbox environment.
DO NOT execute on production systems or distribute maliciously.

Author: Academic Cybersecurity Project
Institution: National Teachers College
Date: June 2025
Encryption: ROT13 Algorithm Only

EDUCATIONAL OBJECTIVES:
- Demonstrate malware behavior simulation
- Showcase ROT13 cryptographic implementation
- Provide hands-on cybersecurity learning experience
- Enable antivirus development and testing

SAFETY FEATURES:
- Virtual machine detection
- Educational consent verification
- Non-destructive file operations
- Comprehensive activity logging
"""

import os
import sys
import time
import json
import shutil
import hashlib
import platform
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import messagebox

class ROT13Cryptography:
    """
    ROT13 Cryptographic Implementation
    
    ROT13 is a simple letter substitution cipher that replaces each letter
    with the letter 13 positions after it in the alphabet. It's a special
    case of the Caesar cipher with a fixed shift of 13.
    
    Key Properties:
    - Self-inverse: applying ROT13 twice returns original text
    - Only affects alphabetic characters
    - Preserves case and non-alphabetic characters
    - Historically used in online forums for spoiler protection
    """
    
    @staticmethod
    def rot13_transform(text):
        """
        Apply ROT13 transformation to input text
        
        Args:
            text (str): Input text to transform
            
        Returns:
            str: ROT13 transformed text
            
        Algorithm Details:
        - For each character in input text:
          - If alphabetic: shift by 13 positions in alphabet
          - If uppercase: maintain uppercase (A-Z range)
          - If lowercase: maintain lowercase (a-z range)
          - If non-alphabetic: preserve unchanged
        """
        result = []
        
        for char in text:
            if char.isalpha():
                # Determine if uppercase or lowercase
                is_upper = char.isupper()
                
                # Convert to uppercase for uniform processing
                char = char.upper()
                
                # Apply ROT13 transformation
                # ASCII 'A' = 65, so we normalize to 0-25 range
                transformed_char = chr(((ord(char) - ord('A') + 13) % 26) + ord('A'))
                
                # Restore original case
                if not is_upper:
                    transformed_char = transformed_char.lower()
                    
                result.append(transformed_char)
            else:
                # Non-alphabetic characters remain unchanged
                result.append(char)
        
        return ''.join(result)
    
    @staticmethod
    def rot13_encrypt(plaintext):
        """
        Encrypt plaintext using ROT13
        
        Args:
            plaintext (str): Text to encrypt
            
        Returns:
            str: ROT13 encrypted text
        """
        return ROT13Cryptography.rot13_transform(plaintext)
    
    @staticmethod
    def rot13_decrypt(ciphertext):
        """
        Decrypt ROT13 ciphertext
        
        Args:
            ciphertext (str): ROT13 encrypted text
            
        Returns:
            str: Decrypted plaintext
            
        Note: ROT13 is self-inverse, so decryption is identical to encryption
        """
        return ROT13Cryptography.rot13_transform(ciphertext)

class SecurityValidator:
    """
    Educational Safety and Security Validation System
    
    Implements multiple safety checks to ensure responsible use:
    - Virtual machine environment detection
    - Educational consent verification
    - Academic context validation
    """
    
    @staticmethod
    def detect_virtual_environment():
        """
        Detect if code is running in virtual machine environment
        
        Returns:
            bool: True if VM detected, False otherwise
            
        Detection Methods:
        1. System platform analysis for VM indicators
        2. File system checks for VM-specific directories
        3. Hardware fingerprint analysis
        """
        # Common VM indicators in platform information
        vm_indicators = [
            'vmware', 'virtualbox', 'vbox', 'qemu', 'xen',
            'hyper-v', 'parallels', 'kvm', 'bochs'
        ]
        
        system_info = platform.platform().lower()
        for indicator in vm_indicators:
            if indicator in system_info:
                return True
        
        # Check for VM-specific file system artifacts
        vm_file_indicators = [
            '/proc/vz',                          # OpenVZ
            '/proc/xen',                         # Xen
            '/sys/bus/vmbus',                    # Hyper-V
            'C:\\Program Files\\VMware',         # VMware Windows
            'C:\\Program Files\\Oracle\\VirtualBox',  # VirtualBox Windows
            '/usr/bin/VBoxService',              # VirtualBox Linux
            '/usr/sbin/vboxguest-service'        # VirtualBox Linux
        ]
        
        for path in vm_file_indicators:
            if os.path.exists(path):
                return True
        
        return False
    
    @staticmethod
    def request_educational_consent():
        """
        Display educational consent dialog and verify user agreement
        
        Returns:
            bool: True if consent granted, False otherwise
        """
        try:
            root = tk.Tk()
            root.withdraw()
            
            consent_message = """
═══════════════════════════════════════════════════
    ODYSSEY EDUCATIONAL VIRUS - ACADEMIC PROJECT
═══════════════════════════════════════════════════

INSTITUTIONAL CONTEXT:
• National Teachers College Cybersecurity Exercise
• Academic Research and Learning Purposes Only
• Supervised Educational Environment Required

SAFETY CONFIRMATION REQUIRED:
✓ I confirm this is for academic purposes only
✓ I am running this in a virtual machine environment  
✓ I understand this is educational malware simulation
✓ I will not distribute or misuse this program
✓ I accept responsibility for ethical usage

TECHNICAL IMPLEMENTATION:
• ROT13 cryptographic algorithm demonstration
• Non-destructive file operation simulation
• Antivirus development and testing framework

Do you provide consent to proceed with this educational exercise?
            """
            
            result = messagebox.askyesno("Educational Consent - Odyssey Virus", consent_message)
            root.destroy()
            return result
            
        except Exception as e:
            # Fallback to console-based consent if GUI unavailable
            print(consent_message)
            response = input("\nType 'CONSENT' to proceed with educational exercise: ").strip().upper()
            return response == 'CONSENT'

class OdysseyEducationalVirus:
    """
    Odyssey Educational Virus Implementation
    
    A comprehensive educational malware simulation designed for cybersecurity
    learning. Implements non-destructive behaviors typical of real malware
    while maintaining safety through multiple protection mechanisms.
    
    BEHAVIORAL FEATURES:
    - File duplication with ROT13 encryption
    - Educational popup message display
    - System activity logging
    - Encrypted payload generation
    - Temporary file manipulation
    - Infection marker placement
    
    CRYPTOGRAPHIC IMPLEMENTATION:
    - ROT13 algorithm for all encryption operations
    - Demonstrates classical cryptographic techniques
    - Provides foundation for antivirus development
    
    SAFETY MECHANISMS:
    - Virtual machine environment verification
    - Educational consent requirement
    - Non-destructive operation guarantee
    - Comprehensive activity logging
    """
    
    def __init__(self):
        """Initialize Odyssey virus with configuration parameters"""
        
        # Virus identification and signature
        self.virus_signature = "ODYSSEY_VIRUS_2025_NTC"
        self.virus_version = "1.0_EDUCATIONAL_ROT13"
        self.institution = "National Teachers College"
        
        # Cryptographic engine
        self.crypto_engine = ROT13Cryptography()
        
        # File system configuration
        self.target_directory = "odyssey_test_environment"
        self.log_file = "odyssey_activity.log"
        self.marker_file = ".odyssey_infection_marker"
        self.payload_file = "odyssey_encrypted_payload.dat"
        self.encryption_log_file = "odyssey_encryption_manifest.json"
        
        # Educational messages (encrypted with ROT13)
        self.encrypted_educational_messages = [
            "Bqlffrk Rqhpngvbany Ivehhf - Plorefrphevgl Yrneavat Cebwrpg",
            "EBG13 Rapekcgvba Qrzbafgengvba - Npnqrzvp Checbfrf Bayl",
            "Angvbany Grnpuref Pbyyrtr - Uloefrphevgl Rkrepvfr"
        ]
        
        # Execution statistics
        self.execution_start_time = None
        self.files_processed = 0
        self.encryption_operations = 0
        
    def initialize_logging_system(self):
        """
        Initialize comprehensive activity logging system
        
        Creates timestamped log entries for all virus activities,
        enabling detailed forensic analysis and educational review.
        """
        self.execution_start_time = datetime.now()
        
        log_header = f"""
═══════════════════════════════════════════════════════════════════
ODYSSEY EDUCATIONAL VIRUS - ACTIVITY LOG
═══════════════════════════════════════════════════════════════════
Virus Signature: {self.virus_signature}
Version: {self.virus_version}
Institution: {self.institution}
Execution Started: {self.execution_start_time.strftime('%Y-%m-%d %H:%M:%S')}
Encryption Algorithm: ROT13
Target Environment: {self.target_directory}
═══════════════════════════════════════════════════════════════════

"""
        
        # FIX: Added encoding='utf-8' to handle Unicode characters
        with open(self.log_file, 'w', encoding='utf-8') as log:
            log.write(log_header)
            
        self.log_activity("Odyssey virus logging system initialized")
    
    def log_activity(self, activity_description, category="INFO"):
        """
        Log virus activity with timestamp and categorization
        
        Args:
            activity_description (str): Description of the activity
            category (str): Activity category (INFO, WARNING, ERROR, CRYPTO)
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{category}] {activity_description}\n"
        
        # FIX: Added encoding='utf-8' to handle Unicode characters
        with open(self.log_file, 'a', encoding='utf-8') as log:
            log.write(log_entry)
        
        # Display to console with appropriate formatting
        if category == "ERROR":
            print(f"❌ {activity_description}")
        elif category == "WARNING":
            print(f"⚠️  {activity_description}")
        elif category == "CRYPTO":
            print(f"🔐 {activity_description}")
        else:
            print(f"📝 {activity_description}")
    
    def create_educational_test_environment(self):
        """
        Create isolated test environment with sample files
        
        Generates a controlled directory structure with various file types
        for demonstrating virus behavior without affecting system files.
        """
        self.log_activity("Creating educational test environment", "INFO")
        
        if not os.path.exists(self.target_directory):
            os.makedirs(self.target_directory)
            self.log_activity(f"Created target directory: {self.target_directory}")
        
        # Sample educational files for demonstration
        test_files_config = [
            {
                "filename": "student_notes.txt",
                "content": "Educational cybersecurity notes\nMalware analysis techniques\nAntivirus development principles"
            },
            {
                "filename": "research_data.csv", 
                "content": "Student,Grade,Project\nAlice,95,Antivirus\nBob,87,Cryptography\nCharlie,92,Network Security"
            },
            {
                "filename": "assignment_instructions.md",
                "content": "# Cybersecurity Assignment\n\n## Objectives\n- Understand malware behavior\n- Develop antivirus tools\n- Apply cryptographic techniques"
            },
            {
                "filename": "lab_report.doc",
                "content": "Cybersecurity Lab Report\nROT13 Encryption Analysis\nMalware Behavioral Study\nAntivirus Development Progress"
            }
        ]
        
        for file_config in test_files_config:
            file_path = os.path.join(self.target_directory, file_config["filename"])
            
            if not os.path.exists(file_path):
                # FIX: Added encoding='utf-8' to handle Unicode characters
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(file_config["content"])
                    f.write(f"\n\nFile created: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                    f.write(f"\nEducational context: National Teachers College")
                    f.write(f"\nProject: Odyssey Virus Simulation")
                
                self.log_activity(f"Created educational file: {file_config['filename']}")
        
        self.log_activity("Educational test environment setup completed")
    
    def perform_file_encryption_simulation(self):
        """
        Simulate file encryption using ROT13 algorithm
        
        Creates encrypted copies of target files while preserving originals
        for educational demonstration of malware encryption behaviors.
        """
        self.log_activity("Initiating file encryption simulation", "CRYPTO")
        
        if not os.path.exists(self.target_directory):
            self.create_educational_test_environment()
        
        encryption_manifest = {}
        processed_files = []
        
        for filename in os.listdir(self.target_directory):
            file_path = os.path.join(self.target_directory, filename)
            
            # Skip directories and special files
            if not os.path.isfile(file_path) or filename.startswith('.'):
                continue
                
            # Skip already encrypted files and system files
            if "ODYSSEY_ENCRYPTED" in filename or filename in [self.log_file, self.marker_file, self.payload_file]:
                continue
            
            try:
                # FIX: Added encoding='utf-8' and error handling for file reading
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    original_content = f.read()
                
                # Apply ROT13 encryption
                encrypted_content = self.crypto_engine.rot13_encrypt(original_content)
                
                # Generate encrypted filename
                name, extension = os.path.splitext(filename)
                encrypted_filename = f"{name}_ODYSSEY_ENCRYPTED{extension}"
                encrypted_file_path = os.path.join(self.target_directory, encrypted_filename)
                
                # FIX: Added encoding='utf-8' to handle Unicode characters
                with open(encrypted_file_path, 'w', encoding='utf-8') as f:
                    f.write(encrypted_content)
                    f.write(f"\n\n<!-- {self.virus_signature} -->")
                    f.write(f"\n<!-- Encryption: ROT13 -->")
                    f.write(f"\n<!-- Original: {filename} -->")
                    f.write(f"\n<!-- Timestamp: {datetime.now().isoformat()} -->")
                
                # Update encryption manifest
                encryption_manifest[encrypted_filename] = {
                    "original_filename": filename,
                    "encryption_algorithm": "ROT13",
                    "encryption_timestamp": datetime.now().isoformat(),
                    "file_size_original": os.path.getsize(file_path),
                    "file_size_encrypted": os.path.getsize(encrypted_file_path),
                    "virus_signature": self.virus_signature
                }
                
                processed_files.append(filename)
                self.files_processed += 1
                self.encryption_operations += 1
                
                self.log_activity(f"Encrypted file: {filename} -> {encrypted_filename}", "CRYPTO")
                
            except Exception as e:
                self.log_activity(f"Failed to encrypt {filename}: {str(e)}", "ERROR")
        
        # Save encryption manifest for antivirus analysis
        manifest_path = os.path.join(self.target_directory, self.encryption_log_file)
        # FIX: Added encoding='utf-8' to handle Unicode characters
        with open(manifest_path, 'w', encoding='utf-8') as f:
            json.dump(encryption_manifest, f, indent=2)
        
        self.log_activity(f"Encryption manifest saved: {len(encryption_manifest)} entries", "CRYPTO")
        self.log_activity(f"File encryption simulation completed: {len(processed_files)} files processed")
    
    def display_educational_messages(self):
        """
        Display educational popup messages with ROT13 decryption demonstration
        
        Shows encrypted messages and their decrypted versions to demonstrate
        the ROT13 algorithm in action for educational purposes.
        """
        self.log_activity("Displaying educational popup messages")
        
        try:
            root = tk.Tk()
            root.withdraw()
            
            for i, encrypted_message in enumerate(self.encrypted_educational_messages, 1):
                # Decrypt the message for display
                decrypted_message = self.crypto_engine.rot13_decrypt(encrypted_message)
                
                # Create educational dialog
                dialog_content = f"""
Odyssey Educational Virus - Message {i}

ENCRYPTED (ROT13): {encrypted_message}

DECRYPTED: {decrypted_message}

This demonstrates ROT13 encryption/decryption for educational purposes.
"""
                
                messagebox.showinfo(f"Odyssey Educational Message {i}", dialog_content)
                self.log_activity(f"Displayed educational message {i}: {decrypted_message}")
                time.sleep(1)
            
            root.destroy()
            
        except Exception as e:
            # Fallback to console display if GUI unavailable
            self.log_activity("GUI unavailable, using console display", "WARNING")
            
            for i, encrypted_message in enumerate(self.encrypted_educational_messages, 1):
                decrypted_message = self.crypto_engine.rot13_decrypt(encrypted_message)
                
                print(f"\n═══ ODYSSEY MESSAGE {i} ═══")
                print(f"ENCRYPTED: {encrypted_message}")
                print(f"DECRYPTED: {decrypted_message}")
                print("═" * 40)
                
                self.log_activity(f"Console message {i}: {decrypted_message}")
                time.sleep(2)
    
    def generate_encrypted_payload(self):
        """
        Generate encrypted virus payload for antivirus analysis
        
        Creates a comprehensive encrypted payload containing virus metadata,
        configuration, and behavioral information for educational analysis.
        """
        self.log_activity("Generating encrypted virus payload", "CRYPTO")
        
        # Comprehensive payload data
        payload_data = {
            "virus_identification": {
                "name": "Odyssey Educational Virus",
                "signature": self.virus_signature,
                "version": self.virus_version,
                "institution": self.institution
            },
            "cryptographic_implementation": {
                "primary_algorithm": "ROT13",
                "algorithm_type": "Substitution Cipher",
                "key_rotation": 13,
                "self_inverse": True
            },
            "execution_metadata": {
                "creation_timestamp": datetime.now().isoformat(),
                "target_environment": self.target_directory,
                "files_processed": self.files_processed,
                "encryption_operations": self.encryption_operations
            },
            "educational_context": {
                "project_type": "Academic Cybersecurity Exercise",
                "learning_objectives": [
                    "Malware behavior analysis",
                    "ROT13 cryptographic implementation", 
                    "Antivirus development",
                    "Ethical cybersecurity research"
                ],
                "safety_measures": [
                    "Virtual machine requirement",
                    "Educational consent verification",
                    "Non-destructive operations",
                    "Comprehensive logging"
                ]
            },
            "antivirus_hints": {
                "detection_patterns": [
                    "*ODYSSEY_ENCRYPTED*",
                    self.virus_signature,
                    "ROT13 encrypted content",
                    ".odyssey_infection_marker"
                ],
                "decryption_algorithm": "ROT13",
                "removal_strategy": "Decrypt and restore original files"
            }
        }
        
        # Convert to JSON and encrypt with ROT13
        payload_json = json.dumps(payload_data, indent=2)
        encrypted_payload = self.crypto_engine.rot13_encrypt(payload_json)
        
        # Save encrypted payload
        payload_path = os.path.join(self.target_directory, self.payload_file)
        # FIX: Added encoding='utf-8' to handle Unicode characters
        with open(payload_path, 'w', encoding='utf-8') as f:
            f.write(encrypted_payload)
            f.write(f"\n\n<!-- {self.virus_signature} -->")
            f.write(f"\n<!-- Payload encrypted with ROT13 -->")
        
        self.log_activity(f"Encrypted payload generated: {self.payload_file}", "CRYPTO")
    
    def simulate_file_manipulation(self):
        """
        Simulate temporary file manipulation behaviors
        
        Demonstrates malware file system manipulation techniques
        through temporary file renaming and restoration.
        """
        self.log_activity("Simulating file manipulation behaviors")
        
        manipulation_targets = []
        
        # Identify text files for manipulation
        for filename in os.listdir(self.target_directory):
            if filename.endswith('.txt') and not filename.startswith('ODYSSEY_'):
                file_path = os.path.join(self.target_directory, filename)
                locked_filename = f"ODYSSEY_LOCKED_{filename}"
                locked_path = os.path.join(self.target_directory, locked_filename)
                
                try:
                    os.rename(file_path, locked_path)
                    manipulation_targets.append((locked_path, file_path))
                    self.log_activity(f"Temporarily locked file: {filename}")
                except Exception as e:
                    self.log_activity(f"Failed to lock {filename}: {str(e)}", "ERROR")
        
        # Simulate processing time
        self.log_activity("Simulating file processing (3 seconds)...")
        time.sleep(3)
        
        # Restore original filenames
        for locked_path, original_path in manipulation_targets:
            try:
                os.rename(locked_path, original_path)
                original_filename = os.path.basename(original_path)
                self.log_activity(f"Restored file: {original_filename}")
            except Exception as e:
                self.log_activity(f"Failed to restore {original_path}: {str(e)}", "ERROR")
        
        self.log_activity("File manipulation simulation completed")
    
    def create_infection_marker(self):
        """
        Create virus infection marker file
        
        Places a marker file indicating successful infection for
        antivirus detection and educational analysis purposes.
        """
        self.log_activity("Creating infection marker")
        
        execution_duration = datetime.now() - self.execution_start_time
        
        marker_data = {
            "infection_metadata": {
                "virus_signature": self.virus_signature,
                "virus_version": self.virus_version,
                "infection_timestamp": self.execution_start_time.isoformat(),
                "execution_duration_seconds": execution_duration.total_seconds()
            },
            "system_information": {
                "platform": platform.platform(),
                "python_version": platform.python_version(),
                "target_directory": self.target_directory
            },
            "execution_statistics": {
                "files_processed": self.files_processed,
                "encryption_operations": self.encryption_operations,
                "messages_displayed": len(self.encrypted_educational_messages)
            },
            "educational_context": {
                "institution": self.institution,
                "project_type": "ROT13 Cryptography Demonstration",
                "safety_verified": True
            },
            "antivirus_guidance": {
                "detection_signature": self.virus_signature,
                "encryption_algorithm": "ROT13",
                "encrypted_files_pattern": "*ODYSSEY_ENCRYPTED*",
                "payload_location": self.payload_file,
                "manifest_location": self.encryption_log_file
            }
        }
        
        marker_path = os.path.join(self.target_directory, self.marker_file)
        # FIX: Added encoding='utf-8' to handle Unicode characters
        with open(marker_path, 'w', encoding='utf-8') as f:
            json.dump(marker_data, f, indent=2)
        
        self.log_activity("Infection marker created successfully")
    
    def execute_educational_simulation(self):
        """
        Main execution routine for educational virus simulation
        
        Orchestrates all virus behaviors in a controlled sequence
        while maintaining safety protocols and comprehensive logging.
        """
        print("🚀 ODYSSEY EDUCATIONAL VIRUS - EXECUTION STARTING")
        print("═" * 60)
        
        try:
            # Initialize systems
            self.initialize_logging_system()
            
            # Safety verification
            print("🔒 Performing safety verification...")
            
            if not SecurityValidator.request_educational_consent():
                self.log_activity("Educational consent denied - execution terminated", "WARNING")
                print("❌ Educational consent required. Execution terminated.")
                return False
            
            if not SecurityValidator.detect_virtual_environment():
                self.log_activity("Virtual environment not detected", "WARNING")
                print("⚠️  WARNING: Virtual machine environment not detected!")
                
                override_response = input("Type 'EDUCATIONAL_OVERRIDE' to continue: ").strip()
                if override_response != 'EDUCATIONAL_OVERRIDE':
                    self.log_activity("Safety override denied - execution terminated", "WARNING")
                    print("❌ Safety verification failed. Execution terminated.")
                    return False
            
            self.log_activity("Safety verification completed successfully")
            print("✅ Safety verification passed. Beginning educational simulation...")
            print()
            
            # Execute virus behaviors
            print("📁 Phase 1: Environment Setup")
            self.create_educational_test_environment()
            
            print("\n🔐 Phase 2: File Encryption Simulation")
            self.perform_file_encryption_simulation()
            
            print("\n💬 Phase 3: Educational Message Display")
            self.display_educational_messages()
            
            print("\n📦 Phase 4: Payload Generation")
            self.generate_encrypted_payload()
            
            print("\n🔄 Phase 5: File Manipulation Simulation")
            self.simulate_file_manipulation()
            
            print("\n🎯 Phase 6: Infection Marker Placement")
            self.create_infection_marker()
            
            # Execution summary
            execution_duration = datetime.now() - self.execution_start_time
            
            print(f"\n✅ ODYSSEY SIMULATION COMPLETED SUCCESSFULLY")
            print("═" * 60)
            print(f"📊 Execution Statistics:")
            print(f"   • Duration: {execution_duration.total_seconds():.2f} seconds")
            print(f"   • Files processed: {self.files_processed}")
            print(f"   • Encryption operations: {self.encryption_operations}")
            print(f"   • Target directory: {self.target_directory}")
            print(f"📋 Generated Files:")
            print(f"   • Activity log: {self.log_file}")
            print(f"   • Infection marker: {self.marker_file}")
            print(f"   • Encrypted payload: {self.payload_file}")
            print(f"   • Encryption manifest: {self.encryption_log_file}")
            print()
            print("🎓 Educational objectives achieved:")
            print("   ✓ ROT13 encryption/decryption demonstrated")
            print("   ✓ Malware behavior simulation completed")
            print("   ✓ Antivirus detection targets created")
            print("   ✓ Comprehensive logging implemented")
            
            self.log_activity("Odyssey educational virus simulation completed successfully")
            return True
            
        except KeyboardInterrupt:
            self.log_activity("Simulation interrupted by user", "WARNING")
            print("\n⚠️  Simulation interrupted by user (Ctrl+C)")
            return False
            
        except Exception as e:
            self.log_activity(f"Simulation error: {str(e)}", "ERROR")
            print(f"\n❌ Simulation error: {str(e)}")
            return False

def main():
    """
    Main entry point for Odyssey Educational Virus
    
    Initializes and executes the educational virus simulation
    with proper error handling and user feedback.
    """
    print("🎓 ODYSSEY EDUCATIONAL VIRUS")
    print("National Teachers College - Cybersecurity Project")
    print("ROT13 Cryptographic Implementation")
    print("=" * 60)
    print()
    print("⚠️  EDUCATIONAL PURPOSE ONLY")
    print("Must be executed in virtual machine environment")
    print("For academic cybersecurity learning and research")
    print()
    
    try:
        # Initialize Odyssey virus
        odyssey = OdysseyEducationalVirus()
        
        # Execute educational simulation
        success = odyssey.execute_educational_simulation()
        
        if success:
            print("\n🎯 Ready for antivirus development and testing!")
            print("Use the generated files to build and test your antivirus solution.")
        else:
            print("\n📚 Review safety requirements and try again in proper environment.")
            
    except Exception as e:
        print(f"\n❌ Fatal error: {str(e)}")
        print("Contact your instructor for assistance.")

if __name__ == "__main__":
    main()