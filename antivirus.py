#!/usr/bin/env python3
"""
Odyssey Antivirus
National Teachers College - Information Assurance and Security 1 Finals Project

Advanced antivirus tool specifically designed to detect and remove
the Odyssey Virus and demonstrate cybersecurity principles.

Author: Tavera'S Group  
Institution: National Teachers College
Date: June 2025
Target: Odyssey Virus

FEATURES:
- Multi-format document processing
- Word Document (.docx) analysis and recovery
- PDF text extraction and decryption
- Excel (.xlsx) and PowerPoint (.pptx) support
- Advanced behavioral analysis
- Document-aware quarantine system
- ROT13 decryption engine
- Comprehensive virus signature detection
- Secure file recovery and restoration
- Real-time scanning with GUI
- Detailed forensic reporting
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

# Document processing libraries
try:
    from docx import Document
    from docx.shared import Inches
    DOCX_AVAILABLE = True
except ImportError:
    DOCX_AVAILABLE = False

try:
    import PyPDF2
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

try:
    import openpyxl
    XLSX_AVAILABLE = True
except ImportError:
    XLSX_AVAILABLE = False

try:
    from pptx import Presentation
    PPTX_AVAILABLE = True
except ImportError:
    PPTX_AVAILABLE = False

class ROT13CryptographyEngine:
    """
    ROT13 Cryptographic Engine for Virus Decryption
    
    Implements the exact ROT13 algorithm used by the Odyssey virus
    to ensure proper decryption and file recovery.
    """
    
    @staticmethod
    def rot13_transform(text):
        """Apply ROT13 transformation (identical to virus implementation)"""
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
        """Decrypt ROT13 ciphertext (ROT13 is self-inverse)"""
        return ROT13CryptographyEngine.rot13_transform(ciphertext)
    
    @staticmethod
    def rot13_encrypt(plaintext):
        """Encrypt plaintext using ROT13 (for testing purposes)"""
        return ROT13CryptographyEngine.rot13_transform(plaintext)

class DocumentAnalyzer:
    """
    Advanced document analysis engine for multiple file formats
    
    Provides analysis and recovery capabilities for:
    - Word Documents (.docx)
    - PDF files (.pdf)
    - Excel files (.xlsx)
    - PowerPoint presentations (.pptx)
    - Plain text files
    """
    
    def __init__(self, crypto_engine):
        self.crypto_engine = crypto_engine
        self.supported_formats = {
            '.docx': 'Word Document',
            '.pdf': 'PDF Document', 
            '.xlsx': 'Excel Spreadsheet',
            '.pptx': 'PowerPoint Presentation',
            '.txt': 'Text File',
            '.md': 'Markdown File',
            '.csv': 'CSV File',
            '.py': 'Python Script',
            '.js': 'JavaScript File',
            '.html': 'HTML File',
            '.css': 'CSS File'
        }
    
    def analyze_word_document(self, file_path):
        """Analyze Word document for virus content"""
        if not DOCX_AVAILABLE:
            return None, "python-docx library not available"
        
        try:
            doc = Document(file_path)
            text_content = []
            virus_indicators = []
            
            # Extract and analyze paragraphs
            for paragraph in doc.paragraphs:
                text = paragraph.text
                if text.strip():
                    text_content.append(text)
                    
                    # Check for virus signatures
                    if "ODYSSEY_VIRUS_2025_NTC" in text:
                        virus_indicators.append(f"Virus signature found: {text[:100]}...")
                    if "ROT13" in text and "Encryption" in text:
                        virus_indicators.append(f"Encryption indicator: {text[:100]}...")
            
            # Analyze tables
            for table in doc.tables:
                for row in table.rows:
                    for cell in row.cells:
                        if cell.text.strip() and "ODYSSEY" in cell.text:
                            virus_indicators.append(f"Table virus content: {cell.text[:50]}...")
            
            analysis_result = {
                'document_type': 'Word Document',
                'paragraphs_count': len([p for p in doc.paragraphs if p.text.strip()]),
                'tables_count': len(doc.tables),
                'text_content': '\n'.join(text_content),
                'virus_indicators': virus_indicators,
                'is_infected': len(virus_indicators) > 0
            }
            
            return analysis_result, None
            
        except Exception as e:
            return None, f"Error analyzing Word document: {str(e)}"
    
    def extract_pdf_content(self, file_path):
        """Extract content from PDF for analysis"""
        if not PDF_AVAILABLE:
            return None, "PyPDF2 library not available"
        
        try:
            with open(file_path, 'rb') as file:
                pdf_reader = PyPDF2.PdfReader(file)
                text_content = []
                virus_indicators = []
                
                for page_num, page in enumerate(pdf_reader.pages):
                    text = page.extract_text()
                    if text.strip():
                        text_content.append(f"=== Page {page_num + 1} ===\n{text}")
                        
                        # Check for virus indicators
                        if "ODYSSEY_VIRUS_2025_NTC" in text:
                            virus_indicators.append(f"Page {page_num + 1}: Virus signature detected")
                        if "ROT13" in text and "encrypted" in text.lower():
                            virus_indicators.append(f"Page {page_num + 1}: Encryption indicators")
                
                analysis_result = {
                    'document_type': 'PDF Document',
                    'pages_count': len(pdf_reader.pages),
                    'text_content': '\n'.join(text_content),
                    'virus_indicators': virus_indicators,
                    'is_infected': len(virus_indicators) > 0
                }
                
                return analysis_result, None
                
        except Exception as e:
            return None, f"Error analyzing PDF: {str(e)}"
    
    def analyze_excel_file(self, file_path):
        """Analyze Excel file for virus content"""
        if not XLSX_AVAILABLE:
            return None, "openpyxl library not available"
        
        try:
            workbook = openpyxl.load_workbook(file_path)
            text_content = []
            virus_indicators = []
            
            for sheet_name in workbook.sheetnames:
                sheet = workbook[sheet_name]
                text_content.append(f"=== Sheet: {sheet_name} ===")
                
                for row in sheet.iter_rows():
                    row_values = []
                    for cell in row:
                        if cell.value is not None:
                            cell_text = str(cell.value)
                            row_values.append(cell_text)
                            
                            # Check for virus indicators
                            if "ODYSSEY_VIRUS_2025_NTC" in cell_text:
                                virus_indicators.append(f"Sheet {sheet_name}: Virus signature in cell")
                    
                    if row_values:
                        text_content.append(" | ".join(row_values))
            
            analysis_result = {
                'document_type': 'Excel Spreadsheet',
                'sheets_count': len(workbook.sheetnames),
                'text_content': '\n'.join(text_content),
                'virus_indicators': virus_indicators,
                'is_infected': len(virus_indicators) > 0
            }
            
            return analysis_result, None
            
        except Exception as e:
            return None, f"Error analyzing Excel file: {str(e)}"
    
    def analyze_powerpoint(self, file_path):
        """Analyze PowerPoint presentation for virus content"""
        if not PPTX_AVAILABLE:
            return None, "python-pptx library not available"
        
        try:
            prs = Presentation(file_path)
            text_content = []
            virus_indicators = []
            
            for i, slide in enumerate(prs.slides, 1):
                text_content.append(f"=== Slide {i} ===")
                
                for shape in slide.shapes:
                    if hasattr(shape, "text") and shape.text.strip():
                        text = shape.text
                        text_content.append(text)
                        
                        # Check for virus indicators
                        if "ODYSSEY_VIRUS_2025_NTC" in text:
                            virus_indicators.append(f"Slide {i}: Virus signature detected")
                        if "ROT13" in text and "encrypted" in text.lower():
                            virus_indicators.append(f"Slide {i}: Encryption indicators")
            
            analysis_result = {
                'document_type': 'PowerPoint Presentation',
                'slides_count': len(prs.slides),
                'text_content': '\n'.join(text_content),
                'virus_indicators': virus_indicators,
                'is_infected': len(virus_indicators) > 0
            }
            
            return analysis_result, None
            
        except Exception as e:
            return None, f"Error analyzing PowerPoint: {str(e)}"
    
    def analyze_document(self, file_path):
        """Analyze document based on file extension"""
        file_extension = os.path.splitext(file_path)[1].lower()
        
        if file_extension == '.docx':
            return self.analyze_word_document(file_path)
        elif file_extension == '.pdf':
            return self.extract_pdf_content(file_path)
        elif file_extension == '.xlsx':
            return self.analyze_excel_file(file_path)
        elif file_extension == '.pptx':
            return self.analyze_powerpoint(file_path)
        elif file_extension in ['.txt', '.md', '.csv', '.py', '.js', '.html', '.css']:
            # Plain text analysis
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                virus_indicators = []
                if "ODYSSEY_VIRUS_2025_NTC" in content:
                    virus_indicators.append("Virus signature detected")
                if "ROT13" in content and "encrypted" in content.lower():
                    virus_indicators.append("Encryption indicators found")
                
                analysis_result = {
                    'document_type': self.supported_formats.get(file_extension, 'Text File'),
                    'text_content': content,
                    'virus_indicators': virus_indicators,
                    'is_infected': len(virus_indicators) > 0
                }
                
                return analysis_result, None
                
            except Exception as e:
                return None, f"Error reading text file: {str(e)}"
        else:
            return None, f"Unsupported file type: {file_extension}"

class OdysseyVirusSignatureDatabase:
    """
    Signature database for multi-document Odyssey virus detection

    Updated to handle the virus with multi-document support
    """
    
    def __init__(self):
        self.virus_signatures = {
            "ODYSSEY_VIRUS_2025_NTC": {
                "name": "Odyssey Virus",
                "version": "2.0_EDUCATIONAL_MULTIDOC",
                "institution": "National Teachers College",
                "type": "Multi-Document Educational Malware",
                "risk_level": "Educational Only",
                "encryption_algorithm": "ROT13",
                "target_directory": "odyssey_test_environment",
                "supported_formats": [".docx", ".pdf", ".xlsx", ".pptx", ".txt", ".md", ".csv"],
                "description": "ROT13-based virus with multi-document support"
            }
        }
        
        self.file_patterns = [
            "*ODYSSEY_ENCRYPTED*",           # All encrypted files
            "*ODYSSEY_LOCKED_*",             # Temporarily locked files
            "odyssey_activity.log",          # Activity log
            ".odyssey_infection_marker",     # Infection marker
            "odyssey_encrypted_payload.dat", # Encrypted payload
            "odyssey_encryption_manifest.json", # Encryption manifest
            "cybersecurity_report_ODYSSEY_ENCRYPTED.docx"  # Sample encrypted Word doc
        ]
        
        self.content_signatures = [
            "ODYSSEY_VIRUS_2025_NTC",
            "<!-- ODYSSEY_VIRUS_2025_NTC -->",
            "<!-- Encryption: ROT13 -->",
            "National Teachers College",
            "Odyssey Virus",
            "ROT13 Cryptographic Implementation",
            "=== ENCRYPTED .DOCX CONTENT ===",
            "=== ENCRYPTED .PDF CONTENT ===",
            "=== ENCRYPTED .XLSX CONTENT ===",
            "=== ENCRYPTED .PPTX CONTENT ===",
            "Odyssey Virus",
            "Multi-Document Support"
        ]
        
        self.document_indicators = {
            'word_document': [
                "Encrypted Document - ROT13",
                "Educational Note:",
                "This document has been encrypted using ROT13"
            ],
            'generic_encrypted': [
                "=== ENCRYPTED",
                "Original File:",
                "Encryption: ROT13",
                "Document Type:"
            ]
        }
        
        self.behavioral_indicators = [
            "File encryption with ODYSSEY_ENCRYPTED suffix",
            "ROT13 encrypted educational messages",
            "Infection marker placement",
            "Temporary file locking with ODYSSEY_LOCKED prefix",
            "Encrypted payload generation",
            "Educational popup message display",
            "Multi-format document processing",
            "Comprehensive activity logging"
        ]
    
    def get_virus_info(self, signature):
        """Get detailed information about virus signature"""
        return self.virus_signatures.get(signature, None)
    
    def is_odyssey_pattern(self, filename):
        """Check if filename matches Odyssey virus patterns"""
        for pattern in self.file_patterns:
            if fnmatch.fnmatch(filename, pattern):
                return True
        return False
    
    def analyze_document_infection(self, content):
        """Analyze document content for infection indicators"""
        indicators = []
        
        for signature in self.content_signatures:
            if signature in content:
                indicators.append(signature)
        
        # Check for document-specific indicators
        for doc_type, patterns in self.document_indicators.items():
            for pattern in patterns:
                if pattern in content:
                    indicators.append(f"{doc_type}: {pattern}")
        
        return indicators
    
    def get_all_signatures(self):
        """Get all known virus signatures"""
        return list(self.virus_signatures.keys())

class AdvancedVirusScanner:
    """
    Virus scanning engine with multi-document support
    
    Implements multiple detection methods:
    - Signature-based detection
    - Heuristic analysis
    - Behavioral pattern recognition
    - Document-specific analysis
    - File integrity verification
    """
    
    def __init__(self):
        self.crypto_engine = ROT13CryptographyEngine()
        self.document_analyzer = DocumentAnalyzer(self.crypto_engine)
        self.signature_db = OdysseyVirusSignatureDatabase()
        self.scan_results = []
        self.quarantine_dir = "odyssey_antivirus_quarantine"
        self.scan_statistics = {
            'files_scanned': 0,
            'documents_analyzed': 0,
            'threats_detected': 0,
            'document_types_scanned': {},
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
                "antivirus": "Odyssey Virus Hunter",
                "institution": "National Teachers College",
                "supported_formats": list(self.document_analyzer.supported_formats.keys())
            }
            
            info_path = os.path.join(self.quarantine_dir, "quarantine_info.json")
            with open(info_path, 'w', encoding='utf-8') as f:
                json.dump(quarantine_info, f, indent=2)

            self.log_activity(f"✅ Odyssey quarantine system initialized: {self.quarantine_dir}")
        else:
            self.log_activity(f"📁 Using existing Odyssey quarantine: {self.quarantine_dir}")

    def log_activity(self, message, level="INFO"):
        """Logging with different levels"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Level-specific prefixes
        level_prefixes = {
            "INFO": "📝",
            "WARNING": "⚠️",
            "ERROR": "❌",
            "SUCCESS": "✅",
            "DETECTION": "🚨",
            "CRYPTO": "🔐",
            "REMOVAL": "🧹",
            "DOCUMENT": "📄"
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
    
    def scan_document_comprehensive(self, filepath):
        """Comprehensive document scanning with multi-format support"""
        detections = []
        file_extension = os.path.splitext(filepath)[1].lower()
        
        try:
            # Skip binary files and directories
            if not os.path.isfile(filepath) or self.quarantine_dir in filepath:
                return detections
            
            # Update statistics
            self.scan_statistics['files_scanned'] += 1
            
            # Calculate file hash
            file_hash = self.calculate_file_hash(filepath)
            
            # Document-specific analysis
            if file_extension in self.document_analyzer.supported_formats:
                self.scan_statistics['documents_analyzed'] += 1
                
                # Track document types
                doc_type = self.document_analyzer.supported_formats[file_extension]
                if doc_type in self.scan_statistics['document_types_scanned']:
                    self.scan_statistics['document_types_scanned'][doc_type] += 1
                else:
                    self.scan_statistics['document_types_scanned'][doc_type] = 1
                
                # Analyze document
                analysis_result, error = self.document_analyzer.analyze_document(filepath)
                
                if error:
                    self.log_activity(f"Document analysis error for {os.path.basename(filepath)}: {error}", "WARNING")
                elif analysis_result and analysis_result['is_infected']:
                    detection = {
                        'type': 'document_infection',
                        'file': filepath,
                        'document_type': analysis_result['document_type'],
                        'virus_indicators': analysis_result['virus_indicators'],
                        'analysis_data': analysis_result,
                        'file_hash': file_hash,
                        'detection_time': datetime.now().isoformat(),
                        'confidence': 'HIGH'
                    }
                    detections.append(detection)
                    self.log_activity(f"🚨 Infected document detected: {os.path.basename(filepath)} ({analysis_result['document_type']})", "DETECTION")
            
            # Standard file content scanning
            try:
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
                
                # Document infection analysis
                infection_indicators = self.signature_db.analyze_document_infection(content)
                if infection_indicators:
                    detection = {
                        'type': 'content_infection',
                        'file': filepath,
                        'indicators': infection_indicators,
                        'file_hash': file_hash,
                        'detection_time': datetime.now().isoformat(),
                        'confidence': 'MEDIUM'
                    }
                    detections.append(detection)
                    self.log_activity(f"🚨 Content infection indicators: {len(infection_indicators)} found in {os.path.basename(filepath)}", "DETECTION")
                    
            except Exception as e:
                # File might be binary or inaccessible
                pass
                
        except Exception as e:
            self.log_activity(f"Error scanning {filepath}: {str(e)}", "ERROR")
        
        return detections
    
    def is_rot13_encrypted(self, content):
        """Heuristic analysis to detect ROT13 encrypted content"""
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
                self.log_activity(f"   Virus Version: {metadata.get('virus_version', 'Unknown')}")
                self.log_activity(f"   Infection Time: {metadata.get('infection_timestamp', 'Unknown')}")
                self.log_activity(f"   Execution Duration: {metadata.get('execution_duration_seconds', 'Unknown')}s")
            
            if 'document_support_status' in marker_data:
                doc_support = marker_data['document_support_status']
                self.log_activity("   Document Support Status:")
                self.log_activity(f"     Word (.docx): {'✅' if doc_support.get('docx_support', False) else '❌'}")
                self.log_activity(f"     PDF (.pdf): {'✅' if doc_support.get('pdf_support', False) else '❌'}")
                self.log_activity(f"     Excel (.xlsx): {'✅' if doc_support.get('xlsx_support', False) else '❌'}")
                self.log_activity(f"     PowerPoint (.pptx): {'✅' if doc_support.get('pptx_support', False) else '❌'}")
            
            if 'execution_statistics' in marker_data:
                stats = marker_data['execution_statistics']
                self.log_activity(f"   Files Processed: {stats.get('files_processed', 'Unknown')}")
                self.log_activity(f"   Encryption Operations: {stats.get('encryption_operations', 'Unknown')}")
                
                if 'document_types_processed' in stats:
                    doc_types = stats['document_types_processed']
                    self.log_activity(f"   Document Types Infected: {list(doc_types.keys())}")
            
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

            self.log_activity("🔐 Analyzing Odyssey encrypted payload...", "CRYPTO")
            
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

            self.log_activity("✅ Successfully decrypted Odyssey virus payload:", "SUCCESS")

            # Display key payload information
            if 'virus_identification' in payload_data:
                virus_id = payload_data['virus_identification']
                self.log_activity(f"   Virus Name: {virus_id.get('name', 'Unknown')}")
                self.log_activity(f"   Version: {virus_id.get('version', 'Unknown')}")
                self.log_activity(f"   Institution: {virus_id.get('institution', 'Unknown')}")
            
            if 'document_processing_capabilities' in payload_data:
                doc_caps = payload_data['document_processing_capabilities']
                self.log_activity("   Document Processing Capabilities:")
                self.log_activity(f"     Supported Formats: {doc_caps.get('supported_formats', [])}")
                self.log_activity(f"     Word Support: {doc_caps.get('word_documents', False)}")
                self.log_activity(f"     PDF Support: {doc_caps.get('pdf_support', False)}")
                self.log_activity(f"     Excel Support: {doc_caps.get('excel_support', False)}")
                self.log_activity(f"     PowerPoint Support: {doc_caps.get('powerpoint_support', False)}")
            
            if 'cryptographic_implementation' in payload_data:
                crypto_info = payload_data['cryptographic_implementation']
                self.log_activity(f"   Encryption: {crypto_info.get('primary_algorithm', 'Unknown')}")
            
            return payload_data
            
        except Exception as e:
            self.log_activity(f"Failed to decrypt Odyssey payload: {str(e)}", "ERROR")
            return None
    
    def perform_comprehensive_scan(self, directories=None):
        """Perform comprehensive system scan"""
        if directories is None:
            directories = [".", "odyssey_test_environment"]
        
        self.log_activity("🔍 Starting comprehensive Odyssey virus scan...", "INFO")
        self.log_activity(f"📄 Document format support:", "INFO")
        self.log_activity(f"   Word (.docx): {'✅' if DOCX_AVAILABLE else '❌'}")
        self.log_activity(f"   PDF (.pdf): {'✅' if PDF_AVAILABLE else '❌'}")
        self.log_activity(f"   Excel (.xlsx): {'✅' if XLSX_AVAILABLE else '❌'}")
        self.log_activity(f"   PowerPoint (.pptx): {'✅' if PPTX_AVAILABLE else '❌'}")
        
        scan_start_time = time.time()
        all_detections = []
        
        for directory in directories:
            if not os.path.exists(directory):
                continue
                
            self.log_activity(f"📁 Scanning directory: {directory}")
            
            # Scan filename patterns
            pattern_detections = self.scan_filename_patterns(directory)
            all_detections.extend(pattern_detections)
            
            # Comprehensive document scanning
            try:
                for root, dirs, files in os.walk(directory):
                    if self.quarantine_dir in root:
                        continue
                        
                    for filename in files:
                        filepath = os.path.join(root, filename)
                        document_detections = self.scan_document_comprehensive(filepath)
                        all_detections.extend(document_detections)
                        
            except Exception as e:
                self.log_activity(f"Error during comprehensive scan in {directory}: {str(e)}", "ERROR")
            
            # Analyze special files
            marker_data = self.analyze_infection_marker(directory)
            payload_data = self.analyze_encrypted_payload(directory)
        
        # Update statistics
        scan_duration = time.time() - scan_start_time
        self.scan_statistics['scan_duration'] = scan_duration
        self.scan_statistics['threats_detected'] = len(all_detections)
        
        self.log_activity(f"🔍 Scan completed in {scan_duration:.2f} seconds", "SUCCESS")
        self.log_activity(f"📊 Scan Statistics:")
        self.log_activity(f"   Files scanned: {self.scan_statistics['files_scanned']}")
        self.log_activity(f"   Documents analyzed: {self.scan_statistics['documents_analyzed']}")
        self.log_activity(f"   Threats detected: {self.scan_statistics['threats_detected']}")
        
        if self.scan_statistics['document_types_scanned']:
            self.log_activity(f"📄 Document types processed:")
            for doc_type, count in self.scan_statistics['document_types_scanned'].items():
                self.log_activity(f"   {doc_type}: {count}")
        
        return all_detections

class OdysseyVirusRemover:
    """
    Virus removal and file recovery system

    Provides comprehensive removal capabilities for multi-document threats:
    - Safe file decryption and recovery
    - Word document reconstruction
    - Multi-format document restoration
    - Secure quarantine management
    - Original file restoration
    - Artifact cleanup
    """
    
    def __init__(self, scanner):
        self.scanner = scanner
        self.crypto_engine = ROT13CryptographyEngine()
        self.document_analyzer = DocumentAnalyzer(self.crypto_engine)
        self.removal_log = []
        self.recovery_statistics = {
            'files_decrypted': 0,
            'documents_recovered': 0,
            'word_docs_recovered': 0,
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
    
    def recover_word_document(self, infected_docx_path, output_path=None):
        """Recover infected Word document"""
        if not DOCX_AVAILABLE:
            return False, "python-docx library not available"
        
        try:
            # Analyze the infected document
            analysis_result, error = self.document_analyzer.analyze_word_document(infected_docx_path)
            
            if error:
                return False, error
            
            if not analysis_result['is_infected']:
                return False, "Document does not appear to be infected"
            
            # Extract text content and decrypt
            encrypted_content = analysis_result['text_content']
            
            # Find the actual encrypted content (skip virus metadata)
            content_lines = encrypted_content.split('\n')
            decrypted_lines = []
            
            for line in content_lines:
                # Skip virus signature lines
                if not (line.strip().startswith('<!--') or 
                       'ODYSSEY_VIRUS_2025_NTC' in line or
                       line.startswith('Encrypted Document - ROT13') or
                       line.startswith('Educational Note:')):
                    # Decrypt the line
                    decrypted_line = self.crypto_engine.rot13_decrypt(line)
                    decrypted_lines.append(decrypted_line)
            
            decrypted_content = '\n'.join(decrypted_lines)
            
            # Create recovered document
            if output_path is None:
                output_path = infected_docx_path.replace("_ODYSSEY_ENCRYPTED", "_RECOVERED")
            
            recovered_doc = Document()
            recovered_doc.add_heading('Recovered Document', 0)
            recovered_doc.add_paragraph('This document has been recovered from ROT13 encryption.')
            recovered_doc.add_paragraph('')
            
            # Add decrypted content
            for paragraph in decrypted_content.split('\n'):
                if paragraph.strip():
                    recovered_doc.add_paragraph(paragraph)
            
            # Add recovery metadata
            recovered_doc.add_paragraph('')
            recovered_doc.add_paragraph('--- Recovery Information ---')
            recovered_doc.add_paragraph(f'Original file: {os.path.basename(infected_docx_path)}')
            recovered_doc.add_paragraph(f'Recovery time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
            recovered_doc.add_paragraph('Recovered by: Odyssey Virus Hunter')
            
            recovered_doc.save(output_path)
            
            self.recovery_statistics['word_docs_recovered'] += 1
            self.log_removal(f"🔐 Word document recovered: {os.path.basename(infected_docx_path)}", "CRYPTO")
            return True, None
            
        except Exception as e:
            return False, f"Error recovering Word document: {str(e)}"
    
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
                    original_filename = file_info.get('original_filename', 'unknown')
                    original_type = file_info.get('original_type', '.txt')
                    
                    # Handle Word documents specially
                    if encrypted_filename.endswith('_ODYSSEY_ENCRYPTED.docx') and DOCX_AVAILABLE:
                        # This is an encrypted Word document
                        recovery_filename = original_filename.replace('.docx', '_RECOVERED.docx')
                        recovery_path = os.path.join(directory, recovery_filename)
                        
                        success, error = self.recover_word_document(encrypted_path, recovery_path)
                        if success:
                            decrypted_count += 1
                            # Remove encrypted version
                            try:
                                os.remove(encrypted_path)
                                self.log_removal(f"🗑️ Removed encrypted Word document: {encrypted_filename}")
                            except Exception as e:
                                self.log_removal(f"⚠️ Could not remove {encrypted_filename}: {str(e)}", "WARNING")
                        else:
                            self.log_removal(f"❌ Failed to recover Word document: {error}", "ERROR")
                    
                    else:
                        # Handle other document types (converted to encrypted text)
                        try:
                            with open(encrypted_path, 'r', encoding='utf-8', errors='ignore') as f:
                                encrypted_content = f.read()
                            
                            # Extract the actual encrypted content
                            lines = encrypted_content.split('\n')
                            content_start = 0
                            
                            # Find where actual content starts (after headers)
                            for i, line in enumerate(lines):
                                if '=' * 50 in line:
                                    content_start = i + 1
                                    break
                            
                            if content_start < len(lines):
                                # Extract encrypted content (before virus signatures)
                                actual_content = []
                                for line in lines[content_start:]:
                                    if not line.strip().startswith('<!--'):
                                        actual_content.append(line)
                                
                                # Remove trailing virus signatures
                                while actual_content and actual_content[-1].strip().startswith('<!--'):
                                    actual_content.pop()
                                
                                encrypted_text = '\n'.join(actual_content)
                                decrypted_content = self.crypto_engine.rot13_decrypt(encrypted_text)
                                
                                # Save recovered file
                                name, ext = os.path.splitext(original_filename)
                                recovery_filename = f"{name}_RECOVERED{original_type}"
                                recovery_path = os.path.join(directory, recovery_filename)
                                
                                with open(recovery_path, 'w', encoding='utf-8') as f:
                                    f.write(decrypted_content)
                                
                                decrypted_count += 1
                                self.recovery_statistics['documents_recovered'] += 1
                                self.log_removal(f"🔐 Document recovered: {original_filename} ({original_type})", "CRYPTO")
                                
                                # Remove encrypted version
                                os.remove(encrypted_path)
                                self.log_removal(f"🗑️ Removed encrypted file: {encrypted_filename}")
                                
                        except Exception as e:
                            self.log_removal(f"❌ Failed to recover {encrypted_filename}: {str(e)}", "ERROR")
            
            # Remove the manifest
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
            "*ODYSSEY_LOCKED_*",
            "cybersecurity_report_ODYSSEY_ENCRYPTED.docx"
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
        self.log_removal(f"📊 Recovery Statistics:")
        self.log_removal(f"   Files decrypted: {decrypted_count}")
        self.log_removal(f"   Documents recovered: {self.recovery_statistics['documents_recovered']}")
        self.log_removal(f"   Word documents recovered: {self.recovery_statistics['word_docs_recovered']}")
        self.log_removal(f"   Files restored: {restored_count}")
        self.log_removal(f"   Artifacts removed: {artifacts_removed}")
        
        return True

class AntivirusGUI:
    """
    GUI for the Odyssey Virus Hunter with multi-document support
    
    Features:
    - Real-time scanning progress
    - Multi-document threat analysis
    - Document format support indicators
    - Interactive removal options
    - Comprehensive reporting
    """
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Odyssey Virus Hunter - Multi-Document Support")
        self.root.geometry("1100x750")
        self.root.configure(bg='#f0f0f0')
        
        self.scanner = AdvancedVirusScanner()
        self.remover = OdysseyVirusRemover(self.scanner)
        self.detections = []
        self.scan_in_progress = False
        
        self.setup_gui()

    def setup_gui(self):
        """Setup GUI components"""
        # Create main notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Virus Scanner tab
        self.scanner_frame = tk.Frame(self.notebook, bg='#f0f0f0')
        self.notebook.add(self.scanner_frame, text="Virus Scanner")
        self.setup_scanner_tab()
        
        # Detection Results tab
        self.results_frame = tk.Frame(self.notebook, bg='#f0f0f0')
        self.notebook.add(self.results_frame, text="Detection Results")
        self.setup_results_tab()
        
        # Document Analysis tab
        self.analysis_frame = tk.Frame(self.notebook, bg='#f0f0f0')
        self.notebook.add(self.analysis_frame, text="Document Analysis")
        self.setup_analysis_tab()

        # Quarantine tab
        self.quarantine_frame = tk.Frame(self.notebook, bg='#f0f0f0')
        self.notebook.add(self.quarantine_frame, text="Quarantine Management")
        self.setup_quarantine_tab()
        
    def setup_scanner_tab(self):
        """Setup the scanner interface"""
        # Title
        title_label = tk.Label(self.scanner_frame,
                             text="🛡️ Odyssey Virus Hunter",
                             font=("Arial", 18, "bold"),
                             bg='#f0f0f0', fg='#333')
        title_label.pack(pady=15)
        
        subtitle_label = tk.Label(self.scanner_frame,
                                text="Multi-Document Odyssey Virus Detection & Removal System",
                                font=("Arial", 12),
                                bg='#f0f0f0', fg='#666')
        subtitle_label.pack(pady=5)
        
        # Document support status frame
        support_frame = tk.LabelFrame(self.scanner_frame, text="Multi-Document Format Support", 
                                    bg='#f0f0f0', font=("Arial", 10, "bold"))
        support_frame.pack(fill=tk.X, padx=20, pady=10)
        
        support_text = f"""
📄 Word Documents (.docx): {'✅ Available' if DOCX_AVAILABLE else '❌ Not Available (install python-docx)'}
📄 PDF Files (.pdf): {'✅ Available' if PDF_AVAILABLE else '❌ Not Available (install PyPDF2)'}
📄 Excel Files (.xlsx): {'✅ Available' if XLSX_AVAILABLE else '❌ Not Available (install openpyxl)'}
📄 PowerPoint (.pptx): {'✅ Available' if PPTX_AVAILABLE else '❌ Not Available (install python-pptx)'}
📄 Text Files: ✅ Always Available
        """
        
        support_label = tk.Label(support_frame, text=support_text.strip(),
                               bg='#f0f0f0', font=("Courier", 9), justify=tk.LEFT)
        support_label.pack(padx=10, pady=10)
        
        # Control buttons frame
        control_frame = tk.Frame(self.scanner_frame, bg='#f0f0f0')
        control_frame.pack(pady=20)

        # Scan button
        self.scan_button = tk.Button(control_frame,
                                   text="🔍 Start Multi-Document Scan",
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

        self.progress_var = tk.StringVar(value="Ready for multi-document scan")
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
        
        self.stats_text = tk.Text(stats_frame, height=8, width=80, font=("Courier", 9), bg='#ffffff')
        self.stats_text.pack(padx=10, pady=10)
        
        # Console output
        console_frame = tk.LabelFrame(self.scanner_frame, text="Scanner Console", bg='#f0f0f0', font=("Arial", 10, "bold"))
        console_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        self.console_text = scrolledtext.ScrolledText(console_frame,
                                                    height=12,
                                                    font=("Courier", 9),
                                                    bg='#1e1e1e', fg='#00ff00',
                                                    insertbackground='#00ff00')
        self.console_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
    def setup_results_tab(self):
        """Setup the results analysis tab"""
        # Results header
        header_frame = tk.Frame(self.results_frame, bg='#f0f0f0')
        header_frame.pack(fill=tk.X, padx=20, pady=10)

        tk.Label(header_frame, text="🚨 Multi-Document Threat Detection Results",
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
        
    def setup_analysis_tab(self):
        """Setup the document analysis tab"""
        # Analysis header
        header_frame = tk.Frame(self.analysis_frame, bg='#f0f0f0')
        header_frame.pack(fill=tk.X, padx=20, pady=10)

        tk.Label(header_frame, text="📄 Document Analysis & Statistics",
                font=("Arial", 14, "bold"), bg='#f0f0f0').pack(anchor=tk.W)
        
        # Analysis display
        self.analysis_text = scrolledtext.ScrolledText(self.analysis_frame,
                                                     height=25,
                                                     font=("Courier", 10),
                                                     bg='#ffffff')
        self.analysis_text.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
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
            self.log_to_console("🛡️ Odyssey Virus Hunter Starting...")
            
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
            
            # Update analysis
            self.update_analysis_display()

            self.log_to_console(f"\n✅ Scan completed: {len(self.detections)} threats detected")

        except Exception as e:
            self.log_to_console(f"❌ Scan error: {str(e)}")

        finally:
            # Reset UI
            self.scan_in_progress = False
            self.scan_button.config(state=tk.NORMAL, text="🔍 Start Multi-Document Scan")
            self.progress_bar.stop()
            self.update_progress("Scan completed")

    def quick_scan(self):
        """Perform quick scan of current directory only"""
        self.log_to_console("⚡ Starting quick scan...")
        self.detections = self.scanner.perform_comprehensive_scan(["."])
        self.update_results_display()
        self.update_analysis_display()
        self.log_to_console(f"✅ Quick scan completed: {len(self.detections)} threats detected")

    def update_results_display(self):
        """Update the results tab with detection information"""
        self.results_text.delete(1.0, tk.END)
        
        if not self.detections:
            self.results_text.insert(tk.END, "✅ No threats detected in any document format. System appears clean.\n")
            return

        self.results_text.insert(tk.END, f"🚨 THREAT DETECTION REPORT\n")
        self.results_text.insert(tk.END, f"=" * 60 + "\n")
        self.results_text.insert(tk.END, f"Total threats detected: {len(self.detections)}\n")
        self.results_text.insert(tk.END, f"Scan time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        # Group by detection type
        by_type = {}
        for detection in self.detections:
            det_type = detection['type']
            if det_type not in by_type:
                by_type[det_type] = []
            by_type[det_type].append(detection)
        
        for det_type, detections in by_type.items():
            self.results_text.insert(tk.END, f"--- {det_type.upper().replace('_', ' ')} ({len(detections)}) ---\n")
            
            for i, detection in enumerate(detections, 1):
                self.results_text.insert(tk.END, f"\n{i}. File: {detection['file']}\n")
                
                if 'document_type' in detection:
                    self.results_text.insert(tk.END, f"   Document Type: {detection['document_type']}\n")
                
                if 'virus_indicators' in detection:
                    self.results_text.insert(tk.END, f"   Virus Indicators: {len(detection['virus_indicators'])}\n")
                    for indicator in detection['virus_indicators'][:3]:  # Show first 3
                        self.results_text.insert(tk.END, f"     • {indicator}\n")
                
                if 'virus_info' in detection:
                    info = detection['virus_info']
                    self.results_text.insert(tk.END, f"   Virus: {info['name']}\n")
                    self.results_text.insert(tk.END, f"   Risk Level: {info['risk_level']}\n")
                    
                if 'description' in detection:
                    self.results_text.insert(tk.END, f"   Description: {detection['description']}\n")
                
                self.results_text.insert(tk.END, f"   Confidence: {detection.get('confidence', 'MEDIUM')}\n")
                self.results_text.insert(tk.END, f"   Detection Time: {detection.get('detection_time', 'Unknown')}\n")
            
            self.results_text.insert(tk.END, "\n")
            
    def update_statistics_display(self):
        """Update scan statistics display"""
        stats = self.scanner.scan_statistics
        
        stats_text = f"""
Files Scanned:        {stats['files_scanned']}
Documents Analyzed:   {stats['documents_analyzed']}
Threats Detected:     {stats['threats_detected']}
Scan Duration:        {stats['scan_duration']:.2f} seconds
Files Quarantined:    {stats.get('files_quarantined', 0)}
Files Cleaned:        {stats.get('files_cleaned', 0)}
Last Scan:           {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Document Types Scanned:
"""
        
        if stats['document_types_scanned']:
            for doc_type, count in stats['document_types_scanned'].items():
                stats_text += f"  {doc_type}: {count}\n"
        else:
            stats_text += "  No documents processed\n"
        
        self.stats_text.delete(1.0, tk.END)
        self.stats_text.insert(tk.END, stats_text.strip())
        
    def update_analysis_display(self):
        """Update document analysis display"""
        self.analysis_text.delete(1.0, tk.END)
        
        stats = self.scanner.scan_statistics
        
        analysis_report = f"""
📊 DOCUMENT ANALYSIS REPORT
{'=' * 60}

SCAN OVERVIEW:
Files Scanned: {stats['files_scanned']}
Documents Analyzed: {stats['documents_analyzed']}
Threats Detected: {stats['threats_detected']}
Scan Duration: {stats['scan_duration']:.2f} seconds

📄 DOCUMENT FORMAT SUPPORT:
Word Document Support: {'✅' if DOCX_AVAILABLE else '❌'}
PDF Support: {'✅' if PDF_AVAILABLE else '❌'}
Excel Support: {'✅' if XLSX_AVAILABLE else '❌'}
PowerPoint Support: {'✅' if PPTX_AVAILABLE else '❌'}

📈 DOCUMENT TYPES PROCESSED:
"""
        
        if stats['document_types_scanned']:
            for doc_type, count in stats['document_types_scanned'].items():
                analysis_report += f"• {doc_type}: {count} files\n"
        else:
            analysis_report += "• No documents processed\n"
        
        analysis_report += f"""

🔍 DETECTION EFFECTIVENESS:
Detection Rate: {(stats['threats_detected'] / max(stats['files_scanned'], 1) * 100):.1f}%
Document Analysis Rate: {(stats['documents_analyzed'] / max(stats['files_scanned'], 1) * 100):.1f}%

🎯 THREAT BREAKDOWN:
"""
        
        # Add threat type breakdown
        threat_types = {}
        for detection in self.detections:
            det_type = detection['type']
            if det_type in threat_types:
                threat_types[det_type] += 1
            else:
                threat_types[det_type] = 1
        
        for threat_type, count in threat_types.items():
            analysis_report += f"• {threat_type.replace('_', ' ').title()}: {count}\n"
        
        self.analysis_text.insert(tk.END, analysis_report.strip())
        
    def remove_threats(self):
        """Remove all detected threats with capabilities"""
        if not self.detections:
            messagebox.showinfo("No Threats", "No threats detected to remove.")
            return
            
        # Count document types in threats
        doc_types = set()
        for detection in self.detections:
            if 'document_type' in detection:
                doc_types.add(detection['document_type'])
        
        doc_list = ", ".join(doc_types) if doc_types else "various files"

        result = messagebox.askyesno("Confirm Removal",
                                   f"Remove {len(self.detections)} detected threats?\n\n"
                                   f"Affected document types: {doc_list}\n\n"
                                   f"This will decrypt and recover documents across multiple formats.")
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
            self.log_to_console(f"   Documents Recovered: {recovery_stats['documents_recovered']}")
            self.log_to_console(f"   Word Documents Recovered: {recovery_stats['word_docs_recovered']}")
            self.log_to_console(f"   Files Restored: {recovery_stats['files_restored']}")
            self.log_to_console(f"   Artifacts Removed: {recovery_stats['artifacts_removed']}")
            
            # Clear detections
            self.detections = []
            self.update_results_display()
            self.update_analysis_display()

            messagebox.showinfo("Removal Complete",
                              "All threats have been successfully removed!\n\n"
                              f"Files decrypted: {recovery_stats['files_decrypted']}\n"
                              f"Documents recovered: {recovery_stats['documents_recovered']}\n"
                              f"Word docs recovered: {recovery_stats['word_docs_recovered']}\n"
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
                reason = f" Threat: {detection['type']}"
                if 'document_type' in detection:
                    reason += f" ({detection['document_type']})"
                    
                if self.remover.quarantine_file(filepath, reason):
                    quarantined_count += 1

        self.log_to_console(f"🔒 Quarantined {quarantined_count} threats")
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
        self.quarantine_text.insert(tk.END, "=" * 60 + "\n\n")
        
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
        """Start the GUI"""
        self.root.mainloop()

class CommandLineInterface:
    """Command-line interface"""

    def __init__(self):
        self.scanner = AdvancedVirusScanner()
        self.remover = OdysseyVirusRemover(self.scanner)
        
    def display_banner(self):
        """Display application banner"""
        banner = """
🛡️  ODYSSEY VIRUS HUNTER
═══════════════════════════════════════════════════════════════════
    Multi-Document Odyssey Virus Detection & Removal System
    National Teachers College - Information Assurance and Security 1 Finals Project
═══════════════════════════════════════════════════════════════════

🎯 Target: Odyssey Virus
🔐 Encryption: ROT13 Decryption Engine
🧹 Features: Advanced Multi-Document Detection & Removal
📊 Reporting: Comprehensive Analysis
📄 Documents: Word, PDF, Excel, PowerPoint Support

"""
        print(banner)
        
    def run_interactive_scan(self):
        """Run interactive command-line scan"""
        self.display_banner()

        print("🔍 Initializing Antivirus Scanner...")
        print(f"📄 Document format support:")
        print(f"   Word (.docx): {'✅' if DOCX_AVAILABLE else '❌'}")
        print(f"   PDF (.pdf): {'✅' if PDF_AVAILABLE else '❌'}")
        print(f"   Excel (.xlsx): {'✅' if XLSX_AVAILABLE else '❌'}")
        print(f"   PowerPoint (.pptx): {'✅' if PPTX_AVAILABLE else '❌'}")
        
        # Initialize quarantine
        self.scanner.initialize_quarantine_system()
        
        while True:
            print("\n" + "="*60)
            print("Odyssey Virus Hunter - Select an option:")
            print("1. 🔍 Comprehensive System Scan")
            print("2. ⚡ Quick Scan (Current Directory)")
            print("3. 🧹 Remove Detected Threats")
            print("4. 🔒 View Quarantine")
            print("5. 📊 View Statistics")
            print("6. 📄 View Document Analysis")
            print("7. 🚪 Exit")
            
            choice = input("\nEnter your choice (1-7): ").strip()
            
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
                self.view_document_analysis()
            elif choice == '7':
                print("\n👋 Thank you for using Odyssey Virus Hunter!")
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
        print("="*50)
        print(f"Threats detected: {len(detections)}")
        
        if detections:
            print("\n🚨 DETECTED THREATS:")

            # Group by type
            by_type = {}
            for detection in detections:
                det_type = detection['type']
                if det_type not in by_type:
                    by_type[det_type] = []
                by_type[det_type].append(detection)
            
            for det_type, type_detections in by_type.items():
                print(f"\n--- {det_type.upper().replace('_', ' ')} ({len(type_detections)}) ---")
                
                for i, detection in enumerate(type_detections, 1):
                    print(f"\n{i}. File: {detection['file']}")
                    print(f"   Confidence: {detection.get('confidence', 'MEDIUM')}")
                    
                    if 'document_type' in detection:
                        print(f"   Document Type: {detection['document_type']}")
                    
                    if 'virus_info' in detection:
                        info = detection['virus_info']
                        print(f"   Virus: {info['name']}")
                        print(f"   Risk: {info['risk_level']}")
                    
                    if 'virus_indicators' in detection and detection['virus_indicators']:
                        print(f"   Indicators: {len(detection['virus_indicators'])} found")
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
            print(f"   Documents Recovered: {stats['documents_recovered']}")
            print(f"   Word Documents Recovered: {stats['word_docs_recovered']}")
            print(f"   Files Restored: {stats['files_restored']}")
            print(f"   Artifacts Removed: {stats['artifacts_removed']}")
        else:
            print("\n❌ Threat removal encountered errors.")

    def view_quarantine(self):
        """View quarantine information"""
        print(f"\n🔒 QUARANTINE INFORMATION")
        print("="*50)
        
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
        print("="*50)
        
        stats = self.scanner.scan_statistics
        recovery_stats = self.remover.recovery_statistics

        print(f"Scan Statistics:")
        print(f"  Files Scanned: {stats['files_scanned']}")
        print(f"  Documents Analyzed: {stats['documents_analyzed']}")
        print(f"  Threats Detected: {stats['threats_detected']}")
        print(f"  Last Scan Duration: {stats['scan_duration']:.2f} seconds")
        
        print(f"\nDocument Types Scanned:")
        if stats['document_types_scanned']:
            for doc_type, count in stats['document_types_scanned'].items():
                print(f"  {doc_type}: {count}")
        else:
            print("  No documents processed yet")

        print(f"\nRecovery Statistics:")
        print(f"  Files Decrypted: {recovery_stats['files_decrypted']}")
        print(f"  Documents Recovered: {recovery_stats['documents_recovered']}")
        print(f"  Word Documents Recovered: {recovery_stats['word_docs_recovered']}")
        print(f"  Files Restored: {recovery_stats['files_restored']}")
        print(f"  Artifacts Removed: {recovery_stats['artifacts_removed']}")
        print(f"  Files Quarantined: {recovery_stats['files_quarantined']}")
        
    def view_document_analysis(self):
        """View document analysis information"""
        print(f"\n📄 DOCUMENT FORMAT ANALYSIS")
        print("="*50)
        
        print("Library Availability:")
        print(f"  Word Document Support: {'✅ Available' if DOCX_AVAILABLE else '❌ Not Available'}")
        print(f"  PDF Support: {'✅ Available' if PDF_AVAILABLE else '❌ Not Available'}")
        print(f"  Excel Support: {'✅ Available' if XLSX_AVAILABLE else '❌ Not Available'}")
        print(f"  PowerPoint Support: {'✅ Available' if PPTX_AVAILABLE else '❌ Not Available'}")
        
        stats = self.scanner.scan_statistics
        
        print(f"\nDocument Processing Statistics:")
        print(f"  Total Files Scanned: {stats['files_scanned']}")
        print(f"  Documents Analyzed: {stats['documents_analyzed']}")
        print(f"  Analysis Rate: {(stats['documents_analyzed'] / max(stats['files_scanned'], 1) * 100):.1f}%")
        
        if stats['document_types_scanned']:
            print(f"\nDocument Types Processed:")
            for doc_type, count in stats['document_types_scanned'].items():
                print(f"  • {doc_type}: {count} files")

def main():
    """Main entry point for Odyssey Virus Hunter"""
    print("🎓 Odyssey Virus Hunter - Initializing...")
    
    # Display library status
    print("\n📦 Document Processing Library Status:")
    print(f"   python-docx (Word): {'✅' if DOCX_AVAILABLE else '❌ - install with: pip install python-docx'}")
    print(f"   PyPDF2 (PDF): {'✅' if PDF_AVAILABLE else '❌ - install with: pip install PyPDF2'}")
    print(f"   openpyxl (Excel): {'✅' if XLSX_AVAILABLE else '❌ - install with: pip install openpyxl'}")
    print(f"   python-pptx (PowerPoint): {'✅' if PPTX_AVAILABLE else '❌ - install with: pip install python-pptx'}")
    
    missing_libs = []
    if not DOCX_AVAILABLE:
        missing_libs.append("python-docx")
    if not PDF_AVAILABLE:
        missing_libs.append("PyPDF2")
    if not XLSX_AVAILABLE:
        missing_libs.append("openpyxl")
    if not PPTX_AVAILABLE:
        missing_libs.append("python-pptx")
    
    if missing_libs:
        print(f"\n⚠️ Optional libraries missing: {', '.join(missing_libs)}")
        print("Install all with: pip install python-docx PyPDF2 openpyxl python-pptx")
        print("(Antivirus will work with reduced functionality)\n")
    else:
        print("\n✅ All document processing libraries available!\n")
    
    # Check for GUI availability
    try:
        # Test if GUI is available
        test_root = tk.Tk()
        test_root.withdraw()
        test_root.destroy()
        
        # GUI available - ask user preference
        print("🖥️ GUI available. Choose interface:")
        print("1. 🖥️ Graphical Interface (Recommended)")
        print("2. 💻 Command Line Interface")
        
        while True:
            choice = input("\nEnter choice (1 or 2): ").strip()
            
            if choice == '1':
                print("🖥️ Starting GUI mode...")
                try:
                    antivirus = AntivirusGUI()
                    antivirus.run()
                except Exception as e:
                    print(f"❌ GUI Error: {str(e)}")
                    print("💻 Falling back to CLI mode...")
                    cli = CommandLineInterface()
                    cli.run_interactive_scan()
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
        print(f"🖥️ GUI not available ({str(e)}), using command line interface...")
        cli = CommandLineInterface()
        cli.run_interactive_scan()