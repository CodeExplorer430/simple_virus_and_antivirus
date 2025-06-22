#!/usr/bin/env python3
"""
Odyssey Virus - Multi-Document Support
National Teachers College - Information Assurance and Security 1 Finals Project

DISCLAIMER: This code is for educational purposes only.
Must be executed in virtual machine or isolated sandbox environment.
DO NOT execute on production systems or distribute maliciously.

Author: Tavera's Group
Institution: National Teachers College
Date: June 2025
Encryption: ROT13 Algorithm Only

NEW FEATURES:
- Word Document (.docx) support
- PDF text extraction and encryption
- Excel file (.xlsx) support
- PowerPoint (.pptx) support
- Document type detection

EDUCATIONAL OBJECTIVES:
- Demonstrate malware behavior simulation across document types
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

# Document processing libraries (install if needed)
try:
    from docx import Document
    from docx.shared import Inches
    DOCX_AVAILABLE = True
except ImportError:
    DOCX_AVAILABLE = False
    print("⚠️ python-docx not available. Word document support will be limited.")

try:
    import PyPDF2
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False
    print("⚠️ PyPDF2 not available. PDF support will be limited.")

try:
    import openpyxl
    XLSX_AVAILABLE = True
except ImportError:
    XLSX_AVAILABLE = False
    print("⚠️ openpyxl not available. Excel support will be limited.")

try:
    from pptx import Presentation
    PPTX_AVAILABLE = True
except ImportError:
    PPTX_AVAILABLE = False
    print("⚠️ python-pptx not available. PowerPoint support will be limited.")

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
    def rot13_encrypt(plaintext):
        """Encrypt plaintext using ROT13"""
        return ROT13Cryptography.rot13_transform(plaintext)
    
    @staticmethod
    def rot13_decrypt(ciphertext):
        """Decrypt ROT13 ciphertext (self-inverse)"""
        return ROT13Cryptography.rot13_transform(ciphertext)

class DocumentProcessor:
    """
    Advanced document processing engine for various file types
    
    Supports:
    - Word Documents (.docx)
    - PDF files (.pdf) - text extraction
    - Excel files (.xlsx)
    - PowerPoint presentations (.pptx)
    - Plain text files (.txt, .md, .csv)
    """
    
    def __init__(self, crypto_engine):
        self.crypto_engine = crypto_engine
        
    def extract_text_from_docx(self, file_path):
        """Extract text content from Word document"""
        if not DOCX_AVAILABLE:
            return None, "python-docx library not available"
        
        try:
            doc = Document(file_path)
            text_content = []
            
            # Extract paragraphs
            for paragraph in doc.paragraphs:
                if paragraph.text.strip():
                    text_content.append(paragraph.text)
            
            # Extract table content
            for table in doc.tables:
                for row in table.rows:
                    row_text = []
                    for cell in row.cells:
                        if cell.text.strip():
                            row_text.append(cell.text)
                    if row_text:
                        text_content.append(" | ".join(row_text))
            
            return "\n".join(text_content), None
            
        except Exception as e:
            return None, f"Error reading DOCX: {str(e)}"
    
    def create_encrypted_docx(self, original_path, encrypted_text, output_path):
        """Create encrypted Word document"""
        if not DOCX_AVAILABLE:
            return False, "python-docx library not available"
        
        try:
            # Create new document
            doc = Document()
            
            # Add title
            title = doc.add_heading('Encrypted Document - ROT13', 0)
            
            # Add virus signature
            doc.add_paragraph(f'<!-- {OdysseyVirus().virus_signature} -->')
            doc.add_paragraph(f'<!-- Encryption: ROT13 -->')
            doc.add_paragraph(f'<!-- Original: {os.path.basename(original_path)} -->')
            doc.add_paragraph(f'<!-- Timestamp: {datetime.now().isoformat()} -->')
            
            # Add encrypted content
            doc.add_heading('Encrypted Content:', level=1)
            
            # Split encrypted text into paragraphs
            paragraphs = encrypted_text.split('\n')
            for para in paragraphs:
                if para.strip():
                    doc.add_paragraph(para)
            
            # Add educational note
            doc.add_heading('Educational Note:', level=1)
            doc.add_paragraph('This document has been encrypted using ROT13 for educational purposes.')
            doc.add_paragraph('ROT13 is a simple Caesar cipher with a shift of 13 positions.')
            doc.add_paragraph('This is part of a cybersecurity learning exercise.')
            
            # Save document
            doc.save(output_path)
            return True, None
            
        except Exception as e:
            return False, f"Error creating encrypted DOCX: {str(e)}"
    
    def extract_text_from_pdf(self, file_path):
        """Extract text from PDF file"""
        if not PDF_AVAILABLE:
            return None, "PyPDF2 library not available"
        
        try:
            with open(file_path, 'rb') as file:
                pdf_reader = PyPDF2.PdfReader(file)
                text_content = []
                
                for page in pdf_reader.pages:
                    text = page.extract_text()
                    if text.strip():
                        text_content.append(text)
                
                return "\n".join(text_content), None
                
        except Exception as e:
            return None, f"Error reading PDF: {str(e)}"
    
    def extract_text_from_xlsx(self, file_path):
        """Extract text from Excel file"""
        if not XLSX_AVAILABLE:
            return None, "openpyxl library not available"
        
        try:
            workbook = openpyxl.load_workbook(file_path)
            text_content = []
            
            for sheet_name in workbook.sheetnames:
                sheet = workbook[sheet_name]
                text_content.append(f"=== Sheet: {sheet_name} ===")
                
                for row in sheet.iter_rows():
                    row_values = []
                    for cell in row:
                        if cell.value is not None:
                            row_values.append(str(cell.value))
                    if row_values:
                        text_content.append(" | ".join(row_values))
            
            return "\n".join(text_content), None
            
        except Exception as e:
            return None, f"Error reading XLSX: {str(e)}"
    
    def extract_text_from_pptx(self, file_path):
        """Extract text from PowerPoint presentation"""
        if not PPTX_AVAILABLE:
            return None, "python-pptx library not available"
        
        try:
            prs = Presentation(file_path)
            text_content = []
            
            for i, slide in enumerate(prs.slides, 1):
                text_content.append(f"=== Slide {i} ===")
                
                for shape in slide.shapes:
                    if hasattr(shape, "text") and shape.text.strip():
                        text_content.append(shape.text)
            
            return "\n".join(text_content), None
            
        except Exception as e:
            return None, f"Error reading PPTX: {str(e)}"
    
    def process_document(self, file_path):
        """
        Process document based on file extension
        
        Returns:
            tuple: (text_content, error_message)
        """
        file_extension = os.path.splitext(file_path)[1].lower()
        
        if file_extension == '.docx':
            return self.extract_text_from_docx(file_path)
        elif file_extension == '.pdf':
            return self.extract_text_from_pdf(file_path)
        elif file_extension == '.xlsx':
            return self.extract_text_from_xlsx(file_path)
        elif file_extension == '.pptx':
            return self.extract_text_from_pptx(file_path)
        elif file_extension in ['.txt', '.md', '.csv', '.py', '.js', '.html', '.css']:
            # Plain text files
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    return f.read(), None
            except Exception as e:
                return None, f"Error reading text file: {str(e)}"
        else:
            return None, f"Unsupported file type: {file_extension}"

class SecurityValidator:
    """Educational Safety and Security Validation System"""
    
    @staticmethod
    def detect_virtual_environment():
        """Detect if code is running in virtual machine environment"""
        vm_indicators = [
            'vmware', 'virtualbox', 'vbox', 'qemu', 'xen',
            'hyper-v', 'parallels', 'kvm', 'bochs'
        ]
        
        system_info = platform.platform().lower()
        for indicator in vm_indicators:
            if indicator in system_info:
                return True
        
        vm_file_indicators = [
            '/proc/vz', '/proc/xen', '/sys/bus/vmbus',
            'C:\\Program Files\\VMware',
            'C:\\Program Files\\Oracle\\VirtualBox',
            '/usr/bin/VBoxService',
            '/usr/sbin/vboxguest-service'
        ]
        
        for path in vm_file_indicators:
            if os.path.exists(path):
                return True
        
        return False
    
    @staticmethod
    def request_educational_consent():
        """Display educational consent dialog"""
        try:
            root = tk.Tk()
            root.withdraw()
            
            consent_message = """
═══════════════════════════════════════════════════
    ODYSSEY VIRUS
═══════════════════════════════════════════════════

NEW FEATURES:
• Word Document (.docx) encryption support
• PDF text extraction and encryption
• Excel (.xlsx) and PowerPoint (.pptx) support
• Multi-format document processing

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
• Multi-format document processing
• Non-destructive file operation simulation
• Antivirus development and testing framework

Do you provide consent to proceed with this educational exercise?
            """
            
            result = messagebox.askyesno("Educational Consent - Odyssey Virus", consent_message)
            root.destroy()
            return result
            
        except Exception as e:
            print(consent_message)
            response = input("\nType 'CONSENT' to proceed with educational exercise: ").strip().upper()
            return response == 'CONSENT'

class OdysseyVirus:
    """Odyssey Virus with Multi-Document Support"""
    
    def __init__(self):
        """Initialize Odyssey virus with document processing"""
        
        # Virus identification and signature
        self.virus_signature = "ODYSSEY_VIRUS_2025_NTC"
        self.virus_version = "2.0_EDUCATIONAL_MULTIDOC"
        self.institution = "National Teachers College"
        
        # Cryptographic and document processing engines
        self.crypto_engine = ROT13Cryptography()
        self.document_processor = DocumentProcessor(self.crypto_engine)
        
        # File system configuration
        self.target_directory = "odyssey_test_environment"
        self.log_file = "odyssey_activity.log"
        self.marker_file = ".odyssey_infection_marker"
        self.payload_file = "odyssey_encrypted_payload.dat"
        self.encryption_log_file = "odyssey_encryption_manifest.json"
        
        # Supported file types
        self.supported_extensions = [
            '.txt', '.md', '.csv', '.py', '.js', '.html', '.css',  # Text files
            '.docx',  # Word documents
            '.pdf',   # PDF files  
            '.xlsx',  # Excel files
            '.pptx'   # PowerPoint files
        ]
        
        # Educational messages (encrypted with ROT13)
        self.encrypted_educational_messages = [
            "Raunaprq Bqlffrk Rqhpngvbany Ivehhf - Zhygv-Qbphzrag Fhccbeg",
            "EBG13 Rapekcgvba Npebff Jbeq, CQS, naq Rkpry Qbphzragf",
            "Angvbany Grnpuref Pbyyrtr - Nqinaprq Plorefrphevgl Rkrepvfr"
        ]
        
        # Execution statistics
        self.execution_start_time = None
        self.files_processed = 0
        self.encryption_operations = 0
        self.document_types_processed = {}
        
    def initialize_logging_system(self):
        """Initialize comprehensive activity logging system"""
        self.execution_start_time = datetime.now()
        
        log_header = f"""
═══════════════════════════════════════════════════════════════════
ODYSSEY VIRUS - ACTIVITY LOG
═══════════════════════════════════════════════════════════════════
Virus Signature: {self.virus_signature}
Version: {self.virus_version}
Institution: {self.institution}
Execution Started: {self.execution_start_time.strftime('%Y-%m-%d %H:%M:%S')}
Encryption Algorithm: ROT13
Target Environment: {self.target_directory}
Supported Documents: {', '.join(self.supported_extensions)}
═══════════════════════════════════════════════════════════════════

"""
        
        with open(self.log_file, 'w', encoding='utf-8') as log:
            log.write(log_header)
            
        self.log_activity("Odyssey virus logging system initialized")
    
    def log_activity(self, activity_description, category="INFO"):
        """Log virus activity with timestamp and categorization"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{category}] {activity_description}\n"
        
        with open(self.log_file, 'a', encoding='utf-8') as log:
            log.write(log_entry)
        
        # Display to console with appropriate formatting
        if category == "ERROR":
            print(f"❌ {activity_description}")
        elif category == "WARNING":
            print(f"⚠️  {activity_description}")
        elif category == "CRYPTO":
            print(f"🔐 {activity_description}")
        elif category == "DOCUMENT":
            print(f"📄 {activity_description}")
        else:
            print(f"📝 {activity_description}")
    
    def create_educational_test_environment(self):
        """Create test environment with various document types"""
        self.log_activity("Creating educational test environment", "INFO")
        
        if not os.path.exists(self.target_directory):
            os.makedirs(self.target_directory)
            self.log_activity(f"Created target directory: {self.target_directory}")
        
        # Sample educational files for demonstration
        test_files_config = [
            {
                "filename": "student_notes.txt",
                "content": "Educational cybersecurity notes\nMalware analysis techniques\nAntivirus development principles\nROT13 encryption demonstration"
            },
            {
                "filename": "research_data.csv", 
                "content": "Student,Grade,Project,Document_Type\nAlice,95,Antivirus,Word_Doc\nBob,87,Cryptography,Excel_Sheet\nCharlie,92,Network_Security,PowerPoint"
            },
            {
                "filename": "assignment_instructions.md",
                "content": "# Cybersecurity Assignment\n\n## Objectives\n- Understand multi-format malware\n- Develop document-aware antivirus tools\n- Apply cryptographic techniques across file types\n\n## Supported Formats\n- Word Documents (.docx)\n- PDF Files (.pdf)\n- Excel Spreadsheets (.xlsx)\n- PowerPoint Presentations (.pptx)"
            },
            {
                "filename": "lab_report.py",
                "content": "#!/usr/bin/env python3\n# Cybersecurity Lab Report\n# Document Processing Analysis\n\ndef analyze_document_encryption():\n    print('ROT13 Encryption Analysis')\n    print('Multi-format Document Processing')\n    print('Malware Behavioral Study')\n    return 'Analysis Complete'\n\nif __name__ == '__main__':\n    analyze_document_encryption()"
            }
        ]
        
        # Create Word document if library is available
        if DOCX_AVAILABLE:
            self.create_sample_word_document()
        
        for file_config in test_files_config:
            file_path = os.path.join(self.target_directory, file_config["filename"])
            
            if not os.path.exists(file_path):
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(file_config["content"])
                    f.write(f"\n\nFile created: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                    f.write(f"\nEducational context: National Teachers College")
                    f.write(f"\nProject: Odyssey Virus Simulation")
                
                self.log_activity(f"Created educational file: {file_config['filename']}")
        
        self.log_activity("Educational test environment setup completed")
    
    def create_sample_word_document(self):
        """Create sample Word document for testing"""
        try:
            from docx import Document
            
            doc_path = os.path.join(self.target_directory, "cybersecurity_report.docx")
            
            if not os.path.exists(doc_path):
                doc = Document()
                
                # Add title
                doc.add_heading('Cybersecurity Research Report', 0)
                
                # Add content
                doc.add_heading('Executive Summary', level=1)
                doc.add_paragraph('This document contains research findings on educational malware simulation and ROT13 cryptographic implementation for academic cybersecurity learning.')
                
                doc.add_heading('Methodology', level=1)
                doc.add_paragraph('Our research methodology includes:')
                doc.add_paragraph('• Multi-format document analysis', style='List Bullet')
                doc.add_paragraph('• ROT13 encryption implementation', style='List Bullet')
                doc.add_paragraph('• Cross-platform malware simulation', style='List Bullet')
                
                doc.add_heading('Findings', level=1)
                doc.add_paragraph('Key findings from our cybersecurity exercise demonstrate the importance of understanding document-based threats and implementing comprehensive detection mechanisms.')
                
                # Add table
                table = doc.add_table(rows=1, cols=3)
                hdr_cells = table.rows[0].cells
                hdr_cells[0].text = 'Document Type'
                hdr_cells[1].text = 'Encryption Method'
                hdr_cells[2].text = 'Detection Rate'
                
                row_cells = table.add_row().cells
                row_cells[0].text = 'Word Document'
                row_cells[1].text = 'ROT13'
                row_cells[2].text = '100%'
                
                doc.add_paragraph('\nDocument created for educational cybersecurity exercise.')
                doc.add_paragraph(f'Institution: {self.institution}')
                doc.add_paragraph(f'Date: {datetime.now().strftime("%Y-%m-%d")}')
                
                doc.save(doc_path)
                self.log_activity("Created sample Word document: cybersecurity_report.docx", "DOCUMENT")
                
        except Exception as e:
            self.log_activity(f"Failed to create sample Word document: {str(e)}", "ERROR")
    
    def perform_file_encryption(self):
        """File encryption supporting multiple document types"""
        self.log_activity("Initiating multi-format file encryption", "CRYPTO")
        
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
            
            # Check if file extension is supported
            file_extension = os.path.splitext(filename)[1].lower()
            if file_extension not in self.supported_extensions:
                self.log_activity(f"Skipping unsupported file type: {filename}", "WARNING")
                continue
            
            try:
                self.log_activity(f"Processing {file_extension} file: {filename}", "DOCUMENT")
                
                # Extract text content using document processor
                text_content, error = self.document_processor.process_document(file_path)
                
                if error:
                    self.log_activity(f"Failed to process {filename}: {error}", "ERROR")
                    continue
                
                if text_content is None:
                    self.log_activity(f"No text content extracted from {filename}", "WARNING")
                    continue
                
                # Apply ROT13 encryption to extracted text
                encrypted_content = self.crypto_engine.rot13_encrypt(text_content)
                
                # Generate encrypted filename
                name, extension = os.path.splitext(filename)
                
                # Handle special case for Word documents
                if extension.lower() == '.docx' and DOCX_AVAILABLE:
                    encrypted_filename = f"{name}_ODYSSEY_ENCRYPTED{extension}"
                    encrypted_file_path = os.path.join(self.target_directory, encrypted_filename)
                    
                    # Create encrypted Word document
                    success, error = self.document_processor.create_encrypted_docx(
                        file_path, encrypted_content, encrypted_file_path
                    )
                    
                    if not success:
                        self.log_activity(f"Failed to create encrypted DOCX: {error}", "ERROR")
                        continue
                        
                else:
                    # For other file types, create encrypted text file
                    encrypted_filename = f"{name}_ODYSSEY_ENCRYPTED.txt"
                    encrypted_file_path = os.path.join(self.target_directory, encrypted_filename)
                    
                    with open(encrypted_file_path, 'w', encoding='utf-8') as f:
                        f.write(f"=== ENCRYPTED {extension.upper()} CONTENT ===\n")
                        f.write(f"Original File: {filename}\n")
                        f.write(f"Encryption: ROT13\n")
                        f.write(f"Timestamp: {datetime.now().isoformat()}\n")
                        f.write("=" * 50 + "\n\n")
                        f.write(encrypted_content)
                        f.write(f"\n\n<!-- {self.virus_signature} -->")
                        f.write(f"\n<!-- Encryption: ROT13 -->")
                        f.write(f"\n<!-- Original: {filename} -->")
                        f.write(f"\n<!-- Document Type: {extension} -->")
                        f.write(f"\n<!-- Timestamp: {datetime.now().isoformat()} -->")
                
                # Update encryption manifest
                encryption_manifest[encrypted_filename] = {
                    "original_filename": filename,
                    "original_type": file_extension,
                    "encryption_algorithm": "ROT13",
                    "encryption_timestamp": datetime.now().isoformat(),
                    "file_size_original": os.path.getsize(file_path),
                    "file_size_encrypted": os.path.getsize(encrypted_file_path),
                    "virus_signature": self.virus_signature,
                    "text_length": len(text_content),
                    "encrypted_length": len(encrypted_content)
                }
                
                # Update statistics
                processed_files.append(filename)
                self.files_processed += 1
                self.encryption_operations += 1
                
                # Track document types
                if file_extension in self.document_types_processed:
                    self.document_types_processed[file_extension] += 1
                else:
                    self.document_types_processed[file_extension] = 1
                
                self.log_activity(f"Encrypted {file_extension} file: {filename} -> {encrypted_filename}", "CRYPTO")
                
            except Exception as e:
                self.log_activity(f"Failed to encrypt {filename}: {str(e)}", "ERROR")
        
        # Save encryption manifest
        manifest_path = os.path.join(self.target_directory, self.encryption_log_file)
        with open(manifest_path, 'w', encoding='utf-8') as f:
            json.dump(encryption_manifest, f, indent=2)
        
        self.log_activity(f"Encryption manifest saved: {len(encryption_manifest)} entries", "CRYPTO")
        self.log_activity(f"Encryption completed: {len(processed_files)} files processed")
        
        # Log document type statistics
        self.log_activity("Document type processing statistics:", "INFO")
        for doc_type, count in self.document_types_processed.items():
            self.log_activity(f"  {doc_type}: {count} files", "INFO")
    
    def display_educational_messages(self):
        """Display educational popup messages with ROT13 decryption demonstration"""
        self.log_activity("Displaying educational popup messages")
        
        try:
            root = tk.Tk()
            root.withdraw()
            
            for i, encrypted_message in enumerate(self.encrypted_educational_messages, 1):
                decrypted_message = self.crypto_engine.rot13_decrypt(encrypted_message)
                
                dialog_content = f"""
Odyssey Virus - Message {i}

ENCRYPTED (ROT13): {encrypted_message}

DECRYPTED: {decrypted_message}

This demonstrates ROT13 encryption/decryption across multiple document types:
• Word Documents (.docx)
• PDF Files (.pdf)
• Excel Spreadsheets (.xlsx)
• PowerPoint Presentations (.pptx)
• Plain Text Files (.txt, .md, .csv)

Educational Purpose: Cybersecurity Learning & Antivirus Development
"""
                
                messagebox.showinfo(f"Odyssey Message {i}", dialog_content)
                self.log_activity(f"Displayed educational message {i}: {decrypted_message}")
                time.sleep(1)
            
            root.destroy()
            
        except Exception as e:
            self.log_activity("GUI unavailable, using console display", "WARNING")
            
            for i, encrypted_message in enumerate(self.encrypted_educational_messages, 1):
                decrypted_message = self.crypto_engine.rot13_decrypt(encrypted_message)
                
                print(f"\n═══ ODYSSEY MESSAGE {i} ═══")
                print(f"ENCRYPTED: {encrypted_message}")
                print(f"DECRYPTED: {decrypted_message}")
                print("Multi-Document Support: Word, PDF, Excel, PowerPoint")
                print("═" * 50)
                
                self.log_activity(f"Console message {i}: {decrypted_message}")
                time.sleep(2)
    
    def generate_payload(self):
        """Generate encrypted payload with document processing info"""
        self.log_activity("Generating encrypted virus payload", "CRYPTO")
        
        payload_data = {
            "virus_identification": {
                "name": "Odyssey Virus",
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
            "document_processing_capabilities": {
                "supported_formats": self.supported_extensions,
                "word_documents": DOCX_AVAILABLE,
                "pdf_support": PDF_AVAILABLE,
                "excel_support": XLSX_AVAILABLE,
                "powerpoint_support": PPTX_AVAILABLE,
                "text_extraction": True
            },
            "execution_metadata": {
                "creation_timestamp": datetime.now().isoformat(),
                "target_environment": self.target_directory,
                "files_processed": self.files_processed,
                "encryption_operations": self.encryption_operations,
                "document_types_processed": self.document_types_processed
            },
            "educational_context": {
                "project_type": "Academic Cybersecurity Exercise",
                "learning_objectives": [
                    "Multi-format malware behavior analysis",
                    "ROT13 cryptographic implementation", 
                    "Document-aware antivirus development",
                    "Cross-platform cybersecurity research"
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
                "removal_strategy": "Extract and decrypt document content, restore original files",
                "document_processing": "Handle multiple document formats appropriately"
            }
        }
        
        payload_json = json.dumps(payload_data, indent=2)
        encrypted_payload = self.crypto_engine.rot13_encrypt(payload_json)
        
        payload_path = os.path.join(self.target_directory, self.payload_file)
        with open(payload_path, 'w', encoding='utf-8') as f:
            f.write(encrypted_payload)
            f.write(f"\n\n<!-- {self.virus_signature} -->")
            f.write(f"\n<!-- Payload encrypted with ROT13 -->")
            f.write(f"\n<!-- Multi-Document Support -->")
        
        self.log_activity(f"Encrypted payload generated: {self.payload_file}", "CRYPTO")
    
    def simulate_file_manipulation(self):
        """Simulate temporary file manipulation behaviors"""
        self.log_activity("Simulating file manipulation behaviors")
        
        manipulation_targets = []
        
        for filename in os.listdir(self.target_directory):
            file_extension = os.path.splitext(filename)[1].lower()
            if file_extension in ['.txt', '.md'] and not filename.startswith('ODYSSEY_'):
                file_path = os.path.join(self.target_directory, filename)
                locked_filename = f"ODYSSEY_LOCKED_{filename}"
                locked_path = os.path.join(self.target_directory, locked_filename)
                
                try:
                    os.rename(file_path, locked_path)
                    manipulation_targets.append((locked_path, file_path))
                    self.log_activity(f"Temporarily locked file: {filename}")
                except Exception as e:
                    self.log_activity(f"Failed to lock {filename}: {str(e)}", "ERROR")
        
        self.log_activity("Simulating document processing (3 seconds)...")
        time.sleep(3)
        
        for locked_path, original_path in manipulation_targets:
            try:
                os.rename(locked_path, original_path)
                original_filename = os.path.basename(original_path)
                self.log_activity(f"Restored file: {original_filename}")
            except Exception as e:
                self.log_activity(f"Failed to restore {original_path}: {str(e)}", "ERROR")
        
        self.log_activity("File manipulation simulation completed")
    
    def create_infection_marker(self):
        """Create virus infection marker"""
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
                "messages_displayed": len(self.encrypted_educational_messages),
                "document_types_processed": self.document_types_processed
            },
            "document_support_status": {
                "docx_support": DOCX_AVAILABLE,
                "pdf_support": PDF_AVAILABLE,
                "xlsx_support": XLSX_AVAILABLE,
                "pptx_support": PPTX_AVAILABLE,
                "supported_extensions": self.supported_extensions
            },
            "educational_context": {
                "institution": self.institution,
                "project_type": "ROT13 Multi-Document Demonstration",
                "safety_verified": True
            },
            "antivirus_guidance": {
                "detection_signature": self.virus_signature,
                "encryption_algorithm": "ROT13",
                "encrypted_files_pattern": "*ODYSSEY_ENCRYPTED*",
                "payload_location": self.payload_file,
                "manifest_location": self.encryption_log_file,
                "document_processing_required": True
            }
        }
        
        marker_path = os.path.join(self.target_directory, self.marker_file)
        with open(marker_path, 'w', encoding='utf-8') as f:
            json.dump(marker_data, f, indent=2)

        self.log_activity("Infection marker created successfully")

    def execute_educational_simulation(self):
        """Main execution routine for educational virus simulation"""
        print("👿 ODYSSEY VIRUS - EXECUTION STARTING")
        print("📄 Multi-Document Support: Word, PDF, Excel, PowerPoint")
        print("═" * 60)
        
        try:
            self.initialize_logging_system()
            
            print("🔒 Performing safety verification...")
            
            if not SecurityValidator.request_educational_consent():
                self.log_activity("Educational consent denied - execution terminated", "WARNING")
                print("❌ Educational consent required. Execution terminated.")
                return False
            
            if not SecurityValidator.detect_virtual_environment():
                self.log_activity("Virtual environment not detected", "WARNING")
                print("⚠️  WARNING: Virtual machine environment not detected!")
                
                override_response = input("Type 'OVERRIDE' to continue: ").strip()
                if override_response != 'OVERRIDE':
                    self.log_activity("Safety override denied - execution terminated", "WARNING")
                    print("❌ Safety verification failed. Execution terminated.")
                    return False
            
            self.log_activity("Safety verification completed successfully")
            print("✅ Safety verification passed. Beginning simulation...")
            print()
            
            # Display available document processing capabilities
            print("📄 Document Processing Capabilities:")
            print(f"   • Word Documents (.docx): {'✅' if DOCX_AVAILABLE else '❌'}")
            print(f"   • PDF Files (.pdf): {'✅' if PDF_AVAILABLE else '❌'}")
            print(f"   • Excel Files (.xlsx): {'✅' if XLSX_AVAILABLE else '❌'}")
            print(f"   • PowerPoint (.pptx): {'✅' if PPTX_AVAILABLE else '❌'}")
            print(f"   • Text Files: ✅")
            print()
            
            # Execute virus behaviors
            print("📁 Phase 1: Environment Setup")
            self.create_educational_test_environment()
            
            print("\n🔐 Phase 2: Multi-Format File Encryption")
            self.perform_file_encryption()
            
            print("\n💬 Phase 3: Educational Messages")
            self.display_educational_messages()
            
            print("\n📦 Phase 4: Payload Generation")
            self.generate_payload()
            
            print("\n🔄 Phase 5: File Manipulation Simulation")
            self.simulate_file_manipulation()
            
            print("\n🎯 Phase 6: Infection Marker")
            self.create_infection_marker()
            
            # Execution summary
            execution_duration = datetime.now() - self.execution_start_time
            
            print(f"\n✅ ODYSSEY SIMULATION COMPLETED")
            print("═" * 60)
            print(f"📊 Execution Statistics:")
            print(f"   • Duration: {execution_duration.total_seconds():.2f} seconds")
            print(f"   • Files processed: {self.files_processed}")
            print(f"   • Encryption operations: {self.encryption_operations}")
            print(f"   • Document types: {len(self.document_types_processed)}")
            print(f"   • Target directory: {self.target_directory}")
            
            if self.document_types_processed:
                print(f"📄 Document Types Processed:")
                for doc_type, count in self.document_types_processed.items():
                    print(f"   • {doc_type}: {count} files")
            
            print(f"📋 Generated Files:")
            print(f"   • Activity log: {self.log_file}")
            print(f"   • Infection marker: {self.marker_file}")
            print(f"   • Encrypted payload: {self.payload_file}")
            print(f"   • Encryption manifest: {self.encryption_log_file}")
            print()
            print("🎓 Educational objectives achieved:")
            print("   ✓ Multi-format document processing")
            print("   ✓ ROT13 encryption across document types")
            print("   ✓ Advanced malware behavior simulation")
            print("   ✓ Antivirus detection targets")
            print("   ✓ Comprehensive logging and reporting")
            
            self.log_activity("Odyssey virus simulation completed successfully")
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
    """Main entry point for Odyssey Virus"""
    print("🎓 ODYSSEY VIRUS")
    print("National Teachers College - Information Assurance and Security 1 Finals Project")
    print("ROT13 Multi-Document Cryptographic Implementation")
    print("=" * 60)
    print()
    print("⚠️  EDUCATIONAL PURPOSE ONLY")
    print("Must be executed in virtual machine environment")
    print("For academic cybersecurity learning and research")
    print()
    print("📄 NEW: Multi-Document Format Support")
    print("   • Word Documents (.docx)")
    print("   • PDF Files (.pdf)")
    print("   • Excel Spreadsheets (.xlsx)")
    print("   • PowerPoint Presentations (.pptx)")
    print()
    
    # Check for optional libraries
    missing_libs = []
    if not DOCX_AVAILABLE:
        missing_libs.append("python-docx (for Word document support)")
    if not PDF_AVAILABLE:
        missing_libs.append("PyPDF2 (for PDF support)")
    if not XLSX_AVAILABLE:
        missing_libs.append("openpyxl (for Excel support)")
    if not PPTX_AVAILABLE:
        missing_libs.append("python-pptx (for PowerPoint support)")
    
    if missing_libs:
        print("📦 Optional libraries not installed:")
        for lib in missing_libs:
            print(f"   • {lib}")
        print("\nInstall with: pip install python-docx PyPDF2 openpyxl python-pptx")
        print("(Virus will work with reduced functionality)\n")
    
    try:
        odyssey = OdysseyVirus()
        success = odyssey.execute_educational_simulation()
        
        if success:
            print("\n🎯 Ready for antivirus development and testing!")
            print("Your antivirus will need to handle multiple document formats.")
        else:
            print("\n📚 Review safety requirements and try again in proper environment.")
            
    except Exception as e:
        print(f"\n❌ Fatal error: {str(e)}")
        print("Contact your instructor for assistance.")

if __name__ == "__main__":
    main()