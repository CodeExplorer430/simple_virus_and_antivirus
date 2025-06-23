# Odyssey Virus and Antivirus Project

Information Assurance and Security 1 - National Teachers College

## What This Is

This is our virus and antivirus project for the Information Assurance and Security 1 class. We had to make a simple virus that encrypts files using our preferred cipher and language, then build an antivirus that can detect and remove it.

The project now features **multi-document support** including Word documents, PDFs, Excel files, and PowerPoint presentations in addition to regular text files.

**⚠️ IMPORTANT: Only run this stuff in a VM. Don't be stupid and run it on your real computer.**

## Project Structure

```
project/
├── odyssey_test_environment/       (created when virus runs)
├── odyssey_antivirus_quarantine/   (created when antivirus runs)
├── antivirus_activity.log          (antivirus log file)
├── antivirus.py                     (main antivirus program)
├── virus.py                         (educational virus)
├── README.md                        (this file)
└── virus_activity.log              (virus execution log)
```

## Features

### Virus Capabilities
- **Multi-format document encryption**: Word (.docx), PDF (.pdf), Excel (.xlsx), PowerPoint (.pptx)
- **ROT13 encryption** across all supported document types
- **Non-destructive operations** - creates encrypted copies, doesn't destroy originals
- **Educational popups** explaining the encryption process
- **Comprehensive logging** of all activities
- **Safety checks** including VM detection and consent verification

### Antivirus Capabilities
- **Multi-document analysis engine** for various file formats
- **Advanced signature detection** with behavioral analysis
- **Document-aware decryption** and recovery
- **Intelligent quarantine system** with metadata tracking
- **Real-time GUI** with progress tracking (Windows-compatible)
- **Automatic fallback** to CLI mode if GUI fails
- **Comprehensive reporting** and forensic analysis

## Installation

### Basic Requirements
- Python 3.8+
- Virtual machine (VirtualBox, VMware, etc.)
- Windows/Linux/macOS

### Optional Libraries (for full document support)
```bash
pip install python-docx PyPDF2 openpyxl python-pptx
```

**Note**: The program works without these libraries but with reduced document format support.

## How to Use

### Step 1: Run the Virus (Testing Only)

```bash
python virus.py
```

The virus will:
1. Ask you to confirm it's for educational use
2. Check if you're in a VM (recommended)
3. Create `odyssey_test_environment/` folder
4. Generate sample files in multiple formats
5. Create encrypted copies using ROT13
6. Show educational popups explaining the process
7. Generate comprehensive logs and metadata

### Step 2: Run the Antivirus

```bash
python antivirus.py
```

The antivirus automatically detects your system and offers:

**GUI Mode (Recommended):**
- Modern tabbed interface with real-time progress
- Click "Start Multi-Document Scan" 
- Review detected threats in the "Detection Results" tab
- Use "Remove All Threats" to decrypt and recover files
- Monitor quarantine in the "Quarantine Management" tab

**CLI Mode (Automatic fallback):**
- Interactive menu system
- Option 1: Comprehensive System Scan
- Option 2: Quick Scan (current directory)
- Option 3: Remove Detected Threats
- Option 4-6: View quarantine, statistics, and analysis
- Option 7: Exit

## Technical Details

### ROT13 Encryption
ROT13 is a simple substitution cipher that shifts each letter 13 places in the alphabet:
- `A` → `N`, `B` → `O`, `M` → `Z`, `N` → `A`
- Self-inverse: applying ROT13 twice returns the original text
- Only affects letters, preserves numbers and punctuation
- Historically used for spoiler protection in online forums

### Multi-Document Processing
The virus can extract and encrypt text content from:
- **Word Documents (.docx)**: Paragraphs, tables, and formatting
- **PDF Files (.pdf)**: Text extraction from all pages
- **Excel Spreadsheets (.xlsx)**: All sheets and cell content
- **PowerPoint Presentations (.pptx)**: Text from all slides
- **Text Files**: .txt, .md, .csv, .py, .js, .html, .css

### Detection Methods
The antivirus uses multiple detection techniques:
- **Signature-based**: Known virus patterns and identifiers
- **Heuristic analysis**: Statistical analysis for encrypted content
- **Behavioral detection**: File naming patterns and structures
- **Document analysis**: Format-specific content inspection
- **Integrity verification**: File hashing and validation

## Virus Artifacts Created

The virus generates these identifiable artifacts:
- Files ending in `_ODYSSEY_ENCRYPTED.*`
- `odyssey_activity.log` - detailed execution log
- `.odyssey_infection_marker` - JSON metadata file
- `odyssey_encrypted_payload.dat` - encrypted virus information
- `odyssey_encryption_manifest.json` - file encryption tracking
- Temporary files with `ODYSSEY_LOCKED_` prefix

## Troubleshooting

### Common Issues

**"No threats detected"**
- Make sure you ran the virus first to create test files
- Check that files were created in `odyssey_test_environment/`
- Verify the antivirus is scanning the correct directory

**GUI won't open on Windows**
- The program automatically falls back to CLI mode
- For debugging, check the console output for detailed error messages
- Test tkinter: `python -c "import tkinter; print('tkinter works')"`

**"Library not available" messages**
- Install optional libraries: `pip install python-docx PyPDF2 openpyxl python-pptx`
- The program works with reduced functionality without these libraries
- Text file processing always works regardless of missing libraries

**Permission errors**
- Ensure you're running from a writable directory
- Check antivirus software isn't blocking file operations
- Run from a location without restricted permissions

**Character encoding issues**
- Updated version includes Windows-compatible text output
- If you see weird characters, make sure you have the latest version
- Console encoding issues are automatically handled

### Debug Mode
If you're having issues, the antivirus now includes extensive debugging:
```bash
python antivirus.py
```
Look for `DEBUG:` messages that show exactly where any problems occur.

### Windows-Specific Notes
- The program automatically detects Windows and uses compatible text formatting
- GUI issues are handled with automatic CLI fallback
- All file operations use cross-platform compatible methods

## Educational Value

This project demonstrates key cybersecurity concepts:

### Malware Analysis
- **Static analysis**: File signature and pattern detection
- **Dynamic analysis**: Behavioral monitoring and heuristics
- **Document malware**: Format-specific threat detection
- **Cryptographic analysis**: Cipher identification and breaking

### Security Programming
- **Defensive coding**: Input validation and error handling
- **Cross-platform compatibility**: Windows/Linux/macOS support
- **User interface design**: Both GUI and CLI interfaces
- **Logging and forensics**: Comprehensive activity tracking

### Cryptography
- **Classical ciphers**: ROT13 implementation and analysis
- **Frequency analysis**: Statistical detection methods
- **Key recovery**: Automated decryption techniques
- **Algorithm weakness**: Understanding cipher limitations

## Development Notes

### Challenges Overcome
- **Windows GUI compatibility**: Extensive testing and fallback mechanisms
- **Multi-format processing**: Different libraries for various document types
- **Cross-platform support**: Unicode handling and path compatibility
- **Error handling**: Graceful degradation when libraries are missing
- **User experience**: Automatic detection of best interface mode

### Code Quality
- **Modular design**: Separate classes for different functionality
- **Comprehensive logging**: Detailed activity tracking for analysis
- **Error recovery**: Fallback mechanisms for various failure modes
- **Documentation**: Extensive comments and docstrings throughout

## Academic Information

**Course**: Information Assurance and Security 1  
**Institution**: National Teachers College  
**Due Date**: June 23, 2025  
**Project Type**: Virus/Antivirus Development  

### Learning Objectives Achieved
- ✅ Malware behavior simulation and analysis
- ✅ Multi-format document security assessment
- ✅ Cryptographic algorithm implementation (ROT13)
- ✅ Cross-platform security tool development
- ✅ User interface design for security applications
- ✅ Comprehensive logging and forensic analysis

## Group Members

**Rhence Bryan Tavera**

## Safety Disclaimer

**⚠️ EDUCATIONAL USE ONLY ⚠️**

This software is designed exclusively for academic purposes and cybersecurity education. 

- **NEVER** run on production systems or personal computers
- **ALWAYS** use in isolated virtual machine environments
- **DO NOT** distribute outside academic contexts
- **RESPECT** ethical guidelines and institutional policies

We are not responsible for any damage caused by misuse of this educational software.

---

*"The best way to learn about cybersecurity is to understand both sides of the equation - how attacks work and how to defend against them."*