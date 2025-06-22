# Virus and Antivirus Project

Information Assurance and Security 1 - National Teachers College

## What This Is

This is our virus and antivirus project for the Information Assurance and Security 1 class. We had to make a simple virus that encrypts files using our preferred cipher and language, then build an antivirus that can detect and remove it.

**IMPORTANT: Only run this stuff in a VM. Don't be stupid and run it on your real computer.**

## Files

```
project/
├── odyssey_antivirus_quarantine/   (created when antivirus runs)
├── virus_test_area/                (created when virus runs)
├── antivirus_activity.log
├── antivirus.py
├── README.md
├── virus_activity.log
└── virus.py
```

## How to Use

### Step 1: Run the Virus (Testing Only)

```bash
python virus.py
```

This creates some test files and encrypts them with ROT13. It will:
- Ask you to confirm it's for educational use
- Create a folder called `virus_test_area`
- Make some sample files and encrypt copies of them
- Show some popup messages about the encryption
- Create log files

### Step 2: Run the Antivirus

```bash
python antivirus.py
```

If you have a GUI it will open a window. Otherwise it runs in the terminal.

**GUI Mode:**
- Click "Start System Scan" 
- Wait for it to find the virus files
- Click "Remove Detected Viruses" to clean everything up

**Terminal Mode:**
- Pick option 1 to scan
- Pick option 3 to remove viruses
- Pick option 6 to exit

## What the Virus Does

- Finds text files in its target folder
- Makes encrypted copies using ROT13 (shifts letters by 13)
- Adds "_ODYSSEY_ENCRYPTED" to the filenames
- Creates some metadata files and logs
- Shows educational popups explaining what it's doing

It's completely safe - doesn't actually damage anything.

## What the Antivirus Does

- Scans for files with virus signatures
- Looks for the specific patterns our virus creates
- Decrypts the ROT13 encrypted files
- Removes virus artifacts and logs
- Can quarantine suspicious files instead of deleting them

## ROT13 Explanation

ROT13 is a really simple "encryption" where you shift each letter 13 places in the alphabet:
- A becomes N
- B becomes O  
- N becomes A
- etc.

It's weak encryption (more like obfuscation) but good for learning how ciphers work.

## Requirements

- Python 3.8+
- Virtual machine (VirtualBox, VMware, whatever)
- That's pretty much it

## Testing

1. Run the virus first to create infected files
2. Run the antivirus to detect and clean them
3. Check the log files to see what happened

## Troubleshooting

**"No threats detected"** - Make sure you ran the virus first

**GUI won't open** - The program will automatically use terminal mode instead

**Permission errors** - Make sure you're running from a folder you can write to

**Weird character errors** - You might have an old version, get the updated files

## Project Notes

This was harder than we thought. Getting the GUI to work properly took forever, and we had to fix a bunch of encoding issues. The ROT13 part was easy but making the antivirus detect everything correctly was tricky.

The virus creates these files:
- Files ending in "_ODYSSEY_ENCRYPTED" 
- "odyssey_activity.log"
- ".odyssey_infection_marker"
- "odyssey_encrypted_payload.dat"

The antivirus looks for all of these and cleans them up.

## Academic Stuff

This project demonstrates:
- Basic malware analysis
- Simple cryptography (ROT13)
- File system operations
- Virus detection techniques
- Python GUI programming

Due date: June 23, 2025

## Group Members

Rhence Bryan Tavera

---

**Again: ONLY USE THIS IN A VIRTUAL MACHINE. We're not responsible if you run this on your main computer and something goes wrong.**