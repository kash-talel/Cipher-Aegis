# Release Notes - v1.0.1

## Date: 2026-01-02

## Changes

### Infrastructure Updates

**Added:**
- `logs/.gitkeep` - Preserves logs directory structure in version control
- Database files (`*.db`, `*.db-journal`) added to .gitignore

**Modified:**
- `.gitignore` - Updated to properly handle:
  - Database files in data/ directory
  - Logs directory (excludes log files but preserves structure)

### Repository Structure

The logs directory is now properly handled in version control:
- Directory structure is preserved via `.gitkeep` file
- Log files are excluded from commits (runtime data only)
- Database files are excluded from commits (runtime data only)

### Documentation Status

All documentation remains current:
- README.md - Comprehensive technical documentation
- CONTRIBUTING.md - Contribution guidelines
- CHANGELOG.md - Version history
- STARTUP_GUIDE.md - Setup and usage instructions
- DASHBOARD_GUIDE.md - Dashboard documentation

### Testing

**Demo Mode Verified:**
- Test data generation working (`generate_test_data.py`)
- Dashboard operational with test data
- No packet capture required for demo mode

**Known Requirements for Live Capture:**
- Npcap installation required (Windows)
- Administrator privileges required
- Virtual environment recommended

### No Breaking Changes

This release contains only infrastructure improvements. All APIs and functionality remain unchanged from v1.0.0.

## Installation

```bash
git clone https://github.com/kash-talel/Cipher-Aegis.git
cd Cipher-Aegis
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or
.\venv\Scripts\Activate.ps1  # Windows

pip install -r requirements.txt
```

## Quick Start

**Demo Mode (No Admin Required):**
```bash
python generate_test_data.py 100 0.15
streamlit run app.py
```

**Live Capture (Requires Admin + Npcap):**
```bash
python main.py
```

## Repository

https://github.com/kash-talel/Cipher-Aegis

## License

MIT License - See LICENSE file for details
