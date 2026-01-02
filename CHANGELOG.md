# Changelog

All notable changes to Cipher Aegis will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- PCAP file replay for offline analysis
- Multi-interface capture support
- Email notification system

## [1.0.1] - 2026-01-02

### Added
- `logs/.gitkeep` file to preserve directory structure in version control
- Database file exclusions to .gitignore (`*.db`, `*.db-journal`)
- RELEASE_NOTES.md for tracking updates

### Changed
- Updated .gitignore to properly handle logs directory (exclude files, preserve structure)
- Updated .gitignore to exclude SQLite database files from version control

### Fixed
- Logs directory now properly preserved in repository structure
- Database runtime files no longer tracked by git

## [1.0.0] - 2026-01-02

### Added
- Initial release of Cipher Aegis
- Network packet capture using Scapy
- Bidirectional flow aggregation with 5-tuple identification
- 16-dimensional feature extraction for ML
- Isolation Forest-based anomaly detection
- Training mode for baseline learning (60-second default)
- Protection mode for real-time detection
- SQLite database for flow and anomaly persistence
- Real-time Streamlit dashboard with metrics and visualizations
- Threat classification (HIGH/MEDIUM/LOW)
- System logging with severity levels
- Test data generator for demo mode
- Command-line interface with configurable parameters
- Model persistence (save/load trained models)
- Thread-safe architecture for concurrent processing
- Comprehensive documentation and API reference

### Technical Details
- Python 3.11+ with full type hints
- Asynchronous packet capture (5000+ packets/sec)
- Flow processing rate: 1000 flows/sec
- Memory efficient: ~5KB per active flow
- SQLite database with optimized indexes
- StandardScaler normalization for ML features

### Supported Platforms
- Windows 10/11 (with Npcap)
- Linux (kernel 2.6+)
- macOS 10.14+

### Dependencies
- scapy >= 2.5.0
- scikit-learn >= 1.3.0
- pandas >= 2.0.0
- numpy >= 1.24.0
- streamlit >= 1.28.0
- plotly >= 5.17.0

## [0.9.0-beta] - 2026-01-01

### Added
- Beta release for testing
- Core packet capture functionality
- Basic feature extraction
- Prototype dashboard

### Known Issues
- Training mode not yet implemented
- Limited protocol support
- No model persistence

## [0.1.0-alpha] - 2025-12-15

### Added
- Initial project structure
- Basic packet sniffing proof of concept
- Development environment setup
