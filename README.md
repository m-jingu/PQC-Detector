# PQC-Detector

A Python tool for analyzing pcap files to detect Post-Quantum Cryptography (PQC) utilization in TLS/QUIC traffic.

## Features

- **Pcap Analysis**: Extract TLS ServerHello packets from large pcap files (GB scale, millions of packets)
- **PQC Detection**: Identify PQC NamedGroups and analyze utilization rates
- **High Performance**: Parallel processing with configurable worker count
- **Comprehensive Statistics**: Detailed analysis of NamedGroups, CipherSuites, and protocol distribution
- **Human-Readable Output**: Convert protocol versions and cipher suites to readable format

## Tools

### 1. detector.py
Extracts TLS ServerHello packets from pcap files and outputs CSV data.

**Usage:**
```bash
python detector.py <pcap_file_or_directory> [--workers N] [--config config.yaml]
```

**Output:**
- CSV files with ServerHello packet information
- Fields: Frame, Src, Dst, Proto, KeyShareGroup, CipherSuite
- Processing speed metrics (packets/second)

### 2. summary.py
Analyzes CSV output from detector.py and generates statistical summaries.

**Usage:**
```bash
python summary.py <csv_directory> [--config config.yaml]
```

**Output:**
- Total ServerHello packets
- PQC packets and utilization rate
- PQC NamedGroups list and usage frequency
- CipherSuite usage frequency (Top 10)
- Protocol distribution (QUIC/TLS/SSL/DTLS versions)

## Installation

1. **Clone the repository:**
```bash
git clone <repository-url>
cd PQC-Detector
```

2. **Create virtual environment:**
```bash
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

3. **Install dependencies:**
```bash
pip install -r requirements.txt
```

## Configuration

### config.yaml
Main configuration file for both tools:

```yaml
# Output configuration
output:
  base_dir: "result"  # Base directory to store results

# Parallel execution configuration
parallel:
  workers: 0  # 0 means auto: use number of CPU cores

# Logging configuration
logging:
  level: "DEBUG"       # DEBUG, INFO, WARNING, ERROR
  file: "detector.log" # Log file name inside the run directory

# Summary tool configuration
summary:
  mappings_dir: "mappings"  # Directory containing mapping files
```

### Mapping Files

The tool uses three YAML mapping files in the `mappings/` directory:

- **supported_groups.yaml**: Maps NamedGroup IDs to human-readable names and PQC flags
- **cipher_suites.yaml**: Maps CipherSuite IDs to human-readable names
- **protocol_versions.yaml**: Maps protocol version numbers to readable names

## Usage Examples

### Basic Analysis
```bash
# Analyze a single pcap file
python detector.py capture.pcap

# Analyze multiple pcap files in a directory
python detector.py /path/to/pcap/files/

# Generate statistics from CSV output
python summary.py result/20251021_114720
```

### Advanced Configuration
```bash
# Use custom configuration
python detector.py capture.pcap --config my_config.yaml

# Specify number of workers
python detector.py capture.pcap --workers 8

# Analyze with custom mappings
python summary.py result/20251021_114720 --config my_config.yaml
```

## Output Format

### CSV Output (detector.py)
```csv
Frame,Src,Dst,Proto,KeyShareGroup,CipherSuite
1,192.168.1.1,192.168.1.2,QUIC,0x11ec,0x1301
2,192.168.1.2,192.168.1.1,TLSv1.3,29,0x1302
```

### Summary Output (summary.py)
```
=== PQC Detection Summary ===

Total ServerHello packets: 1,000
PQC packets: 150
PQC utilization rate: 15.00%

PQC NamedGroups list:
  - X25519MLKEM768
  - P256Kyber1024

PQC NamedGroups usage frequency (Top 10):
  1. X25519MLKEM768: 100 (10.00%)
  2. P256Kyber1024: 50 (5.00%)

CipherSuite usage frequency (Top 10):
  1. TLS_AES_128_GCM_SHA256: 800 (80.00%)
  2. TLS_AES_256_GCM_SHA384: 200 (20.00%)

Protocol distribution:
  - QUIC: 600 (60.00%)
  - TLSv1.3: 300 (30.00%)
  - TLSv1.2: 100 (10.00%)
```

## Requirements

- Python 3.7+
- pyshark
- PyYAML
- tshark (Wireshark command-line tools)

## File Structure

```
PQC-Detector/
├── detector.py              # Main pcap analysis tool
├── summary.py               # Statistical analysis tool
├── config.yaml              # Configuration file
├── requirements.txt         # Python dependencies
├── README.md               # This file
├── .gitignore              # Git ignore rules
├── mappings/               # Mapping files directory
│   ├── supported_groups.yaml
│   ├── cipher_suites.yaml
│   └── protocol_versions.yaml
└── result/                 # Output directory (created automatically)
    └── YYYYMMDD_HHMMSS/   # Timestamped result directories
        ├── *.csv          # CSV output files
        └── detector.log   # Log files
```
