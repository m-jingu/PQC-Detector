# PQC-Detector

A Python tool for analyzing pcap files to detect Post-Quantum Cryptography (PQC) utilization in TLS/QUIC traffic.

## Features

- **Dual Protocol Analysis**: Extract both TLS ServerHello and ClientHello packets from large pcap files (GB scale, millions of packets)
- **Memory Optimization**: Efficient processing with display filters and memory monitoring
- **Compression Support**: Automatic decompression of zst-compressed pcap files
- **PQC Detection**: Identify PQC NamedGroups and analyze utilization rates
- **Packet Matching**: Match ServerHello and ClientHello packets to identify PQC servers
- **High Performance**: Parallel processing with configurable worker count
- **Comprehensive Statistics**: Detailed analysis of NamedGroups, CipherSuites, and protocol distribution
- **Human-Readable Output**: Convert protocol versions and cipher suites to readable format
- **PQC Server Analysis**: Optional identification of PQC-enabled servers with ServerName and port

## Tools

### 1. detector.py
Extracts TLS ServerHello or ClientHello packets from pcap files and outputs CSV data.

**Usage:**
```bash
python detector.py <pcap_file_or_directory> [-m|--mode server|client] [--workers N] [--config config.yaml] [--temp-dir DIR]
```

**Modes:**
- `-m server` or `--mode server` (default): Extract ServerHello packets
- `-m client` or `--mode client`: Extract ClientHello packets

**Output:**
- **ServerHello mode**: CSV files with `*_serverhello.csv` containing Frame, Src, SrcPort, Dst, DstPort, Proto, KeyShareGroup, CipherSuite
- **ClientHello mode**: CSV files with `*_clienthello.csv` containing Frame, Src, SrcPort, Dst, DstPort, Proto, SupportedGroups, ServerName
- Processing speed metrics (packets/second)
- Memory usage monitoring (pyshark and tshark processes)
- Automatic cleanup of temporary decompressed files

### 2. summary.py
Analyzes CSV output from detector.py and generates statistical summaries with optional PQC server analysis.

**Usage:**
```bash
python summary.py <csv_directories...> [--config config.yaml] [--pqc-servers|-p FILE]
```

**Options:**
- `--pqc-servers FILE` or `-p FILE`: Enable PQC server analysis and output to specified file

**Output:**
- **ServerHello Analysis**: Total packets, PQC utilization, NamedGroups, CipherSuites, Protocol distribution, SrcPort distribution
- **ClientHello Analysis**: Total packets, PQC utilization, SupportedGroups, Protocol distribution, DstPort distribution
- **PQC Server Analysis** (optional): List of PQC-enabled servers in "ServerName:Port" format

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

4. **Install zstd (for compressed file support):**
```bash
# macOS
brew install zstd

# Ubuntu/Debian
sudo apt-get install zstd

# CentOS/RHEL
sudo yum install zstd
```

5. **Install tshark (Wireshark command-line tools):**
```bash
# macOS
brew install wireshark

# Ubuntu/Debian
sudo apt-get install tshark

# CentOS/RHEL
sudo yum install wireshark
```

## Configuration

### config.yaml
Main configuration file for both tools:

```yaml
# Output configuration
output:
  base_dir: "result"  # Base directory to store results

# Temporary file configuration
temp:
  decompress_dir: null  # Directory for zst decompression (null = system temp)

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
# Analyze ServerHello packets (default)
python detector.py capture.pcap

# Analyze ClientHello packets
python detector.py capture.pcap -m client

# Analyze multiple pcap files in a directory
python detector.py /path/to/pcap/files/

# Analyze compressed pcap files
python detector.py /path/to/compressed/files/*.pcap.zst

# Generate statistics from CSV output
python summary.py result/20251021_114720

# Generate statistics with PQC server analysis
python summary.py result/20251021_114720 --pqc-servers pqc_servers.txt
```

### Memory-Optimized Analysis
```bash
# Monitor memory usage during processing
python detector.py large_file.pcap

# Check memory usage in logs
tail -f result/YYYYMMDD_HHMMSS/detector.log | grep "memory usage"

# Process with reduced worker count for memory-constrained systems
python detector.py /path/to/pcap/files/ --workers 4

# Use custom temp directory for zst decompression
python detector.py /path/to/pcap/files/ --temp-dir /fast/ssd/temp
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

**ServerHello mode:**
```csv
Frame,Src,SrcPort,Dst,DstPort,Proto,KeyShareGroup,CipherSuite
1,192.168.1.1,12345,192.168.1.2,443,TLSv1.3,29,0x1301
2,192.168.1.2,443,192.168.1.1,12345,QUIC,0x11ec,0x1302
```

**ClientHello mode:**
```csv
Frame,Src,SrcPort,Dst,DstPort,Proto,SupportedGroups,ServerName
1,192.168.1.1,12345,192.168.1.2,443,TLS,29,30,example.com
2,192.168.1.1,12346,192.168.1.2,443,QUIC,29,30,api.example.com
```

### Summary Output (summary.py)
```
=== ServerHello Analysis ===

Total ServerHello packets: 500
PQC packets: 75
PQC utilization rate: 15.00%

=== PQC ServerHello Packet Analysis ===

PQC ServerHello NamedGroups usage frequency (Top 10):
  1. X25519MLKEM768: 50 (10.00%)
  2. P256Kyber1024: 25 (5.00%)

PQC ServerHello packet CipherSuite distribution (Top 10):
   1. TLS_AES_256_GCM_SHA384: 60 (80.00%)
   2. TLS_CHACHA20_POLY1305_SHA256: 15 (20.00%)

PQC ServerHello packet Protocol distribution:
  - TLSv1.3: 60 (80.00%)
  - QUIC: 15 (20.00%)

PQC ServerHello packet SrcPort distribution (Top 10):
   1. Port 443: 60 (80.00%)
   2. Port 8443: 15 (20.00%)

=== All ServerHello Packet Analysis ===

ServerHello CipherSuite usage frequency (Top 10):
  1. TLS_AES_256_GCM_SHA384: 400 (80.00%)
  2. TLS_CHACHA20_POLY1305_SHA256: 100 (20.00%)

ServerHello Protocol distribution:
  - TLSv1.3: 300 (60.00%)
  - QUIC: 200 (40.00%)

ServerHello SrcPort distribution (Top 10):
   1. Port 443: 400 (80.00%)
   2. Port 8443: 100 (20.00%)

=== ClientHello Analysis ===

Total ClientHello packets: 300
PQC packets: 45
PQC utilization rate: 15.00%

=== PQC ClientHello Packet Analysis ===

PQC ClientHello SupportedGroups usage frequency (Top 10):
  1. X25519MLKEM768: 30 (10.00%)
  2. P256Kyber1024: 15 (5.00%)

PQC ClientHello packet Protocol distribution:
  - TLS: 30 (66.67%)
  - QUIC: 15 (33.33%)

PQC ClientHello packet DstPort distribution (Top 10):
   1. Port 443: 36 (80.00%)
   2. Port 8443: 9 (20.00%)

=== All ClientHello Packet Analysis ===

ClientHello Protocol distribution:
  - TLS: 200 (66.67%)
  - QUIC: 100 (33.33%)

ClientHello DstPort distribution (Top 10):
   1. Port 443: 240 (80.00%)
   2. Port 8443: 60 (20.00%)
```

### PQC Server List (optional)
```
example.com:443
api.example.com:8443
secure.example.org:443
pqc-test.example.net:9443
```

## Requirements

- Python 3.7+
- pyshark
- PyYAML
- psutil (for memory monitoring)
- tshark (Wireshark command-line tools)
- zstd (for compressed file support)

## File Structure

```
PQC-Detector/
├── detector.py              # Main pcap analysis tool (ServerHello/ClientHello)
├── summary.py               # Statistical analysis tool with PQC server analysis
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
        ├── *_serverhello.csv  # ServerHello CSV output files
        ├── *_clienthello.csv  # ClientHello CSV output files
        └── detector.log   # Log files with memory usage monitoring
```
