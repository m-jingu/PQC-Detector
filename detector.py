#!/usr/bin/env python3
"""
PQC-Detector: Extract TLS/QUIC ServerHello information from pcap files

This tool analyzes pcap files to extract ServerHello packet information including
KeyShareGroup and CipherSuite for PQC (Post-Quantum Cryptography) analysis.

Features:
- Supports both TLS and QUIC protocols
- Parallel processing for multiple pcap files
- Memory-optimized processing with display filters
- Automatic decompression of zst-compressed files
- Configurable temporary directory for decompression
- Memory usage monitoring (pyshark and tshark processes)
- CSV output for easy aggregation
- Performance metrics and logging
"""

import argparse
import concurrent.futures
import csv
import datetime as dt
import logging
import os
import psutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import List, Optional, Tuple

import yaml


def load_config(config_path: Path) -> dict:
    with config_path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def ensure_run_directory(base_dir: Path) -> Path:
    timestamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = base_dir / timestamp
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


def decompress_zst_file(zst_path: Path, logger: logging.Logger, temp_dir: Optional[Path] = None) -> Optional[Path]:
    """Decompress a .zst file and return the path to the temporary decompressed file."""
    try:
        # Check if zstd is available
        subprocess.run(["zstd", "--version"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        logger.error("zstd command not found. Please install zstd to handle .zst files.")
        return None
    
    try:
        # Create temporary file for decompressed data
        if temp_dir:
            temp_dir.mkdir(parents=True, exist_ok=True)
            temp_fd, temp_path = tempfile.mkstemp(suffix=".pcap", prefix="decompressed_", dir=temp_dir)
        else:
            temp_fd, temp_path = tempfile.mkstemp(suffix=".pcap", prefix="decompressed_")
        os.close(temp_fd)  # Close the file descriptor, we'll use the path
        
        # Decompress the file
        logger.info("Decompressing %s...", zst_path)
        result = subprocess.run(
            ["zstd", "-d", "-f", str(zst_path), "-o", temp_path],
            capture_output=True,
            text=True,
            check=True
        )
        
        logger.info("Successfully decompressed %s to %s", zst_path, temp_path)
        return Path(temp_path)
        
    except subprocess.CalledProcessError as e:
        logger.error("Failed to decompress %s: %s", zst_path, e.stderr)
        return None
    except Exception as e:
        logger.error("Unexpected error decompressing %s: %s", zst_path, e)
        return None


def setup_logging(log_dir: Path, level: str, log_file_name: str) -> logging.Logger:
    """Setup dedicated logger for PQC-Detector with file and console handlers."""
    logger = logging.getLogger("pqc_detector")
    
    # Clear any existing handlers to avoid duplication
    logger.handlers.clear()
    
    log_level = getattr(logging, level.upper(), logging.INFO)
    logger.setLevel(log_level)
    
    # Create formatter
    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(processName)s %(message)s"
    )
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler
    log_file = log_dir / log_file_name
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    # Prevent propagation to root logger
    logger.propagate = False
    
    return logger


def discover_pcap_files(input_path: Path) -> List[Path]:
    if input_path.is_file():
        return [input_path]
    pcaps: List[Path] = []
    for ext in ("*.pcap", "*.pcapng", "*.pcap.zst", "*.pcapng.zst"):
        pcaps.extend(input_path.rglob(ext))
    return sorted(pcaps)


def output_csv_path(run_dir: Path, pcap_path: Path) -> Path:
    base = pcap_path.name
    # Remove all extensions (handle .pcap.zst, .pcapng.zst, etc.)
    while "." in base:
        base = base[: base.rfind(".")]
    return run_dir / f"{base}_serverhello.csv"


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Extract TLS/QUIC ServerHello info to CSV")
    parser.add_argument("pcap_input", type=str, help="pcap file or directory")
    parser.add_argument("--workers", type=int, default=None, help="number of parallel workers")
    parser.add_argument("--config", type=str, default="config.yaml", help="config file path")
    parser.add_argument("--temp-dir", type=str, default=None, help="directory for zst decompression")
    return parser.parse_args(argv)


def get_workers(config: dict, cli_workers: Optional[int]) -> int:
    if cli_workers is not None:
        return max(1, cli_workers)
    workers = int(config.get("parallel", {}).get("workers", 0))
    if workers and workers > 0:
        return workers
    try:
        return max(1, os.cpu_count() or 1)
    except Exception:
        return 1


def process_single_pcap(pcap_path: Path, out_csv: Path, temp_dir: Optional[Path] = None) -> Tuple[Path, int, int, int, float]:
    """
    Process a single pcap file and extract ServerHello information.
    
    Returns:
        Tuple of (pcap_path, extracted_count, error_count, iterated_count, duration)
    """
    import pyshark
    
    # Setup logger for child process
    logger = logging.getLogger("pqc_detector")
    if not logger.handlers:
        # Recreate logger setup for child process using environment variables
        log_level = os.environ.get("PQC_DETECTOR_LOG_LEVEL", "INFO")
        log_file = os.environ.get("PQC_DETECTOR_LOG_FILE", "detector.log")
        
        logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
        
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(processName)s %(message)s"
        )
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        
        # File handler
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
        logger.propagate = False

    extracted = 0
    errors = 0
    iterated = 0
    t0 = time.time()
    
    # Monitor memory usage
    process = psutil.Process()
    initial_memory = process.memory_info().rss / 1024 / 1024
    logger.info("Initial memory usage: %.1f MB", initial_memory)
    
    def get_tshark_memory():
        """Get total memory usage of all tshark processes"""
        total_tshark_memory = 0
        for proc in psutil.process_iter():
            try:
                if 'tshark' in proc.name().lower():
                    total_tshark_memory += proc.memory_info().rss / 1024 / 1024
            except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                continue
        return total_tshark_memory
    
    # Handle compressed files
    actual_pcap_path = pcap_path
    temp_file = None
    
    if pcap_path.suffix.lower() == '.zst':
        logger.info("Detected .zst compressed file: %s", pcap_path)
        temp_file = decompress_zst_file(pcap_path, logger, temp_dir)
        if temp_file is None:
            logger.error("Failed to decompress %s", pcap_path)
            return pcap_path, 0, 1, 0, 0.0
        actual_pcap_path = temp_file
        logger.info("Using decompressed file: %s", actual_pcap_path)

    try:
        # Memory-optimized capture settings for large files
        capture = pyshark.FileCapture(
            str(actual_pcap_path),
            keep_packets=False,
            display_filter="(tcp or udp.port==443) and tls.handshake.type == 2",
            include_raw=False,
            override_prefs={
                'ip.defragment': False,
                'tcp.analyze_sequence_numbers': False,
                'tcp.track_bytes_in_flight': False,
                'tcp.relative_sequence_numbers': False,
                'tcp.calculate_timestamps': False,
            }
        )
    except Exception as e:
        logger.error("Failed to open pcap %s: %s", actual_pcap_path, e)
        if temp_file:
            temp_file.unlink(missing_ok=True)  # Clean up temp file
        return pcap_path, 0, 1, 0, 0.0

    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Frame", "Src", "SrcPort", "Dst", "DstPort", "Proto", "KeyShareGroup", "CipherSuite"])

        for pkt in capture:
            try:
                iterated += 1
                
                # Monitor memory usage every 1000 packets
                if iterated % 1000 == 0:
                    current_memory = process.memory_info().rss / 1024 / 1024
                    memory_delta = current_memory - initial_memory
                    tshark_memory = get_tshark_memory()
                    logger.debug("Processed %d packets, pyshark: %.1f MB (delta: %.1f MB), tshark: %.1f MB", 
                                iterated, current_memory, memory_delta, tshark_memory)

                # Extract source and destination addresses (IPv4 -> IPv6 fallback)
                src = getattr(getattr(pkt, "ip", None), "src", None) or getattr(getattr(pkt, "ipv6", None), "src", None)
                dst = getattr(getattr(pkt, "ip", None), "dst", None) or getattr(getattr(pkt, "ipv6", None), "dst", None)
                if not src or not dst:
                    continue

                # Extract source and destination ports (TCP -> UDP fallback)
                src_port = getattr(getattr(pkt, "tcp", None), "srcport", None) or getattr(getattr(pkt, "udp", None), "srcport", None)
                dst_port = getattr(getattr(pkt, "tcp", None), "dstport", None) or getattr(getattr(pkt, "udp", None), "dstport", None)

                # Protocol detection and field extraction
                if hasattr(pkt, "quic"):
                    # QUIC protocol
                    proto_value = "QUIC"
                    key_share = getattr(pkt.quic, "tls_handshake_extensions_key_share_group", "")
                    cipher = getattr(pkt.quic, "tls_handshake_ciphersuite", "")
                else:
                    # TLS protocol (requires tls layer)
                    tls = getattr(pkt, "tls", None)
                    if tls is None:
                        continue
                    
                    # Determine TLS version
                    proto_value = (
                        getattr(tls, "handshake_extensions_supported_version", "")
                        or getattr(tls, "handshake_version", "")
                        or getattr(tls, "record_version", "")
                        or "TLS"
                    )
                    
                    # Extract TLS fields
                    key_share = getattr(tls, "handshake_extensions_key_share_group", "")
                    cipher = getattr(tls, "handshake_ciphersuite", "")

                frame_no = str(getattr(getattr(pkt, "frame_info", None), "number", ""))
                if not frame_no:
                    continue

                writer.writerow([
                    frame_no,
                    str(src),
                    str(src_port or ""),
                    str(dst),
                    str(dst_port or ""),
                    str(proto_value or ""),
                    str(key_share or ""),
                    str(cipher or ""),
                ])
                extracted += 1

            except Exception as e:
                errors += 1
                logger.debug("Packet parse error on %s: %s", pcap_path, e)
                continue

    try:
        capture.close()
    except Exception:
        pass
    
    # Clean up temporary file if it was created
    if temp_file:
        try:
            temp_file.unlink(missing_ok=True)
            logger.debug("Cleaned up temporary file: %s", temp_file)
        except Exception as e:
            logger.warning("Failed to clean up temporary file %s: %s", temp_file, e)

    # Final memory usage report
    final_memory = process.memory_info().rss / 1024 / 1024
    memory_delta = final_memory - initial_memory
    final_tshark_memory = get_tshark_memory()
    logger.info("Final memory usage - pyshark: %.1f MB (delta: %.1f MB), tshark: %.1f MB", 
                final_memory, memory_delta, final_tshark_memory)
    
    duration = max(0.000001, time.time() - t0)
    return pcap_path, extracted, errors, iterated, duration


def run_parallel(pcaps: List[Path], run_dir: Path, workers: int, temp_dir: Optional[Path] = None) -> None:
    """Process multiple pcap files in parallel and collect performance metrics."""
    logger = logging.getLogger("pqc_detector")
    
    total = len(pcaps)
    if total == 0:
        logger.info("No pcap files found.")
        return

    logger.info("Processing %d pcap(s) with %d worker(s)", total, workers)

    with concurrent.futures.ProcessPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(process_single_pcap, p, output_csv_path(run_dir, p), temp_dir) for p in pcaps]

        total_extracted = total_errors = total_iterated = 0
        total_duration = 0.0
        
        for future in concurrent.futures.as_completed(futures):
            try:
                pcap_path, extracted, errors, iterated, duration = future.result()
                rate = (iterated / duration) if duration > 0 else 0.0
                logger.info(
                    "Done %s: extracted=%d, errors=%d, iterated=%d, time=%.3fs, rate=%.1f pkt/s",
                    pcap_path, extracted, errors, iterated, duration, rate,
                )
                total_extracted += extracted
                total_errors += errors
                total_iterated += iterated
                total_duration += duration
            except Exception as e:
                logger.error("Worker failed: %s", e)
                
        if total_duration > 0:
            avg_rate = total_iterated / total_duration
            logger.info(
                "Summary: extracted=%d, errors=%d, iterated=%d, total_time=%.3fs, avg_rate=%.1f pkt/s",
                total_extracted, total_errors, total_iterated, total_duration, avg_rate,
            )


def main(argv: Optional[List[str]] = None) -> int:
    """Main entry point for the PQC-Detector tool."""
    args = parse_args(argv)

    # Load configuration
    config_path = Path(args.config).resolve()
    if not config_path.exists():
        print(f"Config file not found: {config_path}", file=sys.stderr)
        return 1

    config = load_config(config_path)
    base_dir = Path(config.get("output", {}).get("base_dir", "result")).resolve()
    run_dir = ensure_run_directory(base_dir)

    # Setup logging
    log_level = str(config.get("logging", {}).get("level", "INFO"))
    log_file_name = str(config.get("logging", {}).get("file", "detector.log"))
    logger = setup_logging(run_dir, log_level, log_file_name)
    
    # Set environment variables for child processes
    os.environ["PQC_DETECTOR_LOG_LEVEL"] = log_level
    os.environ["PQC_DETECTOR_LOG_FILE"] = str(run_dir / log_file_name)

    # Discover input files and determine workers
    input_path = Path(args.pcap_input).resolve()
    pcaps = discover_pcap_files(input_path)
    workers = get_workers(config, args.workers)
    
    # Get temp directory from command line or config
    if args.temp_dir:
        temp_dir = Path(args.temp_dir).resolve()
    else:
        temp_dir_config = config.get("temp", {}).get("decompress_dir")
        temp_dir = Path(temp_dir_config).resolve() if temp_dir_config else None

    logger.info("Run directory: %s", run_dir)
    logger.info("Found %d input pcap(s)", len(pcaps))
    if temp_dir:
        logger.info("Using temp directory: %s", temp_dir)

    # Process files in parallel
    run_parallel(pcaps, run_dir, workers, temp_dir)

    logger.info("All done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
