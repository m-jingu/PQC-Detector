#!/usr/bin/env python3
"""
PQC-Detector: Extract TLS/QUIC ServerHello information from pcap files

This tool analyzes pcap files to extract ServerHello packet information including
KeyShareGroup and CipherSuite for PQC (Post-Quantum Cryptography) analysis.

Features:
- Supports both TLS and QUIC protocols
- Parallel processing for multiple pcap files
- CSV output for easy aggregation
- Configurable via YAML config file
- Performance metrics and logging
"""

import argparse
import concurrent.futures
import csv
import datetime as dt
import logging
import os
import sys
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
    for ext in ("*.pcap", "*.pcapng"):
        pcaps.extend(input_path.rglob(ext))
    return sorted(pcaps)


def output_csv_path(run_dir: Path, pcap_path: Path) -> Path:
    base = pcap_path.name
    if "." in base:
        base = base[: base.rfind(".")]
    return run_dir / f"{base}_serverhello.csv"


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Extract TLS/QUIC ServerHello info to CSV")
    parser.add_argument("pcap_input", type=str, help="pcap file or directory")
    parser.add_argument("--workers", type=int, default=None, help="number of parallel workers")
    parser.add_argument("--config", type=str, default="config.yaml", help="config file path")
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


def process_single_pcap(pcap_path: Path, out_csv: Path) -> Tuple[Path, int, int, int, float]:
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

    try:
        capture = pyshark.FileCapture(
            str(pcap_path),
            keep_packets=False,
            display_filter="tls.handshake.type == 2",
        )
    except Exception as e:
        logger.error("Failed to open pcap %s: %s", pcap_path, e)
        return pcap_path, 0, 1, 0, 0.0

    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Frame", "Src", "Dst", "SrcPort", "Proto", "KeyShareGroup", "CipherSuite"])

        for pkt in capture:
            try:
                iterated += 1

                # Extract source and destination addresses (IPv4 -> IPv6 fallback)
                src = getattr(getattr(pkt, "ip", None), "src", None) or getattr(getattr(pkt, "ipv6", None), "src", None)
                dst = getattr(getattr(pkt, "ip", None), "dst", None) or getattr(getattr(pkt, "ipv6", None), "dst", None)
                if not src or not dst:
                    continue

                # Extract source port (TCP -> UDP fallback)
                src_port = getattr(getattr(pkt, "tcp", None), "srcport", None) or getattr(getattr(pkt, "udp", None), "srcport", None)

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
                    str(dst),
                    str(src_port or ""),
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

    duration = max(0.000001, time.time() - t0)
    return pcap_path, extracted, errors, iterated, duration


def run_parallel(pcaps: List[Path], run_dir: Path, workers: int) -> None:
    """Process multiple pcap files in parallel and collect performance metrics."""
    logger = logging.getLogger("pqc_detector")
    
    total = len(pcaps)
    if total == 0:
        logger.info("No pcap files found.")
        return

    logger.info("Processing %d pcap(s) with %d worker(s)", total, workers)

    with concurrent.futures.ProcessPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(process_single_pcap, p, output_csv_path(run_dir, p)) for p in pcaps]

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

    logger.info("Run directory: %s", run_dir)
    logger.info("Found %d input pcap(s)", len(pcaps))

    # Process files in parallel
    run_parallel(pcaps, run_dir, workers)

    logger.info("All done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
