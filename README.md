# Adaptive eBPF-Driven Memory Forensics and Anomaly Intelligence System

This project implements a real-time memory-behavior monitoring and anomaly-detection platform using eBPF and Rust. The system captures structural memory events directly from the kernel, extracts behavioral signals, and feeds them into a user-space analysis engine that learns normal per-process memory patterns and flags deviations such as code injection, fileless malware activity, or abnormal JIT behavior.

The design is fully non-invasive: only memory metadata is collected, and no process memory contents are ever accessed.

## Overview

Memory-based attacks have become increasingly dynamic and evasive. Traditional signature-driven or rule-based systems struggle to detect these behaviors. This project uses eBPF to gather high-fidelity memory telemetry and combines it with adaptive anomaly modeling to detect suspicious activity in real time.

## Architecture

This workspace contains three Rust crates that work together:

### `memory-analyzer-ebpf`
Holds the eBPF programs that attach to kernel functions and tracepoints related to memory events (allocations, page faults, mmap/munmap, mprotect transitions, COW activity). These probes emit compact event structs to user space through a ring buffer.

### `memory-analyzer-common`
Contains shared structs, constants, and data formats used by both the eBPF programs and the user-space analyzer. This ensures consistent serialization and event layouts across components.

### `memory-analyzer`
The user-space controller and analysis engine. It loads and attaches the eBPF probes, receives event streams, extracts behavioral features, and feeds time-series data into an LSTM autoencoder trained to model normal per-process memory behavior. It correlates entropy drifts, mapping churn, and syscall patterns to surface anomalies. A real-time dashboard provides visualization of memory activity and detected anomalies.

## Key Features

- Real-time tracing of memory allocations, page faults, protection changes, and mapping transitions using eBPF  
- Extraction of behavioral indicators: entropy drift, W+X regions, COW bursts, RSS variance, mapping churn  
- LSTM autoencoder for modeling per-process memory fingerprints  
- Detection of code injection, fileless malware unpacking, and abnormal JIT-generated code  
- High recall for unauthorized memory injection through correlation of memory and syscall behavior  
- Metadata-only monitoring with no access to process memory contents  
- Dashboard for live visualization and anomaly monitoring

## Goals

- Provide a precise, low-overhead approach to memory forensics  
- Detect stealthy or evolving memory-based threats with fewer false positives  
- Demonstrate modern eBPF-driven observability techniques for host security  
- Build a modular foundation that can be extended with additional signal types or ML models

## Project Status

The repository currently contains the initial workspace structure. Implementation will proceed through kernel probe development, event streaming, feature engineering, model integration, and dashboard components.
