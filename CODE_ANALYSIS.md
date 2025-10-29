# Code Analysis

I analyzed my codebase to figure out what's actually working and what's just simulated or broken.

## What I Found

A lot of it was simulated or had bugs that made it not work properly. Here's what I discovered:

### 1. eBPF Only Counted Syscalls

The eBPF code was only counting syscalls (like "process 1234 has 50 syscalls") but never capturing WHICH syscalls (read, write, execve, etc.). Then in Python it was simulating events based on those counts.

This made the whole risk scoring system basically useless since it couldn't tell what syscalls were actually happening.

### 2. ML Trained on Random Data

The ML models were being trained on completely random fake data using random.uniform() and random.randint(). The syscall sequences were just randomly generated patterns that had nothing to do with real system behavior.

This made the models useless for actual anomaly detection.

### 3. Memory Leaks

Processes were never being cleaned up from memory, so the dict just kept growing indefinitely. After running for a while it would use tons of memory.

### 4. Race Conditions

There were like 5 different lock sections in one method, and processes could be deleted between locks. Had data corruption issues.

### 5. Container Detection Failing

Regex patterns were wrong and it kept failing silently. The detection logic wasn't robust enough.

## Summary

Architecture was good, but a lot of the core functionality wasn't actually working. I had to go through and fix these bugs to make it functional.

See FIXES_PROGRESS.md for what I fixed.
