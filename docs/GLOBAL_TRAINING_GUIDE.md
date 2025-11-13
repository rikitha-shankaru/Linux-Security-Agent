# 🌍 Global Training Data Integration Guide

## Overview

This guide explains how to expand the training model to use data from multiple sources:
- **Multiple machines**: Aggregate training data from different systems
- **Shared datasets**: Use pre-collected training datasets
- **Cloud storage**: Load training data from S3, GCS, etc.
- **Centralized platform**: Use the Platform API to share training data
- **Public datasets**: Use research datasets or community-contributed data

---

## Architecture Options

### Option 1: File-Based Data Sharing (Simplest)

```
Machine A → Export training data → training_data.json
Machine B → Export training data → training_data.json
Central Server → Merge all files → Train global model → Distribute model
```

### Option 2: Platform API Integration (Recommended)

```
Multiple Agents → Platform API → Central Training Service
                              ↓
                    Global Model Training
                              ↓
                    Distribute Models to Agents
```

### Option 3: Cloud Storage (Scalable)

```
Agents → Export → S3/GCS → Central Training
                              ↓
                    Global Model → S3/GCS
                              ↓
                    Agents Download Updated Models
```

---

## Implementation Steps

### Step 1: Export Training Data

Add functionality to export training data in a standardized format.

### Step 2: Import Training Data

Add functionality to load training data from external sources.

### Step 3: Merge Multiple Datasets

Combine training data from multiple sources before training.

### Step 4: Global Model Training

Train models on aggregated global data.

### Step 5: Model Distribution

Distribute trained models back to agents.

---

## Usage Examples

### Example 1: Export Local Training Data

```bash
# Export current training data
python3 core/enhanced_security_agent.py --export-training-data training_data.json

# Export with metadata
python3 core/enhanced_security_agent.py --export-training-data training_data.json --include-metadata
```

### Example 2: Train from External Dataset

```bash
# Train from local JSON file
python3 core/enhanced_security_agent.py --train-from-file training_data.json

# Train from multiple files (merged)
python3 core/enhanced_security_agent.py --train-from-files data1.json data2.json data3.json

# Train from directory of files
python3 core/enhanced_security_agent.py --train-from-directory ./training_datasets/
```

### Example 3: Train from Platform API

```bash
# Download training data from Platform API
python3 core/enhanced_security_agent.py --train-from-api https://api.example.com/v1/training-data

# Train from API with filters
python3 core/enhanced_security_agent.py --train-from-api https://api.example.com/v1/training-data \
    --api-filter "environment=production&os=linux"
```

### Example 4: Train from Cloud Storage

```bash
# Train from S3
python3 core/enhanced_security_agent.py --train-from-s3 s3://bucket/training-data/

# Train from Google Cloud Storage
python3 core/enhanced_security_agent.py --train-from-gcs gs://bucket/training-data/
```

### Example 5: Merge and Train

```bash
# Merge local + external data, then train
python3 core/enhanced_security_agent.py --merge-and-train \
    --local-data \
    --external-files data1.json data2.json \
    --output-model global_model.pkl
```

---

## Data Format

### Training Data JSON Format

```json
{
  "version": "1.0",
  "metadata": {
    "source": "machine-1",
    "os": "linux",
    "kernel_version": "5.15.0",
    "collection_date": "2025-01-15T10:00:00Z",
    "total_samples": 500,
    "environment": "production"
  },
  "samples": [
    {
      "syscalls": ["read", "write", "open", "close", "mmap"],
      "process_info": {
        "cpu_percent": 10.5,
        "memory_percent": 5.2,
        "num_threads": 2,
        "pid": 1234
      },
      "metadata": {
        "process_name": "python3",
        "timestamp": "2025-01-15T10:00:00Z"
      }
    }
  ]
}
```

---

## Implementation Code

✅ **IMPLEMENTED** - All functionality has been added to the codebase!

---

## Usage Examples

### Example 1: Export Local Training Data

```bash
# Export current training data to JSON
python3 core/enhanced_security_agent.py --export-training-data my_training_data.json

# The exported file will contain:
# - All syscall sequences from monitored processes
# - Process metrics (CPU, memory, threads)
# - Metadata (source machine, OS, collection date)
```

**Output Format:**
```json
{
  "version": "1.0",
  "metadata": {
    "source": "machine-1",
    "os": "Linux",
    "os_version": "5.15.0",
    "collection_date": "2025-01-15T10:00:00Z",
    "total_samples": 150
  },
  "samples": [
    {
      "syscalls": ["read", "write", "open", "close"],
      "process_info": {
        "cpu_percent": 10.5,
        "memory_percent": 5.2,
        "num_threads": 2,
        "pid": 1234
      }
    }
  ]
}
```

---

### Example 2: Train from Single File

```bash
# Train models from a JSON file
python3 core/enhanced_security_agent.py --train-from-file training_data.json

# Train and append to existing feature store
python3 core/enhanced_security_agent.py --train-from-file training_data.json --append
```

---

### Example 3: Train from Multiple Files (Merged)

```bash
# Train from multiple files - automatically merged
python3 core/enhanced_security_agent.py --train-from-files \
    machine1_data.json \
    machine2_data.json \
    machine3_data.json
```

**What happens:**
1. Loads all 3 files
2. Merges datasets into one
3. Trains models on combined data
4. Saves models

---

### Example 4: Train from Directory

```bash
# Train from all JSON files in a directory
python3 core/enhanced_security_agent.py --train-from-directory ./training_datasets/

# This will:
# - Find all *.json files in the directory
# - Load each file
# - Merge all datasets
# - Train on combined data
```

---

### Example 5: Train from URL/API

```bash
# Train from HTTP/HTTPS URL
python3 core/enhanced_security_agent.py --train-from-url \
    https://api.example.com/v1/training-data

# Train from Platform API
python3 core/enhanced_security_agent.py --train-from-api \
    https://platform.example.com/api/v1/training-data
```

**Note:** The URL should return JSON in the same format as exported files.

---

### Example 6: Merge Local + External Data

```bash
# Collect local data + merge with external files, then train
python3 core/enhanced_security_agent.py --merge-and-train \
    --external-files external1.json external2.json

# This will:
# 1. Collect 10 seconds of local training data
# 2. Load external files
# 3. Merge all datasets
# 4. Train on combined data
```

---

## Complete Workflow: Global Training

### Step 1: Collect Data from Multiple Machines

**On Machine A:**
```bash
sudo python3 core/enhanced_security_agent.py --export-training-data machine_a_data.json
```

**On Machine B:**
```bash
sudo python3 core/enhanced_security_agent.py --export-training-data machine_b_data.json
```

**On Machine C:**
```bash
sudo python3 core/enhanced_security_agent.py --export-training-data machine_c_data.json
```

### Step 2: Transfer Files to Central Server

```bash
# Copy all files to central server
scp machine_*_data.json central-server:/data/training/
```

### Step 3: Train Global Model

**On Central Server:**
```bash
# Train from all files (merged)
python3 core/enhanced_security_agent.py --train-from-directory /data/training/

# Or specify files explicitly
python3 core/enhanced_security_agent.py --train-from-files \
    /data/training/machine_a_data.json \
    /data/training/machine_b_data.json \
    /data/training/machine_c_data.json
```

### Step 4: Distribute Models

```bash
# Copy trained models to all machines
scp ~/.cache/security_agent/*.pkl machine-a:~/.cache/security_agent/
scp ~/.cache/security_agent/*.pkl machine-b:~/.cache/security_agent/
scp ~/.cache/security_agent/*.pkl machine-c:~/.cache/security_agent/
```

---

## Advanced: Cloud Storage Integration

### Using AWS S3

```python
# Example script to upload/download training data
import boto3
import json

# Upload training data
s3 = boto3.client('s3')
with open('training_data.json', 'rb') as f:
    s3.upload_fileobj(f, 'my-bucket', 'training-data/global.json')

# Download and train
s3.download_file('my-bucket', 'training-data/global.json', 'downloaded.json')
# Then: python3 core/enhanced_security_agent.py --train-from-file downloaded.json
```

### Using Google Cloud Storage

```python
from google.cloud import storage

# Upload
client = storage.Client()
bucket = client.bucket('my-bucket')
blob = bucket.blob('training-data/global.json')
blob.upload_from_filename('training_data.json')

# Download
blob.download_to_filename('downloaded.json')
```

---

## Integration with Platform API

If you have the Platform API running, you can:

### 1. Export Training Data to API

```python
import requests
import json

# Load training data
with open('training_data.json', 'r') as f:
    data = json.load(f)

# Upload to API
response = requests.post(
    'https://api.example.com/v1/training-data',
    json=data,
    headers={'Authorization': 'Bearer YOUR_TOKEN'}
)
```

### 2. Train from API

```bash
python3 core/enhanced_security_agent.py --train-from-api \
    https://api.example.com/v1/training-data?environment=production
```

---

## Data Validation

The system automatically validates:
- ✅ JSON format correctness
- ✅ Required fields (syscalls, process_info)
- ✅ Data types (lists, floats, ints)
- ✅ Feature dimensions (50 features expected)

Invalid samples are skipped with warnings.

---

## Best Practices

### 1. **Data Quality**
- Only export data from **normal system activity**
- Avoid exporting during attacks or suspicious activity
- Include metadata (OS, kernel version) for better models

### 2. **Data Volume**
- **Minimum**: 50 samples per source
- **Recommended**: 100-500 samples per source
- **Maximum**: 200,000 samples total (bounded)

### 3. **Merging Strategy**
- Merge data from **similar environments** (same OS, similar workloads)
- Or merge diverse data for **general-purpose models**
- Use `--append` to combine with existing local training

### 4. **Model Distribution**
- Train global model on central server
- Distribute models to all agents
- Agents can still do incremental retraining locally

### 5. **Privacy & Security**
- **Sanitize data**: Remove PII, sensitive file paths
- **Encrypt in transit**: Use HTTPS for API/URL transfers
- **Access control**: Use authentication for API endpoints

---

## Troubleshooting

### Issue: "Invalid training data format"
**Solution**: Ensure JSON has `version`, `metadata`, and `samples` fields.

### Issue: "No training data loaded"
**Solution**: Check file paths, URL accessibility, JSON format validity.

### Issue: "Feature dimension mismatch"
**Solution**: All training data must use same feature extraction (50 features). Don't mix old/new code versions.

### Issue: "Error loading from URL"
**Solution**: Check network connectivity, URL accessibility, authentication headers if needed.

---

## Code Locations

**Export functionality:**
- `core/enhanced_anomaly_detector.py` - `export_training_data()`

**Import functionality:**
- `core/enhanced_anomaly_detector.py` - `load_training_data_from_file()`
- `core/enhanced_anomaly_detector.py` - `load_training_data_from_directory()`
- `core/enhanced_anomaly_detector.py` - `load_training_data_from_url()`

**Merge functionality:**
- `core/enhanced_anomaly_detector.py` - `merge_training_datasets()`

**CLI integration:**
- `core/enhanced_security_agent.py` - `main()` function (lines 1899-2077)

---

## Next Steps

1. **Set up data collection**: Export training data from multiple machines
2. **Centralize data**: Copy files to central server or cloud storage
3. **Train global model**: Use `--train-from-directory` or `--train-from-files`
4. **Distribute models**: Copy trained models to all agents
5. **Automate**: Set up cron jobs or scripts for regular updates

---

**Status**: ✅ **FULLY IMPLEMENTED** - Ready to use!

