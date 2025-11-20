#!/bin/bash
# Train ML models with external dataset on Linux VM

echo "🧠 Training ML Models with External Dataset"
echo "==========================================="
echo ""

cd ~/linux_security_agent || exit 1

# Check if dataset exists
if [ ! -f "datasets/normal_behavior_dataset.json" ]; then
    echo "❌ Dataset not found: datasets/normal_behavior_dataset.json"
    echo "   Creating it now..."
    python3 -c "
import json
import random

patterns = [
    ['open', 'read', 'write', 'close', 'stat', 'fstat'],
    ['socket', 'connect', 'send', 'recv', 'close'],
    ['fork', 'execve', 'wait', 'read', 'write'],
    ['mmap', 'read', 'write', 'munmap', 'close'],
    ['openat', 'getdents', 'readlink', 'close'],
]

samples = []
for i in range(500):
    pattern = random.choice(patterns)
    samples.append({
        'syscalls': pattern + random.sample(['fstat', 'lstat', 'access'], random.randint(0, 2)),
        'process_info': {
            'cpu_percent': round(random.uniform(0.1, 5.0), 1),
            'memory_percent': round(random.uniform(0.1, 4.0), 1),
            'num_threads': random.randint(1, 5)
        }
    })

dataset = {
    'metadata': {
        'source': 'synthetic_normal_behavior',
        'collection_date': '2025-11-20',
        'description': 'Normal Linux process behavior patterns',
        'sample_count': len(samples)
    },
    'samples': samples
}

with open('datasets/normal_behavior_dataset.json', 'w') as f:
    json.dump(dataset, f, indent=2)

print(f'✅ Created dataset with {len(samples)} samples')
"
fi

echo ""
echo "📊 Dataset info:"
python3 -c "
import json
with open('datasets/normal_behavior_dataset.json') as f:
    data = json.load(f)
    print(f'   Samples: {len(data[\"samples\"])}')
    print(f'   Source: {data[\"metadata\"].get(\"source\", \"unknown\")}')
"

echo ""
echo "🧠 Training models..."
echo ""

# Train with the dataset
python3 scripts/train_with_dataset.py --file datasets/normal_behavior_dataset.json

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Training complete!"
    echo ""
    echo "📁 Models saved to: ~/.cache/security_agent/"
    echo ""
    echo "🚀 You can now run the agent:"
    echo "   sudo python3 core/simple_agent.py --collector ebpf --threshold 30"
else
    echo ""
    echo "❌ Training failed. Check errors above."
    exit 1
fi

