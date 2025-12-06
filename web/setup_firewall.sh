#!/bin/bash
# Script to set up firewall and start dashboard on Google Cloud VM

echo "🛡️  Setting up Dashboard Access"
echo "================================"
echo ""

# Check if running on Google Cloud
if [ -f /etc/google_instance_id ] || [ -n "$GOOGLE_CLOUD_PROJECT" ]; then
    echo "✅ Detected Google Cloud VM"
    echo ""
    echo "To allow access to the dashboard, run this in Google Cloud Console:"
    echo ""
    echo "gcloud compute firewall-rules create allow-dashboard-port \\"
    echo "  --allow tcp:5001 \\"
    echo "  --source-ranges 0.0.0.0/0 \\"
    echo "  --description 'Allow dashboard access'"
    echo ""
    echo "Or use the web console:"
    echo "1. Go to VPC Network > Firewall"
    echo "2. Create Firewall Rule"
    echo "3. Allow TCP port 5001"
    echo "4. Apply to your VM instance"
    echo ""
fi

echo "Starting dashboard..."
cd "$(dirname "$0")"
python3 app.py

