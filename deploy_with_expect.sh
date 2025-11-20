#!/usr/bin/expect -f
# Deploy script using expect for password handling

set VM_USER "agent"
set VM_HOST "192.168.64.4"
set VM_PASS "rrot"
set VM_SSH "${VM_USER}@${VM_HOST}"
set timeout 30

puts "🚀 Deploying Linux Security Agent to UTM VM"
puts "============================================"
puts ""

# Test connection
spawn ssh -o StrictHostKeyChecking=no ${VM_SSH} "echo 'Connection successful'"
expect {
    "password:" {
        send "${VM_PASS}\r"
        expect eof
    }
    "Connection successful" {
        puts "✅ Connection works"
    }
    timeout {
        puts "❌ Connection timeout"
        exit 1
    }
}

puts ""
puts "📦 Installing dependencies..."
spawn ssh -o StrictHostKeyChecking=no ${VM_SSH}
expect "password:"
send "${VM_PASS}\r"
expect "\$ "
send "sudo apt-get update -qq\r"
expect "password for agent:"
send "${VM_PASS}\r"
expect "\$ "
send "sudo apt-get install -y -qq python3 python3-pip python3-dev build-essential git curl bpfcc-tools python3-bpfcc linux-headers-\\\$(uname -r)\r"
expect "password for agent:"
send "${VM_PASS}\r"
expect "\$ "
send "mkdir -p ~/linux_security_agent\r"
expect "\$ "
send "exit\r"
expect eof

puts ""
puts "📤 Copying files..."
spawn scp -o StrictHostKeyChecking=no -r ./ ${VM_SSH}:~/linux_security_agent/
expect "password:"
send "${VM_PASS}\r"
expect eof

puts ""
puts "📥 Installing Python packages..."
spawn ssh -o StrictHostKeyChecking=no ${VM_SSH}
expect "password:"
send "${VM_PASS}\r"
expect "\$ "
send "cd ~/linux_security_agent\r"
expect "\$ "
send "pip3 install --user -q -r requirements.txt\r"
expect "\$ "
send "python3 -c 'from core.enhanced_security_agent import EnhancedSecurityAgent; print(\"✅ Agent loads\")'\r"
expect "\$ "
send "exit\r"
expect eof

puts ""
puts "🎉 Deployment complete!"

