#!/bin/bash
# Fix git pull conflict on Linux VM
# Run this on the VM to resolve the install_bcc.sh conflict

echo "🔧 Fixing git pull conflict..."
echo ""

# Remove the conflicting file (we deleted it in the repo)
if [ -f "install_bcc.sh" ]; then
    echo "Removing local install_bcc.sh (file was deleted in repo)..."
    rm install_bcc.sh
    echo "✅ Removed"
fi

# Also check for other deleted files that might have local changes
FILES_TO_REMOVE=(
    "install_dependencies.sh"
    "commands_for_linux_vm.sh"
    "connect_linux_vm.sh"
    "setup_and_train_on_linux.sh"
    "setup_on_vm.sh"
    "find_vm_ip.sh"
    "VM_SETUP_COMMANDS.txt"
)

for file in "${FILES_TO_REMOVE[@]}"; do
    if [ -f "$file" ]; then
        echo "Removing $file (deleted in repo)..."
        rm "$file"
    fi
done

echo ""
echo "Now pulling changes..."
git pull origin main

echo ""
echo "✅ Done! If there are still conflicts, run:"
echo "   git stash"
echo "   git pull origin main"
echo "   git stash pop"

