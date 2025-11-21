# Using Web Login for Git (GitHub CLI)

## Option 1: GitHub CLI (Easiest - Web Login)

GitHub CLI (`gh`) allows web-based authentication!

### Install GitHub CLI on VM

```bash
# On your VM
# For Ubuntu/Debian:
sudo apt update
sudo apt install gh

# Or download from: https://github.com/cli/cli/releases
```

### Authenticate via Web Browser

```bash
# On VM
gh auth login

# Follow prompts:
# - Choose: GitHub.com
# - Choose: HTTPS
# - Authenticate: Login with a web browser
# - Copy the code shown
# - Browser will open, paste code
# - Authorize GitHub CLI
```

### Use GitHub CLI for Git Operations

```bash
# After authentication, you can use:
gh repo sync  # Sync repository
# Or continue using regular git commands - they'll use gh credentials
```

## Option 2: SSH Keys (No Password Needed)

Set up SSH keys once, then never need password/token:

### Generate SSH Key (on VM)

```bash
# On VM
ssh-keygen -t ed25519 -C "likithashankar14@gmail.com"
# Press Enter to accept default location
# Press Enter twice for no passphrase (or set one)

# Copy public key
cat ~/.ssh/id_ed25519.pub
```

### Add to GitHub

1. Go to: https://github.com/settings/keys
2. Click "New SSH key"
3. Title: `VM Security Agent`
4. Paste the public key
5. Click "Add SSH key"

### Use SSH URL

```bash
# On VM
git remote set-url origin git@github.com:likitha-shankar/Linux-Security-Agent.git
git push origin main
# No password needed!
```

## Option 3: Git Credential Manager (If Available)

Some systems have credential managers that support OAuth:

```bash
# Check if available
git config --global credential.helper

# If not, install Git Credential Manager (varies by OS)
```

## Recommendation

**Use SSH Keys (Option 2)** - Set it up once, then never worry about authentication again!

