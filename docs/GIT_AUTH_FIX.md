# Fixing Git Authentication on VM

## Problem
GitHub no longer supports password authentication. You need a Personal Access Token (PAT).

## Solution

### Step 1: Check/Update Remote URL (on VM)

```bash
# On your VM, check the current remote URL
cd ~/linux_security_agent
git remote -v

# If it shows 'rikitha-shankaru', update it to 'likitha-shankar'
git remote set-url origin https://github.com/likitha-shankar/Linux-Security-Agent.git

# Verify it's correct
git remote -v
```

### Step 2: Create Personal Access Token (on GitHub)

1. Go to GitHub.com → Your Profile → Settings
2. Scroll down to "Developer settings" (bottom left)
3. Click "Personal access tokens" → "Tokens (classic)"
4. Click "Generate new token" → "Generate new token (classic)"
5. Give it a name: "VM Git Access"
6. Select expiration (90 days or custom)
7. **Check these scopes:**
   - ✅ `repo` (full control of private repositories)
8. Click "Generate token"
9. **COPY THE TOKEN IMMEDIATELY** (you won't see it again!)

### Step 3: Use Token for Authentication (on VM)

When you run `git push origin main`, use:
- **Username**: `likitha-shankar` (your GitHub username)
- **Password**: `<paste your Personal Access Token here>`

### Alternative: Store Credentials (Optional)

To avoid entering the token every time:

```bash
# On VM, configure Git credential helper
git config --global credential.helper store

# Then on first push, enter:
# Username: likitha-shankar
# Password: <your PAT token>
# Git will save it for future use
```

### Quick Test

```bash
# On VM
cd ~/linux_security_agent
git pull origin main  # Test authentication
```

## If You Still Have Issues

1. **Check remote URL is correct:**
   ```bash
   git remote -v
   # Should show: https://github.com/likitha-shankar/Linux-Security-Agent.git
   ```

2. **Verify token has 'repo' scope** (required for push)

3. **Try using SSH instead** (if you have SSH keys set up):
   ```bash
   git remote set-url origin git@github.com:likitha-shankar/Linux-Security-Agent.git
   ```

