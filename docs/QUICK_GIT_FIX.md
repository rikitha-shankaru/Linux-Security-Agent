# Quick Git Push Fix

## The Problem
GitHub **does NOT accept passwords anymore**. You MUST use a Personal Access Token.

## Solution (2 Steps)

### Step 1: Create Personal Access Token

1. Go to: **https://github.com/settings/tokens**
2. Click: **"Generate new token"** → **"Generate new token (classic)"**
3. Name it: `VM Git Access`
4. Expiration: Choose 90 days (or custom)
5. **IMPORTANT:** Check ✅ **`repo`** (this gives full repository access)
6. Click: **"Generate token"**
7. **COPY THE TOKEN** (looks like: `ghp_xxxxxxxxxxxxxxxxxxxx`)

### Step 2: Use Token as Password

When you run `git push origin main`:

```
Username for 'https://github.com': likitha-shankar
Password for 'https://likitha-shankar@github.com': <PASTE YOUR TOKEN HERE>
```

**Important:** 
- Username = your GitHub username (`likitha-shankar`)
- Password = the token you just created (NOT your GitHub password!)

## Alternative: Store Token (Optional)

To avoid entering token every time:

```bash
# On VM
git config --global credential.helper store

# Then on first push, enter token
# Git will save it for future use
```

## Still Not Working?

If you still get errors, try SSH instead:

```bash
# On VM
git remote set-url origin git@github.com:likitha-shankar/Linux-Security-Agent.git
git push origin main
```

(Requires SSH keys to be set up on GitHub)

