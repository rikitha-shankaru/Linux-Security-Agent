# Fix Terminal Input Visibility

If you can't see what you type in the terminal:

## Quick Fixes

### Option 1: Reset Terminal
```bash
reset
```

### Option 2: Turn on Echo
```bash
stty echo
```

### Option 3: Full Terminal Reset
```bash
stty sane
```

### Option 4: If nothing works, press:
```
Ctrl+C
Ctrl+Z
reset
```

### Option 5: Close and reopen terminal
- Close the terminal window
- Open a new one
- SSH back in if needed

## If Terminal is Stuck

1. **Press Ctrl+C** to interrupt any running process
2. **Type:** `reset` and press Enter
3. If that doesn't work, **close terminal and reopen**

## Prevent This

If this happened because of the test script:
- The script might have changed terminal settings
- Always run tests in a separate terminal or use `screen`/`tmux`

