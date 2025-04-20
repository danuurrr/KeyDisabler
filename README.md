# Keyboard Disabler

A Windows-based command-line application that allows you to selectively disable keyboard keys with logging capabilities and emergency override features.

## Features

### Key Management
- Disable multiple keyboard keys simultaneously
- Support for various key types:
  - Letter keys (a-z)
  - Number keys (0-9)
  - Function keys (F1-F12)
  - Special keys (Ctrl, Alt, Shift, Tab, etc.)
  - Navigation keys (arrows, Home, End, Page Up/Down)
  - System keys (Enter, Backspace, Delete, Insert)

### Command Interface
- `add <keys>` - Add keys to the disable list (comma-separated)
- `clear` - Remove all keys from the disable list
- `list` - Display currently disabled keys
- `disable` - Activate key blocking for selected keys
- `enable` - Deactivate key blocking
- `help` - Display available commands
- `exit` - Exit the application

### Safety Features
- Emergency Escape Hatch
  - Press ESC key to instantly enable all keys (configurable)
  - Commands: `escapehatch on/off` to toggle feature
  - `escapehatch` to check current status

### Logging System
- Automatic logging of all actions
- Timestamp for each log entry
- Log file location configurable
- View log file path with `logfile` command
- Events logged:
  - Key disable/enable actions
  - Blocked key attempts
  - System initialization/shutdown
  - Emergency override usage

### Safety and Error Handling
- Graceful shutdown on program exit
- Signal handling for unexpected termination
- Automatic keyboard re-enable on program exit
- Prevention of ESC key disable when escape hatch is active
- Input validation for all commands

## Technical Details
- Written in C++ for Windows systems
- Uses Windows Hook API for keyboard monitoring
- Thread-safe implementation
- Atomic operations for state management
- Support for all standard keyboard keys

## Usage Examples
```bash
> add ctrl, alt, tab
> disable
Selected keys are now disabled.
Press ESC key at any time to enable all keys.

> list
Disabled keys: ctrl, alt, tab

> enable
Keyboard has been enabled.

> escapehatch off
Escape key emergency enable feature: OFF
