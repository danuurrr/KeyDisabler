# Keyboard Disabler

A Windows-based command-line application that allows you to selectively disable keyboard keys.

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
