"""ANSI color codes for terminal output formatting"""

# ANSI escape codes
RED = '\033[91m'          # Bright red for errors/exceptions
MAROON = '\033[31m'       # Maroon-red for version info
YELLOW = '\033[93m'       # Bright yellow for warnings/info
RESET = '\033[0m'         # Reset to default color

def red(text):
    """Format text in red (for errors/exceptions)"""
    return f"{RED}{text}{RESET}"

def maroon(text):
    """Format text in maroon (for version info)"""
    return f"{MAROON}{text}{RESET}"

def yellow(text):
    """Format text in yellow (for warnings/info)"""
    return f"{YELLOW}{text}{RESET}"
