import sys
from typing import Any

BLACK = "\x1b[30m"
RED = "\x1b[31m"
GREEN = "\x1b[32m"
YELLOW = "\x1b[33m"
BLUE = "\x1b[34m"
MAGENTA = "\x1b[35m"
CYAN = "\x1b[36m"
WHITE = "\x1b[37m"
RESET = "\x1b[0m"


def init_colors() -> bool:
    if sys.platform != "win32":
        return True

    try:
        """Terminal coloring for Windows is written with Windows Console API.

        Functions using the following resource.
        https://docs.microsoft.com/en-us/windows/console/console-virtual-terminal-sequences

        """

        from ctypes import POINTER, WINFUNCTYPE, WinError, windll  # type: ignore
        from ctypes.wintypes import BOOL, DWORD, HANDLE

        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        STD_OUTPUT_HANDLE = -11

        def err_check(result, func, args) -> tuple:
            """This function is a helper for the error checking.It is raises an
            exception when the API call failed."""
            if not result:
                raise WinError()
            return args

        def get_std_handle() -> WINFUNCTYPE:
            """GetStdHandle retrieves a handle to the specified standard device
            (standard input, standard output, or standard error)."""
            prototype = WINFUNCTYPE(HANDLE, DWORD)
            paramflags = ((1, "nStdHandle"),)
            function = prototype(("GetStdHandle", windll.kernel32), paramflags)
            function.errcheck = err_check
            return function

        def get_console_mode() -> WINFUNCTYPE:
            """GetConsoleMode retrieves the current input mode of a console's
            input buffer or the current output mode of a console screen
            buffer."""
            prototype = WINFUNCTYPE(BOOL, HANDLE, POINTER(DWORD))
            paramflags = ((1, "hConsoleHandle"), (2, "lpMode"))
            function = prototype(("GetConsoleMode", windll.kernel32), paramflags)
            function.errcheck = err_check
            return function

        def set_console_mode() -> WINFUNCTYPE:
            """SetConsoleMode sets the input mode of a console's input buffer
            or the output mode of a console screen buffer."""
            prototype = WINFUNCTYPE(BOOL, HANDLE, DWORD)
            paramflags = ((1, "hConsoleHandle"), (1, "dwMode"))
            function = prototype(("SetConsoleMode", windll.kernel32), paramflags)
            function.errcheck = err_check
            return function

        GetStdHandle = get_std_handle()
        GetConsoleMode = get_console_mode()
        SetConsoleMode = set_console_mode()

        h_out = GetStdHandle(STD_OUTPUT_HANDLE)
        dw_mode = GetConsoleMode(h_out) | ENABLE_VIRTUAL_TERMINAL_PROCESSING
        SetConsoleMode(h_out, dw_mode)
    except OSError:
        return False
    else:
        return True


USE_COLOR = init_colors()


def set_color(color: str, text: Any) -> str:
    if USE_COLOR:
        return f"{color}{text}{RESET}"
    else:
        return text
