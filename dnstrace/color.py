# ruff: noqa: N806, PLC0415
# N806: Variable in function should be lowercase (allows CamelCase variables)
# PLC0415: Import should be at top-level (allows local imports inside functions)

import sys

COLORS = {
    "black": "\x1b[30m",
    "red": "\x1b[31m",
    "green": "\x1b[32m",
    "yellow": "\x1b[33m",
    "blue": "\x1b[34m",
    "magenta": "\x1b[35m",
    "cyan": "\x1b[36m",
    "white": "\x1b[37m",
    "reset": "\x1b[0m",
}


class ColorPrinter:
    def __init__(self) -> None:
        self.enabled = self.init_colors()

    @staticmethod
    def init_colors() -> bool:
        if sys.platform == "win32":
            try:
                """Terminal coloring for Windows is written with Windows Console API.

                Functions using the following resource.
                https://docs.microsoft.com/en-us/windows/console/console-virtual-terminal-sequences

                """
                from ctypes import POINTER, WINFUNCTYPE, WinError, windll
                from ctypes.wintypes import BOOL, DWORD, HANDLE

                ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
                STD_OUTPUT_HANDLE = -11

                def err_check(result, func, args) -> tuple:  # noqa: ARG001
                    """This function is a helper for the error checking.It is raises an exception when the API call
                    failed.
                    """
                    if not result:
                        raise WinError()
                    return args

                def get_std_handle() -> WINFUNCTYPE:
                    """GetStdHandle retrieves a handle to the specified standard device (standard input, standard
                    output, or standard error).
                    """
                    prototype = WINFUNCTYPE(HANDLE, DWORD)
                    paramflags = ((1, "nStdHandle"),)
                    function = prototype(("GetStdHandle", windll.kernel32), paramflags)
                    function.errcheck = err_check
                    return function

                def get_console_mode() -> WINFUNCTYPE:
                    """GetConsoleMode retrieves the current input mode of a console's input buffer or the current
                    output mode of a console screen buffer.
                    """
                    prototype = WINFUNCTYPE(BOOL, HANDLE, POINTER(DWORD))
                    paramflags = ((1, "hConsoleHandle"), (2, "lpMode"))
                    function = prototype(("GetConsoleMode", windll.kernel32), paramflags)
                    function.errcheck = err_check
                    return function

                def set_console_mode() -> WINFUNCTYPE:
                    """SetConsoleMode sets the input mode of a console's input buffer or the output mode of a console
                    screen buffer.
                    """
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

    def cprint(self, text: str, color: str | None = COLORS["white"], raw_text: str = "", end: str = "\n") -> None:
        if self.enabled and color in COLORS:
            print(f"{COLORS[color]}{text}{COLORS['reset']}{raw_text}", end=end)
        else:
            print(text, end=end)

    @staticmethod
    def cformat(text: str, color: str | None = COLORS["white"], raw_text: str = "") -> str:
        if color is None:
            color = "white"
        return f"{COLORS[color]}{text}{COLORS['reset']}{raw_text}"

    def success(self, text: str, raw_text: str = "", end: str = "\n") -> None:
        self.cprint(text, "green", raw_text, end=end)

    def warning(self, text: str, raw_text: str = "", end: str = "\n") -> None:
        self.cprint(text, "yellow", raw_text, end=end)

    def error(self, text: str, raw_text: str = "", end: str = "\n") -> None:
        self.cprint(text, "red", raw_text, end=end)

    def info(self, text: str, raw_text: str = "", end: str = "\n") -> None:
        self.cprint(text, "blue", raw_text, end=end)


printer = ColorPrinter()
