from enum import Enum
from pathlib import Path

class FunctionStatus(Enum):
    Matching = 0
    NonMatchingMinor = 1
    NonMatchingMajor = 2
    NotDecompiled = 3
    Wip = 4
    Library = 5

STATUS_COLORS = {
    FunctionStatus.Matching: 0x4A7A25,  # Green
    FunctionStatus.NonMatchingMinor: 0x7F7028,  # Yellow
    FunctionStatus.NonMatchingMajor: 0x7F1E1E,  # Red
    FunctionStatus.NotDecompiled: 0x2D2D2D,  # Gray (default of IDA)
    FunctionStatus.Wip: 0x3E3D73,  # Blue
    FunctionStatus.Library: 0x0C777E,  # Purple
}

def get_status_color(status: FunctionStatus) -> int:
    return STATUS_COLORS.get(status, 0xFF0000)  # Default to white if status is unknown

def get_status_from_color(color: int) -> FunctionStatus:
    for status, status_color in STATUS_COLORS.items():
        if color == status_color:
            return status
    return FunctionStatus.NotDecompiled  # Default to NotDecompiled if color is unknown

def RGB_BGR(color: int) -> int:
    r = (color >> 16) & 0xFF
    g = (color >> 8) & 0xFF
    b = color & 0xFF
    return (b << 16) | (g << 8) | r

def get_repo_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent.parent
