"""Search result item model — Textual dependency removed for EDRT integration."""

from typing import Optional

from core.recoverpy_scan.lib.text.text_processing import get_inode, get_printable
from core.recoverpy_scan.log.logger import log


class SearchResult:
    def __init__(self, line: str, inode: Optional[int] = None):
        self.inode = inode if inode is not None else get_inode(line)
        self.line = get_printable(line)
        self.css_class = "search-result"
