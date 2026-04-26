from io import StringIO
from contextlib import redirect_stdout
from directory_tree import display_tree

def show_tree(path: str) -> str:
    buf = StringIO()
    with redirect_stdout(buf):
        display_tree(path)
    return buf.getvalue()