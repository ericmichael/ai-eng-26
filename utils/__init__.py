from contextlib import contextmanager
import inspect


@contextmanager
def unwrap_tools():
    """Temporarily replace FunctionTools with their underlying functions."""
    frame = inspect.currentframe().f_back.f_back
    scope = frame.f_globals
    originals = {}
    for name, val in list(scope.items()):
        if hasattr(val, "on_invoke_tool"):
            try:
                unwrapped = val.on_invoke_tool.__closure__[0].cell_contents.__closure__[1].cell_contents.__wrapped__
                originals[name] = val
                scope[name] = unwrapped
            except (AttributeError, IndexError, TypeError):
                pass
    yield
    scope.update(originals)
