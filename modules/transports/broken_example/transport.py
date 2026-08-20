"""
Intentionally broken transport plugin example for testing fault tolerance.
"""


class BrokenTransport:
    """Class that does NOT inherit ITransport and has no meta attribute."""

    def something(self):
        pass
