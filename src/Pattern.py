""""
    This module contains the implementation of the Pattern class
"""

class Pattern:

    """
        Class used to represent vulnerability patterns
    """


    def __init__(self, name: str, sources: list[str],\
            sanitizer: list[str], sink: list[str], implicit: str):

        self.name = name
        self.sources = sources
        self.sanitizer = sanitizer
        self.sink = sink
        self.implicit = implicit


    def get_name(self):
        """
            Returns the name of the pattern
        """
        return self.name

    def get_sources(self) -> list[str]:
        """
            Returns the list of sources associated to the pattern
        """
        return self.sources

    def get_sanitizers(self) -> list[str]:
        """
            Returns the list of sanitizers associated to the pattern
        """
        return self.sanitizer

    def get_sinks(self) -> list[str]:
        """
            Returns the list of sinks associated to the pattern
        """
        return self.sink

    def is_name(self, name:str):
        """
            Returns whether or not a given name is the pattern name
        """
        return self.name == name

    def is_sources(self, source: str):
        """
            Returns whether or not a given source is one of the pattern's sources
        """

        return source in self.get_sources()

    def is_sanitizer(self, sanitizer: str):
        """
            Returns whether or not a given sanitizer is the pattern sanitizer
        """
        return sanitizer in self.get_sanitizers()


    def is_sink(self, sink: str):
        """
            Returns whether or not a given sink is the pattern sink
        """
        return sink in self.get_sinks()

    def test_name(self,name: str):
        """
            Checks whether a given name is a source, sanitizer or sink for the pattern.
        """
        if self.is_sources(name):
            return 1

        if self.is_sanitizer(name):
            return 2

        if self.is_sink(name):
            return 3

        return 0

    def __str__(self) -> str:
        res = ""
        res += "Vulnerability: " + self.name + '\n'

        res += "Sources: ["
        for i in self.sources:
            res += i + ", "
        res += ']' + '\n'

        res += "Sanitizers: ["
        for i in self.sanitizer:
            res += i + ", "
        res += ']' + '\n'

        res += "Sinks: ["
        for i in self.sink:
            res += i + ", "
        res += ']' + '\n'

        res += "Implicit: " + self.implicit + '\n'

        return res
