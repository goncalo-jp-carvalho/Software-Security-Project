"""
    This module constains the implementation of the Label class
"""

import copy
from Context import Context

class Label:
    """
        Class used to represent the integrity of information that is carried
        by a resource
    """

    def __init__(self, level: int, sanitizers: list[Context], sources: list[Context]) -> None:
        self.level = level
        self.sanitizers = sanitizers
        self.sources = sources

    def add_sources(self, sanitizer: Context) -> None:
        """
            Appends a sanitizer to the list of sanitizers that intercepted the
            information flow
        """
        self.sanitizers.append(sanitizer)

    def add_source(self, source: Context) -> None:
        """
            Appends a source to the list of source that might have influenced
            the information
        """
        self.sources.append(source)

    def is_source(self, source: str):
        """
            Returns whether or not a given source is in the list of sources
            that might have influenced the information
        """
        for context in self.get_sources():
            if source == context.get_name():
                return True
        return False

    def is_sanitizer(self, sanitizer: str):
        """
            Returns whether or not a given sanitizer is in the list of sanitizers
            that might have intercepted the information flow
        """

        for context in self.get_sources():
            if sanitizer == context.get_name():
                return True
        return False

    def get_sources(self) -> list[Context]:
        """
            Returns the sources of the Label object
        """

        return self.sources

    def get_sanitizers(self) -> list[Context]:
        """
            Returns the list of sanitizers through which the information has passed
        """

        return self.sanitizers
    
    def copy_label(self) -> 'Label':
        """
            Returns a deepcopy of the label object
        """

        pass

    def combine_labels(self, label: 'Label'):
        """
            Returns a new label that represents the integrity of information
            that results from combining two pieces of information
        """

        new_level = self.level if self.level <= label.level else label.level

        new_sanitizers = copy.deepcopy(self.sanitizers)
        new_sanitizers_aux = copy.deepcopy(label.sanitizers)

        new_sanitizers += new_sanitizers_aux

        new_sources = copy.deepcopy(self.sources)
        new_sources_aux = copy.deepcopy(label.sources)

        new_sources += new_sources_aux

        return Label(new_level, new_sanitizers, new_sources)

    def __str__(self) -> str:
        res = ""
        res += "Level: " + str(self.level) + '\n'

        res += "Sources: "
        for i in self.sources:
            res += str(i) + ' '
        res += '\n'
        res += "Sanitizers: "
        for i in self.sanitizers:
            res += str(i) + ' '
        res += '\n'
        return res

    def __eq__(self, label: label) -> bool:

