"""
    This module contains the implementation of the class Policy
"""


import copy
from Pattern import Pattern
from MultiLabel import MultiLabel

class Policy:
    """
        Class that represents an information flow policy
    """

    def __init__(self) -> None:
        self.patterns = []

    def add_pattern(self, pattern: Pattern) -> None:
        """
            Adds a pattern to the pattern list
        """
        self.patterns.append(pattern)

    def vulnerability_names(self) -> list:
        """
            Returns the names of the vulnerability that are being considered
        """
        names = []
        for pattern in self.patterns:
            names.append(pattern.name)

        return names

    def is_source(self, name: str) -> list[Pattern]:
        """
            Returns the list of patterns that have a given name as a source
        """
        patterns = []
        for pattern in self.patterns:
            if pattern.is_sources(name):
                patterns.append(pattern)
        return patterns

    def is_sanitizer(self, name: str) -> list[Pattern]:
        """
            Returns the list of patterns that have a given name as a sanitizer
        """

        patterns = []
        for pattern in self.patterns:
            if pattern.is_sanitizer(name):
                patterns.append(pattern)
        return patterns

    def is_sink(self, name: str) -> list[Pattern]:
        """
            Returns the list of patterns that have a given name as a sink 
        """

        patterns = []
        for pattern in self.patterns:
            if pattern.is_sink(name):
                patterns.append(pattern)
        return patterns

    def is_pattern(self, name: str):
        """
            Returns the pattern that has a given name
        """

        for pattern in self.patterns:
            if pattern.name == name:
                return pattern
        return None

    def ilegal_flows(self, multilabel: MultiLabel, name: str) -> MultiLabel:
        """
            Returns an ilegal flow, i.e., which part of the multilabel has the 
            given name as a sink
        """

        #labels = []

        # Check if name is a sink of the pattern
        new_multilabel = MultiLabel()
        for pattern in self.patterns:
            if pattern.is_sink(name):
                if pattern.get_name() in multilabel.get_patterns():
                    for label in multilabel.get_pattern_labels(pattern.get_name()):
                        new_multilabel.add_label(label, pattern.get_name(), self.patterns)

        """
        if name in multilabel.multilabels:
            for pattern in self.patterns:
                if pattern.name == name:
                    for labels in multilabel.multilabels[name]:
                        for label in labels:
                            label_sources = label.sources
                            for source in label_sources:
                                if pattern.is_sources(source):
                                    new_sanitizers = copy.deepcopy(label.sanitizers)
                                    new_sources = copy.deepcopy(label.sources)
                                    new_label = New_Label(new_sanitizers,new_sources)
                                    labels.append(new_label)
                                    break
                    break
        new_multilabel = MultiLabel()
        for label in labels:
            new_multilabel.add_label(label, name, self.patterns)
        """
        return new_multilabel

    def __str__(self) -> str:

        res = ""
        for pattern in self.patterns:
            res += "#-----------------------------" + '\n'
            res += str(pattern)
        return res
