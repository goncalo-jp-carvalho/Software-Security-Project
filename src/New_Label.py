"""
    This module contains the implementation of the label class
"""

import copy
from Context import Context

class New_Label():
    """
        Class used to represent the integrity of information that is carried by
        a resource
    """

    def __init__(self):
        self.inf_flows = []

    def add_source(self, source: Context):
        """
            Adds another information source to the Label
        """
        self.inf_flows.append([source, []])


    def add_sanitizer(self, sanitizer: Context):
        """
            Adds a new sanitizer that intercepted the information after source
        """
        last_inf_flow = self.inf_flows[-1]
        last_inf_flow[1].append(sanitizer)


    def is_source(self, source: str):
        """
            Returns whether or not a given source is a source of the label
        """
        for label_source in self.get_sources():
            if label_source.get_name() == source:
                return True
        return False

    def is_sanitizer(self, sanitizer: str):
        """
            Returns whether or not a given sanitizer is a sanitizer of the label
        """
        for label_sanitizer in self.get_sanitizers():
            if label_sanitizer.get_name() == sanitizer:
                return True
        return False

    def get_sources(self) -> list[Context]:
        """
            Returns the sources of the Label object
        """
        sources = []

        for inf_flow in self.inf_flows:
            sources.append(inf_flow[0])

        return sources

    def get_sanitizers(self) -> list[Context]:
        """
            Returns the sanitizers of the Label object
        """
        sanitizers = []
        for inf_flow in self.inf_flows:
            for sanitizer in inf_flow[1]:
                sanitizers.append(sanitizer)
        return sanitizers

    def get_source_sanitizers(self, source: Context) -> list[Context]:
        """
            Returns the sanitizers associated to a given source
        """

        for inf_flow in self.inf_flows:
            if inf_flow[0] == source:
                return inf_flow[1]
        return []

    def copy_label(self) -> 'New_Label':
        """
            Returns a deepcopy of the Label
        """

        new_label = New_Label()
        old_copy = copy.deepcopy(self.inf_flows)
        for inf_flow in old_copy:
            new_label.add_source(inf_flow[0])
            for sanitizer in inf_flow[1]:
                new_label.add_sanitizer(sanitizer)

        return new_label


    def combine_labels(self, label: 'New_Label') -> 'New_Label':
        """
            Returns a new label that represents the integrity of information that
            results from combining 2 pieces of information
        """

        new_label = New_Label()

        new_inf_flows = copy.deepcopy(self.inf_flows)

        for new_inf_flow in new_inf_flows:
            new_label.add_source(new_inf_flow[0])
            for sanitizer in new_inf_flow[1]:
                new_label.add_sanitizer(new_inf_flow[0], sanitizer)

        new_inf_flows = copy.deepcopy(label.inf_flows)

        for new_inf_flow in new_inf_flows:
            new_label.add_source(new_inf_flow[0])
            for sanitizer in new_inf_flow[1]:
                new_label.add_sanitizer(new_inf_flow[0], sanitizer)

        return new_label

    def __eq__(self, __value) -> bool:
        if not isinstance(__value, self.__class__):
            return False
        for source in self.get_sources():
            if source not in __value.get_sources():
                return False
        for sanitizer in self.get_sanitizers():
            if sanitizer not in __value.get_sanitizers():
                return False
        for source in __value.get_sources():
            if source not in self.get_sources():
                return False
        for sanitizer in __value.get_sanitizers():
            if sanitizer not in self.get_sanitizers():
                return False
        return True
