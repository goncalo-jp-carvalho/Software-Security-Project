"""
    This module contains the implementation of the MultiLabel class
"""

import copy
from Context import Context
from New_Label import New_Label
from Pattern import Pattern

class MultiLabel:
    """
        Class used to represent a generealization of the label class in order
        to represent distinct labels corresponding to different patterns.
    """

    def __init__(self) -> None:
        self.multilabels = {}

    def add_label(self, label: New_Label, pattern_name: str,\
            pattern_list: list[Pattern]) -> None:
        """
            Maps a new label to a pattern
        """

        #  Need to check if the Label sources and sanitizers are also
        # Pattern sources and sanitizers?
        #valid_label = 0
        #for pattern in pattern_list:
        #    if pattern.get_name() == pattern_name:
        #        for inf_flow in label.inf_flows:
        #            if inf_flow[0] in pattern.get_sources():
        #                for sanitizer in inf_flow[1]:
        #                    if sanitizer in pattern.get_sanitizers():
        #                        valid_label = 1
        #                        break
        #                break
        #        break
        valid_label = 1
        if pattern_name in self.multilabels and valid_label ==1:
            self.multilabels[pattern_name].append(label)
        else:
            if valid_label == 1:
                labels = []
                labels.append(label)
                self.multilabels[pattern_name] = labels

    def add_source(self, label: New_Label, source: Context, pattern_list: list[Pattern]):
        """
            Adds a source to a given Label
        """
        # Search for the label in all of the possible patterns
        for pattern_name, labels in self.multilabels.items():
            if label in labels:
                for pattern in pattern_list:
                    if pattern.get_name() == pattern_name:
                        if source.get_name() in pattern.get_sources():
                            label.add_source(source)

    def add_sanitizer(self, label: New_Label, sanitizer: Context, pattern_list: list[Pattern]):
        """
            Adds a source to a given Label
        """
        # Search for the label in all of the possible patterns
        for pattern_name, labels in self.multilabels.items():
            if label in labels:
                for pattern in pattern_list:
                    if pattern.get_name() == pattern_name:
                        if sanitizer in pattern.get_sanitizers():
                            label.add_sanitizer(sanitizer)

    def add_sanitizer_by_pattern(self, pattern: str, sanitizer: Context):
        """
            Adds a sanitizer to the label associated to a certain parameter
        """
        labels = self.get_pattern_labels(pattern)
        for label in labels:
            label.add_sanitizer(sanitizer)

    def get_patterns(self) -> list[str]:
        """
            Returns the patterns associated to the MultiLabel
        """
        return list(self.multilabels.keys())

    def get_pattern_labels(self, pattern: str) -> list[New_Label]:
        """
            Returns the labels associated to a given pattern
        """

        if pattern in self.multilabels:
            return self.multilabels[pattern]
        return []

    def get_items(self):
        """
            Returns the items in the multilabel
        """
        return self.multilabels.items()

    def copy_multilabel(self, pattern_list: list[Pattern]) -> 'MultiLabel':
        """
            Returns a deepcopy of the multilabel
        """
        new_multilabel = MultiLabel()

        for pattern_name, labels in self.multilabels.items():
            for label in labels:
                new_multilabel.add_label(label.copy_label(), pattern_name, pattern_list)

        return new_multilabel

    def combine_multilabels(self, multilabel: 'MultiLabel', pattern_list: list[Pattern]) -> 'MultiLabel':
        """
            Combine 2 multilabels
        """

        new_multilabel = MultiLabel()

        for pattern_name, label_list in self.get_items():
            for label in label_list:
                new_multilabel.add_label(label.copy_label(), pattern_name,\
                        pattern_list)

        for pattern_name, label_list in multilabel.get_items():
            if pattern_name not in new_multilabel.get_patterns():
                for label in label_list:
                    new_multilabel.add_label(label.copy_label(), pattern_name,\
                            pattern_list)
            else:
                for label in label_list:
                    if label not in new_multilabel.get_pattern_labels(pattern_name):
                        new_multilabel.add_label(label.copy_label(), pattern_name,\
                                pattern_list)
        return new_multilabel

    def __eq__(self, __value) -> bool:
        if not isinstance(__value, self.__class__):
            return False
        for pattern in self.get_patterns():
            if pattern not in __value.get_patterns():
                return False
            for label in self.get_pattern_labels(pattern):
                if label not in __value.get_pattern_labels(pattern) or\
                        not isinstance(label, New_Label):
                    return False
        for pattern in __value.get_patterns():
            if pattern not in self.get_patterns():
                return False
            for label in __value.get_pattern_labels(pattern):
                if label not in self.get_pattern_labels(pattern) or not\
                        isinstance(label, New_Label):
                    return False

        return True
