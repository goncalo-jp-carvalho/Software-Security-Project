"""
    This module contains the implementation of the MultiLabelling class
"""

from MultiLabel import MultiLabel
from Pattern import Pattern


class MultiLabelling():
    """
        Class used to represent a mapping from variable names to multilabels
    """

    def __init__(self):
        self.multilabellings = {}

    def add_multilabel(self, multilabel: MultiLabel, var_name: str):
        """
            Maps a new variable to a multilabel
        """
        self.multilabellings[var_name] = multilabel

    def get_items(self):
        """
            Returns the items in the multilabelling
        """

        return self.multilabellings.items()

    def get_vars(self) -> list[str]:
        """
            Returns the variables associated to the multilabelling
        """

        return list(self.multilabellings.keys())

    def get_multilabel(self, name: str):
        """
            Returns the multilabel that is assigned to a given name
        """

        if name in self.multilabellings:
            return self.multilabellings[name]
        return None

    def update_multilabel(self, new_multilabel: MultiLabel, var_name: str) -> None:
        """
            Updates the multilabel that is assigned to a name
        """

        self.multilabellings[var_name] = new_multilabel

    def copy_multilabelling(self, pattern_lis: list[Pattern]) -> 'MultiLabelling':
        """
            Returns a deepcopy of the multilabelling
        """

        new_multilabelling = MultiLabelling()
        for var_name, multilabel in self.multilabellings.items():
            new_multilabelling.add_multilabel(multilabel.copy_multilabel(pattern_lis), var_name)
        return new_multilabelling

    def combine_multilabelling(self, multilabelling: 'MultiLabelling', pattern_list: list[Pattern]) -> 'MultiLabelling':
        """
            Combine 2 multilabellings
        """

        new_multilabelling = MultiLabelling()

        for var_name, multilabel in self.get_items():
            new_multilabelling.add_multilabel(multilabel.copy_multilabel(pattern_list), var_name)

        for var_name, multilabel in multilabelling.get_items():
            if var_name not in new_multilabelling.get_vars():
                new_multilabelling.add_multilabel(multilabel.copy_multilabel(pattern_list), var_name)
            else:
                var_multilabel = new_multilabelling.get_multilabel(var_name)
                if not multilabel == var_multilabel:
                    new_multilabelling.update_multilabel(multilabel.combine_multilabels(var_multilabel, pattern_list),\
                            var_name)
        return new_multilabelling
    
    def __eq__(self, __value: object) -> bool:
        if not isinstance(object, self.__class__):
            return False
        for var in self.get_vars():
            if var not in object.get_vars():
                return False
            for multilabel in self.get_multilabel(var):
                if not (multilabel == object.get_multilabel(var)) or\
                        not isinstance(multilabel, MultiLabel):
                            return False
        for var in object.get_vars():
            if var not in self.get_vars():
                return False
            for multilabel in object.get_multilabel(var):
                if not (multilabel == self.get_multilabel(var)) or\
                        not isinstance(multilabel, MultiLabel):
                            return False
