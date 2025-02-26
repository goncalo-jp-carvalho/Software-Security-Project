"""
    This module contains the implementation of the Token class
"""


class Context:

    """
        Class used to represent a token, we consider a token as a tuple (str, int)
        used as an abstraction to represent either a source, sanitizer or sink
    """

    def __init__(self, name: str, line: int):
        self.token = (name, line)

    def get_name(self):
        """
            Returns the name associated to the token
        """

        return self.token[0]

    def get_line(self):
        """
            Returns the line associated to the token
        """

        return self.token[1]

    def __eq__(self, __value) -> bool:
        if isinstance(__value, self.__class__):
            return self.get_name() == __value.get_name() and\
                self.get_line() == __value.get_line()
        return False
