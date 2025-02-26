"""
    This module contains the main function
"""

import ast
import sys
import json
import re
from MultiLabelling import MultiLabelling

from Pattern import Pattern
from Policy import Policy
from Visitor import PyAnalyzerVisitor
from Vulnerabilities import Vulnerabilities

def parse_input_patterns(file: dict, policy: Policy) -> None:
    """
        Function used to parse the input patterns
    """
    for vulnerability in file:
        pattern = Pattern(vulnerability["vulnerability"], vulnerability["sources"],\
                vulnerability["sanitizers"], vulnerability["sinks"], vulnerability["implicit"])
        policy.add_pattern(pattern)

def parse_ast():
    pass

def build_vulnerabilities_string(vulnerabilities: list) -> str:
    return json.dumps(vulnerabilities)
            
        

def dump_to_json(input: str, file_name: str):
    try:
        json_object = json.loads(input)

        with open(file_name, 'w') as file:
            # json.dump(data, file, indent=None) use for output equal to tests
            # without any identation
            json.dump(json_object, file, indent=4)

        print("File written successfully")
    except json.JSONDecodeError as e:

        print('Error:', e)

def main():
    """
        Main function
    """

    in_file_patterns = sys.argv[2]
    in_file_py = sys.argv[1]

    with open(in_file_patterns, "r") as input_patterns:
        file_contents = input_patterns.read()
        print(file_contents)
    parsed_json = json.loads(file_contents)
    with open(in_file_py, "r") as input_py:
        code = input_py.read()

    policy = Policy()
    multilabelling = MultiLabelling()
    vulnerabilities =  Vulnerabilities()
    parse_input_patterns(parsed_json, policy)
    print(policy)

    node = ast.parse(code)
    visitor = PyAnalyzerVisitor(policy, multilabelling, vulnerabilities)
    visitor.visit(node)

    print(multilabelling.multilabellings)
    print(vulnerabilities.vulnerabilities)

    string = build_vulnerabilities_string(vulnerabilities.vulnerabilities)

    print(string)

    # Getting the slice name from the whole path
    py_filename = in_file_py.split("/")
    output_file_path ="./output/" + re.sub('.py', '', py_filename[-1]) + ".output.json" 
    dump_to_json(string,output_file_path) 


if __name__ == "__main__":
    main()
