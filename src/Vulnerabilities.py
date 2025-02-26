"""
    This class contains the implementation of the Vulnerabilities class
"""

from ast import walk
from MultiLabel import MultiLabel
from Policy import Policy

# Class Vulnerabilities serves as an internal representation of the output
# See the project statement to complete it

class Vulnerabilities:
    """
        This class is used to collect all the illegal flows that are discovered
        during the analysis of the program slice.
    """

    def __init__(self):
        # Dictionary to hold detected vulnerabilities, organized by vulnerability names
        # Should have access to the policy class?
        self.vulnerabilities = []

    def get_vuln_id(self,pattern_name: str, vulnerabilities: list)-> str:

        counter =0
        if(vulnerabilities == []):
            return "_" + str(counter + 1)
        for vulnerability in vulnerabilities:
            if(pattern_name in vulnerability["vulnerability"]):
                counter += 1
        return "_" + str(counter + 1)

    def add_illegal_flow(self, name: str, lineno: int, multilabel: MultiLabel, policy: Policy):
        """
            Adds a new vulnerability
        """

        # TODO: How to handle in case of both sanitized and unsanitized flows?

        new_multilabel = policy.ilegal_flows(multilabel, name)
        print(new_multilabel.multilabels)
        for pattern_name, labels in new_multilabel.get_items():
            for label in labels:
                for source in label.get_sources():
                    vulnerability = {}

                    vulnerability["vulnerability"] = pattern_name + self.get_vuln_id(pattern_name,self.vulnerabilities)
                    vulnerability["source"] = [source.get_name(), source.get_line()]
                    vulnerability["sink"] = [name, lineno]


                    if label.get_source_sanitizers(source) == []:
                        vulnerability["unsanitized_flows"] = "yes"

                    else:
                        vulnerability["unsanitized_flows"] = "no"

                    vulnerability["sanitized_flows"] = []

                    for sanitizer in label.get_source_sanitizers(source):
                        vulnerability["sanitized_flows"].append([sanitizer.get_name(), sanitizer.get_line()])

                    if len(vulnerability["sanitized_flows"]) > 0:
                        vulnerability["sanitized_flows"] = [vulnerability["sanitized_flows"]]

                    vulnerability_already_captured = 0
                    
                    for item in self.vulnerabilities:
                        if item["source"] == vulnerability["source"] and\
                                item["sink"] == vulnerability["sink"]\
                                    and item["vulnerability"][:-2] == vulnerability["vulnerability"][:-2]:
                            
                            vulnerability_already_captured = 1

                            if vulnerability["unsanitized_flows"] == "yes":
                                item["unsanitized_flows"] = "yes"

                            for inf_flow in vulnerability["sanitized_flows"]:
                                if inf_flow not in item["sanitized_flows"]:
                                    item["sanitized_flows"].append(inf_flow)

                    print(vulnerability) 

                    if vulnerability_already_captured == 0:
                        self.vulnerabilities.append(vulnerability)

        """
        for pattern in multilabel.get_patterns():
            for label in multilabel.get_pattern_labels(pattern):
                for label_source in label.get_sources():

                    # Create a new vulnerability object
                    vulnerability = {}

                    vulnerability["vulnerability"] = pattern.name
                    vulnerability["sink"] = name
                    vulnerability["source"] = label_source

                    sanitized_flows = []

                    for label_sanitizer in label.get_sanitizers():
                        if pattern.is_sanitizer(label_sanitizer):
                            sanitized_flows.append(label_sanitizer)

                    if sanitized_flows:
                        vulnerability["unsanitized_flows"] = "NO"
                    else:
                        vulnerability["unsanitized_flows"] = "YES"

                    vulnerability["sanitized_flows"] = sanitized_flows

                    self.vulnerabilities.append(vulnerability)"""
