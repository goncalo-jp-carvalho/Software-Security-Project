"""
    This module contains the visitor implementation for the ast
"""

import ast
import Policy
import MultiLabelling
import Vulnerabilities
import MultiLabel
import New_Label
from Pattern import Pattern
from Context import Context


class PyAnalyzerVisitor(ast.NodeVisitor):
    """
        This class contains the needed methods to traverse the python ast
    """

    def __init__(self, policy: Policy.Policy, multilabelling: MultiLabelling.MultiLabelling,\
                 vulnerabilities: Vulnerabilities.Vulnerabilities) -> None:
        super().__init__()
        self.unassigned_variables = []
        self.modified_vars_if = {}
        self.modified_vars_else = {}
        self.policy = policy
        self.multilabelling = multilabelling
        self.vulnerabilities = vulnerabilities
        self.max_iterations = 5
        pass

    """
    def visit(self, node: ast.AST):
            Function used to go through the AST
        if hasattr(node, 'lineno'):
            print(str(type(node)) + " Lineno: " + str(node.lineno))
        else:
            print(type(node))

        for fields in node._fields:
            print('     ' + fields)

        for child in ast.iter_child_nodes(node):
            if isinstance(node, ast.Name):
                self.visit_Name(node)
            else:
                self.visit(child)
    """
    # -------------------------------------------------------------------------
    # Visitor for Expressions
    # -------------------------------------------------------------------------
    def visit_Constant(self, node: ast.Constant) -> MultiLabel.MultiLabel:
        """
            Visitor for the class Constant
        """
        print("Visiting a Constant Node")
        return MultiLabel.MultiLabel()


    def visit_Name(self, node: ast.Name) -> MultiLabel.MultiLabel:
        """
            Visitor for the class Name
        """
        print("Visiting a Name Node")
        multilabel = self.multilabelling.get_multilabel(node.id)
        if multilabel is None:
            new_label = New_Label.New_Label()
            context = Context(node.id, node.lineno)
            new_label.add_source(context)

            node_is_source = self.policy.is_source(node.id)
            node_is_sink = self.policy.is_sink(node.id)

            multilabel = MultiLabel.MultiLabel()
            
            for pattern in node_is_source:
                multilabel.add_label(new_label, pattern.get_name(), self.policy.patterns)

            if node_is_sink:
                for pattern in self.policy.vulnerability_names():
                    multilabel.add_label(new_label, pattern, self.policy.patterns)

        return multilabel

    def visit_BinOp(self, node: ast.BinOp) -> MultiLabel.MultiLabel:
        """
            Visitor for the  class Binop
        """
        print("Visiting a BinOp Node")

        # Maybe a deep copy is needed for the combination
        left_multilabel = self.visit(node.left)
        right_multilabel = self.visit(node.right)

        if left_multilabel is None:
            return right_multilabel
        elif right_multilabel is None:
            return left_multilabel
        else:
            combined_multilabel = left_multilabel.combine_multilabels(right_multilabel,
                                                                      self.policy.patterns)
            return combined_multilabel


    def visit_UnaryOp(self, node: ast.UnaryOp) -> MultiLabel.MultiLabel:
        """
            Visitor for the class UnaryOp
        """
        print("Visiting a UnaryOp Node")
        print(node.operand)

        operand_multilabel = self.visit(node.operand)

        return operand_multilabel


    def visit_BoolOp(self, node: ast.BoolOp) -> MultiLabel.MultiLabel:
        """
            Visitor for the class BoolOp
        """
        print("Visiting a BoolOp Node")

        final_multilabel = MultiLabel.MultiLabel()
        for value in node.values:
            child_multilabel =self.visit(value)

            final_multilabel = final_multilabel.combine_multilabels(child_multilabel, self.policy.patterns)

        return final_multilabel

    def visit_Compare(self, node: ast.Compare) -> MultiLabel.MultiLabel:
        """
            Visitor for the  class Compare
        """
        print("Visiting a Compare Node")

        final_multilabel = MultiLabel.MultiLabel()
        left_multilabel = self.visit(node.left)
        if left_multilabel is not None:
            final_multilabel = final_multilabel.combine_multilabels(left_multilabel, self.policy.patterns)

        for comparator in node.comparators:
            comparator_multilabel =self.visit(comparator)
            if comparator_multilabel is not None:
                final_multilabel = final_multilabel.combine_multilabels(comparator_multilabel, self.policy.patterns)

        return final_multilabel



    def visit_Call(self, node: ast.Call) -> MultiLabel.MultiLabel:
        """
            Visitor for the class Call
        """
        print("Visiting a Call Node")

        if isinstance(node.func, ast.Attribute):
            print(node.func.value.id)
            print(node.func.attr)
            print("Attribute")
            final_multilabel = self.visit(node.func)
            return final_multilabel
        
        pattern_list_sources = self.policy.is_source(node.func.id)
        pattern_list_sinks = self.policy.is_sink(node.func.id)
        pattern_list_sanitizers = self.policy.is_sanitizer(node.func.id)
        final_multilabel = MultiLabel.MultiLabel()

        if len(pattern_list_sources) > 0:
            print("CALL - SOURCE")
            new_label = New_Label.New_Label()
            context = Context(node.func.id, node.lineno)
            new_label.add_source(context)
            for pattern in pattern_list_sources:
                final_multilabel.add_label(new_label, pattern.get_name(), self.policy.patterns)

        if len(pattern_list_sinks) > 0:
            print("CALL - SINK")
            for arg in node.args:
                if isinstance(arg, ast.Name):
                    multilabel = self.multilabelling.get_multilabel(arg.id)
                    if multilabel is not None:
                        final_multilabel = final_multilabel.combine_multilabels(multilabel, self.policy.patterns)
                        self.vulnerabilities.add_illegal_flow(node.func.id, node.lineno, final_multilabel, self.policy)

                    if arg.id in self.modified_vars_if:
                        if self.modified_vars_if[arg.id] == -1:
                            new_label = New_Label.New_Label()
                            source = Context(arg.id, node.lineno)
                            new_label.add_source(source)
                            new_multilabel = MultiLabel.MultiLabel()
                            for pattern in pattern_list_sinks:
                                new_multilabel.add_label(new_label, pattern.get_name(), self.policy.patterns)
                            self.vulnerabilities.add_illegal_flow(node.func.id, node.lineno, new_multilabel, self.policy)
                        else:
                            multilabel = self.modified_vars_if[arg.id]
                            self.vulnerabilities.add_illegal_flow(node.func.id, node.lineno, multilabel, self.policy)

                    if arg.id in self.modified_vars_else:
                        if self.modified_vars_else[arg.id] == -1:
                            new_label = New_Label.New_Label()
                            source = Context(arg.id, node.lineno)
                            new_label.add_source(source)
                            new_multilabel = MultiLabel.MultiLabel()
                            for pattern in pattern_list_sinks:
                                new_multilabel.add_label(new_label, pattern.get_name(), self.policy.patterns)
                            self.vulnerabilities.add_illegal_flow(node.func.id, node.lineno, new_multilabel, self.policy)
                        else:
                            multilabel = self.modified_vars_else[arg.id]
                            self.vulnerabilities.add_illegal_flow(node.func.id, node.lineno, multilabel, self.policy)

                    arg_is_source = self.policy.is_source(arg.id)
                    if arg_is_source:
                        new_label = New_Label.New_Label()
                        source = Context(arg.id, node.lineno)
                        new_label.add_source(source)
                        multilabel = MultiLabel.MultiLabel()
                        for pattern in arg_is_source:
                            multilabel.add_label(new_label, pattern.get_name(), self.policy.patterns)
                        final_multilabel = final_multilabel.combine_multilabels(multilabel, self.policy.patterns)

                else:
                    multilabel = self.visit(arg)
                    if multilabel is not None:
                        final_multilabel = final_multilabel.combine_multilabels(multilabel, self.policy.patterns)
                        self.vulnerabilities.add_illegal_flow(node.func.id, node.lineno, final_multilabel, self.policy)

        if len(pattern_list_sanitizers) > 0:
            print("CALL - SANITIZER")
            print(pattern_list_sanitizers)
            print("SANITIZER")
            for arg in node.args:
                if isinstance(arg, ast.Name):
                    multilabel = self.multilabelling.get_multilabel(arg.id)
                    if multilabel is not None:
                        final_multilabel = final_multilabel.combine_multilabels(multilabel, self.policy.patterns)
                else:
                    multilabel = self.visit(arg)
                    final_multilabel = final_multilabel.combine_multilabels(multilabel, self.policy.patterns)
            patterns = final_multilabel.get_patterns()
            for pattern in pattern_list_sanitizers:
                if pattern.get_name() in patterns:
                    context = Context(node.func.id, node.lineno)
                    final_multilabel.add_sanitizer_by_pattern(pattern.get_name(), context)

        return final_multilabel

    def visit_Attribute(self, node: ast.Attribute) -> MultiLabel.MultiLabel:

        """
            Visitor for the class Attribute 
        """
        print("Visiting an Attribute Node")
        print(node.value.id)
        print(node.attr)
        #return self.visit(node.attr)
        attribute_is_source = self.policy.is_source(node.attr)
        attribute_is_sanitizer = self.policy.is_sanitizer(node.attr)
        attribute_is_sink = self.policy.is_sink(node.attr)

        multilabel = self.multilabelling.get_multilabel(node.attr) 
        if multilabel is not None:
            return multilabel

        print(node.attr.__class__)
        if attribute_is_source:
            print("ATTR - Source")
            new_label = New_Label.New_Label()
            source = Context(node.attr, node.lineno)
            multilabel = MultiLabel.MultiLabel()
            new_label.add_source(source)
            for pattern in attribute_is_source:
                multilabel.add_label(new_label, pattern.get_name(), self.policy.patterns)

            # Propagate to node.value
            value_is_source = self.policy.is_source(node.value.id)
            if value_is_source:
                multilabel_var = self.multilabelling.get_multilabel(node.value.id)
                if multilabel_var is not None:
                    multilabel = multilabel.combine_multilabels(multilabel_var, self.policy.patterns)
                else:
                    new_label = New_Label.New_Label()
                    source = Context(node.value.id, node.lineno)
                    multilabel_var = MultiLabel.MultiLabel()
                    new_label.add_source(source)
                    for pattern in attribute_is_source:
                        multilabel_var.add_label(new_label, pattern.get_name(), self.policy.patterns)
                    for pattern in value_is_source:
                        multilabel_var.add_label(new_label, pattern.get_name(), self.policy.patterns)
                multilabel = multilabel.combine_multilabels(multilabel_var, self.policy.patterns)
            return multilabel


        elif attribute_is_sanitizer:
            print("ATTR - Sanitizer")
            new_label = New_Label.New_Label()
            sanitizer = Context(node.attr, node.lineno)
            multilabel = MultiLabel.MultiLabel()
            new_label.add_source(sanitizer)
            for pattern in attribute_is_sanitizer:
                multilabel.add_sanitizer_by_pattern(pattern.get_name(), sanitizer)

            # Propagate to node.value
            value_is_source = self.policy.is_sanitizer(node.value.id)
            if value_is_source:
                multilabel_var = self.multilabelling.get_multilabel(node.value.id)
                if multilabel_var is not None:
                    multilabel = multilabel.combine_multilabels(multilabel_var, self.policy.patterns)
                else:
                    new_label = New_Label.New_Label()
                    source = Context(node.value.id, node.lineno)
                    multilabel_var = MultiLabel.MultiLabel()
                    new_label.add_source(source)
                    for pattern in value_is_source:
                        multilabel_var.add_label(new_label, pattern.get_name(), self.policy.patterns)
                    multilabel = multilabel.combine_multilabels(multilabel_var, self.policy.patterns)
                return multilabel


        elif attribute_is_sink:
            print("ATTR - SINK")
            

        else:
            new_label = New_Label.New_Label()
            source_1 = Context(node.value.id, node.lineno)
            multilabel = MultiLabel.MultiLabel()
            new_label.add_source(source_1)
            for pattern in self.policy.patterns:
                multilabel.add_label(new_label, pattern.get_name(), self.policy.patterns)
            return multilabel

        #elif isinstance(node.attr, ast.Call):
        #    print("ATTR - CALL")

        return MultiLabel.MultiLabel()

    # -------------------------------------------------------------------------
    # Visitors for Statements
    # -------------------------------------------------------------------------

    def visit_While(self, node: ast.While):
        """
            Visitor for the class While
        """
        print("Visiting a While Node")
        current_multilabelling = self.multilabelling.copy_multilabelling(self.policy.patterns)

        iterations = 0
        while iterations < self.max_iterations and not self.multilabelling == current_multilabelling:
            for stmt in node.body:
                self.visit(stmt)
            iterations += 1
            print("Iteration: " + str(iterations))

             

        print(current_multilabelling == self.multilabelling)

    def visit_Assign(self, node: ast.Assign):
        """
            Visitor for the  class Assign
        """
        print("Visiting an Assign Node")
        left_value = node.targets[0]
        right_value = node.value

        if isinstance(left_value, ast.Attribute):
            print(left_value.value.id)
            print(left_value.attr)
            
            left_multilabel = self.multilabelling.get_multilabel(left_value.attr)
            if left_multilabel is not None:
                final_multilabel = left_multilabel.combine_multilabels(self.visit(right_value), self.policy.patterns)
                self.multilabelling.add_multilabel(final_multilabel, left_value.attr.id)
            else:
                self.multilabelling.add_multilabel(self.visit(right_value), left_value.value.id)

            left_value_attribute_is_sink = self.policy.is_sink(left_value.attr)
            left_value_is_sink = self.policy.is_sink(left_value.value.id)
            if left_value_attribute_is_sink or left_value_is_sink:
                print("One is Sink")
                if isinstance(right_value, ast.Name):
                    multilabel = self.multilabelling.get_multilabel(right_value.id)
                else:
                    multilabel = self.visit(right_value)
                for pattern in left_value_attribute_is_sink:
                    print("PATTERN: " + pattern.get_name())
                    self.vulnerabilities.add_illegal_flow(left_value.attr, node.lineno, multilabel, self.policy)
                for pattern in left_value_is_sink:
                    print("PATTERN: " + pattern.get_name())
                    self.vulnerabilities.add_illegal_flow(left_value.value.id, node.lineno, multilabel, self.policy)

        if isinstance(right_value, ast.Constant):
            if isinstance(left_value, ast.Name):
                self.multilabelling.add_multilabel(MultiLabel.MultiLabel(), left_value.id)

        elif isinstance(right_value, ast.Name):
            print("NAME")
            left_value_is_sink = self.policy.is_sink(left_value.id)
            if left_value_is_sink:
                print("LEFT IS SINK")
                multilabel = self.multilabelling.get_multilabel(right_value.id)
                self.vulnerabilities.add_illegal_flow(left_value.id, node.lineno, multilabel, self.policy)
            if right_value.id in self.multilabelling.get_vars():
                print("RIGHT IS VAR")
                right_multilabel = self.multilabelling.get_multilabel(right_value.id)
                if isinstance(left_value, ast.Name):
                    if left_value.id in self.multilabelling.get_vars():
                        # Left Value already has a MultiLabel associated, so we need to combine them
                        print("Both have multilabels")
                        left_multilabel = self.multilabelling.get_multilabel(left_value.id)
                        new_multilabel = right_multilabel.combine_multilabels(left_multilabel, self.policy.patterns)
                        self.multilabelling.update_multilabel(new_multilabel, left_value.id)
                    else:
                        # Left Value is not assigned 
                        # Should we delete the entry assigned to right_multilabel?
                        new_multilabel = right_multilabel.copy_multilabel(self.policy.patterns)
                        context = Context(left_value.id, node.lineno)
                        for _, labels in new_multilabel.get_items():
                            for label in labels:
                                new_multilabel.add_source(label, context, self.policy.patterns)
                        self.multilabelling.add_multilabel(new_multilabel, left_value.id)

        elif isinstance(right_value, ast.Call):
            print("CALL")
            pattern_list_sources = self.policy.is_source(right_value.func.id)
            pattern_list_sanitizers = self.policy.is_sanitizer(right_value.func.id)
            pattern_list_sinks = self.policy.is_sink(right_value.func.id)

            if len(pattern_list_sources) > 0:
                left_value_is_sink = self.policy.is_sink(left_value.id)
                new_label = New_Label.New_Label()
                context = Context(right_value.func.id, node.lineno)
                new_label.add_source(context)
                multilabel = MultiLabel.MultiLabel()
                for pattern in pattern_list_sources:
                    multilabel.add_label(new_label, pattern.get_name(), self.policy.patterns)
                self.multilabelling.add_multilabel(multilabel, left_value.id)

                if left_value_is_sink:
                    print("LEFT IS SINK")
                    self.vulnerabilities.add_illegal_flow(left_value.id, node.lineno, multilabel, self.policy)

            elif len(pattern_list_sanitizers) > 0:
                print("FUNCTION IS SANITIZER")
                final_multilabel = MultiLabel.MultiLabel()
                for arg in right_value.args:
                    if isinstance(arg, ast.Name):
                        multilabel = self.multilabelling.get_multilabel(arg.id)
                        if multilabel is not None:
                            print(arg.id)
                            final_multilabel = final_multilabel.combine_multilabels(multilabel, self.policy.patterns)
                        
                        else:
                            print("LABEL DOES NOT EXIST")
                            new_label = New_Label.New_Label()
                            source = Context(arg.id, node.lineno)
                            new_label.add_source(source)
                            new_multilabel = MultiLabel.MultiLabel()
                            for pattern in self.policy.vulnerability_names():
                                new_multilabel.add_label(new_label, pattern, self.policy.patterns)
                            final_multilabel = final_multilabel.combine_multilabels(new_multilabel, self.policy.patterns)
                        arg_is_source = self.policy.is_source(arg.id)
                        if arg_is_source:
                            new_label = New_Label.New_Label()
                            source = Context(arg.id, node.lineno)
                            new_label.add_source(source)
                            multilabel = MultiLabel.MultiLabel()
                            for pattern in arg_is_source:
                                multilabel.add_label(new_label, pattern.get_name(), self.policy.patterns)
                            print(multilabel.multilabels)
                            final_multilabel = final_multilabel.combine_multilabels(multilabel, self.policy.patterns)
                            print(final_multilabel.multilabels)
                            #current_multilabel = self.multilabelling.get_multilabel(left_value.id)
                            #final_multilabel = current_multilabel.combine_multilabels(multilabel, self.policy.patterns)
                    else:
                        multilabel = self.visit(arg)
                        final_multilabel = final_multilabel.combine_multilabels(multilabel, self.policy.patterns)
                patterns = final_multilabel.get_patterns()
                for pattern in pattern_list_sanitizers:
                    if pattern.get_name() in patterns:
                        context = Context(right_value.func.id, node.lineno)
                        final_multilabel.add_sanitizer_by_pattern(pattern.get_name(), context)
                left_value_is_sink = self.policy.is_sink(left_value.id)
                if left_value_is_sink:
                    for pattern in left_value_is_sink:
                        self.vulnerabilities.add_illegal_flow(left_value.id, node.lineno, final_multilabel, self.policy)
                self.multilabelling.add_multilabel(final_multilabel, left_value.id)
            # Case in which the left value is a sink?
            elif len(pattern_list_sinks) > 0:
                print("FUNCTION IS SINK")
                final_multilabel = MultiLabel.MultiLabel()
                for arg in right_value.args:
                    if isinstance(arg, ast.Name):
                        print(arg.id)
                        multilabel = self.multilabelling.get_multilabel(arg.id)
                        if multilabel is not None:
                            final_multilabel = final_multilabel.combine_multilabels(multilabel, self.policy.patterns)

                        arg_is_source = self.policy.is_source(arg.id)
                        if arg_is_source:
                            new_label = New_Label.New_Label()
                            source = Context(arg.id, node.lineno)
                            new_label.add_source(source)
                            multilabel = MultiLabel.MultiLabel()
                            for pattern in arg_is_source:
                                multilabel.add_label(new_label, pattern.get_name(), self.policy.patterns)
                            final_multilabel = final_multilabel.combine_multilabels(multilabel, self.policy.patterns)

                    else:
                        print(arg)
                        aux = self.visit(arg)
                        print(aux.multilabels)
                        final_multilabel = final_multilabel.combine_multilabels(aux, self.policy.patterns)
                self.multilabelling.add_multilabel(final_multilabel, left_value.id)
                self.vulnerabilities.add_illegal_flow(right_value.func.id, node.lineno, final_multilabel, self.policy)
        else:
            multilabel = self.visit(right_value)

    def visit_If(self, node: ast.If):
        """
            Visitor for the class If
        """
        print("Visiting an If Node")
        current_multilabelling = self.multilabelling.copy_multilabelling(self.policy.patterns)

        for stmt in node.body:
            self.visit(stmt)
            for var in self.multilabelling.get_vars():
                if var not in current_multilabelling.get_vars():
                    self.modified_vars_if[var] = -1
                else:
                    if not current_multilabelling.get_multilabel(var) == self.multilabelling.get_multilabel(var):
                        self.modified_vars_if[var] = current_multilabelling.get_multilabel(var)
            multilabelling_after_if = self.multilabelling.copy_multilabelling(self.policy.patterns)

        self.multilabelling = current_multilabelling.copy_multilabelling(self.policy.patterns)
        for stmt in node.orelse:
            self.visit(stmt)

            for var in self.multilabelling.get_vars():
                if var not in current_multilabelling.get_vars():
                    self.modified_vars_else[var] = -1
                else:
                    if not current_multilabelling.get_multilabel(var) == self.multilabelling.get_multilabel(var):
                        self.modified_vars_else[var] = current_multilabelling.get_multilabel(var)
        self.multilabelling = self.multilabelling.combine_multilabelling(multilabelling_after_if, self.policy.patterns)

    def visit_Expr(self, node: ast.Expr):
        """
            Visitor for the class Expr
        """

        print("Visiting an Expr Node")
        self.generic_visit(node)

    # TO create a specific visitor just create a new method like the following
    """
        def visit_<Node type>(self, node:ast.AST):
            pass
    """

    # This works just like an override in java, for the visitors that haven't
    # been overriden the visitor will use the default ones

    """
        Visitors to be implemented:

            Expressions:
                Constant
                Name
                BinOp, UnaryOp
                BoolOp, Compare
                Call
                Attribute

            Satements:
                Expr
                Assign
                If
                While
    """
