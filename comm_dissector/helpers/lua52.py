#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Demo of lrparsing.py - A Lua52 to Python compiler.
#
# SYNOPSIS
#   lua52.py [--] [program.lua]
#
# DESCRIPTION
#
#   Compile a Lua version 5.2 program to Python.  If the "program.lua" is
#   supplied it is converted to "program.py", otherwise a Lua 5.2 program
#   read from standard input is written to standard output.
#
# WARNING
#
#   This is a demo, not working code.  It has compiled and run one Lua 5.2
#   program: k-nucleotide #2 from http://benchmarksgame.alioth.debian.org/ (a
#   copy of which can be found lrparsing-lua.py) that produces the correct
#   output.  This was sufficient to demonstrate lrparing.py,  It is not
#   enough to make it alpha, let alone beta code.
#
#   If you need more reasons you should not use this module:
#
#     (a) An alternative solution would be to make a lua52 C extension to
#         Python.  If you did that it would run 30 times faster.
#
#     (b) In the Lua standard library, packages and coroutines have not been
#         implemented at all.  Most of the rest hasn't been tested at all.
#
# Copyright (c) 2013,2014,2015,2016 Russell Stuart.
# Licensed under GPLv2, or any later version.
#
import itertools
import locale
import math
import os
import random
import re
import stat
import subprocess
import sys
import tempfile
import time

import lrparsing
from lrparsing import (
    Grammar, Keyword, List, Opt, Prio, Repeat, Ref, Right,
    THIS, Token, Tokens, TokenRegistry)


#
# The complete Lua52 grammar.
#
class Lua52Grammar(Grammar):
    class T(TokenRegistry):
        name = Token(re='[a-zA-Z_][a-zA-Z_0-9]*')
        short_string = Token(re=r'"(?:[^"\\]|\\.)*"' + "|" + r"'(?:[^'\\]|\\.)*'")
        long_string = Token(re=r'\[(=*)\[.*?\\]\1\]')
        decimal_number = Token(re=(
            '(?:[0-9]+(?:[.][0-9]*)?|[.][0-9]+)' +
            '(?:[Ee][+-]?[0-9]+)?'))
        hex_number = Token(re=(
            '0[xX]' +
            '(?:[0-9a-fA-Z]+(?:[.][0-9a-fA-F]*)?|[.][0-9a-fA-F]+)' +
            '(?:[pP][+-]?[0-9a-zA-F]+)?'))
        var_args = Token("...")
        line_comment = Token(re='--(?:\n|(?:[^[\n]|\\[=*[^[=])[^\n]*\n)')
        block_comment = Token(re=r'--\[(=*)\[.*?\]\1\]')
    #
    # Forward declarations.
    #
    exp = Ref("exp")
    prefix_exp = Ref("prefix_exp")
    last_statement = Ref("last_statement")
    statement = Ref("statement")
    #
    # Collective tokens.
    #
    string = T.short_string | T.long_string
    number = T.decimal_number | T.hex_number
    variable_ref = List(T.name, ".", min=1)
    subscript_exp = prefix_exp + '[' + exp + ']'
    var = variable_ref | subscript_exp
    var_list = List(var, ',', min=1)
    exp_list = List(exp, ',', min=1)
    #
    # Table constructor.
    #
    field = '[' + exp + ']' + '=' + exp | T.name + '=' + exp | exp
    table_constructor = '{' + List(field, Tokens(", ;"), opt=True) + '}'
    #
    # A function call.
    #
    function_args = (
        '(' + Opt(exp_list) + ')' | table_constructor | string)
    function_call = (
        prefix_exp + function_args |
        prefix_exp + ':' + T.name + function_args)
    #
    # A sequnece of statements.
    #
    block = Repeat(statement + Opt(';')) + Opt(last_statement + Opt(';'))
    #
    # Scope control.  These 0 length productions create and delete scopes
    # for the variables used and declared between them.
    #
    begin_scope = THIS * 0
    end_scope = THIS * 0
    loop = THIS * 0
    begin_loop_scope = begin_scope + loop
    scope = begin_scope + block + end_scope
    loop_scope = begin_loop_scope + block + end_scope
    #
    # A Function definition.
    #
    name_list = Right(List(T.name, ',', min=1))
    _parameter_list = T.name | T.var_args | T.name + ',' + THIS
    parameter_list = Opt(_parameter_list)
    function_body = (
        begin_scope + '(' + parameter_list + ')' +
        block + end_scope + Keyword('end'))
    anon_function = Keyword('function') + function_body
    #
    # An expression.
    #
    constant = Tokens("", 'nil false true')
    adjusted_exp = '(' + exp + ')'
    _atom = (
        constant | number | string | T.var_args | anon_function |
        table_constructor)
    prefix_exp = Prio(function_call, adjusted_exp, var)
    exp = Prio(
        _atom,
        prefix_exp,
        exp >> '^' >> exp,
        Tokens("- #", "not") >> exp,
        exp << Tokens("* / %") << exp,
        exp >> ".." >> exp,
        exp << Tokens("+ -") << exp,
        exp << Tokens("< <= > >= == ~=") << exp,
        exp << Keyword("and") << exp,
        exp << Keyword("or") << exp)
    function_name = variable_ref + Opt(':' + T.name)
    #
    # The statements.
    #
    assign_st = var_list + '=' + exp_list
    do_st = Keyword('do') + scope + Keyword('end')
    while_st = (
        Keyword('while') + exp + Keyword('do') +
        loop_scope + Keyword('end'))
    repeat_st = Keyword('repeat') + loop_scope + Keyword('until') + exp
    if_st = (
        Keyword('if') + exp + Keyword('then') + scope +
        Repeat(Keyword('elseif') + exp + Keyword('then') + scope) +
        Opt(Keyword('else') + scope) +
        Keyword('end'))
    for_steps = T.name + '=' + exp + ',' + exp + Opt(',' + exp)
    for_step_st = (
        Keyword('for') + begin_loop_scope + for_steps +
        Keyword('do') + block + end_scope + Keyword('end'))
    for_name_list = name_list * 1
    for_in_st = (
        Keyword('for') + begin_loop_scope + for_name_list + Keyword('in') +
        exp_list + Keyword('do') + block + end_scope + Keyword('end'))
    function_call_st = function_call * 1
    function_decl_st = Keyword('function') + function_name + function_body
    local_function_decl_st = (
        Keyword('local') + Keyword('function') + T.name + function_body)
    local_assign_st = Keyword('local') + name_list + Opt('=' + exp_list)
    statement = (
        assign_st |
        do_st |
        for_in_st |
        for_step_st |
        function_call_st |
        function_decl_st |
        if_st |
        local_assign_st |
        local_function_decl_st |
        repeat_st |
        while_st)
    return_st = Keyword('return') + Opt(exp_list)
    break_st = Keyword("break")
    last_statement = return_st | break_st
    #
    # Special grammar symbols.
    #
    begin_program = begin_scope * 1
    end_program = end_scope * 1
    START = begin_program + block + end_program
    COMMENTS = T.line_comment | T.block_comment

#
# A List of all python keywords so we can avoid them when generating variable
# names.
#
PYTHON_KEYWORDS = frozenset((
    "and",       "del",       "from",      "not",       "while",
    "as",        "elif",      "global",    "or",        "with",
    "assert",    "else",      "if",        "pass",      "yield",
    "break",     "except",    "import",    "print",
    "class",     "exec",      "in",        "raise",
    "continue",  "finally",   "is",        "return",
    "def",       "for",       "lambda",    "try",))


#
# Return the an object that will generate python name for a lua name
# when passed to str().  The correct python name can't be known until
# we have seen where the lua name is used.
#
class PythonName(object):

    def __init__(self, variable, table_path):
        self.__variable = variable
        self.__table_path = table_path

    def __str__(self):
        indexed = []
        table_path = self.__table_path
        while table_path not in self.__variable.table_members:
            table_path, last = table_path.rsplit(".", 1)
            indexed.insert(0, last)
        names = table_path.split(".", 1)
        if self.__variable.use_namespace:
            names[0] = "%s.%s" % (
                self.__variable.declare_scope,
                self.__variable.escape(names[0]))
        else:
            parent = self.__variable.declare_scope.parent
            while parent is not None:
                if names[0] in parent.declared_vars:
                    var = parent.declared_vars[names[0]]
                    if var in self.__variable.declare_scope.nested_used_vars:
                        if not var.use_namespace:
                            break
                parent = parent.parent
            if parent is None:
                names[0] = self.__variable.escape(names[0])
            else:
                names[0] = "_l%d_%s" % (self.__variable.declare_scope.seq, names[0])
        return '.'.join(names) + ''.join("[%r]" % i for i in reversed(indexed))


#
# Information we keep about a variable declaration.
#
class Variable(object):
    declare_scope = None    # object, The scope the name was declared in
    lua_name = None         # string, The variable name
    table_members = None    # set,    Well known members of this table
    use_namespace = None    # bool,   True if must be an explicit namespace

    def __init__(self, lua_name, declare_scope):
        self.lua_name = lua_name
        self.declare_scope = declare_scope
        self.table_members = set()
        self.use_namespace = False
        self.add_table_path(lua_name)

    def add_table_path(self, table_path):
        self.table_members.add(table_path)

    def escape(self, lua_name):
        escape = lambda lua_name: "_l_" + lua_name
        if lua_name in PYTHON_KEYWORDS:
            return escape(lua_name)
        if lua_name == '_ENV':
            return lua_name
        if (self.declare_scope.parent is None and
                lua_name in Lua52StandardLibrary.__dict__):
            return lua_name
        if lua_name[0] == '_':
            return escape(lua_name)
        return lua_name

    def python_name(self, table_path=None):
        return PythonName(self, table_path or self.lua_name)


#
# This object collects everything we must know about a Lua scope -
# ie the stuff declared within a block.
#
class Scope(object):
    __slots__ = (
        'declared_vars',        # dict,   {'lua_name': Variable(), ...}
        'hoist',                # list,   Code to move above the current code.
        'function_depth',       # int,    Degree of function nexting
        'function_name',        # object, Generate a name for declare function
        'function_vars',        # dict,   set(Variable(),...) used by this function
        'in_loop',              # bool,   True if this scope is inside a loop
        'name',                 # string, Suggested name for this scope.
        'nested_used_vars',     # set,    set(Variable(),...) in nested scopes
        'parent',               # object, Scope() that contains this one.
        'seq',                  # int,    A unique number allocated to us
        'used_vars',            # set,    set(Variable(),...) used by this scope
        'variable',)            # object, Variable this scope was assigned to

    #
    # Generate the name of a function that has this scope as its body.
    # This will be its assigned name if there is one, otherwise we just
    # use the scope name.
    #
    class FunctionName(object):

        def __init__(self, scope):
            self.scope = scope

        def __str__(self):
            if self.scope.variable is not None:
                return str(self.scope.variable.python_name())
            if self.scope.name is not None:
                return "_f_" + self.scope.name
            return str(self.scope)

    #
    # Create a new instance of ourselves.
    #
    def __init__(self, parent, seq):
        self.hoist = []
        self.parent = parent
        self.seq = seq
        self.declared_vars = {'_ENV': Variable('_ENV', self)}
        self.function_name = self.FunctionName(self)
        self.name = None
        self.nested_used_vars = set()
        self.used_vars = set()
        self.variable = None
        if self.parent is None:
            self.function_depth = 0
            self.new_function_scope()
        else:
            self.function_vars = self.parent.function_vars
            self.function_depth = self.parent.function_depth
            self.in_loop = self.parent.in_loop

    #
    # Declare a variable as defined in this scope.
    #
    def declare_var(self, lua_name):
        if lua_name not in self.declared_vars:
            self.declared_vars[lua_name] = Variable(lua_name, self)

    #
    # Set a suggested name for this scope.
    #
    def set_name(self, token):
        self.name = token.token

    #
    # The variable this scope was assigned to (ie, function name).
    #
    def set_variable(self, variable):
        self.variable = variable

    #
    # Say this scope is associated with a function definition.
    #
    def new_function_scope(self):
        self.function_depth += 1
        self.function_vars = set()
        self.in_loop = False

    #
    # Return the Variable() associated with a name reference.  We search up
    # through the scope heirarchy, looking for where it was declared.  If
    # it wasn't declared we declare it in the global scope and return that.
    #
    def use_var(self, token):
        scope = self
        while scope is not None:
            global_scope = scope
            if token.token in scope.declared_vars:
                break
            scope = scope.parent
        if scope is None:
            global_scope.declare_var(token.token)
            return global_scope.use_var(token)
        variable = scope.declared_vars[token.token]
        self.used_vars.add(variable)
        if scope.function_depth < self.function_depth:
            loop_scope = self
            while loop_scope is not None and loop_scope.function_depth == self.function_depth:
                loop_scope = loop_scope.parent
            while loop_scope is not None and loop_scope is not scope:
                if loop_scope.in_loop:
                    assert variable.lua_name != "kfrequency"
                    variable.use_namespace = True
                    break
                loop_scope = loop_scope.parent
        return variable

    #
    # Generate the code needed to initialise this scope.
    #
    def compile(self):
        result = []
        namespace_vars = frozenset(
            var.python_name()
            for var in self.declared_vars.values()
            if var.use_namespace)
        if namespace_vars:
            vars = ', '.join(
                '%s=None' % var
                for var in sorted(namespace_vars) if var != "_ENV")
            result.append([self, '= _lua52.Namespace(%s)' % (vars,)])
        if self.parent is None or self.parent.function_depth != self.function_depth:
            global_vars = frozenset(
                str(v.python_name())
                for v in self.function_vars
                if v.declare_scope.parent is None)
            if global_vars:
                result.append(["global " + ", ".join(sorted(global_vars))])
        if result:
            result.append([""])
        return tuple(result)

    #
    # Return a set of ancestor namespaces used by this scope.
    #
    def used_namespaces(self):
        return sorted(frozenset(
            str(var.declare_scope)
            for var in self.function_vars
            if var.declare_scope.function_depth < self.function_depth
            if var.use_namespace))

    #
    # This scope is finalised.
    #
    def pop(self):
        self.function_vars |= self.used_vars
        self.nested_used_vars |= self.used_vars
        if self.parent is not None:
            self.parent.nested_used_vars |= self.nested_used_vars

    #
    # Return this scopes name.
    #
    def __str__(self):
        scope = self
        name = "_ENV"
        while scope.parent is not None:
            if scope.name is not None:
                name = scope.name
                break
            if scope.variable is not None:
                name = scope.variable.lua_name
                break
            scope = scope.parent
        result = "_s%d_%s" % (self.seq, name)
        return result


#
# Hold global information about the program as we compile it.
#
class Lua52Compiler(object):
    scope = None                # The current variable scope
    _compiled = None            # The parse tree
    _counter = None             # Used to generate unique numbers.

    def __init__(self):
        self._counter = 0

    #
    # Generate a unique number.  Used in variable naming.
    #
    def seq(self):
        self._counter += 1
        return self._counter

    #
    # The tree_factory passed to lrparsing.parse().
    #
    def tree_factory(self, nodes):
        self._compiled = Lua52Node(self, nodes)
        return self._compiled

    #
    # Define a new scope.
    #
    def push_scope(self):
        self.scope = Scope(self.scope, self.seq())
        return self.scope

    #
    # The current scope is completed, go back to the other one.
    #
    def pop_scope(self):
        self.scope.pop()
        self.scope = self.scope.parent

    #
    # Declare a variable in the current scope.
    #
    def declare_var(self, name):
        return self.scope.declare_var(name)

    #
    # Return instance of the variable to use in this scope.
    #
    def use_var(self, token):
        return self.scope.use_var(token)

    #
    # Return the python name for a lua token.
    #
    def python_name(self, token):
        return self.use_var(token).python_name(token.token)

    #
    # Return the compiled parse tree as a string.
    #
    def compiled(self):
        result = []
        stack = [[self._compiled.compiled, 0]]
        indent = 0
        last = "\n"
        while stack:
            top = stack[-1]
            if len(top[0]) == top[1]:
                if isinstance(top[0], list):
                    last = "\n"
                    if result and not ''.join(result[-2:]).endswith("\n\n"):
                        result.append(last)
                stack.pop()
                continue
            atom = top[0][top[1]]
            top[1] += 1
            if isinstance(atom, (list, tuple)):
                stack.append([atom, 0])
                continue
            if atom == Lua52Node.INDENT:
                indent += 1
                continue
            if atom == Lua52Node.OUTDENT:
                indent -= 1
                continue
            output = str(atom)
            if output == "":
                continue
            if last == "\n":
                last = "?"
                result.append("  " * indent)
            new_last = output[-1]
            if new_last == '?':
                output = output[:-1]
            if output[0] == '?':
                result.append(output[1:])
            elif last == '?':
                result.append(output)
            else:
                result.append(" ")
                result.append(output)
            last = new_last
        return ''.join(result)


#
# Each instance of this class represents a node in the parse tree.
#
# It inherits from tuple because it is a super set of what lrparing.parse()
# normally returns.  This has two nice effects.  Firstly it preserves the raw
# output of the parser (the parse_tree), as just adds information (the
# compiled form) in an obvious way.  Secondly lrparsing.repr_parse_tree() works
# on it, which makes printing understandable trace during debugging easier.
#
# The magic that makes this work is hidden in its __new__ function.
#
class Lua52Node(tuple):
    INDENT, OUTDENT = list(range(2))

    #
    # The compiled form mimics the parse tree in that it also is a nested
    # series of tuples, with the leaves being the string of Python code the
    # Lua code was compiled into.  So a Lua expression statement 'x = 1.0 + y'
    # might yield:
    #
    #    ([('x',), '=', (('1.0',), '+', ('y',))])
    #
    # The final result is compiled into one large string after the compile is
    # finished.  It is done this way for 2 reasons.  Firstly it avoids the
    # O(N^2) behaviour of continually concatenating strings.  Secondly, it is
    # the str(leaf) that is used, so a leaf doesn't have to be a string.  This
    # allows us to delay making some decisions until we have seen the entire
    # program, and in particular it allows us to defer naming a variable until
    # we have seen all the ways it has been used.
    #
    # Putting an element in a list rather than a tuple means it belongs on
    # a line by itself.
    #
    compiled = None     # seq,     A tuple of compiled code.
    data = None         # object,  Data(), repository for random bits of info
    rhs = None          # list,    The rhs of the recognised production
    rule = None         # object,  The Grammar.Rule on the lhs

    #
    # A place to store ancillary data a node it might generate that isn't
    # compiled code.  For example, a block puts the reference to the scope
    # so the function that declared the scope can get hold of it using:
    #
    #   self._set_data(scope=compiler.scope)
    #
    class Data(object):
        def __init__(self, **kwds):
            self.__dict__.update(kwds)

    #
    # Create a new instance of ourselves.
    #
    def __new__(cls, compiler, nodes):
        result = super(Lua52Node, cls).__new__(cls, nodes)
        result.rule = nodes[0]
        result.rhs = nodes[1:]
        result.data = None
        if not isinstance(result.rule, Token):
            name = result.rule.name
        else:
            name = result.rule.name.split(".")[-1]
            result.token = nodes[1]
        #
        # These next two lines are the heart of the interface between the
        # Grammar and the compiler.  If Lua52Node has a function with the
        # same name as a Grammar Symbol, then it is called to compile the
        # node just output by the parser.  If not the default action is
        # just to concatenate the compiled outputs from the children.
        #
        if name in cls.__dict__:
            result.compiled = cls.__dict__[name](result, compiler)
        elif isinstance(result.rule, Token):
            result.compiled = (result.token,)
        elif len(nodes) == 2:
            result.compiled = nodes[1].compiled
        else:
            result.compiled = tuple(n.compiled for n in nodes[1:])
        assert result.compiled is not None, str(result.rule)
        return result

    #
    # Useful for debugging.
    #
    def __str__(self):
        return str(self.rule)

    #
    # Useful for debugging.
    #
    def __repr__(self):
        return lrparsing.repr_parse_tree(self, False)

    #
    # Save some information for parent nodes.  The information is passed as
    # keywords, and written into self.data.kwd = value.
    #
    def _set_data(self, **kwds):
        if self.data is None:
            self.data = self.Data()
        self.data.__dict__.update(kwds)

    #
    # Return the position of the current parse tree node in the input stream.
    #
    def _position(self):
        if isinstance(self.rule, Token):
            return self.rule.position(self)
        for node in reversed(self.rhs):
            result = node._position()
            if result:
                return result
        return None

    #
    # Compile the right hand side of an assignment statement so it conforms
    # to Lua assignment semantics.  In Lua, the number of expressions on
    # the right hand side are padded with nil or truncated to match the
    # number of expressions on the left hand side.  Function calls and
    # "..." are treated specially.  If they are the last expression they
    # extend the right hand expression list, otherwise only the first value
    # is used.
    #
    # Given:
    #
    #   name, name, ... = exp, ... exp [, tail]
    #
    #   name_count      is the number of names on the left hand side.
    #   exp_list        is (exp.compiled, ...)
    #   tail            is the trailing "..." or function call, compiled.
    #
    def _assign_rhs(self, name_count, exp_list, tail_compiled=None):
        if not isinstance(exp_list, Lua52Node):
            tail_node = None
        else:
            exp_list, tail_node = exp_list.data.exp_list, exp_list.data.tail
            tail_compiled = tail_node and tail_node.compiled
        nones = name_count - len(exp_list)
        if nones <= 0:
            padding = ()
        elif nones > len(NONE):
            padding = '+ (' + ', '.join(("None",) * nones) + ')'
        else:
            padding = '+ _lua52.NONE%d' % nones
        exp_list_compiled = [(compiled, '?,') for compiled in exp_list]
        if exp_list_compiled:
            exp_list_compiled[-1] = exp_list_compiled[-1][0]
        exp_list_compiled = tuple(exp_list_compiled)
        if tail_compiled is not None:
            if len(exp_list_compiled) == 0:
                if not tail_node or self._nested_rule(tail_node, Lua52Grammar.T.var_args):
                    if name_count == 0:
                        return tail_compiled
                    if name_count == 1:
                        return (tail_compiled, '?[0]')
            elif len(exp_list_compiled) == 1:
                exp_list_compiled = ('(?', exp_list_compiled, '?,) +')
            else:
                exp_list_compiled = ('(?', exp_list_compiled, '?) +')
            if name_count == 0:
                return (exp_list_compiled, tail_compiled)
            exp_list_compiled = (
                '(?', exp_list_compiled, tail_compiled, padding, '?)')
            if name_count == 1:
                return (exp_list_compiled, '?[0]')
            return (exp_list_compiled, '?[:%d]' % name_count)
        if name_count == 0:
            if len(exp_list_compiled) == 1:
                return ('(?', exp_list_compiled, '?,)')
            return exp_list_compiled
        if len(exp_list) == name_count:
            return exp_list_compiled
        if not padding:
            return ('(?', exp_list_compiled, '?)[:%d]' % name_count)
        if len(exp_list) == 1:
            exp_list_compiled = (exp_list_compiled, '?,')
        return ('((?', exp_list_compiled, '?)', padding, '?)[:%d]' % name_count)

    #
    # Compile an argument list according to Lua semantics.  The sematics are
    # the same as assignment, except the list is never truncted.
    #
    def _function_args(self, exp_list):
        compiled = [(compiled, '?,') for compiled in exp_list.data.exp_list]
        if exp_list.data.tail:
            compiled.append(('*?', exp_list.data.tail.compiled))
        else:
            compiled[-1] = compiled[-1][0]
        return tuple(compiled)

    #
    # Verify the method names delcared match rules in the passed grammar.
    # Class members who names start with '_' or who aren't callable are
    # ignored.
    #
    @classmethod
    def _verify(cls, grammar):
        for name, value in cls.__dict__.items():
            if (name[0] != '_' and callable(value) and
                    not isinstance(value, type)):
                if name in grammar.__dict__:
                    attr = grammar.__dict__[name]
                    assert isinstance(attr, lrparsing.Rule), name
                else:
                    attr = grammar.T.__dict__[name]
                    assert isinstance(attr, Token), name

    #
    # Return if the node derives to the passed symbol through singleton
    # productions.
    #
    @classmethod
    def _nested_rule(cls, node, rule):
        n = node
        while True:
            if n.rule is rule:
                return n
            if len(n.rhs) != 1 or isinstance(n.rule, Token):
                return None
            n = n.rhs[0]

    #
    # Test if the passed Lua52Grammar.exp is a list - ie a function call
    # or "...".
    #
    def _is_list(self, exp):
        if self._nested_rule(exp, Lua52Grammar.function_call):
            return Lua52Grammar.function_call
        if self._nested_rule(exp, Lua52Grammar.T.var_args):
            return Lua52Grammar.T.var_args
        return None

    #
    #     ========================================================
    #
    # The remaining functions here have identical names are rules in the
    # Grammar.  The function is called when that rule is recognised.
    #

    def short_string(self, compiler):
        def lua_sub(match):
            data = match.group()
            c = data[1]
            result = self.LUA_SHORT_STRING_ESC.get(c, c)
            if not callable(result):
                return result
            return result(data[1:])
        self._set_data(klass=str)
        return (repr(self.LUA_SHORT_STRING_RE.sub(lua_sub, self.token)[1:-1]),)

    _string_decimal = lambda data: chr(int(data[1:], 10))
    LUA_SHORT_STRING_RE = re.compile(r"(?s)\\[a-v]|\\z\w*|\\[0-9]+|\\x..")
    LUA_SHORT_STRING_ESC = {
        'a': '\a', 'b': '\b', 'f': '\f', 'n': '\n', 'r': '\r', 't': '\t',
        'v': '\v', 'z': '', 'x': lambda data: chr(int(data[2:], 16)),
        '0': _string_decimal, '1': _string_decimal, '2': _string_decimal,
        '3': _string_decimal, '4': _string_decimal, '5': _string_decimal,
        '6': _string_decimal, '7': _string_decimal, '8': _string_decimal,
        '9': _string_decimal}

    def long_string(self, compiler):
        self._set_data(klass=str)
        marker_len = self.token.find('[', 1) + 1
        if self.token[marker_len] == '\n':
            return (repr(self.token[marker_len + 1:-marker_len]),)
        return (repr(self.token[marker_len:-marker_len]),)

    def decimal_number(self, compiler):
        self._set_data(klass=float)
        return (repr(float(self.token)),)

    def hex_number(self, node, compiler):
        toks = self.token.lower().split("p")
        if len(toks) == 1:
            mult = 1.0
        else:
            mult = 2.0 ** int(toks[1])
        toks = toks[0].split(".")
        if len(toks) == 1:
            number = float(toks[0], 16) * mult
        else:
            number = int(toks[0] + toks[1], 16) * mult / 16.0 ** len(toks[1])
        self._set_data(klass=float)
        return (repr(number),)

    def number(self, compiler):
        self._set_data(klass=self.rhs[0].data.klass)
        return self.rhs[0].compiled

    def var_args(self, compiler):
        return ("_vargs",)

    def begin_scope(self, compiler):
        self._set_data(scope=compiler.push_scope())
        return ()

    def end_scope(self, compiler):
        compiler.pop_scope()
        return ()

    def loop(self, compiler):
        compiler.scope.in_loop = True
        return ()

    def scope(self, compiler):
        begin_scope, block = self.rhs[0], self.rhs[1]
        self._set_data(scope=begin_scope.data.scope)
        return (begin_scope.data.scope.compile(), block.compiled)

    def loop_scope(self, compiler):
        begin_loop_scope, block = self.rhs[0], self.rhs[1]
        self._set_data(scope=begin_loop_scope.data.scope)
        return (begin_loop_scope.data.scope.compile(), block.compiled)

    def begin_loop_scope(self, compiler):
        begin_scope = self.rhs[0]
        self._set_data(scope=begin_scope.data.scope)
        return ()

    def variable_ref(self, compiler):
        variable = compiler.use_var(self.rhs[0])
        table_path = '.'.join(
            self.rhs[i].token for i in range(0, len(self.rhs), 2))
        return (variable.python_name(table_path),)

    def constant(self, compiler):
        result, klass = self.CONSTANT[self.rhs[0].token]
        self._set_data(klass=klass)
        return (repr(result),)
    CONSTANT = {'nil': (None, None), 'true': (True, bool), 'false': (False, bool)}

    def _coerce(self, operand, coerce, self_prio=None):
        if self._nested_rule(operand, Lua52Grammar.function_call):
            compiled = (operand.compiled, '?[0]')
            prio = 10
        elif self._nested_rule(operand, Lua52Grammar.T.var_args):
            compiled = ('(?', operand.compiled, '+ _lua52.NONE1', '?)[0]')
            prio = 10
        else:
            compiled = operand.compiled
            prio = operand.data.prio
        if coerce is not None and operand.data.klass != coerce:
            return ('%s(?' % self.COERCE_TYPE[coerce], compiled, '?)')
        else:
            if self_prio is None:
                self_prio = self.data.prio
            if prio < self_prio:
                return ('(?', compiled, '?)')
        return compiled

    COERCE_TYPE = {
        bool: '_lua52.coerce2bool',
        float: "_lua52.coerce2float",
        str: "_lua52.coerce2string",
    }

    def exp(self, compiler):
        if len(self.rhs) == 1:
            _atom = self.rhs[0]
            rhs = _atom
            klass = None if rhs is None or rhs.data is None else rhs.data.klass
            self._set_data(prio=10, klass=klass)
            return _atom.compiled
        if len(self.rhs) == 2:
            prio, klass, coerce, op = self.UNARY_OP[self.rhs[0].token]
            self._set_data(prio=prio, klass=klass)
            if op[-1] == "?":
                return (op, self.rhs[1].compiled, '?)')
            return (op, self._coerce(self.rhs[1], coerce))
        prio, klass, coerce, op = self.BINARY_OP[self.rhs[1].token]
        self._set_data(prio=prio, klass=klass)
        exp0, exp1 = self.rhs[0], self.rhs[2]
        if op[-1] == '?':
            return (op, exp0.compiled, '?,',  exp1.compiled, '?)')
        if op == '==' and self._nested_rule(exp1, Lua52Grammar.constant):
            op = 'is'
        elif op == '!=' and self._nested_rule(exp1, Lua52Grammar.constant):
            op = 'is not'
        return (self._coerce(exp0, coerce), op, self._coerce(exp1, coerce))

    UNARY_OP = {
        '#': (8, float, None, "_lua52.lualen(?"),
        '-': (8, float, float, '-?'),
        'not': (8, bool, bool, 'not'),
    }

    BINARY_OP = {
        '^': (9, float, float, '**'),
        '*': (7, float, float, '*'),
        '/': (7, float, float, '/'),
        '%': (7, float, float, '%'),
        '..': (6, str, None, '_lua52.luaconcat(?'),
        '+': (5, float, float, '+'),
        '-': (5, float, float, '-'),
        '<': (4, bool, None, '<'),
        '<=': (4, bool, None, '<='),
        '>=': (4, bool, None, '>='),
        '>': (4, bool, None, '>'),
        '==': (4, bool, None, '=='),
        '~=': (4, bool, None, '!='),
        'and': (3, bool, bool, 'and'),
        'or': (2, bool, bool, 'or'),
    }

    def adjusted_exp(self, compiler):
        exp = self.rhs[1]
        self._set_data(klass=exp.data.klass)
        if self._is_list(exp):
            return ('(?', exp.compiled, '+ (None,))[0]')
        return exp.compiled

    def prefix_exp(self, compiler):
        if self.rhs[0].rule is Lua52Grammar.adjusted_exp:
            self._set_data(klass=self.rhs[0].data.klass)
        return self.rhs[0].compiled

    def subscript_exp(self, compiler):
        prefix_exp, exp = self.rhs[0], self.rhs[2]
        return (prefix_exp.compiled, '?[?', exp.compiled, '?]')

    def table_constructor(self, compiler):
        args = []
        for i in range(1, len(self.rhs) - 1, 2):
            field = self.rhs[i]
            if len(field.rhs) == 1:
                args.append(field.compiled)
            else:
                if args and args[-2] == '?}':
                    args[-2:] = ['?,']
                else:
                    args.append('{?')
                if len(field.rhs) == 3:
                    key, value = repr(field.rhs[0].token), field.rhs[2].compiled
                else:
                    key, value = field.rhs[1].compiled, field.rhs[4].compiled
                args.extend((key, "?:", value, "?}"))
            args.append("?,")
        if args:
            del args[-1]
        return ("_lua52.LuaTable(?", tuple(args), "?)")

    def block(self, compiler):
        return tuple(
            s.compiled for s in self.rhs if not isinstance(s.rule, Token))

    def exp_list(self, compiler):
        is_list = bool(self._is_list(self.rhs[-1]))
        if not is_list:
            last, tail = len(self.rhs),  None
        else:
            last, tail = len(self.rhs) - 2, self.rhs[-1]
        exp_list = tuple(
            self._coerce(self.rhs[i], None, 0) for i in range(0, last, 2))
        self._set_data(exp_list=exp_list, tail=tail)
        return ()

    def function_args(self, compiler):
        if len(self.rhs) == 1:
            string_or_table_constructor = self.rhs[0]
            return string_or_table_constructor.compiled
        if len(self.rhs) == 2:
            return ()
        exp_list = self.rhs[1]
        return self._function_args(exp_list)

    def function_call(self, compiler):
        prefix_exp = self.rhs[0]
        function_args = self.rhs[-1]
        if len(self.rhs) == 2:
            if prefix_exp.rhs[0].rule is not Lua52Grammar.adjusted_exp:
                return (prefix_exp.compiled, '?(?', function_args.compiled, '?)')
            return ('(?', prefix_exp.compiled, '?)(?', function_args.compiled, '?)')
        name = self.rhs[2]
        if self._nested_rule(prefix_exp, Lua52Grammar.T.name):
            if not function_args.compiled:
                args = ('(?', prefix_exp.compiled, '?)')
            else:
                args = ('(?', prefix_exp.compiled, '?,', function_args.compiled, '?)')
            return (prefix_exp.compiled, '?[%r]?' % name.token, args)
        if not function_args.compiled:
            args = '(m)'
        else:
            args = ('(m,', function_args.compiled, '?)')
        return (
            '(lambda m: m[%r]?' % name.token, args, '?)',
            '?(?', prefix_exp.compiled, '?)')

    def parameter_list(self, compiler):
        compiler.scope.new_function_scope()
        if len(self.rhs) == 0:
            params = ()
            var_args = None
        else:
            var_args = self.rhs[-1]
            if self._nested_rule(var_args, Lua52Grammar.T.var_args):
                names_end = len(self.rhs) - 2
            else:
                names_end = len(self.rhs)
                var_args = None
            params = []
            for i in range(0, names_end, 2):
                var = self.rhs[i]
                compiler.declare_var(var.token)
                params.append(compiler.python_name(var))
        self._set_data(params=params, var_args=var_args)
        return ("?(*%s)" % self.ARG_NAME,)

    def function_body(self, compiler):
        begin_scope, parameter_list, body = (
            self.rhs[0], self.rhs[2], self.rhs[4])
        scope = begin_scope.data.scope
        #
        # We never know now many arguments will be passed, as Lua says
        # if too few are passed the remainder are set to nil, and if too
        # append are passed they are dropped unless captured by ...
        #
        # Arrange to do all that here.
        #
        param_count = len(parameter_list.data.params)
        arg_setup = [scope.compile()]
        if parameter_list.data.var_args is not None and param_count == 0:
            arg_setup.append([
                parameter_list.data.var_args.compiled,
                "= %s" % (self.ARG_NAME,)])
        elif param_count > 0:
            if param_count <= len(NONE):
                extend = '_lua52.NONE%d' % param_count
            else:
                extend = '_lua52.NONE1 * %d' % param_count
            param_vars = sum(
                ([v, '?,'] for v in parameter_list.data.params), [])
            if parameter_list.data.var_args is None:
                add = '(%s + %s)' % (self.ARG_NAME, extend)
                if param_count == 1:
                    param_vars[-1] = '= %s[0]' % (add,)
                else:
                    param_vars[-1] = "= %s[:%d]" % (add, param_count)
                arg_setup.extend([param_vars])
            else:
                arg_setup.extend((
                    ["%s +=" % self.ARG_NAME, extend],
                    param_vars))
                if param_count == 1:
                    param_vars[-1] = '= %s[0]' % (self.ARG_NAME,)
                else:
                    param_vars[-1] = "= %s[:%d]" % (self.ARG_NAME, param_count)
                arg_setup.append([
                    parameter_list.data.var_args.compiled,
                    "= %s[%d:]" % (self.ARG_NAME, param_count)])
        function_definition = (
            ["def", scope.function_name, parameter_list.compiled, "?:"],
            self.INDENT,
            tuple(arg_setup),
            body.compiled,
            self.OUTDENT,)
        used_namespaces = scope.used_namespaces()
        uses_namespaces = bool(used_namespaces)
        self._set_data(scope=scope, uses_namespaces=uses_namespaces)
        if not uses_namespaces:
            compiler.scope.hoist.append(([""], function_definition))
            return (scope.function_name,)
        call = (
            scope.function_name,
            "?(?", tuple((n, '?,') for n in used_namespaces), "?)")
        definition = (
            [''],
            ["def", call, "?:"],
            self.INDENT,
            function_definition, ["return",  scope.function_name],
            self.OUTDENT)
        compiler.scope.hoist.append(definition)
        return call

    ARG_NAME = "_args"

    def anon_function(self, compiler):
        function_body = self.rhs[1]
        return function_body.compiled

    def assign_st(self, compiler):
        var_list, exp_list = self.rhs[0], self.rhs[2]
        name_count = (len(var_list.rhs) + 1) / 2
        rhs = self._assign_rhs(name_count, exp_list)
        return [var_list.compiled, "=", rhs]

    def do_st(self, compiler):
        scope = self.rhs[1]
        return scope.compiled

    def while_st(self, compiler):
        while_exp, loop_scope = self.rhs[1], self.rhs[3]
        return (
            ['while', self._coerce(while_exp, bool, 0),  '?:'],
            self.INDENT, loop_scope.compiled, self.OUTDENT)

    def repeat_st(self, compiler):
        loop_scope, until_exp = self.rhs[1], self.rhs[3]
        prio, klass = self.UNARY_OP["not"][:1]
        return (
            ['while True:'],
            self.INDENT,
            loop_scope.compiled,
            ['if not', self._coerce(untilt_exp, klass, prio),  '?):'],
            self.INDENT, ['break'], self.OUTDENT,
            self.OUTDENT)

    def if_st(self, compiler):
        compiled = []
        i = 0
        while self.rhs[i].token == 'if' or self.rhs[i].token == 'elseif':
            kwd, condition, scope = (
                self.rhs[i], self.rhs[i + 1], self.rhs[i + 3])
            ife = "if" if kwd.token == "if" else "elif"
            compiled.extend([
                [ife, self._coerce(condition, bool, 0), '?:'],
                self.INDENT, scope.compiled, self.OUTDENT])
            i += 4
        if self.rhs[i].token == 'else':
            scope = self.rhs[i + 1]
            compiled.extend([
                ["else:"],
                self.INDENT, scope.compiled, self.OUTDENT])
        return tuple(compiled)

    def for_steps(self, compiler):
        name, exp_start, exp_stop = self.rhs[0], self.rhs[2], self.rhs[4]
        compiler.declare_var(name.token)
        if len(self.rhs) == 5:
            exp_step_compiled = "1"
        else:
            exp_step_compiled = self.rhs[6].compiled
        self._set_data(python_name=compiler.python_name(name))
        return ("_lua52.luarange(?",
                exp_start.compiled, "?,",
                exp_stop.compiled, "?,", exp_step_compiled, "?)")

    def for_step_st(self, compiler):
        begin_loop_scope, for_steps, block = (
            self.rhs[1], self.rhs[2], self.rhs[4])
        return (
            begin_loop_scope.data.scope.compile(),
            ["for", for_steps.data.python_name, "in", for_steps.compiled, "?:"],
            self.INDENT, block.compiled, self.OUTDENT)

    def for_name_list(self, compiler):
        name_list = self.rhs[0]
        compiled = []
        for i in range(0, len(name_list.rhs), 2):
            compiler.declare_var(name_list.rhs[i].token)
            compiled.append((compiler.python_name(name_list.rhs[i]), "?,"))
        self._set_data(name_count=(len(name_list.rhs) + 1) // 2)
        compiled[-1] = (compiled[-1][0],)
        return tuple(compiled)

    def for_in_st(self, compiler):
        begin_loop_scope, for_name_list, exp_list, block = (
            self.rhs[1], self.rhs[2], self.rhs[4], self.rhs[6])
        luaiter = (
            '_lua52.luaiter(%d,' % for_name_list.data.name_count,
            self._function_args(exp_list), '?)')
        return (
            begin_loop_scope.data.scope.compile(),
            ["for", for_name_list.compiled, "in", luaiter, '?:'],
            self.INDENT, block.compiled, self.OUTDENT,)

    def function_call_st(self, compiler):
        function_call = self.rhs[0]
        return [function_call.compiled]

    def function_decl_st(self, compiler):
        function_name, function_body = self.rhs[1], self.rhs[2]
        variable_ref = function_name.rhs[0]
        var = variable_ref.compiled
        if len(function_name.rhs) == 1:
            last_name = variable_ref.rhs[-1]
        else:
            last_name = function_name.rhs[2]
            var += ("?[%r]" % last_name.token,)
        function_body.data.scope.set_name(last_name)
        if (len(function_name.rhs) == 1 and
                len(variable_ref.rhs) == 1 and
                not function_body.data.uses_namespaces):
            return ()
        return ([var, '=', function_body.compiled],)

    def local_function_decl_st(self, compiler):
        name, function_body = self.rhs[2], self.rhs[3]
        compiler.declare_var(name.token)
        variable = compiler.use_var(name)
        function_body.data.scope.set_variable(variable)
        if not function_body.data.uses_namespaces:
            return ()
        return [variable.python_name(name.token), '=', function_body.compiled]

    def local_assign_st(self, compiler):
        name_list = self.rhs[1]
        variables = []
        for i in range(0, len(name_list.rhs), 2):
            name = name_list.rhs[i]
            compiler.declare_var(name.token)
            variables.append((compiler.python_name(name), "?,"))
        variables[-1] = variables[-1][0]
        if len(self.rhs) == 2:
            return ()
        name_count = (len(name_list.rhs) + 1) / 2
        exp_list = self.rhs[3]
        rhs = self._assign_rhs(name_count, exp_list)
        return [tuple(variables), "=", rhs]

    def return_st(self, compiler):
        if len(self.rhs) == 1:
            return (["return _lua52.NONE1"],)
        exp_list = self.rhs[1]
        return (["return", self._assign_rhs(0, exp_list)],)

    def break_st(self, compiler):
        return (["break"],)

    def function_call_st(self, compiler):
        function_call = self.rhs[0]
        return [function_call.compiled]

    def statement(self, compiler):
        st = self.rhs[0]
        hoisted, compiler.scope.hoist = compiler.scope.hoist, []
        blank_line = [""] if hoisted else ()
        return (tuple(hoisted), st.compiled, blank_line)

    def last_statement(self, compiler):
        return self.statement(compiler)

    def begin_program(self, compiler):
        def r(path, root, klass):
            for name, value in klass.__dict__.items():
                if "__" in name:
                    continue
                real_name = name if not name.startswith("_l_") else name[3:]
                new_path = path + "." + real_name
                root.add_table_path(new_path)
                if isinstance(value, type):
                    r(new_path, root, value)
        begin_scope = self.rhs[0]
        scope = begin_scope.data.scope
        for name, value in Lua52StandardLibrary.__dict__.items():
            if "__" not in name:
                real_name = name if not name.startswith("_l_") else name[3:]
                scope.declare_var(real_name)
                root = scope.declared_vars[real_name]
                if isinstance(value, (PythonTable, type)):
                    r(name, root, value)
        self._set_data(scope=scope)
        return ()

    def START(self, compiler):
        begin_program, block = self.rhs[0], self.rhs[1]
        return (
            ["#!/usr/bin/python -W default"],
            ["import lua52 as _lua52"],
            ["_lua52.init(locals())"],
            [""],
            ["def main(*_args):"],
            self.INDENT,
            begin_program.data.scope.compile(), block.compiled,
            self.OUTDENT,
            [""],
            ["if __name__ == '__main__':"],
            self.INDENT, ["main()"], self.OUTDENT,
        )


Lua52Node._verify(Lua52Grammar)

#
# -----------------------------------------------------------------------------
#
# Runtime and Lua Standard Library
#
NONE1 = (None,) * 1
NONE2 = (None,) * 2
NONE3 = (None,) * 3
NONE4 = (None,) * 4
NONE5 = (None,) * 5
NONE6 = (None,) * 6
NONE7 = (None,) * 7
NONE8 = (None,) * 8
NONE9 = (None,) * 9
NONE = (NONE1, NONE2, NONE3, NONE4, NONE5, NONE6, NONE7, NONE8, NONE9)


#
# In Lua a string may be a float or a string.
#
def coerce2string(obj):
    if not isinstance(obj, (float, int)):
        return obj
    i = int(obj)
    if i == obj:
        return str(i)
    return str(obj)


#
# In Lua a float may be a float or a string.
#
def coerce2float(obj):
    if not isinstance(obj, (str, int)):
        return obj
    return float(obj)


#
# Lua's floats are all truthy, including 0.0.
#
class ZeroTrue(float):
    def __bool__(self):
        return True
ZeroTrue.zero = ZeroTrue(0)


#
# Lua's strings are all truthy, including "".
#
class EmptyStringTrue(str):
    def __bool__(self):
        return True
EmptyStringTrue.empty_string = EmptyStringTrue("")


#
# Convery a Lua value to a boolean.
#
def coerce2bool(v):
    if v not in COERCE2BOOL:
        return v
    return COERCE2BOOL[v]

COERCE2BOOL = {
    0.0:    ZeroTrue.zero,
    "":     EmptyStringTrue.empty_string,
}


#
# Concatenate two strings.
#
def luaconcat(s1, s2):
    if isinstance(s1, LuaTable):
        meta = s1.metadict["__concat"]
        if meta != LuaTable.NOTIMPLEMENTED[0]:
            return meta(s1, s2)
    if isinstance(s2, LuaTable):
        meta = s2.metadict["__concat"]
        if meta != LuaTable.NOTIMPLEMENTED[0]:
            return meta(s1, s2)
    return coerce2string(s1) + coerce2string(s2)


#
# In Lua, range() takes floats.
#
def luarange(start, stop, step):
    start = coerce2float(start)
    stop = coerce2float(stop)
    step = coerce2float(step)
    if step < 0:
        while start >= stop:
            yield start
            start += step
    else:
        while start <= stop:
            yield start
            start += step


#
# Convert a Lua iterator into a Python iterator
#
def luaiter(name_count, *_args):
    func, start, nxt = (_args + NONE2)[:3]
    if name_count == 1:
        nxt = func(start, nxt)[0]
        while nxt is not None:
            yield nxt
            nxt = func(start, nxt)[0]
    else:
        padding = (None,) * (name_count - 1)
        nxt = func(start, nxt)
        while nxt[0] is not None:
            yield (nxt + padding)[:name_count]
            nxt = func(start, nxt[0])


#
# Return the length of an object.
#
def lualen(v):
    if isinstance(v, str):
        return len(v)
    if isinstance(v, LuaTable):
        meta = v.metadict["__len"]
        if meta != LuaTable.NOTIMPLEMENTED[0]:
            return meta(v)
        return v.lualen
    assert isinstance(v, (str, LuaTable))


#
# A Namespace object - hold LUA variables that live in a scope.
#
class Namespace(object):

    def __init(cls, **kwds):
        self.__dict__.update(kwds)
        self._ENV = self.__dict__


#
# A Lua table.
#
class LuaTable(dict):
    __NAN = float("nan")
    __METAFUNCS = (
        '__add', '__sub', '__mul', '__div', '__mod', '__pow', '__unm',
        '__concat', '__len', '__eq', '__lt', '__le', '__index',
        '__newindex', '__call')
    __keys = None
    __version = None
    NOTIMPLEMENTED = (lambda *args: NotImplemented,)
    METANOTIMPL = dict.fromkeys(__METAFUNCS, NOTIMPLEMENTED[0])
    lualen = None
    metatable = None
    metadict = None

    def __init__(self, *args):
        i = 0.0
        for arg in args:
            if isinstance(arg, dict):
                self.update(arg)
            else:
                i += 1.0
                if arg is not None:
                    self[i] = arg
        self.__version = 0
        self.__keys = (self.__version, None)
        self.__version += 1
        self.lualen = i
        self.metadict = self.METANOTIMPL

    def __getitem__(self, key):
        if key in self:
            return dict.__getitem__(self, key)
        meta = self.metadict["__index"]
        if meta != LuaTable.NOTIMPLEMENTED[0]:
            return meta(self, key)[0]
        return None

    def keys(self):
        if self.__keys[0] != self.__version:
            self.keys = [self.__version, tuple(self)]
        return self.__keys[1]

    #
    # In Lua, a Table is always truthy, even empty ones.
    #
    def __bool__(self):
        return True

    def __setitem__(self, key, value):
        assert key is not None and key != self.__NAN
        if value is None:
            if key in self:
                meta = self.metadict["__newindex"]
                if meta != LuaTable.NOTIMPLEMENTED[0]:
                    meta(self, key, value)
                    return
                del self[key]
                self.__version += 1
                if key > 0.0 and isinstance(key, float) and math.floor(key) == key:
                    if key >= self.lualen:
                        self.lualen = key - 1.0
        else:
            if key not in self:
                meta = self.metadict["__newindex"]
                if meta != LuaTable.NOTIMPLEMENTED[0]:
                    meta(self, key, value)
                    return
                self.__version += 1
                l = self.lualen + 1.0
                if l == key:
                    l += 1
                    while l in self:
                        l += 1
                    self.lualen = l
            dict.__setitem__(self, key, value)

    def __add__(self, other):
        return self.metadict["__add"](self, other)

    def __sub__(self, other):
        return self.metadict["__sub"](self, other)

    def __div__(self, other):
        return self.metadict["__div"](self, other)

    def __mul__(self, other):
        return self.metadict["__mul"](self, other)

    def __pow__(self, other):
        return self.metadict["__pow"](self, other)

    def __neg__(self, other):
        return self.metadict["__unm"](self)

    def __eq__(self, other):
        if not isinstance(other, LuaTable):
            return False
        meta = self.metadict["__eq"]
        if meta == LuaTable.NOTIMPLEMENTED[0] or meta != other.metadict["__eq"]:
            return False
        return coerce2bool(meta(self, other))

    def __lt__(self, other):
        return self.metadict["__lt"](self, other)

    def __le__(self, other):
        return self.metadict["__le"](self, other)

    def __call__(self, *args):
        return self.metadict["__call"](self, *args)


#
# Initialise the Lua module.
#
def init(module_dict):
    if '_ENV' in module_dict:
        return
    module_dict["_ENV"] = module_dict
    module_dict.update(Lua52StandardLibrary())


#
# A kludge so next operates in O(1).
#
class NextFloat(float):
    def __new__(cls, value, index):
        result = super(NextFloat, cls)(value)
        result.index = index
        return result


class NextString(str):
    def __new__(cls, value, index):
        result = super(NextString, cls)(value)
        result.index = index
        return result


#
# A Lua Table in Python.
#
class PythonTable(LuaTable):

    #
    # Enter all our members into the dict.  This must be done AFTER all
    # members have been initialised, and if change anything the dict
    # must be manually updated.
    #
    def __init__(self):
        LuaTable.__init__(self)
        for obj in self.__class__, self:
            for name, value in obj.__dict__.items():
                if "__" not in name:
                    if not isinstance(value, classmethod):
                        self[name] = value
                    else:
                        self[name] = value.__get__(None, obj)


#
# The Lua string package.
#
class String(PythonTable):

    __RE_CLASSES = {
        '%a':   '[a-zA-Z]',
        '%A':   '[\x00-@\[-`{-\xff]',
        '%d':   '[0-9]',
        '%D':   '[\x00-/:-~]',
        '%g':   '[\x09-\x0d!-~]',
        '%G':   '[\x00-\x08\x0e-\x1f\x7f-\xff]',
        '%l':   '[a-z]',
        '%L':   '[\x00-`{-\xff]',
        '%p':   '[\x09-\x0d!-/:-@[-`{-~]',
        '%P':   '[\x00-x08\x0e- 0-9a-zA-Z\x7f-\xff]',
        '%s':   '[\x09-\x0d ]',
        '%S':   '[\x00-\x08\x0e-\x0d ]',
        '%u':   '[A-Z]',
        '%U':   '[\x00-`{-\xff]',
        '%x':   '[0-9a-zA-F]',
        '%X':   '[\x00-/:-@G-`{-\xff]',
        '\\':   '\\\\',
    }

    __RE_EQUIV = {
        '%*':   '\\*',
        '%?':   '\\?',
        '%.':   '\\.',
        '%1':   '\\1',
        '%2':   '\\2',
        '%3':   '\\3',
        '%4':   '\\4',
        '%5':   '\\5',
        '%6':   '\\6',
        '%7':   '\\7',
        '%8':   '\\8',
        '%9':   '\\9',
        '{':    '\\{',
        '}':    '\\}',
        '|':    '\\|',
    }

    @classmethod
    def _pattern(cls, pattern):
        def sub(match):
            matched = match.group()
            if matched in cls.__RE_EQUIV:
                return cls.__RE_EQUIV[matched]
            if matched[0] == '%':
                if matched in cls.__RE_CLASSES:
                    return cls.__RE_CLASSES[matched]
                if matched[1] == 'b':
                    raise Exception("Sorry, %b isn't supported")
                if matched[1] == 'f':
                    return '(?<!%s)(?=%s)' % (matched[2:], matched[2:])
                return matched[1]
            if matched == '-':
                return '*?'
            if matched[0] == '^':
                if match.start() == 0:
                    return '\\A'
                return '\\^'
            if matched[0] == '$':
                if match.end() == len(pattern):
                    return '\\Z'
                return '\\$'
            if matched[0] == '[':
                def sub1(match):
                    matched = match.group()
                    if replace not in cls.RE_CLASSES[matched]:
                        return matched[1]
                    replace = cls.RE_CLASSES[matched]
                    if replace[0] == '[':
                        return replace[1:-1]
                    return replace
                return '[' + re.sub("%.|\\", match, sub1) + ']'
            assert False
        return re.sub("%.|[{}|\[[^]]*\]", pattern, sub)

    @classmethod
    def __index(cls, s, i, j):
        l = len(s)
        i = int(coerce2float(i))
        if i > 0:
            i -= 1
        elif i < 0:
            i += l
        if j is None:
            j = l - 1
        else:
            j = int(coerce2float(j))
            if j < 0:
                j += l + 1
        return max(i, 0), min(j, l)

    @classmethod
    def byte(cls, s, i=None, j=None):
        s = coerce2string(s)
        if i is None:
            i = 1
        if j is None:
            j = i
        i, j = cls.__index(s, i, j)
        return tuple(ord(s[k - 1]) for k in range(i, j))

    @classmethod
    def char(cls, *args):
        return (''.join(chr(int(coerce2float(a))) for a in args),)

    @classmethod
    def find(cls, s, pattern, init=None, plain=None):
        s = coerce2string(s)
        pattern = coerce2string(pattern)
        if init is not None:
            init = int(coerce2float(init))
            if init > 0:
                init -= 1
            s = s[init:]
        if plain:
            result = s.find(pattern)
            return NONE1 if result == -1 else (result,)
        match = re.search(cls._pattern(pattern), s[init:])
        if match is None:
            return NONE1
        return match.span() + match.groups()

    @classmethod
    def format(cls, format, *args):
        format = coerce2string(format)
        return (format % args,)

    @classmethod
    def gmatch(cls, s, pattern):
        s = coerce2string(s)
        pattern = coerce2string(pattern)
        items = [None, re.finditer(cls._pattern(pattern), s)]

        def _gmatch(s, v):
            if not items[0]:
                match = next(items[1], None)
                if match is None:
                    return NONE1
                items[0] = match.groups()
                if items[0]:
                    items[0] = list(reversed(items[0]))
                else:
                    items[0] = [match.group()]
            return (items[0].pop(),)
        return _gmatch, s, pattern

    @classmethod
    def gsub(cls, s, pattern, repl, n=None):
        s = coerce2string(s)
        pattern = coerce2string(pattern)
        if isinstance(repl, (str, float)):
            repl = coerce2string(repl)

            def sub(match):
                result = match.group()
                for pcnt in reversed(re.finditer("%[%0-9]", result)):
                    pmatch = pcnt.group()
                    if pcnt[1] == "%":
                        repl = '%'
                    else:
                        repl = result.group(int(pcnt[1]))
                    data = data[:pcnt.start()] + repl + data[pcnt.end():]
                return data
        elif isinstance(repl, LuaTable):
            def sub(match):
                matched = match.group()
                matches = match.groups()
                key = matches[0] if matches else matched
                retval = repr[key]
                if not coerce2bool(retval[0]):
                    return matched
                return key
        elif callable(repl):
            def sub(match):
                matched = match.group()
                args = match.groups()
                retval = repl(*args) if args else repl(matched)
                if not coerce2bool(retval[0]):
                    return matched
                return retval
        else:
            assert isinstance(repl, (str, LuaTable)) or callable(repl)
        if n is None:
            return re.subn(cls._pattern(pattern), s, sub)
        return re.subn(cls._pattern(pattern), s, sub, int(coerce2float(n)))

    @classmethod
    def len(cls, s):
        return (len(coerce2string(s)),)

    @classmethod
    def lower(cls, s):
        return (coerce2string(s).lower(),)

    @classmethod
    def match(cls, s, pattern, init=None):
        s = coerce2string(s)
        pattern = coerce2string(pattern)
        if init is not None:
            init = int(coerce2float(init))
            if init > 0:
                init -= 1
            s = s[init:]
        match = re.search(cls._pattern(pattern), s[init:])
        if match is None:
            return NONE1
        result = match.groups()
        if result:
            return (result,)
        return (match.group(),)

    @classmethod
    def rep(cls, s, n, sep=None):
        s = coerce2string(s)
        n = int(coerce2float(n))
        if sep is not None:
            sep = coerce2string(sep)
            return (sep.join((s,) * n),)
        return (s * n,)

    @classmethod
    def reverse(cls, s):
        return (''.join(reverse(coerce2string(s))),)

    @classmethod
    def sub(cls, s, i, j=None):
        s = coerce2string(s)
        i, j = cls.__index(s, i, j)
        return (s[i:j],)

    @classmethod
    def upper(cls, s):
        return (coerce2string(s).upper(),)


#
# The Lua table package.
#
class Table(PythonTable):

    @classmethod
    def concat(cls, table, sep=None, i=None, j=None):
        sep = '' if sep is None else coerce2string(sep)
        i = 1.0 if i is None else coerce2float(i)
        j = lualen(table) if j is None else coerce2float(j)
        return (sep.join(table[k] for k in luarange(i, j, 1.0)),)

    @classmethod
    def insert(cls, table, pos, value=None):
        l = lualen(table)
        if value is not None:
            pos = math.floor(coerce2float(pos))
        else:
            value, pos = pos, l + 1.0
        for i in luarange(l, pos, -1.0):
            dict.__setitem__(table, i + 1.0, table[i])
        if value is not None:
            table[pos] = value
        table.lualen = l + 1.0
        return NONE1

    @classmethod
    def pack(cls, *args):
        n = len(args)
        return (LuaTable(('n', n), *args),)

    @classmethod
    def remove(cls, table, pos=None):
        if pos is None:
            pos = table.lualen
        assert isinstance(pos, float)
        if pos not in table:
            return NONE1
        result = table[pos]
        while pos in table:
            table[pos + 1.0] = table[pos]
        del table[pos]
        return (result,)

    @classmethod
    def sort(cls, table, comp=None):
        values = [table[i] for i in luarange(1.0, lualen(table), 1.0)]
        if comp is None:
            values.sort()
        else:
            cmp = lambda o1, o2: -1 if comp(o1, o2)[0] else 0 if o1 == o2 else 1
            values.sort(cmp)
        for i in range(len(values)):
            table[float(i + 1.0)] = values[i]
        return NONE1

    @classmethod
    def unpack(cls, table, i=None, j=None):
        assert isinstance(table, LuaTable)
        return tuple(table[i] for i in luarange(1.0, table.lualen, 1.0))


#
# The Lua math package.
#
class Math(PythonTable):

    @classmethod
    def abs(cls, x):
        return (math.abs(x),)

    @classmethod
    def acos(cls, x):
        return (math.acos(x),)

    @classmethod
    def asin(cls, x):
        return (math.asin(x),)

    @classmethod
    def atan(cls, x):
        return (math.atan(x),)

    @classmethod
    def atan2(cls, x):
        return (math.atan2(x),)

    @classmethod
    def ceil(cls, x):
        return (math.ceil(x),)

    @classmethod
    def acos(cls, x):
        return (math.acos(x),)

    @classmethod
    def cosh(cls, x):
        return (math.cosh(x),)

    @classmethod
    def acos(cls, x):
        return (math.acos(x),)

    @classmethod
    def deg(cls, x):
        return (math.degrees(x),)

    @classmethod
    def exp(cls, x):
        return (math.exp(x),)

    @classmethod
    def floor(cls, x):
        return (math.floor(x),)

    @classmethod
    def fmod(cls, x):
        return (math.fmod(x),)

    @classmethod
    def frexp(cls, x):
        return (math.frexp(x),)

    @classmethod
    def acos(cls, x):
        return (math.acos(x),)

    huge = 1.79769313486231580793e308

    @classmethod
    def ldexp(cls, x):
        return (math.ldexp(x),)

    @classmethod
    def log(cls, x, base=None):
        if base is None:
            return (math.log(x),)
        return (math.log(x, base),)

    @classmethod
    def max(cls, *args):
        return (math.max(args),)

    @classmethod
    def min(cls, *args):
        return (math.min(args),)

    @classmethod
    def modf(cls, x):
        return math.modf(x)

    @classmethod
    def acos(cls, x):
        return (math.acos(x),)

    pi = math.pi

    @classmethod
    def pow(cls, x):
        return (math.pow(x),)

    @classmethod
    def rad(cls, x):
        return (math.rad(x),)

    @classmethod
    def random(cls, m=None, n=None):
        random = randon.random()
        if m is None:
            return (random,)
        if n is None:
            n, m = m, 1.0
        return (m + random * m,)

    @classmethod
    def randomseed(cls, x):
        random.seed(x)
        return NONE1

    @classmethod
    def sin(cls, x):
        return (math.sin(x),)

    @classmethod
    def sinh(cls, x):
        return (math.sinh(x),)

    @classmethod
    def sqrt(cls, x):
        return (math.sqrt(x),)

    @classmethod
    def tan(cls, x):
        return (math.tan(x),)

    @classmethod
    def tanh(cls, x):
        return (math.tanh(x),)


#
# The Lua bit32 package.
#
class Bit32(PythonTable):

    @classmethod
    def bit32(cls, x, disp):
        if disp < 0:
            return (int(x) << disp,)
        return (float(int(x) >> disp),)

    @classmethod
    def band(cls, *args):
        result = -1
        for arg in args:
            result &= int(arg)
        return (float(result & 0xffffffff),)

    @classmethod
    def bnot(cls, *args):
        result = -1
        for arg in args:
            result &= ~int(arg)
        return (float(result & 0xffffffff),)

    @classmethod
    def bor(cls, *args):
        result = 0
        for arg in args:
            result |= int(arg)
        return (float(result & 0xffffffff),)

    @classmethod
    def btest(cls, *args):
        result = -1
        for arg in args:
            result &= int(arg)
        return (result != 0,)

    @classmethod
    def bxor(cls, *args):
        result = 0
        for arg in args:
            result ^= int(arg)
        return (float(result & 0xffffffff),)

    @classmethod
    def extract(cls, n, field, width=None):
        field = int(field)
        width = 1 if width is None else int(width)
        mask = (1 << field + width) - (1 << field) + 1
        return (float((int(n) & mask) >> field),)

    @classmethod
    def replace(cls, n, v, field, width=None):
        n = int(n) & 0xffffffff
        field = int(field)
        v = int(v) & ((1 << field + 1) - 1)
        return (float((n - cls.extract(n, field, width)) + v),)

    @classmethod
    def lrotate(cls, n, disp):
        if disp < 0:
            return cls.rrotate(cls, n, -disp)
        n = int(n) & 0xffffffff
        disp = int(disp)
        return (float(n >> disp | (n & (1 << disp) - 1) << (32 - disp)),)

    @classmethod
    def lshift(cls, n, disp):
        if disp < 0:
            return cls.rshift(cls, n, -disp)
        n = int(n)
        disp = int(disp)
        return (float(n >> disp),)

    @classmethod
    def rrotate(cls, n, disp):
        if disp < 0:
            return cls.lrotate(cls, n, -disp)
        n = int(n)
        disp = int(disp)
        i = (n << disp & 0xffffffff)
        i |= (n & (1 << 32) - (1 << disp)) >> disp
        return (float(i),)

    @classmethod
    def rshift(cls, n, disp):
        if disp < 0:
            return cls.lshift(cls, n, -disp)
        n = int(n)
        disp = int(disp)
        return (float(n << disp & 0xffffffff),)


#
# The Lua io package.
#
class Io(PythonTable):

    def __init__(self):
        super(Io, self).__init__()
        self.__default_input = self.__Io(sys.stdin)
        self.__default_output = self.__Io(sys.stdout)

    class __Io(PythonTable):
        __DEFAULT_FORMAT = ("*l",)

        def __init__(self, handle):
            PythonTable.__init__(self)
            self["buffering"] = "full"
            self["handle"] = handle
            self["lookahead"] = ""
            self["open"] = True

        @classmethod
        def close(cls, io):
            try:
                io["hande"].close()
                io["open"] = False
            except EnvironmentError as e:
                return (None, str(e), e.errno)
            return (True,)

        @classmethod
        def flush(cls, io):
            try:
                io["hande"].flush()
            except EnvironmentError as e:
                return (None, str(e), e.errno)
            return (True,)

        @classmethod
        def lines(cls, io, *formats):
            if not formats:
                formats = cls.__DEFAULT_FORMAT

            def lines(io, v):
                eof, result = cls.__read(io, formats)
                return NONE1 if eof else result
            return lines, io, None

        @classmethod
        def __read_n(cls, io, arg):
            read = ['']

            def next():
                c = io["lookahead"]
                if c:
                    c, io["lookahead"] = c[0], c[1:]
                else:
                    c = io["handle"].read(1)
                read[0] += c
                return c

            def abort():
                io["lookahead"] = read[0]
                return (read == '', None)
            c = next()
            if c and c in "+-":
                c = next()
            if c and c in '0123456789':
                while c and c in '0123456789':
                    c = next()
                decimals = c == '.'
                if decimals:
                    c = next()
            elif c != '.':
                return abort()
            else:
                c = next()
                if not c or c not in '0123456789':
                    return abort()
                decimals = True
            if decimals:
                while c and c in '0123456789':
                    c = next()
            if c and c in "eE":
                c = next()
                if c in '-+':
                    c = next()
                while c and c in '0123456789':
                    c = next()
            if c:
                io["lookahead"] += read[0][-1]
                read[0] = read[0][:-1]
            return (not c, float(read[0]))

        @classmethod
        def __read_l(cls, io, arg):
            lookahead = io["lookahead"]
            if not lookahead:
                line = next(io["handle"], None)
                if line is None:
                    return (True, line)
            else:
                io["lookahead"] = ""
                if lookahead[-1] == '\n':
                    line = lookahead
                else:
                    line = next(io["handle"], None)
                    if line is None:
                        line = lookahead
                    else:
                        line = lookahead + line
            return (False, line.rstrip("\n"))

        @classmethod
        def __read_L(cls, io, arg):
            lookahead = io["lookahead"]
            if not lookahead:
                line = next(io["handle"], None)
                if line is None:
                    return (True, line)
            else:
                io["lookahead"] = ""
                if lookahead[-1] == '\n':
                    line = lookahead
                else:
                    line = next(io["handle"], None)
                    if line is None:
                        line = lookahead
                    else:
                        line = lookahead + line
            return (False, line)

        @classmethod
        def __read_bytes(cls, io, arg):
            data = io["lookahead"]
            if arg >= len(lookahead):
                data, io["lookahead"] = data[:arg], data[arg:]
                return data
            data = data + io["handle"].read(arg - len(data))
            if not data:
                return (True, None)
            return (False, data)

        @classmethod
        def __read(cls, io, formats):
            result = []
            read_bytes = cls.__read_bytes
            for fmt in formats:
                eof, data = cls.__READ.get(fmt, read_bytes)(io, fmt)
                result.append(data)
                if eof:
                    break
            return (eof, tuple(result))

        @classmethod
        def read(cls, io, *formats):
            if not formats:
                formats = cls.__DEFAULT_FORMAT
            try:
                return cls.__read(io, formats)[1]
            except EnvironmentError as e:
                return (None, str(e), e.errno)

        @classmethod
        def seek(cls, io, whence=None, offset=None):
            if whence is not None:
                assert whence in cls.__WHENCE_MAP
                io["handle"].seek(offset or 0, cls.__WHENCE_MAP[whence])
            return (io["handle"].tell(),)

        __WHENCE_MAP = {
            "set": os.SEEK_SET,
            "cur": os.SEEK_CUR,
            "end": os.SEEK_END}

        @classmethod
        def setvbuf(cls, io, mode, size=None):
            assert mode in ("no", "full", "line")
            io["buffering"] = mode
            return NONE1

        @classmethod
        def write(cls, io, *args):
            nlseen = False
            for arg in args:
                data = coerce2string(arg)
                nlseen = nlseen or "\n" in data
                io["handle"].write(data)
            if (io["buffering"] == "no" or
                    io["buffering"] == "line" and nlseen):
                io["handle"].flush()
            return NONE1

    __Io.__READ = {
        "*l": __Io.__read_l,
        "*L": __Io.__read_L,
        "*n": __Io.__read_n,
    }

    def close(self, io=None):
        if io is None:
            io = self.__default_output
        return io.close(io)

    def flush(self):
        io = self.__default_output
        return io.flush(io)

    def input(self, io):
        if io is not None:
            if isinstance(io, str):
                io = self.__Io(open(io))
            self.__default_input = io
        return (self.__default_input,)

    def lines(self, filename=None, *formats):
        if filename is None:
            io = self.__default_input
            return io.lines(io, *formats)
        if not formats:
            formats = cls.__DEFAULT_FORMAT
        io = self.__Io(open(filename))
        func, obj, index = io.lines(io, formats)

        def lines(obj, index):
            result = func(obj, index)
            if result[0] is None:
                obj.close(obj)
            return obj
        return lines, obj, index

    def open(self, filename, mode=None):
        assert mode in (
            None,
            "r", "w", "a", "r+", "w+", "a+",
            "rb", "wb", "ab", "r+b", "w+b", "a+b",)
        return (self.__Io(open(filename, mode or 'r')),)

    def output(self, io):
        if io is not None:
            if isinstance(io, str):
                io = self.__Io(open(io, "w"))
            self.__default_output = io
        return (self.__default_output,)

    def popen(self, prog, mode=None):
        assert mode in (None, "r", "w")
        if mode == 'w':
            kwds = {'stdin': subprocess.PIPE}
            handle = subprocess.Popen(prog, shell=True, **kwds).stdin
        else:
            kwds = {'stdout', subprocess.PIPE}
            handle = subprocess.Popen(prog, shell=True, **kwds).stdout
        return (self.__Io(handle),)

    def read(self, *args):
        io = self.__default_input
        return io.read(io, *args)

    def tmpfile(self):
        return (self.__Io(tempfile.TemporaryFile("w+")),)

    def type(self, obj):
        if not isinstance(obj, self.__Io):
            return NONE1
        return (obj["open"] and "file" or "closed file",)

    def write(self, *args):
        io = self.__default_output
        return io.write(io, *args)


#
# The Lua os package.
#
class Os(PythonTable):

    def __init__(self):
        super(Os, self).__init__()
        self.__start_time = time.time()

    def clock(self):
        return (time.time() - self.__start_time,)

    @classmethod
    def date(cls, fmt=None, t=None):
        if t is None:
            t = time.time()
        if not fmt:
            utc, fmt = False, ""
        elif fmt[0] != '!':
            utc = False
        else:
            utc, fmt = True, fmt[1:]
        if utc:
            t = time.localtime(t)
        else:
            t = time.gmtime(t)
        if fmt == "*t":
            result = LuaTable({
                year: "%4d" % t.tm_year,
                month: "%02d" % t.tm_mon,
                day: "%02d" % t.tm_mday,
                hour: "%02d" % t.tm_hour,
                min: "%02d" % t.tm_min,
                sec: "%02d" % t.tm_sec,
                wday: "%d" % t.tm_wday,
                yday: "%d" % t.tm_yday,
                isdst: "%d" % t.tm_isdst
            })
            return (result,)
        if not fmt:
            return (time.strftime("%c", t),)
        return (time.strftime(fmt, t),)

    @classmethod
    def difftime(cls, t2, t1):
        return (t2 - t1,)

    @classmethod
    def execute(cls, command=None):
        if command is None:
            return (True,)
        retval = subprocess.call(command, shell=True)
        result = retval == 0 and True or None
        if os.WIFSIGNALED(retvat):
            return (result, "signal", os.WTERMSIG(retval))
        return (result, "exit", os.WEXITSTATUS(retval))

    @classmethod
    def exit(cls, code=None, close=None):
        if code is None or code is True:
            os.exit(0)
        if code is False:
            os.exit(1)
        os.exit(int(code))

    @classmethod
    def getenv(cls, varname):
        return (os.environ.get(varname),)

    @classmethod
    def remove(cls, filename):
        try:
            os.remove(filename)
        except EnvironmentError as e:
            return (None, str(e), e.errno)
        return (True,)

    @classmethod
    def rename(cls, oldname, newname):
        try:
            os.rename(oldname, newname)
        except EnvironmentError as e:
            return (None, str(e), e.errno)
        return (True,)

    _LOCAL_CATEGORIES = dict(
        (name[3:].lower(), value)
        for name, value in locale.__dict__.items()
        if name.startswith("LC_"))

    @classmethod
    def setlocale(cls, locale, category=None):
        if category is None:
            category = "all"
        assert category in cls._LOCAL_CATEGORIES
        cat = cls._LOCAL_CATEGORIES[category]
        if locale is None:
            return (locale.setlocale(cat),)
        assert isinstance(locale, str)
        try:
            return (locale.setlocale(cat, locale),)
        except locale.Error:
            return NONE1

    @classmethod
    def time(cls, table=None):
        if table is None:
            return (time.time(),)
        tup = (
            int(table["year"], 10),
            int(table["month"], 10),
            int(table["mday"], 10),
            int(table["hour"], 10),
            int(table["min"], 10),
            int(table["sec"], 10),
            0,
            0,
            int(table["isdst"], 10),)
        return time.mktime(tup)

    @classmethod
    def tmpname(cls):
        return tempfile.mkstemp()


#
# Members of this class (and it's nested classes) are the Lua standard library.
#
class Lua52StandardLibrary(PythonTable):
    __is_running = True
    _G = LuaTable()
    _VERSION = "Lua 5.2"

    def __init__(self):
        for name, value in self.__class__.__dict__.items():
            if "__" not in name:
                if isinstance(value, type) and PythonTable in value.__bases__:
                    self.__dict__[name] = value()
        super(Lua52StandardLibrary, self).__init__()

    bit32 = Bit32
    io = Io
    math = Math
    os = Os
    string = String
    table = Table

    @classmethod
    def _l_assert(cls, v, message=None):
        assert v, message
        return NONE1

    @classmethod
    def collectgarbage(self, opt, arg=None):
        if opt == "count":
            return 1, 1
        if opt == "isrunning":
            return self.__is_running
        if opt == "stop":
            self.__is_running = False
        if opt == "restart":
            self.__is_running = True
        return NONE1

    @classmethod
    def dofile(cls, filename=None):
        assert NotImplementedError()

    @classmethod
    def getmetatable(cls, obj):
        if not isinstance(obj, LuaTable):
            return NONE1
        return (table.metatable,)

    @classmethod
    def ipairs(cls, t):
        if isinstance(t, LuaTable) and "__ipairs" in t.metadict:
            return t.metadict["__ipairs"](t)

        def _ipairs(s, v):
            v += 1.0
            if v in s:
                return (v, s[v])
            return NONE1
        return _ipairs, t, 0.0

    @classmethod
    def next(cls, t, index=None):
        keys = list(t.keys())
        if index is None:
            i = -1
        elif isinstance(index, (NextFloat, NextString)):
            i = index.index
        else:
            try:
                i = keys.index(index)
            except ValueError:
                return NONE1
        i += 1
        if i >= len(keys):
            return NONE1
        result = keys[i]
        if isinstance(result, float):
            result = NextFloat(result, i)
        elif isinstance(result, str):
            result = NextString(result, i)
        return (result,)

    @classmethod
    def pairs(cls, t):
        if isinstance(t, LuaTable) and "__ipairs" in t.metadict:
            return t.metadict["__pairs"](t)
        items = iter(t.items())

        def _pairs(s, v):
            return next(items, (None,))
        return _pairs, t, None

    @classmethod
    def pcall(cls, function, *args):
        try:
            return (True,) + function(*args)
        except Exception as e:
            return (False, str(e))

    @classmethod
    def _l_print(cls, *args):
        for arg in args:
            print(cls.tostring(arg)[0], end=' ')
        print()
        return NONE1

    @classmethod
    def rawequal(cls, v1, v2):
        v1, v2 = (args + NONE2)[:2]
        return (v1 == v2,)

    @classmethod
    def rawget(cls, table, index):
        if not dict.__contains__(table, index):
            return (None,)
        return (dict.__getitem__(table, index),)

    @classmethod
    def rawlen(cls, obj):
        if isinstance(obj, LuaTable):
            return obj.lualen
        return (lualen(obj),)

    @classmethod
    def rawset(cls, table, index, value):
        assert index is not None and index is not float("nan")
        dict.__setitem__(table, index, value)
        return (table,)

    @classmethod
    def select(cls, index, *rest):
        if index == "#":
            return len(rest)
        return rest[int(coerce2float(index)):]

    @classmethod
    def setmetatable(cls, table, metatable):
        assert isinstance(table, LuaTable), table
        if metatable is None:
            table.metatable = LuaTable.METANOTIMPL
            table.metadict = LuaTable()
        else:
            assert isinstance(metatable, LuaTable)
            assert metatable.metatable is None
            table.metatable = metatable
            table.metadict = LuaTable.METANOTIMPL.copy()
            table.metadict.update(metatable)
        return (table,)

    @classmethod
    def tonumber(cls, obj, base=None):
        if base is not None:
            return float(int(coerce2string(obj), int(base)))
        try:
            return (coerce2float(obj),)
        except ValueError:
            return NONE1

    @classmethod
    def tostring(cls, obj):
        if isinstance(obj, LuaTable) and "__tostring" in obj.metadict:
            return t.metadict["__tostring"](t)
        if obj is None:
            return ("nil",)
        if isinstance(obj, (float, str)):
            return (coerce2string(obj),)
        return ("%s: 0x%x" % (cls.type(obj), id(obj)),)

    __TYPES = {
        bool: "boolean",
        float: "number",
        str: "string",
        LuaTable: "table",
        type(lambda: None): "function",
    }

    @classmethod
    def type(cls, v):
        return (cls.__TYPES[type(v)],)


#
# Compile a Lua program and return the Python source code.
#
def compile_lua52(lua52_source):
    pre_comp = Lua52Grammar.pre_compile_grammar(Lua52Grammar.pre_compiled)
    if pre_comp is not None:
        print("Please edit set %r and set %s.pre_compiled to:" % (
            __file__, Lua52Grammar.__name__))
        print(pre_comp)
        sys.exit(1)
    lua52_compiler = Lua52Compiler()
    parse_tree = Lua52Grammar.parse(lua52_source, lua52_compiler.tree_factory)
    return lua52_compiler.compiled()


def main(argv=sys.argv):
    i = 1
    if len(argv) == 2 and argv[1] == '--compile':
        pre_compiled_in = None
    else:
        pre_compiled_in = Lua52Grammar.pre_compiled
    start_time = time.time()
    try:
        pre_comp = Lua52Grammar.pre_compile_grammar(pre_compiled_in)
    except:
        try:
            print(Lua52Grammar.repr_grammar())
            print()
            print(Lua52Grammar.repr_productions())
            print()
            print(Lua52Grammar.repr_parse_table())
        finally:
            raise
    if pre_comp is not None:
        print("compile time: %f secs" % (time.time() - start_time))
        print("Please edit set %r and set %s.pre_compiled to:" % (
            __file__, Lua52Grammar.__name__))
        print(pre_comp)
        sys.exit(1)
    if len(argv) > i and argv[i] == '--':
        i += 1
    if len(argv) > i + 1 or i == 2 and argv[i].startswith("-"):
        sys.stderr.write("usage: %s [--] [lua_source]\n" % argv[0])
        sys.exit(1)
    if len(argv) < i + 1:
        sys.stdout.write(compile_lua52(sys.stdin.read()))
    else:
        input_filename = argv[i]
        compiled = compile_lua52(open(input_filename).read())
        output_filename = os.path.splitext(input_filename)[0] + ".py"
        open(output_filename, "w").write(compiled)
        mode = stat.S_IMODE(os.stat(input_filename).st_mode)
        try:
            os.chmod(output_filename, mode & 0o777)
            os.chmod(output_filename, mode)
        except EnvironmentError as e:
            if e.errno != errno.EPERM:
                raise


Lua52Grammar.pre_compiled = ('3a6d52d160ea5fddb860ea01cde9b1d14504d073161423b74c84b6886ba7ddaa88b0bbcea73521718d5f5d16396fa7daba528e1ee4da692a087990afd2907a86', 0, ({"'return'": (7, 0, 'begin_scope'), 'T.name': (7, 0, 'begin_scope'), "'function'": (7, 0, 'begin_scope'), '__end_of_input__': (7, 0, 'begin_scope'), "'local'": (7, 0, 'begin_scope'), "'for'": (7, 0, 'begin_scope'), "'('": (7, 0, 'begin_scope'), "'repeat'": (7, 0, 'begin_scope'), "'do'": (7, 0, 'begin_scope'), "'break'": (7, 0, 'begin_scope'), "'while'": (7, 0, 'begin_scope'), "'if'": (7, 0, 'begin_scope')}, {2: 1, 4: 2, 7: 3}, ['<Lua52Grammar>']), ({'__end_of_input__': 4}, {}, ['<Lua52Grammar>']), ({"'return'": 11, 'T.name': 31, "'function'": 28, '__end_of_input__': (5, 0, 'block'), "'local'": 30, "'for'": 26, "'('": 37, "'repeat'": 32, "'do'": 25, "'break'": 12, "'while'": 33, "'if'": 29}, {5: 5, 8: 6, 10: 7, 12: 8, 13: 9, 14: 10, 18: 13, 19: 14, 20: 15, 21: 16, 22: 17, 23: 18, 24: 19, 25: 20, 26: 21, 27: 22, 28: 23, 30: 24, 40: 27, 57: 34, 59: 35, 62: 36, 69: 38, 70: 39, 73: 40, 86: 41, 87: 42, 88: 43, 89: 44, 108: 45}, ['START']), ({"'return'": (4, 1, 'begin_program'), 'T.name': (4, 1, 'begin_program'), "'function'": (4, 1, 'begin_program'), '__end_of_input__': (4, 1, 'begin_program'), "'local'": (4, 1, 'begin_program'), "'for'": (4, 1, 'begin_program'), "'('": (4, 1, 'begin_program'), "'repeat'": (4, 1, 'begin_program'), "'do'": (4, 1, 'begin_program'), "'break'": (4, 1, 'begin_program'), "'while'": (4, 1, 'begin_program'), "'if'": (4, 1, 'begin_program')}, {}, ['begin_program']), ({'__empty__': (0, 2, '<Lua52Grammar>')}, {}, ['<Lua52Grammar>']), ({'__end_of_input__': (11, 0, 'end_scope')}, {11: 47, 6: 46}, ['START']), ({"'else'": (5, 1, 'block'), '__end_of_input__': (5, 1, 'block'), "';'": 48, "'elseif'": (5, 1, 'block'), "'end'": (5, 1, 'block'), "'until'": (5, 1, 'block')}, {}, ['block']), ({"'return'": 11, 'T.name': 31, "'end'": (5, 1, 'block'), "'function'": 28, "'if'": 29, '__end_of_input__': (5, 1, 'block'), "'local'": 30, "'else'": (5, 1, 'block'), "'for'": 26, "'('": 37, "'repeat'": 32, "'do'": 25, "'break'": 12, "'elseif'": (5, 1, 'block'), "'while'": 33, "'until'": (5, 1, 'block')}, {8: 49, 12: 8, 13: 9, 14: 50, 18: 13, 19: 14, 20: 15, 21: 16, 22: 17, 23: 18, 24: 19, 25: 20, 26: 21, 27: 22, 28: 23, 30: 24, 40: 27, 57: 34, 59: 35, 62: 36, 69: 38, 70: 39, 73: 40, 86: 41, 87: 42, 88: 43, 89: 44, 108: 45}, ['block']), ({"'else'": (8, 1, 'last_statement'), '__end_of_input__': (8, 1, 'last_statement'), "';'": (8, 1, 'last_statement'), "'elseif'": (8, 1, 'last_statement'), "'end'": (8, 1, 'last_statement'), "'until'": (8, 1, 'last_statement')}, {}, ['last_statement']), ({"'else'": (8, 1, 'last_statement'), '__end_of_input__': (8, 1, 'last_statement'), "';'": (8, 1, 'last_statement'), "'elseif'": (8, 1, 'last_statement'), "'end'": (8, 1, 'last_statement'), "'until'": (8, 1, 'last_statement')}, {}, ['last_statement']), ({"'return'": (10, 1), 'T.name': (10, 1), "'end'": (10, 1), "'function'": (10, 1), "'else'": (10, 1), '__end_of_input__': (10, 1), "';'": 51, "'break'": (10, 1), "'for'": (10, 1), "'('": (10, 1), "'repeat'": (10, 1), "'do'": (10, 1), "'local'": (10, 1), "'elseif'": (10, 1), "'if'": (10, 1), "'while'": (10, 1), "'until'": (10, 1)}, {}, ['block']), ({"'{'": 81, 'T.name': 57, "'end'": (12, 1, 'return_st'), "'true'": 103, "'#'": 99, "'else'": (12, 1, 'return_st'), "'false'": 102, 'T.decimal_number': 104, 'T.hex_number': 105, "'-'": 98, "'nil'": 101, '__end_of_input__': (12, 1, 'return_st'), "'('": 60, "';'": (12, 1, 'return_st'), 'T.var_args': 84, "'not'": 100, "'function'": 55, "'elseif'": (12, 1, 'return_st'), 'T.long_string': 83, 'T.short_string': 82, "'until'": (12, 1, 'return_st')}, {16: 52, 29: 53, 40: 54, 45: 56, 59: 58, 62: 59, 66: 61, 69: 62, 70: 63, 71: 64, 72: 65, 73: 66, 75: 67, 76: 68, 77: 69, 78: 70, 79: 71, 80: 72, 81: 73, 82: 74, 83: 75, 84: 76, 86: 77, 87: 78, 88: 79, 89: 80, 97: 85, 98: 86, 99: 87, 100: 88, 101: 89, 102: 90, 103: 91, 104: 92, 105: 93, 108: 94, 110: 95, 111: 96, 112: 97}, ['return_st']), ({"'else'": (13, 1, 'break_st'), '__end_of_input__': (13, 1, 'break_st'), "';'": (13, 1, 'break_st'), "'elseif'": (13, 1, 'break_st'), "'end'": (13, 1, 'break_st'), "'until'": (13, 1, 'break_st')}, {}, ['break_st']), ({"'return'": (14, 1, 'statement'), 'T.name': (14, 1, 'statement'), "'end'": (14, 1, 'statement'), "'function'": (14, 1, 'statement'), "'else'": (14, 1, 'statement'), '__end_of_input__': (14, 1, 'statement'), "';'": (14, 1, 'statement'), "'break'": (14, 1, 'statement'), "'for'": (14, 1, 'statement'), "'('": (14, 1, 'statement'), "'repeat'": (14, 1, 'statement'), "'do'": (14, 1, 'statement'), "'local'": (14, 1, 'statement'), "'elseif'": (14, 1, 'statement'), "'if'": (14, 1, 'statement'), "'while'": (14, 1, 'statement'), "'until'": (14, 1, 'statement')}, {}, ['statement']), ({"'return'": (14, 1, 'statement'), 'T.name': (14, 1, 'statement'), "'end'": (14, 1, 'statement'), "'function'": (14, 1, 'statement'), "'else'": (14, 1, 'statement'), '__end_of_input__': (14, 1, 'statement'), "';'": (14, 1, 'statement'), "'break'": (14, 1, 'statement'), "'for'": (14, 1, 'statement'), "'('": (14, 1, 'statement'), "'repeat'": (14, 1, 'statement'), "'do'": (14, 1, 'statement'), "'local'": (14, 1, 'statement'), "'elseif'": (14, 1, 'statement'), "'if'": (14, 1, 'statement'), "'while'": (14, 1, 'statement'), "'until'": (14, 1, 'statement')}, {}, ['statement']), ({"'return'": (14, 1, 'statement'), 'T.name': (14, 1, 'statement'), "'end'": (14, 1, 'statement'), "'function'": (14, 1, 'statement'), "'else'": (14, 1, 'statement'), '__end_of_input__': (14, 1, 'statement'), "';'": (14, 1, 'statement'), "'break'": (14, 1, 'statement'), "'for'": (14, 1, 'statement'), "'('": (14, 1, 'statement'), "'repeat'": (14, 1, 'statement'), "'do'": (14, 1, 'statement'), "'local'": (14, 1, 'statement'), "'elseif'": (14, 1, 'statement'), "'if'": (14, 1, 'statement'), "'while'": (14, 1, 'statement'), "'until'": (14, 1, 'statement')}, {}, ['statement']), ({"'return'": (14, 1, 'statement'), 'T.name': (14, 1, 'statement'), "'end'": (14, 1, 'statement'), "'function'": (14, 1, 'statement'), "'else'": (14, 1, 'statement'), '__end_of_input__': (14, 1, 'statement'), "';'": (14, 1, 'statement'), "'break'": (14, 1, 'statement'), "'for'": (14, 1, 'statement'), "'('": (14, 1, 'statement'), "'repeat'": (14, 1, 'statement'), "'do'": (14, 1, 'statement'), "'local'": (14, 1, 'statement'), "'elseif'": (14, 1, 'statement'), "'if'": (14, 1, 'statement'), "'while'": (14, 1, 'statement'), "'until'": (14, 1, 'statement')}, {}, ['statement']), ({"'return'": (14, 1, 'statement'), 'T.name': (14, 1, 'statement'), "'end'": (14, 1, 'statement'), "'function'": (14, 1, 'statement'), "'else'": (14, 1, 'statement'), '__end_of_input__': (14, 1, 'statement'), "';'": (14, 1, 'statement'), "'break'": (14, 1, 'statement'), "'for'": (14, 1, 'statement'), "'('": (14, 1, 'statement'), "'repeat'": (14, 1, 'statement'), "'do'": (14, 1, 'statement'), "'local'": (14, 1, 'statement'), "'elseif'": (14, 1, 'statement'), "'if'": (14, 1, 'statement'), "'while'": (14, 1, 'statement'), "'until'": (14, 1, 'statement')}, {}, ['statement']), ({"'return'": (14, 1, 'statement'), 'T.name': (14, 1, 'statement'), "'end'": (14, 1, 'statement'), "'function'": (14, 1, 'statement'), "'else'": (14, 1, 'statement'), '__end_of_input__': (14, 1, 'statement'), "';'": (14, 1, 'statement'), "'break'": (14, 1, 'statement'), "'for'": (14, 1, 'statement'), "'('": (14, 1, 'statement'), "'repeat'": (14, 1, 'statement'), "'do'": (14, 1, 'statement'), "'local'": (14, 1, 'statement'), "'elseif'": (14, 1, 'statement'), "'if'": (14, 1, 'statement'), "'while'": (14, 1, 'statement'), "'until'": (14, 1, 'statement')}, {}, ['statement']), ({"'return'": (14, 1, 'statement'), 'T.name': (14, 1, 'statement'), "'end'": (14, 1, 'statement'), "'function'": (14, 1, 'statement'), "'else'": (14, 1, 'statement'), '__end_of_input__': (14, 1, 'statement'), "';'": (14, 1, 'statement'), "'break'": (14, 1, 'statement'), "'for'": (14, 1, 'statement'), "'('": (14, 1, 'statement'), "'repeat'": (14, 1, 'statement'), "'do'": (14, 1, 'statement'), "'local'": (14, 1, 'statement'), "'elseif'": (14, 1, 'statement'), "'if'": (14, 1, 'statement'), "'while'": (14, 1, 'statement'), "'until'": (14, 1, 'statement')}, {}, ['statement']), ({"'return'": (14, 1, 'statement'), 'T.name': (14, 1, 'statement'), "'end'": (14, 1, 'statement'), "'function'": (14, 1, 'statement'), "'else'": (14, 1, 'statement'), '__end_of_input__': (14, 1, 'statement'), "';'": (14, 1, 'statement'), "'break'": (14, 1, 'statement'), "'for'": (14, 1, 'statement'), "'('": (14, 1, 'statement'), "'repeat'": (14, 1, 'statement'), "'do'": (14, 1, 'statement'), "'local'": (14, 1, 'statement'), "'elseif'": (14, 1, 'statement'), "'if'": (14, 1, 'statement'), "'while'": (14, 1, 'statement'), "'until'": (14, 1, 'statement')}, {}, ['statement']), ({"'return'": (14, 1, 'statement'), 'T.name': (14, 1, 'statement'), "'end'": (14, 1, 'statement'), "'function'": (14, 1, 'statement'), "'else'": (14, 1, 'statement'), '__end_of_input__': (14, 1, 'statement'), "';'": (14, 1, 'statement'), "'break'": (14, 1, 'statement'), "'for'": (14, 1, 'statement'), "'('": (14, 1, 'statement'), "'repeat'": (14, 1, 'statement'), "'do'": (14, 1, 'statement'), "'local'": (14, 1, 'statement'), "'elseif'": (14, 1, 'statement'), "'if'": (14, 1, 'statement'), "'while'": (14, 1, 'statement'), "'until'": (14, 1, 'statement')}, {}, ['statement']), ({"'return'": (14, 1, 'statement'), 'T.name': (14, 1, 'statement'), "'end'": (14, 1, 'statement'), "'function'": (14, 1, 'statement'), "'else'": (14, 1, 'statement'), '__end_of_input__': (14, 1, 'statement'), "';'": (14, 1, 'statement'), "'break'": (14, 1, 'statement'), "'for'": (14, 1, 'statement'), "'('": (14, 1, 'statement'), "'repeat'": (14, 1, 'statement'), "'do'": (14, 1, 'statement'), "'local'": (14, 1, 'statement'), "'elseif'": (14, 1, 'statement'), "'if'": (14, 1, 'statement'), "'while'": (14, 1, 'statement'), "'until'": (14, 1, 'statement')}, {}, ['statement']), ({"'return'": (14, 1, 'statement'), 'T.name': (14, 1, 'statement'), "'end'": (14, 1, 'statement'), "'function'": (14, 1, 'statement'), "'else'": (14, 1, 'statement'), '__end_of_input__': (14, 1, 'statement'), "';'": (14, 1, 'statement'), "'break'": (14, 1, 'statement'), "'for'": (14, 1, 'statement'), "'('": (14, 1, 'statement'), "'repeat'": (14, 1, 'statement'), "'do'": (14, 1, 'statement'), "'local'": (14, 1, 'statement'), "'elseif'": (14, 1, 'statement'), "'if'": (14, 1, 'statement'), "'while'": (14, 1, 'statement'), "'until'": (14, 1, 'statement')}, {}, ['statement']), ({"'='": 106}, {}, ['assign_st']), ({"'return'": (7, 0, 'begin_scope'), 'T.name': (7, 0, 'begin_scope'), "'end'": (7, 0, 'begin_scope'), "'function'": (7, 0, 'begin_scope'), "'local'": (7, 0, 'begin_scope'), "'for'": (7, 0, 'begin_scope'), "'('": (7, 0, 'begin_scope'), "'repeat'": (7, 0, 'begin_scope'), "'do'": (7, 0, 'begin_scope'), "'break'": (7, 0, 'begin_scope'), "'while'": (7, 0, 'begin_scope'), "'if'": (7, 0, 'begin_scope')}, {33: 108, 7: 107}, ['do_st']), ({'T.name': (7, 0, 'begin_scope')}, {36: 110, 7: 109}, ['for_in_st', 'for_step_st']), ({"';'": (22, 1, 'function_call_st'), "'end'": (22, 1, 'function_call_st'), 'T.long_string': (87, 1), "'return'": (22, 1, 'function_call_st'), "'function'": (22, 1, 'function_call_st'), "'elseif'": (22, 1, 'function_call_st'), "'('": (22, 1, 'function_call_st'), 'T.short_string': (87, 1), "'do'": (22, 1, 'function_call_st'), "'break'": (22, 1, 'function_call_st'), '__end_of_input__': (22, 1, 'function_call_st'), "':'": (87, 1), "'{'": (87, 1), "'else'": (22, 1, 'function_call_st'), "'repeat'": (22, 1, 'function_call_st'), "'while'": (22, 1, 'function_call_st'), "'until'": (22, 1, 'function_call_st'), 'T.name': (22, 1, 'function_call_st'), "'['": (87, 1), "'for'": (22, 1, 'function_call_st'), "'if'": (22, 1, 'function_call_st'), "'local'": (22, 1, 'function_call_st')}, {}, ['function_call_st', 'prefix_exp']), ({'T.name': 31}, {73: 40, 42: 111, 62: 112}, ['function_decl_st']), ({'T.name': 57, "'true'": 103, "'#'": 99, "'false'": 102, 'T.var_args': 84, "'-'": 98, "'{'": 81, "'not'": 100, "'('": 60, "'nil'": 101, 'T.hex_number': 105, "'function'": 55, 'T.decimal_number': 104, 'T.long_string': 83, 'T.short_string': 82}, {40: 54, 45: 113, 59: 58, 62: 59, 66: 61, 69: 62, 70: 63, 71: 64, 72: 65, 73: 66, 75: 67, 76: 68, 77: 69, 78: 70, 79: 71, 80: 72, 81: 73, 82: 74, 83: 75, 84: 76, 86: 77, 87: 78, 88: 79, 89: 80, 97: 85, 98: 86, 99: 87, 100: 88, 101: 89, 102: 90, 103: 91, 104: 92, 105: 93, 108: 94, 110: 95, 111: 96, 112: 97}, ['if_st']), ({'T.name': 174, "'function'": 172}, {50: 173, 68: 175, 85: 176}, ['local_assign_st', 'local_function_decl_st']), ({"'{'": (73, 1), "':'": (73, 1), "'['": (73, 1), "','": (73, 1), "'('": (73, 1), "'.'": (73, 1), "'='": (73, 1), 'T.long_string': (73, 1), 'T.short_string': (73, 1)}, {}, ['variable_ref']), ({"'return'": (7, 0, 'begin_scope'), 'T.name': (7, 0, 'begin_scope'), "'function'": (7, 0, 'begin_scope'), "'if'": (7, 0, 'begin_scope'), "'local'": (7, 0, 'begin_scope'), "'for'": (7, 0, 'begin_scope'), "'('": (7, 0, 'begin_scope'), "'repeat'": (7, 0, 'begin_scope'), "'do'": (7, 0, 'begin_scope'), "'break'": (7, 0, 'begin_scope'), "'while'": (7, 0, 'begin_scope'), "'until'": (7, 0, 'begin_scope')}, {36: 177, 53: 178, 7: 109}, ['repeat_st']), ({'T.name': 57, "'true'": 103, "'#'": 99, "'false'": 102, 'T.var_args': 84, "'-'": 98, "'{'": 81, "'not'": 100, "'('": 60, "'nil'": 101, 'T.hex_number': 105, "'function'": 55, 'T.decimal_number': 104, 'T.long_string': 83, 'T.short_string': 82}, {40: 54, 45: 180, 59: 58, 62: 59, 66: 61, 69: 62, 70: 63, 71: 64, 72: 65, 73: 66, 75: 67, 76: 68, 77: 69, 78: 70, 79: 71, 80: 72, 81: 73, 82: 74, 83: 75, 84: 76, 86: 77, 87: 78, 88: 79, 89: 80, 97: 85, 98: 86, 99: 87, 100: 88, 101: 89, 102: 90, 103: 91, 104: 92, 105: 93, 108: 94, 110: 95, 111: 96, 112: 97}, ['while_st']), ({"'='": (30, 1, 'var_list'), "','": 189}, {}, ['var_list']), ({"':'": 161, "'{'": 81, "'('": 162, "'['": 190, 'T.long_string': 83, 'T.short_string': 82}, {72: 164, 60: 160, 71: 163}, ['function_call', 'subscript_exp']), ({"':'": (69, 1, 'var'), "'{'": (69, 1, 'var'), "','": (69, 1, 'var'), "'('": (69, 1, 'var'), "'['": (69, 1, 'var'), "'='": (69, 1, 'var'), 'T.long_string': (69, 1, 'var'), 'T.short_string': (69, 1, 'var')}, {}, ['var']), ({'T.name': 57, "'true'": 103, "'#'": 99, "'false'": 102, 'T.var_args': 84, "'-'": 98, "'{'": 81, "'not'": 100, "'('": 60, "'nil'": 101, 'T.hex_number': 105, "'function'": 55, 'T.decimal_number': 104, 'T.long_string': 83, 'T.short_string': 82}, {40: 54, 45: 193, 59: 58, 62: 59, 66: 61, 69: 62, 70: 63, 71: 64, 72: 65, 73: 66, 75: 67, 76: 68, 77: 69, 78: 70, 79: 71, 80: 72, 81: 73, 82: 74, 83: 75, 84: 76, 86: 77, 87: 78, 88: 79, 89: 80, 97: 85, 98: 86, 99: 87, 100: 88, 101: 89, 102: 90, 103: 91, 104: 92, 105: 93, 108: 94, 110: 95, 111: 96, 112: 97}, ['adjusted_exp']), ({"':'": (89, 1), "'{'": (89, 1), "','": (57, 1), "'('": (89, 1), "'['": (89, 1), "'='": (57, 1), 'T.long_string': (89, 1), 'T.short_string': (89, 1)}, {}, ['prefix_exp', 'var_list']), ({"':'": (59, 1, 'prefix_exp'), "'{'": (59, 1, 'prefix_exp'), "'('": (59, 1, 'prefix_exp'), "'['": (59, 1, 'prefix_exp'), 'T.long_string': (59, 1, 'prefix_exp'), 'T.short_string': (59, 1, 'prefix_exp')}, {}, ['prefix_exp']), ({"'{'": (62, 1, 'variable_ref'), "':'": (62, 1, 'variable_ref'), "'['": (62, 1, 'variable_ref'), "','": (62, 1, 'variable_ref'), "'('": (62, 1, 'variable_ref'), "'.'": 194, "'='": (62, 1, 'variable_ref'), 'T.long_string': (62, 1, 'variable_ref'), 'T.short_string': (62, 1, 'variable_ref')}, {}, ['variable_ref']), ({"':'": (69, 1, 'var'), "'{'": (69, 1, 'var'), "','": (69, 1, 'var'), "'('": (69, 1, 'var'), "'['": (69, 1, 'var'), "'='": (69, 1, 'var'), 'T.long_string': (69, 1, 'var'), 'T.short_string': (69, 1, 'var')}, {}, ['var']), ({"':'": (70, 1), "'{'": (70, 1), "'('": (70, 1), "'['": (70, 1), 'T.long_string': (70, 1), 'T.short_string': (70, 1)}, {}, ['prefix_exp']), ({"':'": (70, 1), "'{'": (70, 1), "'('": (70, 1), "'['": (70, 1), 'T.long_string': (70, 1), 'T.short_string': (70, 1)}, {}, ['prefix_exp']), ({"':'": (70, 1), "'{'": (70, 1), "'('": (70, 1), "'['": (70, 1), 'T.long_string': (70, 1), 'T.short_string': (70, 1)}, {}, ['prefix_exp']), ({"':'": (88, 1), "'{'": (88, 1), "'('": (88, 1), "'['": (88, 1), 'T.long_string': (88, 1), 'T.short_string': (88, 1)}, {}, ['prefix_exp']), ({'__end_of_input__': (2, 3, 'START')}, {}, ['START']), ({'__end_of_input__': (6, 1, 'end_program')}, {}, ['end_program']), ({'__end_of_input__': (5, 2, 'block'), "'else'": (5, 2, 'block'), "'end'": (5, 2, 'block'), "'elseif'": (5, 2, 'block'), "'until'": (5, 2, 'block')}, {}, ['block']), ({"'else'": (5, 2, 'block'), '__end_of_input__': (5, 2, 'block'), "';'": 195, "'elseif'": (5, 2, 'block'), "'end'": (5, 2, 'block'), "'until'": (5, 2, 'block')}, {}, ['block']), ({"'return'": (10, 2), 'T.name': (10, 2), "'end'": (10, 2), "'function'": (10, 2), "'else'": (10, 2), '__end_of_input__': (10, 2), "';'": 196, "'local'": (10, 2), "'for'": (10, 2), "'('": (10, 2), "'repeat'": (10, 2), "'do'": (10, 2), "'break'": (10, 2), "'elseif'": (10, 2), "'if'": (10, 2), "'while'": (10, 2), "'until'": (10, 2)}, {}, ['block']), ({"'return'": (10, 2), 'T.name': (10, 2), "'end'": (10, 2), "'function'": (10, 2), "'else'": (10, 2), '__end_of_input__': (10, 2), "'local'": (10, 2), "'for'": (10, 2), "'('": (10, 2), "'repeat'": (10, 2), "'do'": (10, 2), "'break'": (10, 2), "'elseif'": (10, 2), "'if'": (10, 2), "'while'": (10, 2), "'until'": (10, 2)}, {}, ['block']), ({"'else'": (12, 2, 'return_st'), '__end_of_input__': (12, 2, 'return_st'), "';'": (12, 2, 'return_st'), "'elseif'": (12, 2, 'return_st'), "'end'": (12, 2, 'return_st'), "'until'": (12, 2, 'return_st')}, {}, ['return_st']), ({"'return'": (16, 1, 'exp_list'), 'T.name': (16, 1, 'exp_list'), "'end'": (16, 1, 'exp_list'), "'function'": (16, 1, 'exp_list'), "'else'": (16, 1, 'exp_list'), '__end_of_input__': (16, 1, 'exp_list'), "';'": (16, 1, 'exp_list'), "','": 186, "')'": (16, 1, 'exp_list'), "'local'": (16, 1, 'exp_list'), "'for'": (16, 1, 'exp_list'), "'('": (16, 1, 'exp_list'), "'repeat'": (16, 1, 'exp_list'), "'do'": (16, 1, 'exp_list'), "'break'": (16, 1, 'exp_list'), "'elseif'": (16, 1, 'exp_list'), "'if'": (16, 1, 'exp_list'), "'while'": (16, 1, 'exp_list'), "'until'": (16, 1, 'exp_list')}, {}, ['exp_list']), ({"'=='": (87, 1), "';'": (87, 1), "'<='": (87, 1), "'%'": (87, 1), "'end'": (87, 1), "']'": (87, 1), 'T.long_string': (87, 1), "'return'": (87, 1), "'function'": (87, 1), "'^'": (87, 1), "'elseif'": (87, 1), 'T.short_string': (87, 1), "','": (87, 1), "'('": (87, 1), "'while'": (87, 1), "'>='": (87, 1), "'break'": (87, 1), "'*'": (87, 1), "'>'": (87, 1), '__end_of_input__': (87, 1), "':'": (87, 1), "'do'": (87, 1), "'{'": (87, 1), "'else'": (87, 1), "'and'": (87, 1), "'repeat'": (87, 1), "'or'": (87, 1), "'..'": (87, 1), "'until'": (87, 1), 'T.name': (87, 1), "'then'": (87, 1), "'/'": (87, 1), "'-'": (87, 1), "'['": (87, 1), "')'": (87, 1), "'for'": (87, 1), "'if'": (87, 1), "'~='": (87, 1), "'local'": (87, 1), "'}'": (87, 1), "'+'": (87, 1), "'<'": (87, 1)}, {}, ['prefix_exp']), ({"'('": (7, 0, 'begin_scope')}, {43: 171, 7: 170}, ['anon_function']), ({"'=='": 134, "';'": (29, 1), "'<='": 131, "'%'": 127, "'end'": (29, 1), "'return'": (29, 1), "'function'": (29, 1), "'^'": 123, "'elseif'": (29, 1), "','": (29, 1), "'('": (29, 1), "'while'": (29, 1), "'>='": 133, "'break'": (29, 1), "'*'": 125, "'>'": 132, '__end_of_input__': (29, 1), "'do'": (29, 1), "'else'": (29, 1), "'and'": 136, "'repeat'": (29, 1), "'or'": 137, "'..'": 128, "'until'": (29, 1), 'T.name': (29, 1), "'/'": 126, "'-'": 124, "')'": (29, 1), "'for'": (29, 1), "'if'": (29, 1), "'~='": 135, "'local'": (29, 1), "'+'": 129, "'<'": 130}, {}, ['exp', 'exp_list']), ({"'=='": (73, 1), "';'": (73, 1), "'<='": (73, 1), "'%'": (73, 1), "'end'": (73, 1), "']'": (73, 1), 'T.long_string': (73, 1), "'return'": (73, 1), "'function'": (73, 1), "'^'": (73, 1), "'elseif'": (73, 1), 'T.short_string': (73, 1), "','": (73, 1), "'('": (73, 1), "'..'": (73, 1), "'>='": (73, 1), "'break'": (73, 1), "'*'": (73, 1), "'.'": (73, 1), "'>'": (73, 1), '__end_of_input__': (73, 1), "':'": (73, 1), "'do'": (73, 1), "'{'": (73, 1), "'else'": (73, 1), "'and'": (73, 1), "'repeat'": (73, 1), "'or'": (73, 1), "'while'": (73, 1), "'until'": (73, 1), 'T.name': (73, 1), "'then'": (73, 1), "'/'": (73, 1), "'-'": (73, 1), "'['": (73, 1), "')'": (73, 1), "'for'": (73, 1), "'if'": (73, 1), "'~='": (73, 1), "'local'": (73, 1), "'}'": (73, 1), "'+'": (73, 1), "'<'": (73, 1)}, {}, ['variable_ref']), ({"'=='": (76, 1), "';'": (76, 1), "'<='": (76, 1), "'%'": (76, 1), "'end'": (76, 1), "']'": (76, 1), 'T.long_string': 83, "'^'": (76, 1), "'elseif'": (76, 1), "','": (76, 1), "'('": 162, "'..'": (76, 1), "'do'": (76, 1), "'*'": (76, 1), "'>'": (76, 1), '__end_of_input__': (76, 1), "':'": 161, "'>='": (76, 1), "'{'": 81, "'else'": (76, 1), "'and'": (76, 1), "'or'": (76, 1), 'T.short_string': 82, "'until'": (76, 1), "'then'": (76, 1), "'/'": (76, 1), "'-'": (76, 1), "'['": 165, "')'": (76, 1), "'~='": (76, 1), "'}'": (76, 1), "'+'": (76, 1), "'<'": (76, 1)}, {72: 164, 60: 160, 71: 163}, ['exp', 'function_call', 'subscript_exp']), ({"'=='": (69, 1, 'var'), "';'": (69, 1, 'var'), "'<='": (69, 1, 'var'), "'%'": (69, 1, 'var'), "'end'": (69, 1, 'var'), "']'": (69, 1, 'var'), 'T.long_string': (69, 1, 'var'), "'return'": (69, 1, 'var'), "'function'": (69, 1, 'var'), "'^'": (69, 1, 'var'), "'elseif'": (69, 1, 'var'), "','": (69, 1, 'var'), "'('": (69, 1, 'var'), 'T.short_string': (69, 1, 'var'), "'>='": (69, 1, 'var'), "'break'": (69, 1, 'var'), "'*'": (69, 1, 'var'), "'while'": (69, 1, 'var'), "'>'": (69, 1, 'var'), '__end_of_input__': (69, 1, 'var'), "':'": (69, 1, 'var'), "'do'": (69, 1, 'var'), "'{'": (69, 1, 'var'), "'else'": (69, 1, 'var'), "'and'": (69, 1, 'var'), "'repeat'": (69, 1, 'var'), "'or'": (69, 1, 'var'), "'..'": (69, 1, 'var'), "'until'": (69, 1, 'var'), 'T.name': (69, 1, 'var'), "'then'": (69, 1, 'var'), "'/'": (69, 1, 'var'), "'-'": (69, 1, 'var'), "'['": (69, 1, 'var'), "')'": (69, 1, 'var'), "'for'": (69, 1, 'var'), "'if'": (69, 1, 'var'), "'~='": (69, 1, 'var'), "'local'": (69, 1, 'var'), "'}'": (69, 1, 'var'), "'+'": (69, 1, 'var'), "'<'": (69, 1, 'var')}, {}, ['var']), ({'T.name': 57, "'true'": 103, "'#'": 99, "'false'": 102, 'T.var_args': 84, "'-'": 98, "'{'": 81, "'not'": 100, "'('": 60, "'nil'": 101, 'T.hex_number': 105, "'function'": 55, 'T.decimal_number': 104, 'T.long_string': 83, 'T.short_string': 82}, {40: 54, 45: 159, 59: 58, 62: 59, 66: 61, 69: 62, 70: 63, 71: 64, 72: 65, 73: 66, 75: 67, 76: 68, 77: 69, 78: 70, 79: 71, 80: 72, 81: 73, 82: 74, 83: 75, 84: 76, 86: 77, 87: 78, 88: 79, 89: 80, 97: 85, 98: 86, 99: 87, 100: 88, 101: 89, 102: 90, 103: 91, 104: 92, 105: 93, 108: 94, 110: 95, 111: 96, 112: 97}, ['adjusted_exp']), ({"'=='": (45, 1, 'exp'), "';'": (45, 1, 'exp'), "'<='": (45, 1, 'exp'), "'%'": (45, 1, 'exp'), "'end'": (45, 1, 'exp'), "']'": (45, 1, 'exp'), "'return'": (45, 1, 'exp'), "'function'": (45, 1, 'exp'), "'^'": (45, 1, 'exp'), "'elseif'": (45, 1, 'exp'), "','": (45, 1, 'exp'), "'('": (45, 1, 'exp'), "'while'": (45, 1, 'exp'), "'>='": (45, 1, 'exp'), "'break'": (45, 1, 'exp'), "'*'": (45, 1, 'exp'), "'>'": (45, 1, 'exp'), '__end_of_input__': (45, 1, 'exp'), "'do'": (45, 1, 'exp'), "'else'": (45, 1, 'exp'), "'and'": (45, 1, 'exp'), "'repeat'": (45, 1, 'exp'), "'or'": (45, 1, 'exp'), "'..'": (45, 1, 'exp'), "'until'": (45, 1, 'exp'), 'T.name': (45, 1, 'exp'), "'then'": (45, 1, 'exp'), "'/'": (45, 1, 'exp'), "'-'": (45, 1, 'exp'), "')'": (45, 1, 'exp'), "'for'": (45, 1, 'exp'), "'if'": (45, 1, 'exp'), "'~='": (45, 1, 'exp'), "'local'": (45, 1, 'exp'), "'}'": (45, 1, 'exp'), "'+'": (45, 1, 'exp'), "'<'": (45, 1, 'exp')}, {}, ['exp']), ({"'=='": (89, 1), "';'": (89, 1), "'<='": (89, 1), "'%'": (89, 1), "'end'": (89, 1), "']'": (89, 1), 'T.long_string': (89, 1), "'return'": (89, 1), "'function'": (89, 1), "'^'": (89, 1), "'elseif'": (89, 1), 'T.short_string': (89, 1), "','": (89, 1), "'('": (89, 1), "'while'": (89, 1), "'>='": (89, 1), "'break'": (89, 1), "'*'": (89, 1), "'>'": (89, 1), '__end_of_input__': (89, 1), "':'": (89, 1), "'do'": (89, 1), "'{'": (89, 1), "'else'": (89, 1), "'and'": (89, 1), "'repeat'": (89, 1), "'or'": (89, 1), "'..'": (89, 1), "'until'": (89, 1), 'T.name': (89, 1), "'then'": (89, 1), "'/'": (89, 1), "'-'": (89, 1), "'['": (89, 1), "')'": (89, 1), "'for'": (89, 1), "'if'": (89, 1), "'~='": (89, 1), "'local'": (89, 1), "'}'": (89, 1), "'+'": (89, 1), "'<'": (89, 1)}, {}, ['prefix_exp']), ({"'=='": (59, 1, 'prefix_exp'), "';'": (59, 1, 'prefix_exp'), "'<='": (59, 1, 'prefix_exp'), "'%'": (59, 1, 'prefix_exp'), "'end'": (59, 1, 'prefix_exp'), "']'": (59, 1, 'prefix_exp'), 'T.long_string': (59, 1, 'prefix_exp'), "'return'": (59, 1, 'prefix_exp'), "'function'": (59, 1, 'prefix_exp'), "'^'": (59, 1, 'prefix_exp'), "'elseif'": (59, 1, 'prefix_exp'), 'T.short_string': (59, 1, 'prefix_exp'), "','": (59, 1, 'prefix_exp'), "'('": (59, 1, 'prefix_exp'), "'while'": (59, 1, 'prefix_exp'), "'>='": (59, 1, 'prefix_exp'), "'break'": (59, 1, 'prefix_exp'), "'*'": (59, 1, 'prefix_exp'), "'>'": (59, 1, 'prefix_exp'), '__end_of_input__': (59, 1, 'prefix_exp'), "':'": (59, 1, 'prefix_exp'), "'do'": (59, 1, 'prefix_exp'), "'{'": (59, 1, 'prefix_exp'), "'else'": (59, 1, 'prefix_exp'), "'and'": (59, 1, 'prefix_exp'), "'repeat'": (59, 1, 'prefix_exp'), "'or'": (59, 1, 'prefix_exp'), "'..'": (59, 1, 'prefix_exp'), "'until'": (59, 1, 'prefix_exp'), 'T.name': (59, 1, 'prefix_exp'), "'then'": (59, 1, 'prefix_exp'), "'/'": (59, 1, 'prefix_exp'), "'-'": (59, 1, 'prefix_exp'), "'['": (59, 1, 'prefix_exp'), "')'": (59, 1, 'prefix_exp'), "'for'": (59, 1, 'prefix_exp'), "'if'": (59, 1, 'prefix_exp'), "'~='": (59, 1, 'prefix_exp'), "'local'": (59, 1, 'prefix_exp'), "'}'": (59, 1, 'prefix_exp'), "'+'": (59, 1, 'prefix_exp'), "'<'": (59, 1, 'prefix_exp')}, {}, ['prefix_exp']), ({"'=='": (97, 1), "';'": (97, 1), "'<='": (97, 1), "'%'": (97, 1), "'end'": (97, 1), "']'": (97, 1), "'return'": (97, 1), "'function'": (97, 1), "'^'": (97, 1), "'elseif'": (97, 1), "','": (97, 1), "'('": (97, 1), "'while'": (97, 1), "'>='": (97, 1), "'break'": (97, 1), "'*'": (97, 1), "'>'": (97, 1), '__end_of_input__': (97, 1), "'do'": (97, 1), "'else'": (97, 1), "'and'": (97, 1), "'repeat'": (97, 1), "'or'": (97, 1), "'..'": (97, 1), "'until'": (97, 1), 'T.name': (97, 1), "'then'": (97, 1), "'/'": (97, 1), "'-'": (97, 1), "')'": (97, 1), "'for'": (97, 1), "'if'": (97, 1), "'~='": (97, 1), "'local'": (97, 1), "'}'": (97, 1), "'+'": (97, 1), "'<'": (97, 1)}, {}, ['_atom']), ({"'=='": (97, 1), "';'": (97, 1), "'<='": (97, 1), "'%'": (97, 1), "'end'": (97, 1), "']'": (97, 1), "'return'": (97, 1), "'function'": (97, 1), "'^'": (97, 1), "'elseif'": (97, 1), "','": (97, 1), "'('": (97, 1), "'while'": (97, 1), "'>='": (97, 1), "'break'": (97, 1), "'*'": (97, 1), "'>'": (97, 1), '__end_of_input__': (97, 1), "'do'": (97, 1), "'else'": (97, 1), "'and'": (97, 1), "'repeat'": (97, 1), "'or'": (97, 1), "'..'": (97, 1), "'until'": (97, 1), 'T.name': (97, 1), "'then'": (97, 1), "'/'": (97, 1), "'-'": (97, 1), "')'": (97, 1), "'for'": (97, 1), "'if'": (97, 1), "'~='": (97, 1), "'local'": (97, 1), "'}'": (97, 1), "'+'": (97, 1), "'<'": (97, 1)}, {}, ['_atom']), ({"'=='": (62, 1, 'variable_ref'), "';'": (62, 1, 'variable_ref'), "'<='": (62, 1, 'variable_ref'), "'%'": (62, 1, 'variable_ref'), "'end'": (62, 1, 'variable_ref'), "']'": (62, 1, 'variable_ref'), 'T.long_string': (62, 1, 'variable_ref'), "'return'": (62, 1, 'variable_ref'), "'function'": (62, 1, 'variable_ref'), "'^'": (62, 1, 'variable_ref'), "'elseif'": (62, 1, 'variable_ref'), 'T.short_string': (62, 1, 'variable_ref'), "','": (62, 1, 'variable_ref'), "'('": (62, 1, 'variable_ref'), "'..'": (62, 1, 'variable_ref'), "'>='": (62, 1, 'variable_ref'), "'break'": (62, 1, 'variable_ref'), "'*'": (62, 1, 'variable_ref'), "'.'": 138, "'>'": (62, 1, 'variable_ref'), '__end_of_input__': (62, 1, 'variable_ref'), "':'": (62, 1, 'variable_ref'), "'do'": (62, 1, 'variable_ref'), "'{'": (62, 1, 'variable_ref'), "'else'": (62, 1, 'variable_ref'), "'and'": (62, 1, 'variable_ref'), "'repeat'": (62, 1, 'variable_ref'), "'or'": (62, 1, 'variable_ref'), "'while'": (62, 1, 'variable_ref'), "'until'": (62, 1, 'variable_ref'), 'T.name': (62, 1, 'variable_ref'), "'then'": (62, 1, 'variable_ref'), "'/'": (62, 1, 'variable_ref'), "'-'": (62, 1, 'variable_ref'), "'['": (62, 1, 'variable_ref'), "')'": (62, 1, 'variable_ref'), "'for'": (62, 1, 'variable_ref'), "'if'": (62, 1, 'variable_ref'), "'~='": (62, 1, 'variable_ref'), "'local'": (62, 1, 'variable_ref'), "'}'": (62, 1, 'variable_ref'), "'+'": (62, 1, 'variable_ref'), "'<'": (62, 1, 'variable_ref')}, {}, ['variable_ref']), ({"'=='": (66, 1), "';'": (66, 1), "'<='": (66, 1), "'%'": (66, 1), "'end'": (66, 1), "']'": (66, 1), "'return'": (66, 1), "'function'": (66, 1), "'^'": (66, 1), "'elseif'": (66, 1), "','": (66, 1), "'('": (66, 1), "'while'": (66, 1), "'>='": (66, 1), "'break'": (66, 1), "'*'": (66, 1), "'>'": (66, 1), '__end_of_input__': (66, 1), "'do'": (66, 1), "'else'": (66, 1), "'and'": (66, 1), "'repeat'": (66, 1), "'or'": (66, 1), "'..'": (66, 1), "'until'": (66, 1), 'T.name': (66, 1), "'then'": (66, 1), "'/'": (66, 1), "'-'": (66, 1), "')'": (66, 1), "'for'": (66, 1), "'if'": (66, 1), "'~='": (66, 1), "'local'": (66, 1), "'}'": (66, 1), "'+'": (66, 1), "'<'": (66, 1)}, {}, ['exp']), ({"'=='": (66, 1), "';'": (66, 1), "'<='": (66, 1), "'%'": (66, 1), "'end'": (66, 1), "']'": (66, 1), "'return'": (66, 1), "'function'": (66, 1), "'^'": (66, 1), "'elseif'": (66, 1), "','": (66, 1), "'('": (66, 1), "'while'": (66, 1), "'>='": (66, 1), "'break'": (66, 1), "'*'": (66, 1), "'>'": (66, 1), '__end_of_input__': (66, 1), "'do'": (66, 1), "'else'": (66, 1), "'and'": (66, 1), "'repeat'": (66, 1), "'or'": (66, 1), "'..'": (66, 1), "'until'": (66, 1), 'T.name': (66, 1), "'then'": (66, 1), "'/'": (66, 1), "'-'": (66, 1), "')'": (66, 1), "'for'": (66, 1), "'if'": (66, 1), "'~='": (66, 1), "'local'": (66, 1), "'}'": (66, 1), "'+'": (66, 1), "'<'": (66, 1)}, {}, ['exp']), ({"'=='": (66, 1), "';'": (66, 1), "'<='": (66, 1), "'%'": (66, 1), "'end'": (66, 1), "']'": (66, 1), "'return'": (66, 1), "'function'": (66, 1), "'^'": (66, 1), "'elseif'": (66, 1), "','": (66, 1), "'('": (66, 1), "'while'": (66, 1), "'>='": (66, 1), "'break'": (66, 1), "'*'": (66, 1), "'>'": (66, 1), '__end_of_input__': (66, 1), "'do'": (66, 1), "'else'": (66, 1), "'and'": (66, 1), "'repeat'": (66, 1), "'or'": (66, 1), "'..'": (66, 1), "'until'": (66, 1), 'T.name': (66, 1), "'then'": (66, 1), "'/'": (66, 1), "'-'": (66, 1), "')'": (66, 1), "'for'": (66, 1), "'if'": (66, 1), "'~='": (66, 1), "'local'": (66, 1), "'}'": (66, 1), "'+'": (66, 1), "'<'": (66, 1)}, {}, ['exp']), ({"'=='": (66, 1), "';'": (66, 1), "'<='": (66, 1), "'%'": (66, 1), "'end'": (66, 1), "']'": (66, 1), "'return'": (66, 1), "'function'": (66, 1), "'^'": (66, 1), "'elseif'": (66, 1), "','": (66, 1), "'('": (66, 1), "'while'": (66, 1), "'>='": (66, 1), "'break'": (66, 1), "'*'": (66, 1), "'>'": (66, 1), '__end_of_input__': (66, 1), "'do'": (66, 1), "'else'": (66, 1), "'and'": (66, 1), "'repeat'": (66, 1), "'or'": (66, 1), "'..'": (66, 1), "'until'": (66, 1), 'T.name': (66, 1), "'then'": (66, 1), "'/'": (66, 1), "'-'": (66, 1), "')'": (66, 1), "'for'": (66, 1), "'if'": (66, 1), "'~='": (66, 1), "'local'": (66, 1), "'}'": (66, 1), "'+'": (66, 1), "'<'": (66, 1)}, {}, ['exp']), ({"'=='": (66, 1), "';'": (66, 1), "'<='": (66, 1), "'%'": (66, 1), "'end'": (66, 1), "']'": (66, 1), "'return'": (66, 1), "'function'": (66, 1), "'^'": (66, 1), "'elseif'": (66, 1), "','": (66, 1), "'('": (66, 1), "'while'": (66, 1), "'>='": (66, 1), "'break'": (66, 1), "'*'": (66, 1), "'>'": (66, 1), '__end_of_input__': (66, 1), "'do'": (66, 1), "'else'": (66, 1), "'and'": (66, 1), "'repeat'": (66, 1), "'or'": (66, 1), "'..'": (66, 1), "'until'": (66, 1), 'T.name': (66, 1), "'then'": (66, 1), "'/'": (66, 1), "'-'": (66, 1), "')'": (66, 1), "'for'": (66, 1), "'if'": (66, 1), "'~='": (66, 1), "'local'": (66, 1), "'}'": (66, 1), "'+'": (66, 1), "'<'": (66, 1)}, {}, ['exp']), ({"'=='": (66, 1), "';'": (66, 1), "'<='": (66, 1), "'%'": (66, 1), "'end'": (66, 1), "']'": (66, 1), "'return'": (66, 1), "'function'": (66, 1), "'^'": (66, 1), "'elseif'": (66, 1), "','": (66, 1), "'('": (66, 1), "'while'": (66, 1), "'>='": (66, 1), "'break'": (66, 1), "'*'": (66, 1), "'>'": (66, 1), '__end_of_input__': (66, 1), "'do'": (66, 1), "'else'": (66, 1), "'and'": (66, 1), "'repeat'": (66, 1), "'or'": (66, 1), "'..'": (66, 1), "'until'": (66, 1), 'T.name': (66, 1), "'then'": (66, 1), "'/'": (66, 1), "'-'": (66, 1), "')'": (66, 1), "'for'": (66, 1), "'if'": (66, 1), "'~='": (66, 1), "'local'": (66, 1), "'}'": (66, 1), "'+'": (66, 1), "'<'": (66, 1)}, {}, ['exp']), ({"'=='": (66, 1), "';'": (66, 1), "'<='": (66, 1), "'%'": (66, 1), "'end'": (66, 1), "']'": (66, 1), "'return'": (66, 1), "'function'": (66, 1), "'^'": (66, 1), "'elseif'": (66, 1), "','": (66, 1), "'('": (66, 1), "'while'": (66, 1), "'>='": (66, 1), "'break'": (66, 1), "'*'": (66, 1), "'>'": (66, 1), '__end_of_input__': (66, 1), "'do'": (66, 1), "'else'": (66, 1), "'and'": (66, 1), "'repeat'": (66, 1), "'or'": (66, 1), "'..'": (66, 1), "'until'": (66, 1), 'T.name': (66, 1), "'then'": (66, 1), "'/'": (66, 1), "'-'": (66, 1), "')'": (66, 1), "'for'": (66, 1), "'if'": (66, 1), "'~='": (66, 1), "'local'": (66, 1), "'}'": (66, 1), "'+'": (66, 1), "'<'": (66, 1)}, {}, ['exp']), ({"'=='": (66, 1), "';'": (66, 1), "'<='": (66, 1), "'%'": (66, 1), "'end'": (66, 1), "']'": (66, 1), "'return'": (66, 1), "'function'": (66, 1), "'^'": (66, 1), "'elseif'": (66, 1), "','": (66, 1), "'('": (66, 1), "'while'": (66, 1), "'>='": (66, 1), "'break'": (66, 1), "'*'": (66, 1), "'>'": (66, 1), '__end_of_input__': (66, 1), "'do'": (66, 1), "'else'": (66, 1), "'and'": (66, 1), "'repeat'": (66, 1), "'or'": (66, 1), "'..'": (66, 1), "'until'": (66, 1), 'T.name': (66, 1), "'then'": (66, 1), "'/'": (66, 1), "'-'": (66, 1), "')'": (66, 1), "'for'": (66, 1), "'if'": (66, 1), "'~='": (66, 1), "'local'": (66, 1), "'}'": (66, 1), "'+'": (66, 1), "'<'": (66, 1)}, {}, ['exp']), ({"'=='": (66, 1), "';'": (66, 1), "'<='": (66, 1), "'%'": (66, 1), "'end'": (66, 1), "']'": (66, 1), "'return'": (66, 1), "'function'": (66, 1), "'^'": (66, 1), "'elseif'": (66, 1), "','": (66, 1), "'('": (66, 1), "'while'": (66, 1), "'>='": (66, 1), "'break'": (66, 1), "'*'": (66, 1), "'>'": (66, 1), '__end_of_input__': (66, 1), "'do'": (66, 1), "'else'": (66, 1), "'and'": (66, 1), "'repeat'": (66, 1), "'or'": (66, 1), "'..'": (66, 1), "'until'": (66, 1), 'T.name': (66, 1), "'then'": (66, 1), "'/'": (66, 1), "'-'": (66, 1), "')'": (66, 1), "'for'": (66, 1), "'if'": (66, 1), "'~='": (66, 1), "'local'": (66, 1), "'}'": (66, 1), "'+'": (66, 1), "'<'": (66, 1)}, {}, ['exp']), ({"'=='": (66, 1), "';'": (66, 1), "'<='": (66, 1), "'%'": (66, 1), "'end'": (66, 1), "']'": (66, 1), "'return'": (66, 1), "'function'": (66, 1), "'^'": (66, 1), "'elseif'": (66, 1), "','": (66, 1), "'('": (66, 1), "'while'": (66, 1), "'>='": (66, 1), "'break'": (66, 1), "'*'": (66, 1), "'>'": (66, 1), '__end_of_input__': (66, 1), "'do'": (66, 1), "'else'": (66, 1), "'and'": (66, 1), "'repeat'": (66, 1), "'or'": (66, 1), "'..'": (66, 1), "'until'": (66, 1), 'T.name': (66, 1), "'then'": (66, 1), "'/'": (66, 1), "'-'": (66, 1), "')'": (66, 1), "'for'": (66, 1), "'if'": (66, 1), "'~='": (66, 1), "'local'": (66, 1), "'}'": (66, 1), "'+'": (66, 1), "'<'": (66, 1)}, {}, ['exp']), ({"'=='": (69, 1, 'var'), "';'": (69, 1, 'var'), "'<='": (69, 1, 'var'), "'%'": (69, 1, 'var'), "'end'": (69, 1, 'var'), "']'": (69, 1, 'var'), 'T.long_string': (69, 1, 'var'), "'return'": (69, 1, 'var'), "'function'": (69, 1, 'var'), "'^'": (69, 1, 'var'), "'elseif'": (69, 1, 'var'), "','": (69, 1, 'var'), "'('": (69, 1, 'var'), 'T.short_string': (69, 1, 'var'), "'>='": (69, 1, 'var'), "'break'": (69, 1, 'var'), "'*'": (69, 1, 'var'), "'while'": (69, 1, 'var'), "'>'": (69, 1, 'var'), '__end_of_input__': (69, 1, 'var'), "':'": (69, 1, 'var'), "'do'": (69, 1, 'var'), "'{'": (69, 1, 'var'), "'else'": (69, 1, 'var'), "'and'": (69, 1, 'var'), "'repeat'": (69, 1, 'var'), "'or'": (69, 1, 'var'), "'..'": (69, 1, 'var'), "'until'": (69, 1, 'var'), 'T.name': (69, 1, 'var'), "'then'": (69, 1, 'var'), "'/'": (69, 1, 'var'), "'-'": (69, 1, 'var'), "'['": (69, 1, 'var'), "')'": (69, 1, 'var'), "'for'": (69, 1, 'var'), "'if'": (69, 1, 'var'), "'~='": (69, 1, 'var'), "'local'": (69, 1, 'var'), "'}'": (69, 1, 'var'), "'+'": (69, 1, 'var'), "'<'": (69, 1, 'var')}, {}, ['var']), ({"'=='": (70, 1), "';'": (70, 1), "'<='": (70, 1), "'%'": (70, 1), "'end'": (70, 1), "']'": (70, 1), 'T.long_string': (70, 1), "'return'": (70, 1), "'function'": (70, 1), "'^'": (70, 1), "'elseif'": (70, 1), "','": (70, 1), "'('": (70, 1), 'T.short_string': (70, 1), "'>='": (70, 1), "'break'": (70, 1), "'*'": (70, 1), "'while'": (70, 1), "'>'": (70, 1), '__end_of_input__': (70, 1), "':'": (70, 1), "'do'": (70, 1), "'{'": (70, 1), "'else'": (70, 1), "'and'": (70, 1), "'repeat'": (70, 1), "'or'": (70, 1), "'..'": (70, 1), "'until'": (70, 1), 'T.name': (70, 1), "'then'": (70, 1), "'/'": (70, 1), "'-'": (70, 1), "'['": (70, 1), "')'": (70, 1), "'for'": (70, 1), "'if'": (70, 1), "'~='": (70, 1), "'local'": (70, 1), "'}'": (70, 1), "'+'": (70, 1), "'<'": (70, 1)}, {}, ['prefix_exp']), ({"'=='": (70, 1), "';'": (70, 1), "'<='": (70, 1), "'%'": (70, 1), "'end'": (70, 1), "']'": (70, 1), 'T.long_string': (70, 1), "'return'": (70, 1), "'function'": (70, 1), "'^'": (70, 1), "'elseif'": (70, 1), "','": (70, 1), "'('": (70, 1), 'T.short_string': (70, 1), "'>='": (70, 1), "'break'": (70, 1), "'*'": (70, 1), "'while'": (70, 1), "'>'": (70, 1), '__end_of_input__': (70, 1), "':'": (70, 1), "'do'": (70, 1), "'{'": (70, 1), "'else'": (70, 1), "'and'": (70, 1), "'repeat'": (70, 1), "'or'": (70, 1), "'..'": (70, 1), "'until'": (70, 1), 'T.name': (70, 1), "'then'": (70, 1), "'/'": (70, 1), "'-'": (70, 1), "'['": (70, 1), "')'": (70, 1), "'for'": (70, 1), "'if'": (70, 1), "'~='": (70, 1), "'local'": (70, 1), "'}'": (70, 1), "'+'": (70, 1), "'<'": (70, 1)}, {}, ['prefix_exp']), ({"'=='": (70, 1), "';'": (70, 1), "'<='": (70, 1), "'%'": (70, 1), "'end'": (70, 1), "']'": (70, 1), 'T.long_string': (70, 1), "'return'": (70, 1), "'function'": (70, 1), "'^'": (70, 1), "'elseif'": (70, 1), "','": (70, 1), "'('": (70, 1), 'T.short_string': (70, 1), "'>='": (70, 1), "'break'": (70, 1), "'*'": (70, 1), "'while'": (70, 1), "'>'": (70, 1), '__end_of_input__': (70, 1), "':'": (70, 1), "'do'": (70, 1), "'{'": (70, 1), "'else'": (70, 1), "'and'": (70, 1), "'repeat'": (70, 1), "'or'": (70, 1), "'..'": (70, 1), "'until'": (70, 1), 'T.name': (70, 1), "'then'": (70, 1), "'/'": (70, 1), "'-'": (70, 1), "'['": (70, 1), "')'": (70, 1), "'for'": (70, 1), "'if'": (70, 1), "'~='": (70, 1), "'local'": (70, 1), "'}'": (70, 1), "'+'": (70, 1), "'<'": (70, 1)}, {}, ['prefix_exp']), ({"'nil'": 101, 'T.name': 118, "'true'": 103, "'#'": 99, "'false'": 102, 'T.decimal_number': 104, 'T.hex_number': 105, "'-'": 98, "'['": 121, "'not'": 100, "'('": 60, "'{'": 81, 'T.var_args': 84, "'function'": 55, "'}'": 119, 'T.long_string': 83, 'T.short_string': 82}, {40: 54, 45: 117, 59: 58, 62: 59, 66: 61, 69: 62, 70: 63, 71: 64, 72: 65, 73: 66, 75: 67, 76: 68, 77: 69, 78: 70, 79: 71, 80: 72, 81: 73, 82: 74, 83: 75, 84: 76, 86: 77, 87: 78, 88: 79, 89: 80, 92: 120, 97: 85, 98: 86, 99: 87, 100: 88, 101: 89, 102: 90, 103: 91, 104: 92, 105: 93, 108: 94, 109: 122, 110: 95, 111: 96, 112: 97}, ['table_constructor']), ({"'=='": (72, 1, 'string'), "';'": (72, 1, 'string'), "'<='": (72, 1, 'string'), "'%'": (72, 1, 'string'), "'end'": (72, 1, 'string'), "']'": (72, 1, 'string'), 'T.long_string': (72, 1, 'string'), "'return'": (72, 1, 'string'), "'function'": (72, 1, 'string'), "'^'": (72, 1, 'string'), "'elseif'": (72, 1, 'string'), 'T.short_string': (72, 1, 'string'), "','": (72, 1, 'string'), "'('": (72, 1, 'string'), "'while'": (72, 1, 'string'), "'>='": (72, 1, 'string'), "'break'": (72, 1, 'string'), "'*'": (72, 1, 'string'), "'>'": (72, 1, 'string'), '__end_of_input__': (72, 1, 'string'), "':'": (72, 1, 'string'), "'do'": (72, 1, 'string'), "'{'": (72, 1, 'string'), "'else'": (72, 1, 'string'), "'and'": (72, 1, 'string'), "'repeat'": (72, 1, 'string'), "'or'": (72, 1, 'string'), "'..'": (72, 1, 'string'), "'until'": (72, 1, 'string'), 'T.name': (72, 1, 'string'), "'then'": (72, 1, 'string'), "'/'": (72, 1, 'string'), "'-'": (72, 1, 'string'), "'['": (72, 1, 'string'), "')'": (72, 1, 'string'), "'for'": (72, 1, 'string'), "'if'": (72, 1, 'string'), "'~='": (72, 1, 'string'), "'local'": (72, 1, 'string'), "'}'": (72, 1, 'string'), "'+'": (72, 1, 'string'), "'<'": (72, 1, 'string')}, {}, ['string']), ({"'=='": (72, 1, 'string'), "';'": (72, 1, 'string'), "'<='": (72, 1, 'string'), "'%'": (72, 1, 'string'), "'end'": (72, 1, 'string'), "']'": (72, 1, 'string'), 'T.long_string': (72, 1, 'string'), "'return'": (72, 1, 'string'), "'function'": (72, 1, 'string'), "'^'": (72, 1, 'string'), "'elseif'": (72, 1, 'string'), 'T.short_string': (72, 1, 'string'), "','": (72, 1, 'string'), "'('": (72, 1, 'string'), "'while'": (72, 1, 'string'), "'>='": (72, 1, 'string'), "'break'": (72, 1, 'string'), "'*'": (72, 1, 'string'), "'>'": (72, 1, 'string'), '__end_of_input__': (72, 1, 'string'), "':'": (72, 1, 'string'), "'do'": (72, 1, 'string'), "'{'": (72, 1, 'string'), "'else'": (72, 1, 'string'), "'and'": (72, 1, 'string'), "'repeat'": (72, 1, 'string'), "'or'": (72, 1, 'string'), "'..'": (72, 1, 'string'), "'until'": (72, 1, 'string'), 'T.name': (72, 1, 'string'), "'then'": (72, 1, 'string'), "'/'": (72, 1, 'string'), "'-'": (72, 1, 'string'), "'['": (72, 1, 'string'), "')'": (72, 1, 'string'), "'for'": (72, 1, 'string'), "'if'": (72, 1, 'string'), "'~='": (72, 1, 'string'), "'local'": (72, 1, 'string'), "'}'": (72, 1, 'string'), "'+'": (72, 1, 'string'), "'<'": (72, 1, 'string')}, {}, ['string']), ({"'=='": (97, 1), "';'": (97, 1), "'<='": (97, 1), "'%'": (97, 1), "'end'": (97, 1), "']'": (97, 1), "'return'": (97, 1), "'function'": (97, 1), "'^'": (97, 1), "'elseif'": (97, 1), "','": (97, 1), "'('": (97, 1), "'while'": (97, 1), "'>='": (97, 1), "'break'": (97, 1), "'*'": (97, 1), "'>'": (97, 1), '__end_of_input__': (97, 1), "'do'": (97, 1), "'else'": (97, 1), "'and'": (97, 1), "'repeat'": (97, 1), "'or'": (97, 1), "'..'": (97, 1), "'until'": (97, 1), 'T.name': (97, 1), "'then'": (97, 1), "'/'": (97, 1), "'-'": (97, 1), "')'": (97, 1), "'for'": (97, 1), "'if'": (97, 1), "'~='": (97, 1), "'local'": (97, 1), "'}'": (97, 1), "'+'": (97, 1), "'<'": (97, 1)}, {}, ['_atom']), ({"'=='": (75, 1), "';'": (75, 1), "'<='": (75, 1), "'%'": (75, 1), "'end'": (75, 1), "']'": (75, 1), "'return'": (75, 1), "'function'": (75, 1), "'^'": (75, 1), "'elseif'": (75, 1), "','": (75, 1), "'('": (75, 1), "'while'": (75, 1), "'>='": (75, 1), "'break'": (75, 1), "'*'": (75, 1), "'>'": (75, 1), '__end_of_input__': (75, 1), "'do'": (75, 1), "'else'": (75, 1), "'and'": (75, 1), "'repeat'": (75, 1), "'or'": (75, 1), "'..'": (75, 1), "'until'": (75, 1), 'T.name': (75, 1), "'then'": (75, 1), "'/'": (75, 1), "'-'": (75, 1), "')'": (75, 1), "'for'": (75, 1), "'if'": (75, 1), "'~='": (75, 1), "'local'": (75, 1), "'}'": (75, 1), "'+'": (75, 1), "'<'": (75, 1)}, {}, ['exp']), ({"'=='": (77, 1), "';'": (77, 1), "'<='": (77, 1), "'%'": (77, 1), "'end'": (77, 1), "']'": (77, 1), "'return'": (77, 1), "'function'": (77, 1), "'^'": (77, 1), "'elseif'": (77, 1), "','": (77, 1), "'('": (77, 1), "'while'": (77, 1), "'>='": (77, 1), "'break'": (77, 1), "'*'": (77, 1), "'>'": (77, 1), '__end_of_input__': (77, 1), "'do'": (77, 1), "'else'": (77, 1), "'and'": (77, 1), "'repeat'": (77, 1), "'or'": (77, 1), "'..'": (77, 1), "'until'": (77, 1), 'T.name': (77, 1), "'then'": (77, 1), "'/'": (77, 1), "'-'": (77, 1), "')'": (77, 1), "'for'": (77, 1), "'if'": (77, 1), "'~='": (77, 1), "'local'": (77, 1), "'}'": (77, 1), "'+'": (77, 1), "'<'": (77, 1)}, {}, ['exp']), ({"'=='": (78, 1), "';'": (78, 1), "'<='": (78, 1), "'%'": (78, 1), "'end'": (78, 1), "']'": (78, 1), "'return'": (78, 1), "'function'": (78, 1), "'^'": (78, 1), "'elseif'": (78, 1), "','": (78, 1), "'('": (78, 1), "'while'": (78, 1), "'>='": (78, 1), "'break'": (78, 1), "'*'": (78, 1), "'>'": (78, 1), '__end_of_input__': (78, 1), "'do'": (78, 1), "'else'": (78, 1), "'and'": (78, 1), "'repeat'": (78, 1), "'or'": (78, 1), "'..'": (78, 1), "'until'": (78, 1), 'T.name': (78, 1), "'then'": (78, 1), "'/'": (78, 1), "'-'": (78, 1), "')'": (78, 1), "'for'": (78, 1), "'if'": (78, 1), "'~='": (78, 1), "'local'": (78, 1), "'}'": (78, 1), "'+'": (78, 1), "'<'": (78, 1)}, {}, ['exp']), ({"'=='": (79, 1), "';'": (79, 1), "'<='": (79, 1), "'%'": (79, 1), "'end'": (79, 1), "']'": (79, 1), "'return'": (79, 1), "'function'": (79, 1), "'^'": (79, 1), "'elseif'": (79, 1), "','": (79, 1), "'('": (79, 1), "'while'": (79, 1), "'>='": (79, 1), "'break'": (79, 1), "'*'": (79, 1), "'>'": (79, 1), '__end_of_input__': (79, 1), "'do'": (79, 1), "'else'": (79, 1), "'and'": (79, 1), "'repeat'": (79, 1), "'or'": (79, 1), "'..'": (79, 1), "'until'": (79, 1), 'T.name': (79, 1), "'then'": (79, 1), "'/'": (79, 1), "'-'": (79, 1), "')'": (79, 1), "'for'": (79, 1), "'if'": (79, 1), "'~='": (79, 1), "'local'": (79, 1), "'}'": (79, 1), "'+'": (79, 1), "'<'": (79, 1)}, {}, ['exp']), ({"'=='": (80, 1), "';'": (80, 1), "'<='": (80, 1), "'%'": (80, 1), "'end'": (80, 1), "']'": (80, 1), "'return'": (80, 1), "'function'": (80, 1), "'^'": (80, 1), "'elseif'": (80, 1), "','": (80, 1), "'('": (80, 1), "'while'": (80, 1), "'>='": (80, 1), "'break'": (80, 1), "'*'": (80, 1), "'>'": (80, 1), '__end_of_input__': (80, 1), "'do'": (80, 1), "'else'": (80, 1), "'and'": (80, 1), "'repeat'": (80, 1), "'or'": (80, 1), "'..'": (80, 1), "'until'": (80, 1), 'T.name': (80, 1), "'then'": (80, 1), "'/'": (80, 1), "'-'": (80, 1), "')'": (80, 1), "'for'": (80, 1), "'if'": (80, 1), "'~='": (80, 1), "'local'": (80, 1), "'}'": (80, 1), "'+'": (80, 1), "'<'": (80, 1)}, {}, ['exp']), ({"'=='": (81, 1), "';'": (81, 1), "'<='": (81, 1), "'%'": (81, 1), "'end'": (81, 1), "']'": (81, 1), "'return'": (81, 1), "'function'": (81, 1), "'^'": (81, 1), "'elseif'": (81, 1), "','": (81, 1), "'('": (81, 1), "'while'": (81, 1), "'>='": (81, 1), "'break'": (81, 1), "'*'": (81, 1), "'>'": (81, 1), '__end_of_input__': (81, 1), "'do'": (81, 1), "'else'": (81, 1), "'and'": (81, 1), "'repeat'": (81, 1), "'or'": (81, 1), "'..'": (81, 1), "'until'": (81, 1), 'T.name': (81, 1), "'then'": (81, 1), "'/'": (81, 1), "'-'": (81, 1), "')'": (81, 1), "'for'": (81, 1), "'if'": (81, 1), "'~='": (81, 1), "'local'": (81, 1), "'}'": (81, 1), "'+'": (81, 1), "'<'": (81, 1)}, {}, ['exp']), ({"'=='": (82, 1), "';'": (82, 1), "'<='": (82, 1), "'%'": (82, 1), "'end'": (82, 1), "']'": (82, 1), "'return'": (82, 1), "'function'": (82, 1), "'^'": (82, 1), "'elseif'": (82, 1), "','": (82, 1), "'('": (82, 1), "'while'": (82, 1), "'>='": (82, 1), "'break'": (82, 1), "'*'": (82, 1), "'>'": (82, 1), '__end_of_input__': (82, 1), "'do'": (82, 1), "'else'": (82, 1), "'and'": (82, 1), "'repeat'": (82, 1), "'or'": (82, 1), "'..'": (82, 1), "'until'": (82, 1), 'T.name': (82, 1), "'then'": (82, 1), "'/'": (82, 1), "'-'": (82, 1), "')'": (82, 1), "'for'": (82, 1), "'if'": (82, 1), "'~='": (82, 1), "'local'": (82, 1), "'}'": (82, 1), "'+'": (82, 1), "'<'": (82, 1)}, {}, ['exp']), ({"'=='": (83, 1), "';'": (83, 1), "'<='": (83, 1), "'%'": (83, 1), "'end'": (83, 1), "']'": (83, 1), "'return'": (83, 1), "'function'": (83, 1), "'^'": (83, 1), "'elseif'": (83, 1), "','": (83, 1), "'('": (83, 1), "'while'": (83, 1), "'>='": (83, 1), "'break'": (83, 1), "'*'": (83, 1), "'>'": (83, 1), '__end_of_input__': (83, 1), "'do'": (83, 1), "'else'": (83, 1), "'and'": (83, 1), "'repeat'": (83, 1), "'or'": (83, 1), "'..'": (83, 1), "'until'": (83, 1), 'T.name': (83, 1), "'then'": (83, 1), "'/'": (83, 1), "'-'": (83, 1), "')'": (83, 1), "'for'": (83, 1), "'if'": (83, 1), "'~='": (83, 1), "'local'": (83, 1), "'}'": (83, 1), "'+'": (83, 1), "'<'": (83, 1)}, {}, ['exp']), ({"'=='": (84, 1), "';'": (84, 1), "'<='": (84, 1), "'%'": (84, 1), "'end'": (84, 1), "']'": (84, 1), "'return'": (84, 1), "'function'": (84, 1), "'^'": (84, 1), "'elseif'": (84, 1), "','": (84, 1), "'('": (84, 1), "'while'": (84, 1), "'>='": (84, 1), "'break'": (84, 1), "'*'": (84, 1), "'>'": (84, 1), '__end_of_input__': (84, 1), "'do'": (84, 1), "'else'": (84, 1), "'and'": (84, 1), "'repeat'": (84, 1), "'or'": (84, 1), "'..'": (84, 1), "'until'": (84, 1), 'T.name': (84, 1), "'then'": (84, 1), "'/'": (84, 1), "'-'": (84, 1), "')'": (84, 1), "'for'": (84, 1), "'if'": (84, 1), "'~='": (84, 1), "'local'": (84, 1), "'}'": (84, 1), "'+'": (84, 1), "'<'": (84, 1)}, {}, ['exp']), ({"'=='": (88, 1), "';'": (88, 1), "'<='": (88, 1), "'%'": (88, 1), "'end'": (88, 1), "']'": (88, 1), 'T.long_string': (88, 1), "'return'": (88, 1), "'function'": (88, 1), "'^'": (88, 1), "'elseif'": (88, 1), 'T.short_string': (88, 1), "','": (88, 1), "'('": (88, 1), "'while'": (88, 1), "'>='": (88, 1), "'break'": (88, 1), "'*'": (88, 1), "'>'": (88, 1), '__end_of_input__': (88, 1), "':'": (88, 1), "'do'": (88, 1), "'{'": (88, 1), "'else'": (88, 1), "'and'": (88, 1), "'repeat'": (88, 1), "'or'": (88, 1), "'..'": (88, 1), "'until'": (88, 1), 'T.name': (88, 1), "'then'": (88, 1), "'/'": (88, 1), "'-'": (88, 1), "'['": (88, 1), "')'": (88, 1), "'for'": (88, 1), "'if'": (88, 1), "'~='": (88, 1), "'local'": (88, 1), "'}'": (88, 1), "'+'": (88, 1), "'<'": (88, 1)}, {}, ['prefix_exp']), ({"'=='": (97, 1), "';'": (97, 1), "'<='": (97, 1), "'%'": (97, 1), "'end'": (97, 1), "']'": (97, 1), "'return'": (97, 1), "'function'": (97, 1), "'^'": (97, 1), "'elseif'": (97, 1), "','": (97, 1), "'('": (97, 1), "'while'": (97, 1), "'>='": (97, 1), "'break'": (97, 1), "'*'": (97, 1), "'>'": (97, 1), '__end_of_input__': (97, 1), "'do'": (97, 1), "'else'": (97, 1), "'and'": (97, 1), "'repeat'": (97, 1), "'or'": (97, 1), "'..'": (97, 1), "'until'": (97, 1), 'T.name': (97, 1), "'then'": (97, 1), "'/'": (97, 1), "'-'": (97, 1), "')'": (97, 1), "'for'": (97, 1), "'if'": (97, 1), "'~='": (97, 1), "'local'": (97, 1), "'}'": (97, 1), "'+'": (97, 1), "'<'": (97, 1)}, {}, ['_atom']), ({"'=='": (97, 1), "';'": (97, 1), "'<='": (97, 1), "'%'": (97, 1), "'end'": (97, 1), "']'": (97, 1), "'return'": (97, 1), "'function'": (97, 1), "'^'": (97, 1), "'elseif'": (97, 1), "','": (97, 1), "'('": (97, 1), "'while'": (97, 1), "'>='": (97, 1), "'break'": (97, 1), "'*'": (97, 1), "'>'": (97, 1), '__end_of_input__': (97, 1), "'do'": (97, 1), "'else'": (97, 1), "'and'": (97, 1), "'repeat'": (97, 1), "'or'": (97, 1), "'..'": (97, 1), "'until'": (97, 1), 'T.name': (97, 1), "'then'": (97, 1), "'/'": (97, 1), "'-'": (97, 1), "')'": (97, 1), "'for'": (97, 1), "'if'": (97, 1), "'~='": (97, 1), "'local'": (97, 1), "'}'": (97, 1), "'+'": (97, 1), "'<'": (97, 1)}, {}, ['_atom']), ({"'=='": (97, 1), "';'": (97, 1), "'<='": (97, 1), "'%'": (97, 1), "'end'": (97, 1), "']'": (97, 1), "'return'": (97, 1), "'function'": (97, 1), "'^'": (97, 1), "'elseif'": (97, 1), "','": (97, 1), "'('": (97, 1), "'while'": (97, 1), "'>='": (97, 1), "'break'": (97, 1), "'*'": (97, 1), "'>'": (97, 1), '__end_of_input__': (97, 1), "'do'": (97, 1), "'else'": (97, 1), "'and'": (97, 1), "'repeat'": (97, 1), "'or'": (97, 1), "'..'": (97, 1), "'until'": (97, 1), 'T.name': (97, 1), "'then'": (97, 1), "'/'": (97, 1), "'-'": (97, 1), "')'": (97, 1), "'for'": (97, 1), "'if'": (97, 1), "'~='": (97, 1), "'local'": (97, 1), "'}'": (97, 1), "'+'": (97, 1), "'<'": (97, 1)}, {}, ['_atom']), ({'T.name': 57, "'true'": 103, "'#'": 99, "'false'": 102, 'T.var_args': 84, "'-'": 98, "'{'": 81, "'not'": 100, "'('": 60, "'nil'": 101, 'T.hex_number': 105, "'function'": 55, 'T.decimal_number': 104, 'T.long_string': 83, 'T.short_string': 82}, {40: 54, 45: 116, 59: 211, 62: 59, 66: 61, 69: 62, 70: 63, 71: 64, 72: 65, 73: 66, 75: 67, 76: 68, 77: 69, 78: 70, 79: 71, 80: 72, 81: 73, 82: 74, 83: 75, 84: 76, 86: 77, 87: 78, 88: 79, 89: 80, 97: 85, 98: 86, 99: 87, 100: 88, 101: 89, 102: 90, 103: 91, 104: 92, 105: 93, 108: 94, 110: 95, 111: 96, 112: 97}, ['exp']), ({'T.name': 57, "'true'": 103, "'#'": 99, "'false'": 102, 'T.var_args': 84, "'-'": 98, "'{'": 81, "'not'": 100, "'('": 60, "'nil'": 101, 'T.hex_number': 105, "'function'": 55, 'T.decimal_number': 104, 'T.long_string': 83, 'T.short_string': 82}, {40: 54, 45: 115, 59: 211, 62: 59, 66: 61, 69: 62, 70: 63, 71: 64, 72: 65, 73: 66, 75: 67, 76: 68, 77: 69, 78: 70, 79: 71, 80: 72, 81: 73, 82: 74, 83: 75, 84: 76, 86: 77, 87: 78, 88: 79, 89: 80, 97: 85, 98: 86, 99: 87, 100: 88, 101: 89, 102: 90, 103: 91, 104: 92, 105: 93, 108: 94, 110: 95, 111: 96, 112: 97}, ['exp']), ({'T.name': 57, "'true'": 103, "'#'": 99, "'false'": 102, 'T.var_args': 84, "'-'": 98, "'{'": 81, "'not'": 100, "'('": 60, "'nil'": 101, 'T.hex_number': 105, "'function'": 55, 'T.decimal_number': 104, 'T.long_string': 83, 'T.short_string': 82}, {40: 54, 45: 114, 59: 211, 62: 59, 66: 61, 69: 62, 70: 63, 71: 64, 72: 65, 73: 66, 75: 67, 76: 68, 77: 69, 78: 70, 79: 71, 80: 72, 81: 73, 82: 74, 83: 75, 84: 76, 86: 77, 87: 78, 88: 79, 89: 80, 97: 85, 98: 86, 99: 87, 100: 88, 101: 89, 102: 90, 103: 91, 104: 92, 105: 93, 108: 94, 110: 95, 111: 96, 112: 97}, ['exp']), ({"'=='": (110, 1, 'constant'), "';'": (110, 1, 'constant'), "'<='": (110, 1, 'constant'), "'%'": (110, 1, 'constant'), "'end'": (110, 1, 'constant'), "']'": (110, 1, 'constant'), "'return'": (110, 1, 'constant'), "'function'": (110, 1, 'constant'), "'^'": (110, 1, 'constant'), "'elseif'": (110, 1, 'constant'), "','": (110, 1, 'constant'), "'('": (110, 1, 'constant'), "'while'": (110, 1, 'constant'), "'>='": (110, 1, 'constant'), "'break'": (110, 1, 'constant'), "'*'": (110, 1, 'constant'), "'>'": (110, 1, 'constant'), '__end_of_input__': (110, 1, 'constant'), "'do'": (110, 1, 'constant'), "'else'": (110, 1, 'constant'), "'and'": (110, 1, 'constant'), "'repeat'": (110, 1, 'constant'), "'or'": (110, 1, 'constant'), "'..'": (110, 1, 'constant'), "'until'": (110, 1, 'constant'), 'T.name': (110, 1, 'constant'), "'then'": (110, 1, 'constant'), "'/'": (110, 1, 'constant'), "'-'": (110, 1, 'constant'), "')'": (110, 1, 'constant'), "'for'": (110, 1, 'constant'), "'if'": (110, 1, 'constant'), "'~='": (110, 1, 'constant'), "'local'": (110, 1, 'constant'), "'}'": (110, 1, 'constant'), "'+'": (110, 1, 'constant'), "'<'": (110, 1, 'constant')}, {}, ['constant']), ({"'=='": (110, 1, 'constant'), "';'": (110, 1, 'constant'), "'<='": (110, 1, 'constant'), "'%'": (110, 1, 'constant'), "'end'": (110, 1, 'constant'), "']'": (110, 1, 'constant'), "'return'": (110, 1, 'constant'), "'function'": (110, 1, 'constant'), "'^'": (110, 1, 'constant'), "'elseif'": (110, 1, 'constant'), "','": (110, 1, 'constant'), "'('": (110, 1, 'constant'), "'while'": (110, 1, 'constant'), "'>='": (110, 1, 'constant'), "'break'": (110, 1, 'constant'), "'*'": (110, 1, 'constant'), "'>'": (110, 1, 'constant'), '__end_of_input__': (110, 1, 'constant'), "'do'": (110, 1, 'constant'), "'else'": (110, 1, 'constant'), "'and'": (110, 1, 'constant'), "'repeat'": (110, 1, 'constant'), "'or'": (110, 1, 'constant'), "'..'": (110, 1, 'constant'), "'until'": (110, 1, 'constant'), 'T.name': (110, 1, 'constant'), "'then'": (110, 1, 'constant'), "'/'": (110, 1, 'constant'), "'-'": (110, 1, 'constant'), "')'": (110, 1, 'constant'), "'for'": (110, 1, 'constant'), "'if'": (110, 1, 'constant'), "'~='": (110, 1, 'constant'), "'local'": (110, 1, 'constant'), "'}'": (110, 1, 'constant'), "'+'": (110, 1, 'constant'), "'<'": (110, 1, 'constant')}, {}, ['constant']), ({"'=='": (110, 1, 'constant'), "';'": (110, 1, 'constant'), "'<='": (110, 1, 'constant'), "'%'": (110, 1, 'constant'), "'end'": (110, 1, 'constant'), "']'": (110, 1, 'constant'), "'return'": (110, 1, 'constant'), "'function'": (110, 1, 'constant'), "'^'": (110, 1, 'constant'), "'elseif'": (110, 1, 'constant'), "','": (110, 1, 'constant'), "'('": (110, 1, 'constant'), "'while'": (110, 1, 'constant'), "'>='": (110, 1, 'constant'), "'break'": (110, 1, 'constant'), "'*'": (110, 1, 'constant'), "'>'": (110, 1, 'constant'), '__end_of_input__': (110, 1, 'constant'), "'do'": (110, 1, 'constant'), "'else'": (110, 1, 'constant'), "'and'": (110, 1, 'constant'), "'repeat'": (110, 1, 'constant'), "'or'": (110, 1, 'constant'), "'..'": (110, 1, 'constant'), "'until'": (110, 1, 'constant'), 'T.name': (110, 1, 'constant'), "'then'": (110, 1, 'constant'), "'/'": (110, 1, 'constant'), "'-'": (110, 1, 'constant'), "')'": (110, 1, 'constant'), "'for'": (110, 1, 'constant'), "'if'": (110, 1, 'constant'), "'~='": (110, 1, 'constant'), "'local'": (110, 1, 'constant'), "'}'": (110, 1, 'constant'), "'+'": (110, 1, 'constant'), "'<'": (110, 1, 'constant')}, {}, ['constant']), ({"'=='": (111, 1, 'number'), "';'": (111, 1, 'number'), "'<='": (111, 1, 'number'), "'%'": (111, 1, 'number'), "'end'": (111, 1, 'number'), "']'": (111, 1, 'number'), "'return'": (111, 1, 'number'), "'function'": (111, 1, 'number'), "'^'": (111, 1, 'number'), "'elseif'": (111, 1, 'number'), "','": (111, 1, 'number'), "'('": (111, 1, 'number'), "'while'": (111, 1, 'number'), "'>='": (111, 1, 'number'), "'break'": (111, 1, 'number'), "'*'": (111, 1, 'number'), "'>'": (111, 1, 'number'), '__end_of_input__': (111, 1, 'number'), "'do'": (111, 1, 'number'), "'else'": (111, 1, 'number'), "'and'": (111, 1, 'number'), "'repeat'": (111, 1, 'number'), "'or'": (111, 1, 'number'), "'..'": (111, 1, 'number'), "'until'": (111, 1, 'number'), 'T.name': (111, 1, 'number'), "'then'": (111, 1, 'number'), "'/'": (111, 1, 'number'), "'-'": (111, 1, 'number'), "')'": (111, 1, 'number'), "'for'": (111, 1, 'number'), "'if'": (111, 1, 'number'), "'~='": (111, 1, 'number'), "'local'": (111, 1, 'number'), "'}'": (111, 1, 'number'), "'+'": (111, 1, 'number'), "'<'": (111, 1, 'number')}, {}, ['number']), ({"'=='": (111, 1, 'number'), "';'": (111, 1, 'number'), "'<='": (111, 1, 'number'), "'%'": (111, 1, 'number'), "'end'": (111, 1, 'number'), "']'": (111, 1, 'number'), "'return'": (111, 1, 'number'), "'function'": (111, 1, 'number'), "'^'": (111, 1, 'number'), "'elseif'": (111, 1, 'number'), "','": (111, 1, 'number'), "'('": (111, 1, 'number'), "'while'": (111, 1, 'number'), "'>='": (111, 1, 'number'), "'break'": (111, 1, 'number'), "'*'": (111, 1, 'number'), "'>'": (111, 1, 'number'), '__end_of_input__': (111, 1, 'number'), "'do'": (111, 1, 'number'), "'else'": (111, 1, 'number'), "'and'": (111, 1, 'number'), "'repeat'": (111, 1, 'number'), "'or'": (111, 1, 'number'), "'..'": (111, 1, 'number'), "'until'": (111, 1, 'number'), 'T.name': (111, 1, 'number'), "'then'": (111, 1, 'number'), "'/'": (111, 1, 'number'), "'-'": (111, 1, 'number'), "')'": (111, 1, 'number'), "'for'": (111, 1, 'number'), "'if'": (111, 1, 'number'), "'~='": (111, 1, 'number'), "'local'": (111, 1, 'number'), "'}'": (111, 1, 'number'), "'+'": (111, 1, 'number'), "'<'": (111, 1, 'number')}, {}, ['number']), ({'T.name': 199, "'true'": 103, "'#'": 99, "'false'": 102, 'T.var_args': 84, "'-'": 98, "'{'": 81, "'not'": 100, "'('": 202, "'nil'": 101, 'T.hex_number': 105, "'function'": 55, 'T.decimal_number': 104, 'T.long_string': 83, 'T.short_string': 82}, {16: 197, 29: 53, 40: 198, 45: 56, 59: 200, 62: 201, 66: 61, 69: 203, 70: 204, 71: 64, 72: 65, 73: 205, 75: 67, 76: 68, 77: 69, 78: 70, 79: 71, 80: 72, 81: 73, 82: 74, 83: 75, 84: 76, 86: 206, 87: 207, 88: 208, 89: 209, 97: 85, 98: 86, 99: 87, 100: 88, 101: 89, 102: 90, 103: 91, 104: 92, 105: 93, 108: 210, 110: 95, 111: 96, 112: 97}, ['assign_st']), ({"'return'": 11, 'T.name': 31, "'function'": 28, "'else'": (5, 0, 'block'), "'elseif'": (5, 0, 'block'), "'local'": 30, "'end'": (5, 0, 'block'), "'for'": 26, "'('": 37, "'repeat'": 32, "'do'": 25, "'break'": 12, "'while'": 33, "'if'": 29}, {5: 217, 8: 6, 10: 7, 12: 8, 13: 9, 14: 10, 18: 13, 19: 14, 20: 15, 21: 16, 22: 17, 23: 18, 24: 19, 25: 20, 26: 21, 27: 22, 28: 23, 30: 24, 40: 27, 57: 34, 59: 35, 62: 36, 69: 38, 70: 39, 73: 40, 86: 41, 87: 42, 88: 43, 89: 44, 108: 45}, ['scope']), ({"'end'": 230}, {}, ['do_st']), ({"'return'": (58, 0, 'loop'), 'T.name': (58, 0, 'loop'), "'end'": (58, 0, 'loop'), "'function'": (58, 0, 'loop'), "'if'": (58, 0, 'loop'), "'local'": (58, 0, 'loop'), "'for'": (58, 0, 'loop'), "'('": (58, 0, 'loop'), "'repeat'": (58, 0, 'loop'), "'do'": (58, 0, 'loop'), "'break'": (58, 0, 'loop'), "'while'": (58, 0, 'loop'), "'until'": (58, 0, 'loop')}, {58: 179}, ['begin_loop_scope']), ({'T.name': 229}, {50: 228, 37: 226, 68: 175, 85: 176, 39: 227}, ['for_in_st', 'for_step_st']), ({"'('": (7, 0, 'begin_scope')}, {43: 224, 7: 170}, ['function_decl_st']), ({"':'": 235, "'('": (42, 1, 'function_name')}, {}, ['function_name']), ({"'>='": 133, "'^'": 123, "'then'": 223, "'=='": 134, "'/'": 126, "'or'": 137, "'-'": 124, "'<='": 131, "'%'": 127, "'and'": 136, "'+'": 129, "'~='": 135, "'*'": 125, "'<'": 130, "'..'": 128, "'>'": 132}, {}, ['exp', 'if_st']), ({"'=='": (99, 2), "';'": (99, 2), "'<='": (99, 2), "'%'": (99, 2), "'end'": (99, 2), "']'": (99, 2), "'return'": (99, 2), "'function'": (99, 2), "'^'": 123, "'elseif'": (99, 2), "','": (99, 2), "'('": (99, 2), "'while'": (99, 2), "'>='": (99, 2), "'break'": (99, 2), "'*'": (99, 2), "'>'": (99, 2), '__end_of_input__': (99, 2), "'do'": (99, 2), "'else'": (99, 2), "'and'": (99, 2), "'repeat'": (99, 2), "'or'": (99, 2), "'..'": (99, 2), "'until'": (99, 2), 'T.name': (99, 2), "'then'": (99, 2), "'/'": (99, 2), "'-'": (99, 2), "')'": (99, 2), "'for'": (99, 2), "'if'": (99, 2), "'~='": (99, 2), "'local'": (99, 2), "'}'": (99, 2), "'+'": (99, 2), "'<'": (99, 2)}, {}, ['exp']), ({"'=='": (99, 2), "';'": (99, 2), "'<='": (99, 2), "'%'": (99, 2), "'end'": (99, 2), "']'": (99, 2), "'return'": (99, 2), "'function'": (99, 2), "'^'": 123, "'elseif'": (99, 2), "','": (99, 2), "'('": (99, 2), "'while'": (99, 2), "'>='": (99, 2), "'break'": (99, 2), "'*'": (99, 2), "'>'": (99, 2), '__end_of_input__': (99, 2), "'do'": (99, 2), "'else'": (99, 2), "'and'": (99, 2), "'repeat'": (99, 2), "'or'": (99, 2), "'..'": (99, 2), "'until'": (99, 2), 'T.name': (99, 2), "'then'": (99, 2), "'/'": (99, 2), "'-'": (99, 2), "')'": (99, 2), "'for'": (99, 2), "'if'": (99, 2), "'~='": (99, 2), "'local'": (99, 2), "'}'": (99, 2), "'+'": (99, 2), "'<'": (99, 2)}, {}, ['exp']), ({"'=='": (99, 2), "';'": (99, 2), "'<='": (99, 2), "'%'": (99, 2), "'end'": (99, 2), "']'": (99, 2), "'return'": (99, 2), "'function'": (99, 2), "'^'": 123, "'elseif'": (99, 2), "','": (99, 2), "'('": (99, 2), "'while'": (99, 2), "'>='": (99, 2), "'break'": (99, 2), "'*'": (99, 2), "'>'": (99, 2), '__end_of_input__': (99, 2), "'do'": (99, 2), "'else'": (99, 2), "'and'": (99, 2), "'repeat'": (99, 2), "'or'": (99, 2), "'..'": (99, 2), "'until'": (99, 2), 'T.name': (99, 2), "'then'": (99, 2), "'/'": (99, 2), "'-'": (99, 2), "')'": (99, 2), "'for'": (99, 2), "'if'": (99, 2), "'~='": (99, 2), "'local'": (99, 2), "'}'": (99, 2), "'+'": (99, 2), "'<'": (99, 2)}, {}, ['exp']), ({"'^'": 123, "'>'": 132, "'=='": 134, "'/'": 126, "'or'": 137, "'-'": 124, "';'": (109, 1, 'field'), "','": (109, 1, 'field'), "'<='": 131, "'~='": 135, "'%'": 127, "'..'": 128, "'>='": 133, "'and'": 136, "'}'": (109, 1, 'field'), "'*'": 125, "'+'": 129, "'<'": 130}, {}, ['exp', 'field']), ({"'=='": (73, 1), "';'": (73, 1), "'<='": (73, 1), "'%'": (73, 1), 'T.long_string': (73, 1), "'^'": (73, 1), "','": (73, 1), "'('": (73, 1), "'.'": (73, 1), "'>='": (73, 1), "'*'": (73, 1), "'='": 236, "'>'": (73, 1), "':'": (73, 1), "'{'": (73, 1), "'..'": (73, 1), "'and'": (73, 1), "'or'": (73, 1), 'T.short_string': (73, 1), "'/'": (73, 1), "'-'": (73, 1), "'['": (73, 1), "'~='": (73, 1), "'}'": (73, 1), "'+'": (73, 1), "'<'": (73, 1)}, {}, ['field', 'variable_ref']), ({"'=='": (71, 2, 'table_constructor'), "';'": (71, 2, 'table_constructor'), "'<='": (71, 2, 'table_constructor'), "'%'": (71, 2, 'table_constructor'), "'end'": (71, 2, 'table_constructor'), "']'": (71, 2, 'table_constructor'), 'T.long_string': (71, 2, 'table_constructor'), "'return'": (71, 2, 'table_constructor'), "'function'": (71, 2, 'table_constructor'), "'^'": (71, 2, 'table_constructor'), "'elseif'": (71, 2, 'table_constructor'), "','": (71, 2, 'table_constructor'), "'('": (71, 2, 'table_constructor'), 'T.short_string': (71, 2, 'table_constructor'), "'>='": (71, 2, 'table_constructor'), "'break'": (71, 2, 'table_constructor'), "'*'": (71, 2, 'table_constructor'), "'while'": (71, 2, 'table_constructor'), "'>'": (71, 2, 'table_constructor'), '__end_of_input__': (71, 2, 'table_constructor'), "':'": (71, 2, 'table_constructor'), "'do'": (71, 2, 'table_constructor'), "'{'": (71, 2, 'table_constructor'), "'else'": (71, 2, 'table_constructor'), "'and'": (71, 2, 'table_constructor'), "'repeat'": (71, 2, 'table_constructor'), "'or'": (71, 2, 'table_constructor'), "'..'": (71, 2, 'table_constructor'), "'until'": (71, 2, 'table_constructor'), 'T.name': (71, 2, 'table_constructor'), "'then'": (71, 2, 'table_constructor'), "'/'": (71, 2, 'table_constructor'), "'-'": (71, 2, 'table_constructor'), "'['": (71, 2, 'table_constructor'), "')'": (71, 2, 'table_constructor'), "'for'": (71, 2, 'table_constructor'), "'if'": (71, 2, 'table_constructor'), "'~='": (71, 2, 'table_constructor'), "'local'": (71, 2, 'table_constructor'), "'}'": (71, 2, 'table_constructor'), "'+'": (71, 2, 'table_constructor'), "'<'": (71, 2, 'table_constructor')}, {}, ['table_constructor']), ({"'}'": 157, "';'": 155, "','": 156}, {}, ['table_constructor']), ({'T.name': 57, "'true'": 103, "'#'": 99, "'false'": 102, 'T.var_args': 84, "'-'": 98, "'{'": 81, "'not'": 100, "'('": 60, "'nil'": 101, 'T.hex_number': 105, "'function'": 55, 'T.decimal_number': 104, 'T.long_string': 83, 'T.short_string': 82}, {40: 54, 45: 237, 59: 58, 62: 59, 66: 61, 69: 62, 70: 63, 71: 64, 72: 65, 73: 66, 75: 67, 76: 68, 77: 69, 78: 70, 79: 71, 80: 72, 81: 73, 82: 74, 83: 75, 84: 76, 86: 77, 87: 78, 88: 79, 89: 80, 97: 85, 98: 86, 99: 87, 100: 88, 101: 89, 102: 90, 103: 91, 104: 92, 105: 93, 108: 94, 110: 95, 111: 96, 112: 97}, ['field']), ({"'}'": (92, 1), "';'": (92, 1), "','": (92, 1)}, {}, ['table_constructor']), ({'T.name': 57, "'true'": 103, "'#'": 99, "'false'": 102, 'T.var_args': 84, "'-'": 98, "'{'": 81, "'not'": 100, "'('": 60, "'nil'": 101, 'T.hex_number': 105, "'function'": 55, 'T.decimal_number': 104, 'T.long_string': 83, 'T.short_string': 82}, {40: 54, 45: 154, 59: 211, 62: 59, 66: 61, 69: 62, 70: 63, 71: 64, 72: 65, 73: 66, 75: 67, 76: 68, 77: 69, 78: 70, 79: 71, 80: 72, 81: 73, 82: 74, 83: 75, 84: 76, 86: 77, 87: 78, 88: 79, 89: 80, 97: 85, 98: 86, 99: 87, 100: 88, 101: 89, 102: 90, 103: 91, 104: 92, 105: 93, 108: 94, 110: 95, 111: 96, 112: 97}, ['exp']), ({'T.name': 57, "'true'": 103, "'#'": 99, "'false'": 102, 'T.var_args': 84, "'-'": 98, "'{'": 81, "'not'": 100, "'('": 60, "'nil'": 101, 'T.hex_number': 105, "'function'": 55, 'T.decimal_number': 104, 'T.long_string': 83, 'T.short_string': 82}, {40: 54, 45: 153, 59: 211, 62: 59, 66: 61, 69: 62, 70: 63, 71: 64, 72: 65, 73: 66, 75: 67, 76: 68, 77: 69, 78: 70, 79: 71, 80: 72, 81: 73, 82: 74, 83: 75, 84: 76, 86: 77, 87: 78, 88: 79, 89: 80, 97: 85, 98: 86, 99: 87, 100: 88, 101: 89, 102: 90, 103: 91, 104: 92, 105: 93, 108: 94, 110: 95, 111: 96, 112: 97}, ['exp']), ({'T.name': 57, "'true'": 103, "'#'": 99, "'false'": 102, 'T.var_args': 84, "'-'": 98, "'{'": 81, "'not'": 100, "'('": 60, "'nil'": 101, 'T.hex_number': 105, "'function'": 55, 'T.decimal_number': 104, 'T.long_string': 83, 'T.short_string': 82}, {40: 54, 45: 152, 59: 211, 62: 59, 66: 61, 69: 62, 70: 63, 71: 64, 72: 65, 73: 66, 75: 67, 76: 68, 77: 69, 78: 70, 79: 71, 80: 72, 81: 73, 82: 74, 83: 75, 84: 76, 86: 77, 87: 78, 88: 79, 89: 80, 97: 85, 98: 86, 99: 87, 100: 88, 101: 89, 102: 90, 103: 91, 104: 92, 105: 93, 108: 94, 110: 95, 111: 96, 112: 97}, ['exp']), ({'T.name': 57, "'true'": 103, "'#'": 99, "'false'": 102, 'T.var_args': 84, "'-'": 98, "'{'": 81, "'not'": 100, "'('": 60, "'nil'": 101, 'T.hex_number': 105, "'function'": 55, 'T.decimal_number': 104, 'T.long_string': 83, 'T.short_string': 82}, {40: 54, 45: 151, 59: 211, 62: 59, 66: 61, 69: 62, 70: 63, 71: 64, 72: 65, 73: 66, 75: 67, 76: 68, 77: 69, 78: 70, 79: 71, 80: 72, 81: 73, 82: 74, 83: 75, 84: 76, 86: 77, 87: 78, 88: 79, 89: 80, 97: 85, 98: 86, 99: 87, 100: 88, 101: 89, 102: 90, 103: 91, 104: 92, 105: 93, 108: 94, 110: 95, 111: 96, 112: 97}, ['exp']), ({'T.name': 57, "'true'": 103, "'#'": 99, "'false'": 102, 'T.var_args': 84, "'-'": 98, "'{'": 81, "'not'": 100, "'('": 60, "'nil'": 101, 'T.hex_number': 105, "'function'": 55, 'T.decimal_number': 104, 'T.long_string': 83, 'T.short_string': 82}, {40: 54, 45: 150, 59: 211, 62: 59, 66: 61, 69: 62, 70: 63, 71: 64, 72: 65, 73: 66, 75: 67, 76: 68, 77: 69, 78: 70, 79: 71, 80: 72, 81: 73, 82: 74, 83: 75, 84: 76, 86: 77, 87: 78, 88: 79, 89: 80, 97: 85, 98: 86, 99: 87, 100: 88, 101: 89, 102: 90, 103: 91, 104: 92, 105: 93, 108: 94, 110: 95, 111: 96, 112: 97}, ['exp']), ({'T.name': 57, "'true'": 103, "'#'": 99, "'false'": 102, 'T.var_args': 84, "'-'": 98, "'{'": 81, "'not'": 100, "'('": 60, "'nil'": 101, 'T.hex_number': 105, "'function'": 55, 'T.decimal_number': 104, 'T.long_string': 83, 'T.short_string': 82}, {40: 54, 45: 149, 59: 211, 62: 59, 66: 61, 69: 62, 70: 63, 71: 64, 72: 65, 73: 66, 75: 67, 76: 68, 77: 69, 78: 70, 79: 71, 80: 72, 81: 73, 82: 74, 83: 75, 84: 76, 86: 77, 87: 78, 88: 79, 89: 80, 97: 85, 98: 86, 99: 87, 100: 88, 101: 89, 102: 90, 103: 91, 104: 92, 105: 93, 108: 94, 110: 95, 111: 96, 112: 97}, ['exp']), ({'T.name': 57, "'true'": 103, "'#'": 99, "'false'": 102, 'T.var_args': 84, "'-'": 98, "'{'": 81, "'not'": 100, "'('": 60, "'nil'": 101, 'T.hex_number': 105, "'function'": 55, 'T.decimal_number': 104, 'T.long_string': 83, 'T.short_string': 82}, {40: 54, 45: 148, 59: 211, 62: 59, 66: 61, 69: 62, 70: 63, 71: 64, 72: 65, 73: 66, 75: 67, 76: 68, 77: 69, 78: 70, 79: 71, 80: 72, 81: 73, 82: 74, 83: 75, 84: 76, 86: 77, 87: 78, 88: 79, 89: 80, 97: 85, 98: 86, 99: 87, 100: 88, 101: 89, 102: 90, 103: 91, 104: 92, 105: 93, 108: 94, 110: 95, 111: 96, 112: 97}, ['exp']), ({'T.name': 57, "'true'": 103, "'#'": 99, "'false'": 102, 'T.var_args': 84, "'-'": 98, "'{'": 81, "'not'": 100, "'('": 60, "'nil'": 101, 'T.hex_number': 105, "'function'": 55, 'T.decimal_number': 104, 'T.long_string': 83, 'T.short_string': 82}, {40: 54, 45: 147, 59: 211, 62: 59, 66: 61, 69: 62, 70: 63, 71: 64, 72: 65, 73: 66, 75: 67, 76: 68, 77: 69, 78: 70, 79: 71, 80: 72, 81: 73, 82: 74, 83: 75, 84: 76, 86: 77, 87: 78, 88: 79, 89: 80, 97: 85, 98: 86, 99: 87, 100: 88, 101: 89, 102: 90, 103: 91, 104: 92, 105: 93, 108: 94, 110: 95, 111: 96, 112: 97}, ['exp']), ({'T.name': 57, "'true'": 103, "'#'": 99, "'false'": 102, 'T.var_args': 84, "'-'": 98, "'{'": 81, "'not'": 100, "'('": 60, "'nil'": 101, 'T.hex_number': 105, "'function'": 55, 'T.decimal_number': 104, 'T.long_string': 83, 'T.short_string': 82}, {40: 54, 45: 146, 59: 211, 62: 59, 66: 61, 69: 62, 70: 63, 71: 64, 72: 65, 73: 66, 75: 67, 76: 68, 77: 69, 78: 70, 79: 71, 80: 72, 81: 73, 82: 74, 83: 75, 84: 76, 86: 77, 87: 78, 88: 79, 89: 80, 97: 85, 98: 86, 99: 87, 100: 88, 101: 89, 102: 90, 103: 91, 104: 92, 105: 93, 108: 94, 110: 95, 111: 96, 112: 97}, ['exp']), ({'T.name': 57, "'true'": 103, "'#'": 99, "'false'": 102, 'T.var_args': 84, "'-'": 98, "'{'": 81, "'not'": 100, "'('": 60, "'nil'": 101, 'T.hex_number': 105, "'function'": 55, 'T.decimal_number': 104, 'T.long_string': 83, 'T.short_string': 82}, {40: 54, 45: 145, 59: 211, 62: 59, 66: 61, 69: 62, 70: 63, 71: 64, 72: 65, 73: 66, 75: 67, 76: 68, 77: 69, 78: 70, 79: 71, 80: 72, 81: 73, 82: 74, 83: 75, 84: 76, 86: 77, 87: 78, 88: 79, 89: 80, 97: 85, 98: 86, 99: 87, 100: 88, 101: 89, 102: 90, 103: 91, 104: 92, 105: 93, 108: 94, 110: 95, 111: 96, 112: 97}, ['exp']), ({'T.name': 57, "'true'": 103, "'#'": 99, "'false'": 102, 'T.var_args': 84, "'-'": 98, "'{'": 81, "'not'": 100, "'('": 60, "'nil'": 101, 'T.hex_number': 105, "'function'": 55, 'T.decimal_number': 104, 'T.long_string': 83, 'T.short_string': 82}, {40: 54, 45: 144, 59: 211, 62: 59, 66: 61, 69: 62, 70: 63, 71: 64, 72: 65, 73: 66, 75: 67, 76: 68, 77: 69, 78: 70, 79: 71, 80: 72, 81: 73, 82: 74, 83: 75, 84: 76, 86: 77, 87: 78, 88: 79, 89: 80, 97: 85, 98: 86, 99: 87, 100: 88, 101: 89, 102: 90, 103: 91, 104: 92, 105: 93, 108: 94, 110: 95, 111: 96, 112: 97}, ['exp']), ({'T.name': 57, "'true'": 103, "'#'": 99, "'false'": 102, 'T.var_args': 84, "'-'": 98, "'{'": 81, "'not'": 100, "'('": 60, "'nil'": 101, 'T.hex_number': 105, "'function'": 55, 'T.decimal_number': 104, 'T.long_string': 83, 'T.short_string': 82}, {40: 54, 45: 143, 59: 211, 62: 59, 66: 61, 69: 62, 70: 63, 71: 64, 72: 65, 73: 66, 75: 67, 76: 68, 77: 69, 78: 70, 79: 71, 80: 72, 81: 73, 82: 74, 83: 75, 84: 76, 86: 77, 87: 78, 88: 79, 89: 80, 97: 85, 98: 86, 99: 87, 100: 88, 101: 89, 102: 90, 103: 91, 104: 92, 105: 93, 108: 94, 110: 95, 111: 96, 112: 97}, ['exp']), ({'T.name': 57, "'true'": 103, "'#'": 99, "'false'": 102, 'T.var_args': 84, "'-'": 98, "'{'": 81, "'not'": 100, "'('": 60, "'nil'": 101, 'T.hex_number': 105, "'function'": 55, 'T.decimal_number': 104, 'T.long_string': 83, 'T.short_string': 82}, {40: 54, 45: 142, 59: 211, 62: 59, 66: 61, 69: 62, 70: 63, 71: 64, 72: 65, 73: 66, 75: 67, 76: 68, 77: 69, 78: 70, 79: 71, 80: 72, 81: 73, 82: 74, 83: 75, 84: 76, 86: 77, 87: 78, 88: 79, 89: 80, 97: 85, 98: 86, 99: 87, 100: 88, 101: 89, 102: 90, 103: 91, 104: 92, 105: 93, 108: 94, 110: 95, 111: 96, 112: 97}, ['exp']), ({'T.name': 57, "'true'": 103, "'#'": 99, "'false'": 102, 'T.var_args': 84, "'-'": 98, "'{'": 81, "'not'": 100, "'('": 60, "'nil'": 101, 'T.hex_number': 105, "'function'": 55, 'T.decimal_number': 104, 'T.long_string': 83, 'T.short_string': 82}, {40: 54, 45: 141, 59: 211, 62: 59, 66: 61, 69: 62, 70: 63, 71: 64, 72: 65, 73: 66, 75: 67, 76: 68, 77: 69, 78: 70, 79: 71, 80: 72, 81: 73, 82: 74, 83: 75, 84: 76, 86: 77, 87: 78, 88: 79, 89: 80, 97: 85, 98: 86, 99: 87, 100: 88, 101: 89, 102: 90, 103: 91, 104: 92, 105: 93, 108: 94, 110: 95, 111: 96, 112: 97}, ['exp']), ({'T.name': 57, "'true'": 103, "'#'": 99, "'false'": 102, 'T.var_args': 84, "'-'": 98, "'{'": 81, "'not'": 100, "'('": 60, "'nil'": 101, 'T.hex_number': 105, "'function'": 55, 'T.decimal_number': 104, 'T.long_string': 83, 'T.short_string': 82}, {40: 54, 45: 140, 59: 211, 62: 59, 66: 61, 69: 62, 70: 63, 71: 64, 72: 65, 73: 66, 75: 67, 76: 68, 77: 69, 78: 70, 79: 71, 80: 72, 81: 73, 82: 74, 83: 75, 84: 76, 86: 77, 87: 78, 88: 79, 89: 80, 97: 85, 98: 86, 99: 87, 100: 88, 101: 89, 102: 90, 103: 91, 104: 92, 105: 93, 108: 94, 110: 95, 111: 96, 112: 97}, ['exp']), ({'T.name': 158}, {}, ['variable_ref']), ({"'^'": 123, "'>'": 132, "'=='": 134, "'/'": 126, "'>='": 133, "'-'": 124, "')'": 181, "'<='": 131, "'%'": 127, "'~='": 135, "'and'": 136, "'..'": 128, "'or'": 137, "'*'": 125, "'+'": 129, "'<'": 130}, {}, ['adjusted_exp', 'exp']), ({"'=='": 134, "';'": (105, 3), "'<='": 131, "'%'": 127, "'end'": (105, 3), "']'": (105, 3), "'return'": (105, 3), "'function'": (105, 3), "'^'": 123, "'elseif'": (105, 3), "','": (105, 3), "'('": (105, 3), "'while'": (105, 3), "'>='": 133, "'break'": (105, 3), "'*'": 125, "'>'": 132, '__end_of_input__': (105, 3), "'do'": (105, 3), "'else'": (105, 3), "'and'": 136, "'repeat'": (105, 3), "'or'": (105, 3), "'..'": 128, "'until'": (105, 3), 'T.name': (105, 3), "'then'": (105, 3), "'/'": 126, "'-'": 124, "')'": (105, 3), "'for'": (105, 3), "'if'": (105, 3), "'~='": 135, "'local'": (105, 3), "'}'": (105, 3), "'+'": 129, "'<'": 130}, {}, ['exp']), ({"'=='": 134, "';'": (104, 3), "'<='": 131, "'%'": 127, "'end'": (104, 3), "']'": (104, 3), "'return'": (104, 3), "'function'": (104, 3), "'^'": 123, "'elseif'": (104, 3), "','": (104, 3), "'('": (104, 3), "'while'": (104, 3), "'>='": 133, "'break'": (104, 3), "'*'": 125, "'>'": 132, '__end_of_input__': (104, 3), "'do'": (104, 3), "'else'": (104, 3), "'and'": (104, 3), "'repeat'": (104, 3), "'or'": (104, 3), "'..'": 128, "'until'": (104, 3), 'T.name': (104, 3), "'then'": (104, 3), "'/'": 126, "'-'": 124, "')'": (104, 3), "'for'": (104, 3), "'if'": (104, 3), "'~='": 135, "'local'": (104, 3), "'}'": (104, 3), "'+'": 129, "'<'": 130}, {}, ['exp']), ({"'=='": (103, 3), "';'": (103, 3), "'<='": (103, 3), "'%'": 127, "'end'": (103, 3), "']'": (103, 3), "'return'": (103, 3), "'function'": (103, 3), "'^'": 123, "'elseif'": (103, 3), "','": (103, 3), "'('": (103, 3), "'while'": (103, 3), "'>='": (103, 3), "'break'": (103, 3), "'*'": 125, "'>'": (103, 3), '__end_of_input__': (103, 3), "'do'": (103, 3), "'else'": (103, 3), "'and'": (103, 3), "'repeat'": (103, 3), "'or'": (103, 3), "'..'": 128, "'until'": (103, 3), 'T.name': (103, 3), "'then'": (103, 3), "'/'": 126, "'-'": 124, "')'": (103, 3), "'for'": (103, 3), "'if'": (103, 3), "'~='": (103, 3), "'local'": (103, 3), "'}'": (103, 3), "'+'": 129, "'<'": (103, 3)}, {}, ['exp']), ({"'=='": (103, 3), "';'": (103, 3), "'<='": (103, 3), "'%'": 127, "'end'": (103, 3), "']'": (103, 3), "'return'": (103, 3), "'function'": (103, 3), "'^'": 123, "'elseif'": (103, 3), "','": (103, 3), "'('": (103, 3), "'while'": (103, 3), "'>='": (103, 3), "'break'": (103, 3), "'*'": 125, "'>'": (103, 3), '__end_of_input__': (103, 3), "'do'": (103, 3), "'else'": (103, 3), "'and'": (103, 3), "'repeat'": (103, 3), "'or'": (103, 3), "'..'": 128, "'until'": (103, 3), 'T.name': (103, 3), "'then'": (103, 3), "'/'": 126, "'-'": 124, "')'": (103, 3), "'for'": (103, 3), "'if'": (103, 3), "'~='": (103, 3), "'local'": (103, 3), "'}'": (103, 3), "'+'": 129, "'<'": (103, 3)}, {}, ['exp']), ({"'=='": (103, 3), "';'": (103, 3), "'<='": (103, 3), "'%'": 127, "'end'": (103, 3), "']'": (103, 3), "'return'": (103, 3), "'function'": (103, 3), "'^'": 123, "'elseif'": (103, 3), "','": (103, 3), "'('": (103, 3), "'while'": (103, 3), "'>='": (103, 3), "'break'": (103, 3), "'*'": 125, "'>'": (103, 3), '__end_of_input__': (103, 3), "'do'": (103, 3), "'else'": (103, 3), "'and'": (103, 3), "'repeat'": (103, 3), "'or'": (103, 3), "'..'": 128, "'until'": (103, 3), 'T.name': (103, 3), "'then'": (103, 3), "'/'": 126, "'-'": 124, "')'": (103, 3), "'for'": (103, 3), "'if'": (103, 3), "'~='": (103, 3), "'local'": (103, 3), "'}'": (103, 3), "'+'": 129, "'<'": (103, 3)}, {}, ['exp']), ({"'=='": (103, 3), "';'": (103, 3), "'<='": (103, 3), "'%'": 127, "'end'": (103, 3), "']'": (103, 3), "'return'": (103, 3), "'function'": (103, 3), "'^'": 123, "'elseif'": (103, 3), "','": (103, 3), "'('": (103, 3), "'while'": (103, 3), "'>='": (103, 3), "'break'": (103, 3), "'*'": 125, "'>'": (103, 3), '__end_of_input__': (103, 3), "'do'": (103, 3), "'else'": (103, 3), "'and'": (103, 3), "'repeat'": (103, 3), "'or'": (103, 3), "'..'": 128, "'until'": (103, 3), 'T.name': (103, 3), "'then'": (103, 3), "'/'": 126, "'-'": 124, "')'": (103, 3), "'for'": (103, 3), "'if'": (103, 3), "'~='": (103, 3), "'local'": (103, 3), "'}'": (103, 3), "'+'": 129, "'<'": (103, 3)}, {}, ['exp']), ({"'=='": (103, 3), "';'": (103, 3), "'<='": (103, 3), "'%'": 127, "'end'": (103, 3), "']'": (103, 3), "'return'": (103, 3), "'function'": (103, 3), "'^'": 123, "'elseif'": (103, 3), "','": (103, 3), "'('": (103, 3), "'while'": (103, 3), "'>='": (103, 3), "'break'": (103, 3), "'*'": 125, "'>'": (103, 3), '__end_of_input__': (103, 3), "'do'": (103, 3), "'else'": (103, 3), "'and'": (103, 3), "'repeat'": (103, 3), "'or'": (103, 3), "'..'": 128, "'until'": (103, 3), 'T.name': (103, 3), "'then'": (103, 3), "'/'": 126, "'-'": 124, "')'": (103, 3), "'for'": (103, 3), "'if'": (103, 3), "'~='": (103, 3), "'local'": (103, 3), "'}'": (103, 3), "'+'": 129, "'<'": (103, 3)}, {}, ['exp']), ({"'=='": (103, 3), "';'": (103, 3), "'<='": (103, 3), "'%'": 127, "'end'": (103, 3), "']'": (103, 3), "'return'": (103, 3), "'function'": (103, 3), "'^'": 123, "'elseif'": (103, 3), "','": (103, 3), "'('": (103, 3), "'while'": (103, 3), "'>='": (103, 3), "'break'": (103, 3), "'*'": 125, "'>'": (103, 3), '__end_of_input__': (103, 3), "'do'": (103, 3), "'else'": (103, 3), "'and'": (103, 3), "'repeat'": (103, 3), "'or'": (103, 3), "'..'": 128, "'until'": (103, 3), 'T.name': (103, 3), "'then'": (103, 3), "'/'": 126, "'-'": 124, "')'": (103, 3), "'for'": (103, 3), "'if'": (103, 3), "'~='": (103, 3), "'local'": (103, 3), "'}'": (103, 3), "'+'": 129, "'<'": (103, 3)}, {}, ['exp']), ({"'=='": (102, 3), "';'": (102, 3), "'<='": (102, 3), "'%'": 127, "'end'": (102, 3), "']'": (102, 3), "'return'": (102, 3), "'function'": (102, 3), "'^'": 123, "'elseif'": (102, 3), "','": (102, 3), "'('": (102, 3), "'while'": (102, 3), "'>='": (102, 3), "'break'": (102, 3), "'*'": 125, "'>'": (102, 3), '__end_of_input__': (102, 3), "'do'": (102, 3), "'else'": (102, 3), "'and'": (102, 3), "'repeat'": (102, 3), "'or'": (102, 3), "'..'": 128, "'until'": (102, 3), 'T.name': (102, 3), "'then'": (102, 3), "'/'": 126, "'-'": (102, 3), "')'": (102, 3), "'for'": (102, 3), "'if'": (102, 3), "'~='": (102, 3), "'local'": (102, 3), "'}'": (102, 3), "'+'": (102, 3), "'<'": (102, 3)}, {}, ['exp']), ({"'=='": (101, 3), "';'": (101, 3), "'<='": (101, 3), "'%'": 127, "'end'": (101, 3), "']'": (101, 3), "'return'": (101, 3), "'function'": (101, 3), "'^'": 123, "'elseif'": (101, 3), "','": (101, 3), "'('": (101, 3), "'while'": (101, 3), "'>='": (101, 3), "'break'": (101, 3), "'*'": 125, "'>'": (101, 3), '__end_of_input__': (101, 3), "'do'": (101, 3), "'else'": (101, 3), "'and'": (101, 3), "'repeat'": (101, 3), "'or'": (101, 3), "'..'": 128, "'until'": (101, 3), 'T.name': (101, 3), "'then'": (101, 3), "'/'": 126, "'-'": (101, 3), "')'": (101, 3), "'for'": (101, 3), "'if'": (101, 3), "'~='": (101, 3), "'local'": (101, 3), "'}'": (101, 3), "'+'": (101, 3), "'<'": (101, 3)}, {}, ['exp']), ({"'=='": (100, 3), "';'": (100, 3), "'<='": (100, 3), "'%'": (100, 3), "'end'": (100, 3), "']'": (100, 3), "'return'": (100, 3), "'function'": (100, 3), "'^'": 123, "'elseif'": (100, 3), "','": (100, 3), "'('": (100, 3), "'while'": (100, 3), "'>='": (100, 3), "'break'": (100, 3), "'*'": (100, 3), "'>'": (100, 3), '__end_of_input__': (100, 3), "'do'": (100, 3), "'else'": (100, 3), "'and'": (100, 3), "'repeat'": (100, 3), "'or'": (100, 3), "'..'": (100, 3), "'until'": (100, 3), 'T.name': (100, 3), "'then'": (100, 3), "'/'": (100, 3), "'-'": (100, 3), "')'": (100, 3), "'for'": (100, 3), "'if'": (100, 3), "'~='": (100, 3), "'local'": (100, 3), "'}'": (100, 3), "'+'": (100, 3), "'<'": (100, 3)}, {}, ['exp']), ({"'=='": (100, 3), "';'": (100, 3), "'<='": (100, 3), "'%'": (100, 3), "'end'": (100, 3), "']'": (100, 3), "'return'": (100, 3), "'function'": (100, 3), "'^'": 123, "'elseif'": (100, 3), "','": (100, 3), "'('": (100, 3), "'while'": (100, 3), "'>='": (100, 3), "'break'": (100, 3), "'*'": (100, 3), "'>'": (100, 3), '__end_of_input__': (100, 3), "'do'": (100, 3), "'else'": (100, 3), "'and'": (100, 3), "'repeat'": (100, 3), "'or'": (100, 3), "'..'": (100, 3), "'until'": (100, 3), 'T.name': (100, 3), "'then'": (100, 3), "'/'": (100, 3), "'-'": (100, 3), "')'": (100, 3), "'for'": (100, 3), "'if'": (100, 3), "'~='": (100, 3), "'local'": (100, 3), "'}'": (100, 3), "'+'": (100, 3), "'<'": (100, 3)}, {}, ['exp']), ({"'=='": (100, 3), "';'": (100, 3), "'<='": (100, 3), "'%'": (100, 3), "'end'": (100, 3), "']'": (100, 3), "'return'": (100, 3), "'function'": (100, 3), "'^'": 123, "'elseif'": (100, 3), "','": (100, 3), "'('": (100, 3), "'while'": (100, 3), "'>='": (100, 3), "'break'": (100, 3), "'*'": (100, 3), "'>'": (100, 3), '__end_of_input__': (100, 3), "'do'": (100, 3), "'else'": (100, 3), "'and'": (100, 3), "'repeat'": (100, 3), "'or'": (100, 3), "'..'": (100, 3), "'until'": (100, 3), 'T.name': (100, 3), "'then'": (100, 3), "'/'": (100, 3), "'-'": (100, 3), "')'": (100, 3), "'for'": (100, 3), "'if'": (100, 3), "'~='": (100, 3), "'local'": (100, 3), "'}'": (100, 3), "'+'": (100, 3), "'<'": (100, 3)}, {}, ['exp']), ({"'=='": (102, 3), "';'": (102, 3), "'<='": (102, 3), "'%'": 127, "'end'": (102, 3), "']'": (102, 3), "'return'": (102, 3), "'function'": (102, 3), "'^'": 123, "'elseif'": (102, 3), "','": (102, 3), "'('": (102, 3), "'while'": (102, 3), "'>='": (102, 3), "'break'": (102, 3), "'*'": 125, "'>'": (102, 3), '__end_of_input__': (102, 3), "'do'": (102, 3), "'else'": (102, 3), "'and'": (102, 3), "'repeat'": (102, 3), "'or'": (102, 3), "'..'": 128, "'until'": (102, 3), 'T.name': (102, 3), "'then'": (102, 3), "'/'": 126, "'-'": (102, 3), "')'": (102, 3), "'for'": (102, 3), "'if'": (102, 3), "'~='": (102, 3), "'local'": (102, 3), "'}'": (102, 3), "'+'": (102, 3), "'<'": (102, 3)}, {}, ['exp']), ({"'=='": (98, 3), "';'": (98, 3), "'<='": (98, 3), "'%'": (98, 3), "'end'": (98, 3), "']'": (98, 3), "'return'": (98, 3), "'function'": (98, 3), "'^'": 123, "'elseif'": (98, 3), "','": (98, 3), "'('": (98, 3), "'while'": (98, 3), "'>='": (98, 3), "'break'": (98, 3), "'*'": (98, 3), "'>'": (98, 3), '__end_of_input__': (98, 3), "'do'": (98, 3), "'else'": (98, 3), "'and'": (98, 3), "'repeat'": (98, 3), "'or'": (98, 3), "'..'": (98, 3), "'until'": (98, 3), 'T.name': (98, 3), "'then'": (98, 3), "'/'": (98, 3), "'-'": (98, 3), "')'": (98, 3), "'for'": (98, 3), "'if'": (98, 3), "'~='": (98, 3), "'local'": (98, 3), "'}'": (98, 3), "'+'": (98, 3), "'<'": (98, 3)}, {}, ['exp']), ({"'nil'": 101, 'T.name': 118, "'true'": 103, "'#'": 99, "'false'": 102, 'T.decimal_number': 104, 'T.hex_number': 105, "'-'": 98, "'['": 121, "'not'": 100, "'('": 60, "'{'": 81, 'T.var_args': 84, "'function'": 55, "'}'": 168, 'T.long_string': 83, 'T.short_string': 82}, {40: 54, 45: 117, 59: 58, 62: 59, 66: 61, 69: 62, 70: 63, 71: 64, 72: 65, 73: 66, 75: 67, 76: 68, 77: 69, 78: 70, 79: 71, 80: 72, 81: 73, 82: 74, 83: 75, 84: 76, 86: 77, 87: 78, 88: 79, 89: 80, 97: 85, 98: 86, 99: 87, 100: 88, 101: 89, 102: 90, 103: 91, 104: 92, 105: 93, 108: 94, 109: 169, 110: 95, 111: 96, 112: 97}, ['table_constructor']), ({"'nil'": 101, 'T.name': 118, "'true'": 103, "'#'": 99, "'false'": 102, 'T.decimal_number': 104, 'T.hex_number': 105, "'-'": 98, "'['": 121, "'not'": 100, "'('": 60, "'{'": 81, 'T.var_args': 84, "'function'": 55, "'}'": 166, 'T.long_string': 83, 'T.short_string': 82}, {40: 54, 45: 117, 59: 58, 62: 59, 66: 61, 69: 62, 70: 63, 71: 64, 72: 65, 73: 66, 75: 67, 76: 68, 77: 69, 78: 70, 79: 71, 80: 72, 81: 73, 82: 74, 83: 75, 84: 76, 86: 77, 87: 78, 88: 79, 89: 80, 97: 85, 98: 86, 99: 87, 100: 88, 101: 89, 102: 90, 103: 91, 104: 92, 105: 93, 108: 94, 109: 167, 110: 95, 111: 96, 112: 97}, ['table_constructor']), ({"'=='": (71, 3, 'table_constructor'), "';'": (71, 3, 'table_constructor'), "'<='": (71, 3, 'table_constructor'), "'%'": (71, 3, 'table_constructor'), "'end'": (71, 3, 'table_constructor'), "']'": (71, 3, 'table_constructor'), 'T.long_string': (71, 3, 'table_constructor'), "'return'": (71, 3, 'table_constructor'), "'function'": (71, 3, 'table_constructor'), "'^'": (71, 3, 'table_constructor'), "'elseif'": (71, 3, 'table_constructor'), "','": (71, 3, 'table_constructor'), "'('": (71, 3, 'table_constructor'), "'..'": (71, 3, 'table_constructor'), "'>='": (71, 3, 'table_constructor'), "'break'": (71, 3, 'table_constructor'), "'*'": (71, 3, 'table_constructor'), "'while'": (71, 3, 'table_constructor'), "'>'": (71, 3, 'table_constructor'), '__end_of_input__': (71, 3, 'table_constructor'), "':'": (71, 3, 'table_constructor'), "'do'": (71, 3, 'table_constructor'), "'{'": (71, 3, 'table_constructor'), "'else'": (71, 3, 'table_constructor'), "'and'": (71, 3, 'table_constructor'), "'repeat'": (71, 3, 'table_constructor'), "'or'": (71, 3, 'table_constructor'), 'T.short_string': (71, 3, 'table_constructor'), "'until'": (71, 3, 'table_constructor'), 'T.name': (71, 3, 'table_constructor'), "'then'": (71, 3, 'table_constructor'), "'/'": (71, 3, 'table_constructor'), "'-'": (71, 3, 'table_constructor'), "'['": (71, 3, 'table_constructor'), "')'": (71, 3, 'table_constructor'), "'for'": (71, 3, 'table_constructor'), "'if'": (71, 3, 'table_constructor'), "'~='": (71, 3, 'table_constructor'), "'local'": (71, 3, 'table_constructor'), "'}'": (71, 3, 'table_constructor'), "'+'": (71, 3, 'table_constructor'), "'<'": (71, 3, 'table_constructor')}, {}, ['table_constructor']), ({"'=='": (73, 3), "';'": (73, 3), "'<='": (73, 3), "'%'": (73, 3), "'end'": (73, 3), "']'": (73, 3), 'T.long_string': (73, 3), "'return'": (73, 3), "'function'": (73, 3), "'^'": (73, 3), "'elseif'": (73, 3), 'T.short_string': (73, 3), "','": (73, 3), "'('": (73, 3), "'..'": (73, 3), "'>='": (73, 3), "'break'": (73, 3), "'*'": (73, 3), "'.'": (73, 3), "'>'": (73, 3), '__end_of_input__': (73, 3), "':'": (73, 3), "'do'": (73, 3), "'{'": (73, 3), "'else'": (73, 3), "'and'": (73, 3), "'repeat'": (73, 3), "'or'": (73, 3), "'while'": (73, 3), "'until'": (73, 3), 'T.name': (73, 3), "'then'": (73, 3), "'/'": (73, 3), "'-'": (73, 3), "'['": (73, 3), "')'": (73, 3), "'for'": (73, 3), "'if'": (73, 3), "'~='": (73, 3), "'local'": (73, 3), "'}'": (73, 3), "'+'": (73, 3), "'<'": (73, 3)}, {}, ['variable_ref']), ({"'^'": 123, "'>'": 132, "'=='": 134, "'/'": 126, "'>='": 133, "'-'": 124, "')'": 181, "'<='": 131, "'%'": 127, "'~='": 135, "'and'": 136, "'..'": 128, "'or'": 137, "'*'": 125, "'+'": 129, "'<'": 130}, {}, ['adjusted_exp', 'exp']), ({"'=='": (40, 2, 'function_call'), "';'": (40, 2, 'function_call'), "'<='": (40, 2, 'function_call'), "'%'": (40, 2, 'function_call'), "'end'": (40, 2, 'function_call'), "']'": (40, 2, 'function_call'), 'T.long_string': (40, 2, 'function_call'), "'return'": (40, 2, 'function_call'), "'function'": (40, 2, 'function_call'), "'^'": (40, 2, 'function_call'), "'elseif'": (40, 2, 'function_call'), "','": (40, 2, 'function_call'), "'('": (40, 2, 'function_call'), 'T.short_string': (40, 2, 'function_call'), "'>='": (40, 2, 'function_call'), "'break'": (40, 2, 'function_call'), "'*'": (40, 2, 'function_call'), "'while'": (40, 2, 'function_call'), "'>'": (40, 2, 'function_call'), '__end_of_input__': (40, 2, 'function_call'), "':'": (40, 2, 'function_call'), "'do'": (40, 2, 'function_call'), "'{'": (40, 2, 'function_call'), "'else'": (40, 2, 'function_call'), "'and'": (40, 2, 'function_call'), "'repeat'": (40, 2, 'function_call'), "'or'": (40, 2, 'function_call'), "'..'": (40, 2, 'function_call'), "'until'": (40, 2, 'function_call'), 'T.name': (40, 2, 'function_call'), "'then'": (40, 2, 'function_call'), "'/'": (40, 2, 'function_call'), "'-'": (40, 2, 'function_call'), "'['": (40, 2, 'function_call'), "')'": (40, 2, 'function_call'), "'for'": (40, 2, 'function_call'), "'if'": (40, 2, 'function_call'), "'~='": (40, 2, 'function_call'), "'local'": (40, 2, 'function_call'), "'}'": (40, 2, 'function_call'), "'+'": (40, 2, 'function_call'), "'<'": (40, 2, 'function_call')}, {}, ['function_call']), ({'T.name': 187}, {}, ['function_call']), ({'T.name': 57, "'true'": 103, "'#'": 99, "'false'": 102, 'T.decimal_number': 104, 'T.hex_number': 105, "'-'": 98, "'{'": 81, "')'": 185, "'not'": 100, "'('": 60, "'nil'": 101, 'T.var_args': 84, "'function'": 55, 'T.long_string': 83, 'T.short_string': 82}, {16: 184, 29: 53, 40: 54, 45: 56, 59: 58, 62: 59, 66: 61, 69: 62, 70: 63, 71: 64, 72: 65, 73: 66, 75: 67, 76: 68, 77: 69, 78: 70, 79: 71, 80: 72, 81: 73, 82: 74, 83: 75, 84: 76, 86: 77, 87: 78, 88: 79, 89: 80, 97: 85, 98: 86, 99: 87, 100: 88, 101: 89, 102: 90, 103: 91, 104: 92, 105: 93, 108: 94, 110: 95, 111: 96, 112: 97}, ['function_args']), ({"'=='": (60, 1, 'function_args'), "';'": (60, 1, 'function_args'), "'<='": (60, 1, 'function_args'), "'%'": (60, 1, 'function_args'), "'end'": (60, 1, 'function_args'), "']'": (60, 1, 'function_args'), 'T.long_string': (60, 1, 'function_args'), "'return'": (60, 1, 'function_args'), "'function'": (60, 1, 'function_args'), "'^'": (60, 1, 'function_args'), "'elseif'": (60, 1, 'function_args'), "','": (60, 1, 'function_args'), "'('": (60, 1, 'function_args'), "'..'": (60, 1, 'function_args'), "'>='": (60, 1, 'function_args'), "'break'": (60, 1, 'function_args'), "'*'": (60, 1, 'function_args'), "'while'": (60, 1, 'function_args'), "'>'": (60, 1, 'function_args'), '__end_of_input__': (60, 1, 'function_args'), "':'": (60, 1, 'function_args'), "'do'": (60, 1, 'function_args'), "'{'": (60, 1, 'function_args'), "'else'": (60, 1, 'function_args'), "'and'": (60, 1, 'function_args'), "'repeat'": (60, 1, 'function_args'), "'or'": (60, 1, 'function_args'), 'T.short_string': (60, 1, 'function_args'), "'until'": (60, 1, 'function_args'), 'T.name': (60, 1, 'function_args'), "'then'": (60, 1, 'function_args'), "'/'": (60, 1, 'function_args'), "'-'": (60, 1, 'function_args'), "'['": (60, 1, 'function_args'), "')'": (60, 1, 'function_args'), "'for'": (60, 1, 'function_args'), "'if'": (60, 1, 'function_args'), "'~='": (60, 1, 'function_args'), "'local'": (60, 1, 'function_args'), "'}'": (60, 1, 'function_args'), "'+'": (60, 1, 'function_args'), "'<'": (60, 1, 'function_args')}, {}, ['function_args']), ({"'=='": (60, 1, 'function_args'), "';'": (60, 1, 'function_args'), "'<='": (60, 1, 'function_args'), "'%'": (60, 1, 'function_args'), "'end'": (60, 1, 'function_args'), "']'": (60, 1, 'function_args'), 'T.long_string': (60, 1, 'function_args'), "'return'": (60, 1, 'function_args'), "'function'": (60, 1, 'function_args'), "'^'": (60, 1, 'function_args'), "'elseif'": (60, 1, 'function_args'), "','": (60, 1, 'function_args'), "'('": (60, 1, 'function_args'), "'..'": (60, 1, 'function_args'), "'>='": (60, 1, 'function_args'), "'break'": (60, 1, 'function_args'), "'*'": (60, 1, 'function_args'), "'while'": (60, 1, 'function_args'), "'>'": (60, 1, 'function_args'), '__end_of_input__': (60, 1, 'function_args'), "':'": (60, 1, 'function_args'), "'do'": (60, 1, 'function_args'), "'{'": (60, 1, 'function_args'), "'else'": (60, 1, 'function_args'), "'and'": (60, 1, 'function_args'), "'repeat'": (60, 1, 'function_args'), "'or'": (60, 1, 'function_args'), 'T.short_string': (60, 1, 'function_args'), "'until'": (60, 1, 'function_args'), 'T.name': (60, 1, 'function_args'), "'then'": (60, 1, 'function_args'), "'/'": (60, 1, 'function_args'), "'-'": (60, 1, 'function_args'), "'['": (60, 1, 'function_args'), "')'": (60, 1, 'function_args'), "'for'": (60, 1, 'function_args'), "'if'": (60, 1, 'function_args'), "'~='": (60, 1, 'function_args'), "'local'": (60, 1, 'function_args'), "'}'": (60, 1, 'function_args'), "'+'": (60, 1, 'function_args'), "'<'": (60, 1, 'function_args')}, {}, ['function_args']), ({'T.name': 57, "'true'": 103, "'#'": 99, "'false'": 102, 'T.var_args': 84, "'-'": 98, "'{'": 81, "'not'": 100, "'('": 60, "'nil'": 101, 'T.hex_number': 105, "'function'": 55, 'T.decimal_number': 104, 'T.long_string': 83, 'T.short_string': 82}, {40: 54, 45: 183, 59: 58, 62: 59, 66: 61, 69: 62, 70: 63, 71: 64, 72: 65, 73: 66, 75: 67, 76: 68, 77: 69, 78: 70, 79: 71, 80: 72, 81: 73, 82: 74, 83: 75, 84: 76, 86: 77, 87: 78, 88: 79, 89: 80, 97: 85, 98: 86, 99: 87, 100: 88, 101: 89, 102: 90, 103: 91, 104: 92, 105: 93, 108: 94, 110: 95, 111: 96, 112: 97}, ['subscript_exp']), ({"'=='": (71, 4, 'table_constructor'), "';'": (71, 4, 'table_constructor'), "'<='": (71, 4, 'table_constructor'), "'%'": (71, 4, 'table_constructor'), "'end'": (71, 4, 'table_constructor'), "']'": (71, 4, 'table_constructor'), 'T.long_string': (71, 4, 'table_constructor'), "'return'": (71, 4, 'table_constructor'), "'function'": (71, 4, 'table_constructor'), "'^'": (71, 4, 'table_constructor'), "'elseif'": (71, 4, 'table_constructor'), 'T.short_string': (71, 4, 'table_constructor'), "','": (71, 4, 'table_constructor'), "'('": (71, 4, 'table_constructor'), "'while'": (71, 4, 'table_constructor'), "'>='": (71, 4, 'table_constructor'), "'break'": (71, 4, 'table_constructor'), "'*'": (71, 4, 'table_constructor'), "'>'": (71, 4, 'table_constructor'), '__end_of_input__': (71, 4, 'table_constructor'), "':'": (71, 4, 'table_constructor'), "'do'": (71, 4, 'table_constructor'), "'{'": (71, 4, 'table_constructor'), "'else'": (71, 4, 'table_constructor'), "'and'": (71, 4, 'table_constructor'), "'repeat'": (71, 4, 'table_constructor'), "'or'": (71, 4, 'table_constructor'), "'..'": (71, 4, 'table_constructor'), "'until'": (71, 4, 'table_constructor'), 'T.name': (71, 4, 'table_constructor'), "'then'": (71, 4, 'table_constructor'), "'/'": (71, 4, 'table_constructor'), "'-'": (71, 4, 'table_constructor'), "'['": (71, 4, 'table_constructor'), "')'": (71, 4, 'table_constructor'), "'for'": (71, 4, 'table_constructor'), "'if'": (71, 4, 'table_constructor'), "'~='": (71, 4, 'table_constructor'), "'local'": (71, 4, 'table_constructor'), "'}'": (71, 4, 'table_constructor'), "'+'": (71, 4, 'table_constructor'), "'<'": (71, 4, 'table_constructor')}, {}, ['table_constructor']), ({"'}'": (92, 3), "';'": (92, 3), "','": (92, 3)}, {}, ['table_constructor']), ({"'=='": (71, 4, 'table_constructor'), "';'": (71, 4, 'table_constructor'), "'<='": (71, 4, 'table_constructor'), "'%'": (71, 4, 'table_constructor'), "'end'": (71, 4, 'table_constructor'), "']'": (71, 4, 'table_constructor'), 'T.long_string': (71, 4, 'table_constructor'), "'return'": (71, 4, 'table_constructor'), "'function'": (71, 4, 'table_constructor'), "'^'": (71, 4, 'table_constructor'), "'elseif'": (71, 4, 'table_constructor'), 'T.short_string': (71, 4, 'table_constructor'), "','": (71, 4, 'table_constructor'), "'('": (71, 4, 'table_constructor'), "'while'": (71, 4, 'table_constructor'), "'>='": (71, 4, 'table_constructor'), "'break'": (71, 4, 'table_constructor'), "'*'": (71, 4, 'table_constructor'), "'>'": (71, 4, 'table_constructor'), '__end_of_input__': (71, 4, 'table_constructor'), "':'": (71, 4, 'table_constructor'), "'do'": (71, 4, 'table_constructor'), "'{'": (71, 4, 'table_constructor'), "'else'": (71, 4, 'table_constructor'), "'and'": (71, 4, 'table_constructor'), "'repeat'": (71, 4, 'table_constructor'), "'or'": (71, 4, 'table_constructor'), "'..'": (71, 4, 'table_constructor'), "'until'": (71, 4, 'table_constructor'), 'T.name': (71, 4, 'table_constructor'), "'then'": (71, 4, 'table_constructor'), "'/'": (71, 4, 'table_constructor'), "'-'": (71, 4, 'table_constructor'), "'['": (71, 4, 'table_constructor'), "')'": (71, 4, 'table_constructor'), "'for'": (71, 4, 'table_constructor'), "'if'": (71, 4, 'table_constructor'), "'~='": (71, 4, 'table_constructor'), "'local'": (71, 4, 'table_constructor'), "'}'": (71, 4, 'table_constructor'), "'+'": (71, 4, 'table_constructor'), "'<'": (71, 4, 'table_constructor')}, {}, ['table_constructor']), ({"'}'": (92, 3), "';'": (92, 3), "','": (92, 3)}, {}, ['table_constructor']), ({"'('": 188}, {}, ['function_body']), ({"'=='": (112, 2, 'anon_function'), "';'": (112, 2, 'anon_function'), "'<='": (112, 2, 'anon_function'), "'%'": (112, 2, 'anon_function'), "'end'": (112, 2, 'anon_function'), "']'": (112, 2, 'anon_function'), "'return'": (112, 2, 'anon_function'), "'function'": (112, 2, 'anon_function'), "'^'": (112, 2, 'anon_function'), "'elseif'": (112, 2, 'anon_function'), "','": (112, 2, 'anon_function'), "'('": (112, 2, 'anon_function'), "'while'": (112, 2, 'anon_function'), "'>='": (112, 2, 'anon_function'), "'break'": (112, 2, 'anon_function'), "'*'": (112, 2, 'anon_function'), "'>'": (112, 2, 'anon_function'), '__end_of_input__': (112, 2, 'anon_function'), "'do'": (112, 2, 'anon_function'), "'else'": (112, 2, 'anon_function'), "'and'": (112, 2, 'anon_function'), "'repeat'": (112, 2, 'anon_function'), "'or'": (112, 2, 'anon_function'), "'..'": (112, 2, 'anon_function'), "'until'": (112, 2, 'anon_function'), 'T.name': (112, 2, 'anon_function'), "'then'": (112, 2, 'anon_function'), "'/'": (112, 2, 'anon_function'), "'-'": (112, 2, 'anon_function'), "')'": (112, 2, 'anon_function'), "'for'": (112, 2, 'anon_function'), "'if'": (112, 2, 'anon_function'), "'~='": (112, 2, 'anon_function'), "'local'": (112, 2, 'anon_function'), "'}'": (112, 2, 'anon_function'), "'+'": (112, 2, 'anon_function'), "'<'": (112, 2, 'anon_function')}, {}, ['anon_function']), ({'T.name': 222}, {}, ['local_function_decl_st']), ({"'return'": (25, 2, 'local_assign_st'), 'T.name': (25, 2, 'local_assign_st'), "'end'": (25, 2, 'local_assign_st'), "'function'": (25, 2, 'local_assign_st'), "'else'": (25, 2, 'local_assign_st'), '__end_of_input__': (25, 2, 'local_assign_st'), "'if'": (25, 2, 'local_assign_st'), "';'": (25, 2, 'local_assign_st'), "'local'": (25, 2, 'local_assign_st'), "'for'": (25, 2, 'local_assign_st'), "'('": (25, 2, 'local_assign_st'), "'repeat'": (25, 2, 'local_assign_st'), "'do'": (25, 2, 'local_assign_st'), "'break'": (25, 2, 'local_assign_st'), "'elseif'": (25, 2, 'local_assign_st'), "'='": 221, "'while'": (25, 2, 'local_assign_st'), "'until'": (25, 2, 'local_assign_st')}, {}, ['local_assign_st']), ({"'return'": (85, 1), 'T.name': (85, 1), "'end'": (85, 1), "'function'": (85, 1), "'else'": (85, 1), '__end_of_input__': (85, 1), "'='": (85, 1), "'local'": (85, 1), "'in'": (85, 1), "';'": (85, 1), "','": 220, "'elseif'": (85, 1), "'for'": (85, 1), "'('": (85, 1), "'repeat'": (85, 1), "'do'": (85, 1), "'break'": (85, 1), "'if'": (85, 1), "'while'": (85, 1), "'until'": (85, 1)}, {}, ['name_list']), ({"'return'": (50, 1, 'name_list'), 'T.name': (50, 1, 'name_list'), "'end'": (50, 1, 'name_list'), "'function'": (50, 1, 'name_list'), "'if'": (50, 1, 'name_list'), "'else'": (50, 1, 'name_list'), '__end_of_input__': (50, 1, 'name_list'), "'local'": (50, 1, 'name_list'), "'in'": (50, 1, 'name_list'), "';'": (50, 1, 'name_list'), "'elseif'": (50, 1, 'name_list'), "'for'": (50, 1, 'name_list'), "'('": (50, 1, 'name_list'), "'repeat'": (50, 1, 'name_list'), "'do'": (50, 1, 'name_list'), "'break'": (50, 1, 'name_list'), "'='": (50, 1, 'name_list'), "'while'": (50, 1, 'name_list'), "'until'": (50, 1, 'name_list')}, {}, ['name_list']), ({"'return'": (68, 1), 'T.name': (68, 1), "'end'": (68, 1), "'function'": (68, 1), "'if'": (68, 1), "'else'": (68, 1), '__end_of_input__': (68, 1), "'local'": (68, 1), "'in'": (68, 1), "';'": (68, 1), "'elseif'": (68, 1), "'for'": (68, 1), "'('": (68, 1), "'repeat'": (68, 1), "'do'": (68, 1), "'break'": (68, 1), "'='": (68, 1), "'while'": (68, 1), "'until'": (68, 1)}, {}, ['name_list']), ({"'return'": 11, 'T.name': 31, "'end'": (5, 0, 'block'), "'function'": 28, "'if'": 29, "'local'": 30, "'for'": 26, "'('": 37, "'repeat'": 32, "'do'": 25, "'break'": 12, "'while'": 33, "'until'": (5, 0, 'block')}, {5: 238, 8: 6, 10: 7, 12: 8, 13: 9, 14: 10, 18: 13, 19: 14, 20: 15, 21: 16, 22: 17, 23: 18, 24: 19, 25: 20, 26: 21, 27: 22, 28: 23, 30: 24, 40: 27, 57: 34, 59: 35, 62: 36, 69: 38, 70: 39, 73: 40, 86: 41, 87: 42, 88: 43, 89: 44, 108: 45}, ['loop_scope']), ({"'until'": 219}, {}, ['repeat_st']), ({"'return'": (36, 2, 'begin_loop_scope'), 'T.name': (36, 2, 'begin_loop_scope'), "'end'": (36, 2, 'begin_loop_scope'), "'function'": (36, 2, 'begin_loop_scope'), "'if'": (36, 2, 'begin_loop_scope'), "'local'": (36, 2, 'begin_loop_scope'), "'for'": (36, 2, 'begin_loop_scope'), "'('": (36, 2, 'begin_loop_scope'), "'repeat'": (36, 2, 'begin_loop_scope'), "'do'": (36, 2, 'begin_loop_scope'), "'break'": (36, 2, 'begin_loop_scope'), "'while'": (36, 2, 'begin_loop_scope'), "'until'": (36, 2, 'begin_loop_scope')}, {}, ['begin_loop_scope']), ({"'>='": 133, "'^'": 123, "'=='": 134, "'/'": 126, "'or'": 137, "'-'": 124, "'<='": 131, "'%'": 127, "'and'": 136, "'+'": 129, "'>'": 132, "'~='": 135, "'*'": 125, "'do'": 218, "'..'": 128, "'<'": 130}, {}, ['exp', 'while_st']), ({"'=='": (108, 3, 'adjusted_exp'), "';'": (108, 3, 'adjusted_exp'), "'<='": (108, 3, 'adjusted_exp'), "'%'": (108, 3, 'adjusted_exp'), "'end'": (108, 3, 'adjusted_exp'), "']'": (108, 3, 'adjusted_exp'), 'T.long_string': (108, 3, 'adjusted_exp'), "'return'": (108, 3, 'adjusted_exp'), "'function'": (108, 3, 'adjusted_exp'), "'^'": (108, 3, 'adjusted_exp'), "'elseif'": (108, 3, 'adjusted_exp'), "','": (108, 3, 'adjusted_exp'), "'('": (108, 3, 'adjusted_exp'), "'..'": (108, 3, 'adjusted_exp'), "'>='": (108, 3, 'adjusted_exp'), "'break'": (108, 3, 'adjusted_exp'), "'*'": (108, 3, 'adjusted_exp'), "'while'": (108, 3, 'adjusted_exp'), "'>'": (108, 3, 'adjusted_exp'), '__end_of_input__': (108, 3, 'adjusted_exp'), "':'": (108, 3, 'adjusted_exp'), "'do'": (108, 3, 'adjusted_exp'), "'{'": (108, 3, 'adjusted_exp'), "'else'": (108, 3, 'adjusted_exp'), "'and'": (108, 3, 'adjusted_exp'), "'repeat'": (108, 3, 'adjusted_exp'), "'or'": (108, 3, 'adjusted_exp'), 'T.short_string': (108, 3, 'adjusted_exp'), "'until'": (108, 3, 'adjusted_exp'), 'T.name': (108, 3, 'adjusted_exp'), "'then'": (108, 3, 'adjusted_exp'), "'/'": (108, 3, 'adjusted_exp'), "'-'": (108, 3, 'adjusted_exp'), "'['": (108, 3, 'adjusted_exp'), "')'": (108, 3, 'adjusted_exp'), "'for'": (108, 3, 'adjusted_exp'), "'if'": (108, 3, 'adjusted_exp'), "'~='": (108, 3, 'adjusted_exp'), "'local'": (108, 3, 'adjusted_exp'), "'}'": (108, 3, 'adjusted_exp'), "'+'": (108, 3, 'adjusted_exp'), "'<'": (108, 3, 'adjusted_exp')}, {}, ['adjusted_exp']), ({"'>='": 133, "'^'": 123, "'=='": 134, "'/'": 126, "'or'": 137, "'-'": 124, "'<='": 131, "'%'": 127, "'and'": 136, "'+'": 129, "'>'": 132, "'~='": 135, "'*'": 125, "']'": 231, "'..'": 128, "'<'": 130}, {}, ['exp', 'subscript_exp']), ({"'>='": 133, "'^'": 123, "'=='": 134, "'/'": 126, "'or'": 137, "'-'": 124, "'<='": 131, "'%'": 127, "'and'": 136, "'+'": 129, "'>'": 132, "'~='": 135, "'*'": 125, "']'": 231, "'..'": 128, "'<'": 130}, {}, ['exp', 'subscript_exp']), ({"')'": 191}, {}, ['function_args']), ({"'=='": (60, 2, 'function_args'), "';'": (60, 2, 'function_args'), "'<='": (60, 2, 'function_args'), "'%'": (60, 2, 'function_args'), "'end'": (60, 2, 'function_args'), "']'": (60, 2, 'function_args'), 'T.long_string': (60, 2, 'function_args'), "'return'": (60, 2, 'function_args'), "'function'": (60, 2, 'function_args'), "'^'": (60, 2, 'function_args'), "'elseif'": (60, 2, 'function_args'), "','": (60, 2, 'function_args'), "'('": (60, 2, 'function_args'), 'T.short_string': (60, 2, 'function_args'), "'>='": (60, 2, 'function_args'), "'break'": (60, 2, 'function_args'), "'*'": (60, 2, 'function_args'), "'while'": (60, 2, 'function_args'), "'>'": (60, 2, 'function_args'), '__end_of_input__': (60, 2, 'function_args'), "':'": (60, 2, 'function_args'), "'do'": (60, 2, 'function_args'), "'{'": (60, 2, 'function_args'), "'else'": (60, 2, 'function_args'), "'and'": (60, 2, 'function_args'), "'repeat'": (60, 2, 'function_args'), "'or'": (60, 2, 'function_args'), "'..'": (60, 2, 'function_args'), "'until'": (60, 2, 'function_args'), 'T.name': (60, 2, 'function_args'), "'then'": (60, 2, 'function_args'), "'/'": (60, 2, 'function_args'), "'-'": (60, 2, 'function_args'), "'['": (60, 2, 'function_args'), "')'": (60, 2, 'function_args'), "'for'": (60, 2, 'function_args'), "'if'": (60, 2, 'function_args'), "'~='": (60, 2, 'function_args'), "'local'": (60, 2, 'function_args'), "'}'": (60, 2, 'function_args'), "'+'": (60, 2, 'function_args'), "'<'": (60, 2, 'function_args')}, {}, ['function_args']), ({'T.name': 57, "'true'": 103, "'#'": 99, "'false'": 102, 'T.var_args': 84, "'-'": 98, "'{'": 81, "'not'": 100, "'('": 60, "'nil'": 101, 'T.hex_number': 105, "'function'": 55, 'T.decimal_number': 104, 'T.long_string': 83, 'T.short_string': 82}, {40: 54, 45: 216, 59: 211, 62: 59, 66: 61, 69: 62, 70: 63, 71: 64, 72: 65, 73: 66, 75: 67, 76: 68, 77: 69, 78: 70, 79: 71, 80: 72, 81: 73, 82: 74, 83: 75, 84: 76, 86: 77, 87: 78, 88: 79, 89: 80, 97: 85, 98: 86, 99: 87, 100: 88, 101: 89, 102: 90, 103: 91, 104: 92, 105: 93, 108: 94, 110: 95, 111: 96, 112: 97}, ['exp_list']), ({"'{'": 81, "'('": 162, 'T.long_string': 83, 'T.short_string': 82}, {72: 164, 60: 192, 71: 163}, ['function_call']), ({"')'": (64, 0, 'parameter_list'), 'T.var_args': 215, 'T.name': 212}, {64: 213, 74: 214}, ['function_body']), ({'T.name': 31, "'('": 37}, {69: 261, 70: 39, 40: 260, 73: 40, 108: 45, 86: 41, 87: 42, 88: 43, 89: 44, 59: 35, 62: 36}, ['var_list']), ({'T.name': 57, "'true'": 103, "'#'": 99, "'false'": 102, 'T.var_args': 84, "'-'": 98, "'{'": 81, "'not'": 100, "'('": 60, "'nil'": 101, 'T.hex_number': 105, "'function'": 55, 'T.decimal_number': 104, 'T.long_string': 83, 'T.short_string': 82}, {40: 54, 45: 262, 59: 58, 62: 59, 66: 61, 69: 62, 70: 63, 71: 64, 72: 65, 73: 66, 75: 67, 76: 68, 77: 69, 78: 70, 79: 71, 80: 72, 81: 73, 82: 74, 83: 75, 84: 76, 86: 77, 87: 78, 88: 79, 89: 80, 97: 85, 98: 86, 99: 87, 100: 88, 101: 89, 102: 90, 103: 91, 104: 92, 105: 93, 108: 94, 110: 95, 111: 96, 112: 97}, ['subscript_exp']), ({"'=='": (60, 3, 'function_args'), "';'": (60, 3, 'function_args'), "'<='": (60, 3, 'function_args'), "'%'": (60, 3, 'function_args'), "'end'": (60, 3, 'function_args'), "']'": (60, 3, 'function_args'), 'T.long_string': (60, 3, 'function_args'), "'return'": (60, 3, 'function_args'), "'function'": (60, 3, 'function_args'), "'^'": (60, 3, 'function_args'), "'elseif'": (60, 3, 'function_args'), "','": (60, 3, 'function_args'), "'('": (60, 3, 'function_args'), "'..'": (60, 3, 'function_args'), "'>='": (60, 3, 'function_args'), "'break'": (60, 3, 'function_args'), "'*'": (60, 3, 'function_args'), "'while'": (60, 3, 'function_args'), "'>'": (60, 3, 'function_args'), '__end_of_input__': (60, 3, 'function_args'), "':'": (60, 3, 'function_args'), "'do'": (60, 3, 'function_args'), "'{'": (60, 3, 'function_args'), "'else'": (60, 3, 'function_args'), "'and'": (60, 3, 'function_args'), "'repeat'": (60, 3, 'function_args'), "'or'": (60, 3, 'function_args'), 'T.short_string': (60, 3, 'function_args'), "'until'": (60, 3, 'function_args'), 'T.name': (60, 3, 'function_args'), "'then'": (60, 3, 'function_args'), "'/'": (60, 3, 'function_args'), "'-'": (60, 3, 'function_args'), "'['": (60, 3, 'function_args'), "')'": (60, 3, 'function_args'), "'for'": (60, 3, 'function_args'), "'if'": (60, 3, 'function_args'), "'~='": (60, 3, 'function_args'), "'local'": (60, 3, 'function_args'), "'}'": (60, 3, 'function_args'), "'+'": (60, 3, 'function_args'), "'<'": (60, 3, 'function_args')}, {}, ['function_args']), ({"'=='": (40, 4, 'function_call'), "';'": (40, 4, 'function_call'), "'<='": (40, 4, 'function_call'), "'%'": (40, 4, 'function_call'), "'end'": (40, 4, 'function_call'), "']'": (40, 4, 'function_call'), 'T.long_string': (40, 4, 'function_call'), "'return'": (40, 4, 'function_call'), "'function'": (40, 4, 'function_call'), "'^'": (40, 4, 'function_call'), "'elseif'": (40, 4, 'function_call'), "','": (40, 4, 'function_call'), "'('": (40, 4, 'function_call'), 'T.short_string': (40, 4, 'function_call'), "'>='": (40, 4, 'function_call'), "'break'": (40, 4, 'function_call'), "'*'": (40, 4, 'function_call'), "'while'": (40, 4, 'function_call'), "'>'": (40, 4, 'function_call'), '__end_of_input__': (40, 4, 'function_call'), "':'": (40, 4, 'function_call'), "'do'": (40, 4, 'function_call'), "'{'": (40, 4, 'function_call'), "'else'": (40, 4, 'function_call'), "'and'": (40, 4, 'function_call'), "'repeat'": (40, 4, 'function_call'), "'or'": (40, 4, 'function_call'), "'..'": (40, 4, 'function_call'), "'until'": (40, 4, 'function_call'), 'T.name': (40, 4, 'function_call'), "'then'": (40, 4, 'function_call'), "'/'": (40, 4, 'function_call'), "'-'": (40, 4, 'function_call'), "'['": (40, 4, 'function_call'), "')'": (40, 4, 'function_call'), "'for'": (40, 4, 'function_call'), "'if'": (40, 4, 'function_call'), "'~='": (40, 4, 'function_call'), "'local'": (40, 4, 'function_call'), "'}'": (40, 4, 'function_call'), "'+'": (40, 4, 'function_call'), "'<'": (40, 4, 'function_call')}, {}, ['function_call']), ({"'^'": 123, "'>'": 132, "'=='": 134, "'/'": 126, "'>='": 133, "'-'": 124, "')'": 263, "'<='": 131, "'%'": 127, "'~='": 135, "'and'": 136, "'..'": 128, "'or'": 137, "'*'": 125, "'+'": 129, "'<'": 130}, {}, ['adjusted_exp', 'exp']), ({'T.name': 264}, {}, ['variable_ref']), ({'__end_of_input__': (5, 3, 'block'), "'else'": (5, 3, 'block'), "'end'": (5, 3, 'block'), "'elseif'": (5, 3, 'block'), "'until'": (5, 3, 'block')}, {}, ['block']), ({"'return'": (10, 3), 'T.name': (10, 3), "'end'": (10, 3), "'function'": (10, 3), "'else'": (10, 3), '__end_of_input__': (10, 3), "'local'": (10, 3), "'for'": (10, 3), "'('": (10, 3), "'repeat'": (10, 3), "'do'": (10, 3), "'break'": (10, 3), "'elseif'": (10, 3), "'if'": (10, 3), "'while'": (10, 3), "'until'": (10, 3)}, {}, ['block']), ({"'return'": (18, 3, 'assign_st'), 'T.name': (18, 3, 'assign_st'), "'end'": (18, 3, 'assign_st'), "'function'": (18, 3, 'assign_st'), "'else'": (18, 3, 'assign_st'), '__end_of_input__': (18, 3, 'assign_st'), "';'": (18, 3, 'assign_st'), "'local'": (18, 3, 'assign_st'), "'for'": (18, 3, 'assign_st'), "'('": (18, 3, 'assign_st'), "'repeat'": (18, 3, 'assign_st'), "'do'": (18, 3, 'assign_st'), "'break'": (18, 3, 'assign_st'), "'elseif'": (18, 3, 'assign_st'), "'if'": (18, 3, 'assign_st'), "'while'": (18, 3, 'assign_st'), "'until'": (18, 3, 'assign_st')}, {}, ['assign_st']), ({"'=='": (87, 1), "';'": (87, 1), "'<='": (87, 1), "'%'": (87, 1), "'end'": (87, 1), 'T.long_string': (87, 1), "'return'": (87, 1), "'function'": (87, 1), "'^'": (87, 1), "'elseif'": (87, 1), "','": (87, 1), "'('": (87, 1), 'T.short_string': (87, 1), "'>='": (87, 1), "'break'": (87, 1), "'*'": (87, 1), "'while'": (87, 1), "'>'": (87, 1), '__end_of_input__': (87, 1), "':'": (87, 1), "'do'": (87, 1), "'{'": (87, 1), "'else'": (87, 1), "'and'": (87, 1), "'repeat'": (87, 1), "'or'": (87, 1), "'..'": (87, 1), "'until'": (87, 1), 'T.name': (87, 1), "'/'": (87, 1), "'-'": (87, 1), "'['": (87, 1), "'for'": (87, 1), "'if'": (87, 1), "'~='": (87, 1), "'local'": (87, 1), "'+'": (87, 1), "'<'": (87, 1)}, {}, ['prefix_exp']), ({"'=='": (73, 1), "';'": (73, 1), "'<='": (73, 1), "'%'": (73, 1), "'end'": (73, 1), 'T.long_string': (73, 1), "'return'": (73, 1), "'function'": (73, 1), "'^'": (73, 1), "'elseif'": (73, 1), "','": (73, 1), "'('": (73, 1), "'..'": (73, 1), "'do'": (73, 1), "'break'": (73, 1), "'*'": (73, 1), "'.'": (73, 1), "'while'": (73, 1), "'>'": (73, 1), '__end_of_input__': (73, 1), "':'": (73, 1), "'>='": (73, 1), "'{'": (73, 1), "'else'": (73, 1), "'and'": (73, 1), "'repeat'": (73, 1), "'or'": (73, 1), 'T.short_string': (73, 1), "'until'": (73, 1), 'T.name': (73, 1), "'/'": (73, 1), "'-'": (73, 1), "'['": (73, 1), "'for'": (73, 1), "'if'": (73, 1), "'~='": (73, 1), "'local'": (73, 1), "'+'": (73, 1), "'<'": (73, 1)}, {}, ['variable_ref']), ({"'=='": (76, 1), "';'": (76, 1), "'<='": (76, 1), "'%'": (76, 1), "'end'": (76, 1), 'T.long_string': 83, "'return'": (76, 1), "'function'": (76, 1), "'^'": (76, 1), "'elseif'": (76, 1), "','": (76, 1), "'('": 162, "'..'": (76, 1), "'>='": (76, 1), "'break'": (76, 1), "'*'": (76, 1), "'while'": (76, 1), "'>'": (76, 1), '__end_of_input__': (76, 1), "':'": 161, "'do'": (76, 1), "'{'": 81, "'else'": (76, 1), "'and'": (76, 1), "'repeat'": (76, 1), "'or'": (76, 1), 'T.short_string': 82, "'until'": (76, 1), 'T.name': (76, 1), "'/'": (76, 1), "'-'": (76, 1), "'['": 234, "'for'": (76, 1), "'if'": (76, 1), "'~='": (76, 1), "'local'": (76, 1), "'+'": (76, 1), "'<'": (76, 1)}, {72: 164, 60: 160, 71: 163}, ['exp', 'function_call', 'subscript_exp']), ({"'=='": (69, 1, 'var'), "';'": (69, 1, 'var'), "'<='": (69, 1, 'var'), "'%'": (69, 1, 'var'), "'end'": (69, 1, 'var'), 'T.long_string': (69, 1, 'var'), "'return'": (69, 1, 'var'), "'function'": (69, 1, 'var'), "'^'": (69, 1, 'var'), "'elseif'": (69, 1, 'var'), 'T.short_string': (69, 1, 'var'), "','": (69, 1, 'var'), "'('": (69, 1, 'var'), "'while'": (69, 1, 'var'), "'>='": (69, 1, 'var'), "'break'": (69, 1, 'var'), "'*'": (69, 1, 'var'), "'>'": (69, 1, 'var'), '__end_of_input__': (69, 1, 'var'), "':'": (69, 1, 'var'), "'do'": (69, 1, 'var'), "'{'": (69, 1, 'var'), "'else'": (69, 1, 'var'), "'and'": (69, 1, 'var'), "'repeat'": (69, 1, 'var'), "'or'": (69, 1, 'var'), "'..'": (69, 1, 'var'), "'until'": (69, 1, 'var'), 'T.name': (69, 1, 'var'), "'/'": (69, 1, 'var'), "'-'": (69, 1, 'var'), "'['": (69, 1, 'var'), "'for'": (69, 1, 'var'), "'if'": (69, 1, 'var'), "'~='": (69, 1, 'var'), "'local'": (69, 1, 'var'), "'+'": (69, 1, 'var'), "'<'": (69, 1, 'var')}, {}, ['var']), ({'T.name': 57, "'true'": 103, "'#'": 99, "'false'": 102, 'T.var_args': 84, "'-'": 98, "'{'": 81, "'not'": 100, "'('": 60, "'nil'": 101, 'T.hex_number': 105, "'function'": 55, 'T.decimal_number': 104, 'T.long_string': 83, 'T.short_string': 82}, {40: 54, 45: 233, 59: 58, 62: 59, 66: 61, 69: 62, 70: 63, 71: 64, 72: 65, 73: 66, 75: 67, 76: 68, 77: 69, 78: 70, 79: 71, 80: 72, 81: 73, 82: 74, 83: 75, 84: 76, 86: 77, 87: 78, 88: 79, 89: 80, 97: 85, 98: 86, 99: 87, 100: 88, 101: 89, 102: 90, 103: 91, 104: 92, 105: 93, 108: 94, 110: 95, 111: 96, 112: 97}, ['adjusted_exp']), ({"'=='": (89, 1), "';'": (89, 1), "'<='": (89, 1), "'%'": (89, 1), "'end'": (89, 1), 'T.long_string': (89, 1), "'return'": (89, 1), "'function'": (89, 1), "'^'": (89, 1), "'elseif'": (89, 1), "','": (89, 1), "'('": (89, 1), 'T.short_string': (89, 1), "'>='": (89, 1), "'break'": (89, 1), "'*'": (89, 1), "'while'": (89, 1), "'>'": (89, 1), '__end_of_input__': (89, 1), "':'": (89, 1), "'do'": (89, 1), "'{'": (89, 1), "'else'": (89, 1), "'and'": (89, 1), "'repeat'": (89, 1), "'or'": (89, 1), "'..'": (89, 1), "'until'": (89, 1), 'T.name': (89, 1), "'/'": (89, 1), "'-'": (89, 1), "'['": (89, 1), "'for'": (89, 1), "'if'": (89, 1), "'~='": (89, 1), "'local'": (89, 1), "'+'": (89, 1), "'<'": (89, 1)}, {}, ['prefix_exp']), ({"'=='": (59, 1, 'prefix_exp'), "';'": (59, 1, 'prefix_exp'), "'<='": (59, 1, 'prefix_exp'), "'%'": (59, 1, 'prefix_exp'), "'end'": (59, 1, 'prefix_exp'), 'T.long_string': (59, 1, 'prefix_exp'), "'return'": (59, 1, 'prefix_exp'), "'function'": (59, 1, 'prefix_exp'), "'^'": (59, 1, 'prefix_exp'), "'elseif'": (59, 1, 'prefix_exp'), "','": (59, 1, 'prefix_exp'), "'('": (59, 1, 'prefix_exp'), "'..'": (59, 1, 'prefix_exp'), "'>='": (59, 1, 'prefix_exp'), "'break'": (59, 1, 'prefix_exp'), "'*'": (59, 1, 'prefix_exp'), "'while'": (59, 1, 'prefix_exp'), "'>'": (59, 1, 'prefix_exp'), '__end_of_input__': (59, 1, 'prefix_exp'), "':'": (59, 1, 'prefix_exp'), "'do'": (59, 1, 'prefix_exp'), "'{'": (59, 1, 'prefix_exp'), "'else'": (59, 1, 'prefix_exp'), "'and'": (59, 1, 'prefix_exp'), "'repeat'": (59, 1, 'prefix_exp'), "'or'": (59, 1, 'prefix_exp'), 'T.short_string': (59, 1, 'prefix_exp'), "'until'": (59, 1, 'prefix_exp'), 'T.name': (59, 1, 'prefix_exp'), "'/'": (59, 1, 'prefix_exp'), "'-'": (59, 1, 'prefix_exp'), "'['": (59, 1, 'prefix_exp'), "'for'": (59, 1, 'prefix_exp'), "'if'": (59, 1, 'prefix_exp'), "'~='": (59, 1, 'prefix_exp'), "'local'": (59, 1, 'prefix_exp'), "'+'": (59, 1, 'prefix_exp'), "'<'": (59, 1, 'prefix_exp')}, {}, ['prefix_exp']), ({"'=='": (62, 1, 'variable_ref'), "';'": (62, 1, 'variable_ref'), "'<='": (62, 1, 'variable_ref'), "'%'": (62, 1, 'variable_ref'), "'end'": (62, 1, 'variable_ref'), 'T.long_string': (62, 1, 'variable_ref'), "'return'": (62, 1, 'variable_ref'), "'function'": (62, 1, 'variable_ref'), "'^'": (62, 1, 'variable_ref'), "'elseif'": (62, 1, 'variable_ref'), 'T.short_string': (62, 1, 'variable_ref'), "','": (62, 1, 'variable_ref'), "'('": (62, 1, 'variable_ref'), "'..'": (62, 1, 'variable_ref'), "'>='": (62, 1, 'variable_ref'), "'break'": (62, 1, 'variable_ref'), "'*'": (62, 1, 'variable_ref'), "'.'": 232, "'>'": (62, 1, 'variable_ref'), '__end_of_input__': (62, 1, 'variable_ref'), "':'": (62, 1, 'variable_ref'), "'do'": (62, 1, 'variable_ref'), "'{'": (62, 1, 'variable_ref'), "'else'": (62, 1, 'variable_ref'), "'and'": (62, 1, 'variable_ref'), "'repeat'": (62, 1, 'variable_ref'), "'or'": (62, 1, 'variable_ref'), "'while'": (62, 1, 'variable_ref'), "'until'": (62, 1, 'variable_ref'), 'T.name': (62, 1, 'variable_ref'), "'/'": (62, 1, 'variable_ref'), "'-'": (62, 1, 'variable_ref'), "'['": (62, 1, 'variable_ref'), "'for'": (62, 1, 'variable_ref'), "'if'": (62, 1, 'variable_ref'), "'~='": (62, 1, 'variable_ref'), "'local'": (62, 1, 'variable_ref'), "'+'": (62, 1, 'variable_ref'), "'<'": (62, 1, 'variable_ref')}, {}, ['variable_ref']), ({"'=='": (69, 1, 'var'), "';'": (69, 1, 'var'), "'<='": (69, 1, 'var'), "'%'": (69, 1, 'var'), "'end'": (69, 1, 'var'), 'T.long_string': (69, 1, 'var'), "'return'": (69, 1, 'var'), "'function'": (69, 1, 'var'), "'^'": (69, 1, 'var'), "'elseif'": (69, 1, 'var'), 'T.short_string': (69, 1, 'var'), "','": (69, 1, 'var'), "'('": (69, 1, 'var'), "'while'": (69, 1, 'var'), "'>='": (69, 1, 'var'), "'break'": (69, 1, 'var'), "'*'": (69, 1, 'var'), "'>'": (69, 1, 'var'), '__end_of_input__': (69, 1, 'var'), "':'": (69, 1, 'var'), "'do'": (69, 1, 'var'), "'{'": (69, 1, 'var'), "'else'": (69, 1, 'var'), "'and'": (69, 1, 'var'), "'repeat'": (69, 1, 'var'), "'or'": (69, 1, 'var'), "'..'": (69, 1, 'var'), "'until'": (69, 1, 'var'), 'T.name': (69, 1, 'var'), "'/'": (69, 1, 'var'), "'-'": (69, 1, 'var'), "'['": (69, 1, 'var'), "'for'": (69, 1, 'var'), "'if'": (69, 1, 'var'), "'~='": (69, 1, 'var'), "'local'": (69, 1, 'var'), "'+'": (69, 1, 'var'), "'<'": (69, 1, 'var')}, {}, ['var']), ({"'=='": (70, 1), "';'": (70, 1), "'<='": (70, 1), "'%'": (70, 1), "'end'": (70, 1), 'T.long_string': (70, 1), "'return'": (70, 1), "'function'": (70, 1), "'^'": (70, 1), "'elseif'": (70, 1), "','": (70, 1), "'('": (70, 1), 'T.short_string': (70, 1), "'>='": (70, 1), "'break'": (70, 1), "'*'": (70, 1), "'while'": (70, 1), "'>'": (70, 1), '__end_of_input__': (70, 1), "':'": (70, 1), "'do'": (70, 1), "'{'": (70, 1), "'else'": (70, 1), "'and'": (70, 1), "'repeat'": (70, 1), "'or'": (70, 1), "'..'": (70, 1), "'until'": (70, 1), 'T.name': (70, 1), "'/'": (70, 1), "'-'": (70, 1), "'['": (70, 1), "'for'": (70, 1), "'if'": (70, 1), "'~='": (70, 1), "'local'": (70, 1), "'+'": (70, 1), "'<'": (70, 1)}, {}, ['prefix_exp']), ({"'=='": (70, 1), "';'": (70, 1), "'<='": (70, 1), "'%'": (70, 1), "'end'": (70, 1), 'T.long_string': (70, 1), "'return'": (70, 1), "'function'": (70, 1), "'^'": (70, 1), "'elseif'": (70, 1), "','": (70, 1), "'('": (70, 1), 'T.short_string': (70, 1), "'>='": (70, 1), "'break'": (70, 1), "'*'": (70, 1), "'while'": (70, 1), "'>'": (70, 1), '__end_of_input__': (70, 1), "':'": (70, 1), "'do'": (70, 1), "'{'": (70, 1), "'else'": (70, 1), "'and'": (70, 1), "'repeat'": (70, 1), "'or'": (70, 1), "'..'": (70, 1), "'until'": (70, 1), 'T.name': (70, 1), "'/'": (70, 1), "'-'": (70, 1), "'['": (70, 1), "'for'": (70, 1), "'if'": (70, 1), "'~='": (70, 1), "'local'": (70, 1), "'+'": (70, 1), "'<'": (70, 1)}, {}, ['prefix_exp']), ({"'=='": (70, 1), "';'": (70, 1), "'<='": (70, 1), "'%'": (70, 1), "'end'": (70, 1), 'T.long_string': (70, 1), "'return'": (70, 1), "'function'": (70, 1), "'^'": (70, 1), "'elseif'": (70, 1), "','": (70, 1), "'('": (70, 1), 'T.short_string': (70, 1), "'>='": (70, 1), "'break'": (70, 1), "'*'": (70, 1), "'while'": (70, 1), "'>'": (70, 1), '__end_of_input__': (70, 1), "':'": (70, 1), "'do'": (70, 1), "'{'": (70, 1), "'else'": (70, 1), "'and'": (70, 1), "'repeat'": (70, 1), "'or'": (70, 1), "'..'": (70, 1), "'until'": (70, 1), 'T.name': (70, 1), "'/'": (70, 1), "'-'": (70, 1), "'['": (70, 1), "'for'": (70, 1), "'if'": (70, 1), "'~='": (70, 1), "'local'": (70, 1), "'+'": (70, 1), "'<'": (70, 1)}, {}, ['prefix_exp']), ({"'=='": (88, 1), "';'": (88, 1), "'<='": (88, 1), "'%'": (88, 1), "'end'": (88, 1), 'T.long_string': (88, 1), "'return'": (88, 1), "'function'": (88, 1), "'^'": (88, 1), "'elseif'": (88, 1), "','": (88, 1), "'('": (88, 1), 'T.short_string': (88, 1), "'>='": (88, 1), "'break'": (88, 1), "'*'": (88, 1), "'while'": (88, 1), "'>'": (88, 1), '__end_of_input__': (88, 1), "':'": (88, 1), "'do'": (88, 1), "'{'": (88, 1), "'else'": (88, 1), "'and'": (88, 1), "'repeat'": (88, 1), "'or'": (88, 1), "'..'": (88, 1), "'until'": (88, 1), 'T.name': (88, 1), "'/'": (88, 1), "'-'": (88, 1), "'['": (88, 1), "'for'": (88, 1), "'if'": (88, 1), "'~='": (88, 1), "'local'": (88, 1), "'+'": (88, 1), "'<'": (88, 1)}, {}, ['prefix_exp']), ({"'=='": (76, 1), "';'": (76, 1), "'<='": (76, 1), "'%'": (76, 1), "'end'": (76, 1), "']'": (76, 1), 'T.long_string': 83, "'return'": (76, 1), "'function'": (76, 1), "'^'": (76, 1), "'elseif'": (76, 1), "','": (76, 1), "'('": 162, "'..'": (76, 1), "'>='": (76, 1), "'break'": (76, 1), "'*'": (76, 1), "'while'": (76, 1), "'>'": (76, 1), '__end_of_input__': (76, 1), "':'": 161, "'do'": (76, 1), "'{'": 81, "'else'": (76, 1), "'and'": (76, 1), "'repeat'": (76, 1), "'or'": (76, 1), 'T.short_string': 82, "'until'": (76, 1), 'T.name': (76, 1), "'then'": (76, 1), "'/'": (76, 1), "'-'": (76, 1), "'['": 165, "')'": (76, 1), "'for'": (76, 1), "'if'": (76, 1), "'~='": (76, 1), "'local'": (76, 1), "'}'": (76, 1), "'+'": (76, 1), "'<'": (76, 1)}, {72: 164, 60: 160, 71: 163}, ['exp', 'function_call', 'subscript_exp']), ({"')'": (74, 1), "','": 265}, {}, ['_parameter_list']), ({"')'": 225}, {}, ['function_body']), ({"')'": (64, 1, 'parameter_list')}, {}, ['parameter_list']), ({"')'": (74, 1)}, {}, ['_parameter_list']), ({"'=='": 134, "';'": (29, 3), "'<='": 131, "'%'": 127, "'end'": (29, 3), "'return'": (29, 3), "'function'": (29, 3), "'^'": 123, "'elseif'": (29, 3), "','": (29, 3), "'('": (29, 3), "'while'": (29, 3), "'>='": 133, "'break'": (29, 3), "'*'": 125, "'>'": 132, '__end_of_input__': (29, 3), "'do'": (29, 3), "'else'": (29, 3), "'and'": 136, "'repeat'": (29, 3), "'or'": 137, "'..'": 128, "'until'": (29, 3), 'T.name': (29, 3), "'/'": 126, "'-'": 124, "')'": (29, 3), "'for'": (29, 3), "'if'": (29, 3), "'~='": 135, "'local'": (29, 3), "'+'": 129, "'<'": 130}, {}, ['exp', 'exp_list']), ({"'end'": (11, 0, 'end_scope'), "'else'": (11, 0, 'end_scope'), "'elseif'": (11, 0, 'end_scope')}, {11: 259}, ['scope']), ({"'return'": (7, 0, 'begin_scope'), 'T.name': (7, 0, 'begin_scope'), "'end'": (7, 0, 'begin_scope'), "'function'": (7, 0, 'begin_scope'), "'local'": (7, 0, 'begin_scope'), "'for'": (7, 0, 'begin_scope'), "'('": (7, 0, 'begin_scope'), "'repeat'": (7, 0, 'begin_scope'), "'do'": (7, 0, 'begin_scope'), "'break'": (7, 0, 'begin_scope'), "'while'": (7, 0, 'begin_scope'), "'if'": (7, 0, 'begin_scope')}, {36: 177, 53: 239, 7: 109}, ['while_st']), ({'T.name': 199, "'true'": 103, "'#'": 99, "'false'": 102, 'T.var_args': 84, "'-'": 98, "'{'": 81, "'not'": 100, "'('": 202, "'nil'": 101, 'T.hex_number': 105, "'function'": 55, 'T.decimal_number': 104, 'T.long_string': 83, 'T.short_string': 82}, {40: 198, 45: 241, 59: 200, 62: 201, 66: 61, 69: 203, 70: 204, 71: 64, 72: 65, 73: 205, 75: 67, 76: 68, 77: 69, 78: 70, 79: 71, 80: 72, 81: 73, 82: 74, 83: 75, 84: 76, 86: 206, 87: 207, 88: 208, 89: 209, 97: 85, 98: 86, 99: 87, 100: 88, 101: 89, 102: 90, 103: 91, 104: 92, 105: 93, 108: 210, 110: 95, 111: 96, 112: 97}, ['repeat_st']), ({'T.name': 174}, {85: 246}, ['name_list']), ({'T.name': 199, "'true'": 103, "'#'": 99, "'false'": 102, 'T.var_args': 84, "'-'": 98, "'{'": 81, "'not'": 100, "'('": 202, "'nil'": 101, 'T.hex_number': 105, "'function'": 55, 'T.decimal_number': 104, 'T.long_string': 83, 'T.short_string': 82}, {16: 247, 29: 53, 40: 198, 45: 56, 59: 200, 62: 201, 66: 61, 69: 203, 70: 204, 71: 64, 72: 65, 73: 205, 75: 67, 76: 68, 77: 69, 78: 70, 79: 71, 80: 72, 81: 73, 82: 74, 83: 75, 84: 76, 86: 206, 87: 207, 88: 208, 89: 209, 97: 85, 98: 86, 99: 87, 100: 88, 101: 89, 102: 90, 103: 91, 104: 92, 105: 93, 108: 210, 110: 95, 111: 96, 112: 97}, ['local_assign_st']), ({"'('": (7, 0, 'begin_scope')}, {43: 248, 7: 170}, ['local_function_decl_st']), ({"'return'": (7, 0, 'begin_scope'), 'T.name': (7, 0, 'begin_scope'), "'end'": (7, 0, 'begin_scope'), "'function'": (7, 0, 'begin_scope'), "'else'": (7, 0, 'begin_scope'), "'elseif'": (7, 0, 'begin_scope'), "'local'": (7, 0, 'begin_scope'), "'for'": (7, 0, 'begin_scope'), "'('": (7, 0, 'begin_scope'), "'repeat'": (7, 0, 'begin_scope'), "'do'": (7, 0, 'begin_scope'), "'break'": (7, 0, 'begin_scope'), "'while'": (7, 0, 'begin_scope'), "'if'": (7, 0, 'begin_scope')}, {33: 249, 7: 107}, ['if_st']), ({"'return'": (23, 3, 'function_decl_st'), 'T.name': (23, 3, 'function_decl_st'), "'end'": (23, 3, 'function_decl_st'), "'function'": (23, 3, 'function_decl_st'), "'else'": (23, 3, 'function_decl_st'), '__end_of_input__': (23, 3, 'function_decl_st'), "';'": (23, 3, 'function_decl_st'), "'local'": (23, 3, 'function_decl_st'), "'for'": (23, 3, 'function_decl_st'), "'('": (23, 3, 'function_decl_st'), "'repeat'": (23, 3, 'function_decl_st'), "'do'": (23, 3, 'function_decl_st'), "'break'": (23, 3, 'function_decl_st'), "'elseif'": (23, 3, 'function_decl_st'), "'if'": (23, 3, 'function_decl_st'), "'while'": (23, 3, 'function_decl_st'), "'until'": (23, 3, 'function_decl_st')}, {}, ['function_decl_st']), ({"'return'": 11, 'T.name': 31, "'end'": (5, 0, 'block'), "'function'": 28, "'local'": 30, "'for'": 26, "'('": 37, "'repeat'": 32, "'do'": 25, "'break'": 12, "'while'": 33, "'if'": 29}, {5: 245, 8: 6, 10: 7, 12: 8, 13: 9, 14: 10, 18: 13, 19: 14, 20: 15, 21: 16, 22: 17, 23: 18, 24: 19, 25: 20, 26: 21, 27: 22, 28: 23, 30: 24, 40: 27, 57: 34, 59: 35, 62: 36, 69: 38, 70: 39, 73: 40, 86: 41, 87: 42, 88: 43, 89: 44, 108: 45}, ['function_body']), ({"'in'": 258}, {}, ['for_in_st']), ({"'do'": 257}, {}, ['for_step_st']), ({"'in'": (37, 1, 'for_name_list')}, {}, ['for_name_list']), ({"'='": 266, "'in'": (85, 1), "','": 220}, {}, ['for_steps', 'name_list']), ({"'return'": (19, 3, 'do_st'), 'T.name': (19, 3, 'do_st'), "'end'": (19, 3, 'do_st'), "'function'": (19, 3, 'do_st'), "'else'": (19, 3, 'do_st'), '__end_of_input__': (19, 3, 'do_st'), "';'": (19, 3, 'do_st'), "'local'": (19, 3, 'do_st'), "'for'": (19, 3, 'do_st'), "'('": (19, 3, 'do_st'), "'repeat'": (19, 3, 'do_st'), "'do'": (19, 3, 'do_st'), "'break'": (19, 3, 'do_st'), "'elseif'": (19, 3, 'do_st'), "'if'": (19, 3, 'do_st'), "'while'": (19, 3, 'do_st'), "'until'": (19, 3, 'do_st')}, {}, ['do_st']), ({"'=='": (86, 4, 'subscript_exp'), "';'": (86, 4, 'subscript_exp'), "'<='": (86, 4, 'subscript_exp'), "'%'": (86, 4, 'subscript_exp'), "'end'": (86, 4, 'subscript_exp'), "']'": (86, 4, 'subscript_exp'), 'T.long_string': (86, 4, 'subscript_exp'), "'return'": (86, 4, 'subscript_exp'), "'function'": (86, 4, 'subscript_exp'), "'^'": (86, 4, 'subscript_exp'), "'elseif'": (86, 4, 'subscript_exp'), 'T.short_string': (86, 4, 'subscript_exp'), "','": (86, 4, 'subscript_exp'), "'('": (86, 4, 'subscript_exp'), "'while'": (86, 4, 'subscript_exp'), "'>='": (86, 4, 'subscript_exp'), "'break'": (86, 4, 'subscript_exp'), "'*'": (86, 4, 'subscript_exp'), "'>'": (86, 4, 'subscript_exp'), '__end_of_input__': (86, 4, 'subscript_exp'), "':'": (86, 4, 'subscript_exp'), "'do'": (86, 4, 'subscript_exp'), "'{'": (86, 4, 'subscript_exp'), "'else'": (86, 4, 'subscript_exp'), "'and'": (86, 4, 'subscript_exp'), "'repeat'": (86, 4, 'subscript_exp'), "'or'": (86, 4, 'subscript_exp'), "'..'": (86, 4, 'subscript_exp'), "'until'": (86, 4, 'subscript_exp'), 'T.name': (86, 4, 'subscript_exp'), "'then'": (86, 4, 'subscript_exp'), "'/'": (86, 4, 'subscript_exp'), "'-'": (86, 4, 'subscript_exp'), "'['": (86, 4, 'subscript_exp'), "')'": (86, 4, 'subscript_exp'), "'for'": (86, 4, 'subscript_exp'), "'if'": (86, 4, 'subscript_exp'), "'~='": (86, 4, 'subscript_exp'), "'local'": (86, 4, 'subscript_exp'), "'}'": (86, 4, 'subscript_exp'), "'+'": (86, 4, 'subscript_exp'), "'<'": (86, 4, 'subscript_exp')}, {}, ['subscript_exp']), ({'T.name': 242}, {}, ['variable_ref']), ({"'^'": 123, "'>'": 132, "'=='": 134, "'/'": 126, "'>='": 133, "'-'": 124, "')'": 243, "'<='": 131, "'%'": 127, "'~='": 135, "'and'": 136, "'..'": 128, "'or'": 137, "'*'": 125, "'+'": 129, "'<'": 130}, {}, ['adjusted_exp', 'exp']), ({'T.name': 57, "'true'": 103, "'#'": 99, "'false'": 102, 'T.var_args': 84, "'-'": 98, "'{'": 81, "'not'": 100, "'('": 60, "'nil'": 101, 'T.hex_number': 105, "'function'": 55, 'T.decimal_number': 104, 'T.long_string': 83, 'T.short_string': 82}, {40: 54, 45: 244, 59: 58, 62: 59, 66: 61, 69: 62, 70: 63, 71: 64, 72: 65, 73: 66, 75: 67, 76: 68, 77: 69, 78: 70, 79: 71, 80: 72, 81: 73, 82: 74, 83: 75, 84: 76, 86: 77, 87: 78, 88: 79, 89: 80, 97: 85, 98: 86, 99: 87, 100: 88, 101: 89, 102: 90, 103: 91, 104: 92, 105: 93, 108: 94, 110: 95, 111: 96, 112: 97}, ['subscript_exp']), ({'T.name': 267}, {}, ['function_name']), ({'T.name': 57, "'true'": 103, "'#'": 99, "'false'": 102, 'T.var_args': 84, "'-'": 98, "'{'": 81, "'not'": 100, "'('": 60, "'nil'": 101, 'T.hex_number': 105, "'function'": 55, 'T.decimal_number': 104, 'T.long_string': 83, 'T.short_string': 82}, {40: 54, 45: 268, 59: 58, 62: 59, 66: 61, 69: 62, 70: 63, 71: 64, 72: 65, 73: 66, 75: 67, 76: 68, 77: 69, 78: 70, 79: 71, 80: 72, 81: 73, 82: 74, 83: 75, 84: 76, 86: 77, 87: 78, 88: 79, 89: 80, 97: 85, 98: 86, 99: 87, 100: 88, 101: 89, 102: 90, 103: 91, 104: 92, 105: 93, 108: 94, 110: 95, 111: 96, 112: 97}, ['field']), ({"'^'": 123, "'=='": 134, "'/'": 126, "'>='": 133, "'-'": 124, "'<='": 131, "'%'": 127, "'~='": 135, "'and'": 136, "'+'": 129, "'>'": 132, "'or'": 137, "'*'": 125, "']'": 269, "'..'": 128, "'<'": 130}, {}, ['exp', 'field']), ({"'end'": (11, 0, 'end_scope'), "'until'": (11, 0, 'end_scope')}, {11: 240}, ['loop_scope']), ({"'end'": 250}, {}, ['while_st']), ({"'end'": (53, 3, 'loop_scope'), "'until'": (53, 3, 'loop_scope')}, {}, ['loop_scope']), ({"'=='": 134, "';'": (27, 4, 'repeat_st'), "'<='": 131, "'%'": 127, "'end'": (27, 4, 'repeat_st'), "'return'": (27, 4, 'repeat_st'), "'function'": (27, 4, 'repeat_st'), "'^'": 123, "'elseif'": (27, 4, 'repeat_st'), "'('": (27, 4, 'repeat_st'), "'while'": (27, 4, 'repeat_st'), "'>='": 133, "'break'": (27, 4, 'repeat_st'), "'*'": 125, "'>'": 132, '__end_of_input__': (27, 4, 'repeat_st'), "'do'": (27, 4, 'repeat_st'), "'else'": (27, 4, 'repeat_st'), "'and'": 136, "'repeat'": (27, 4, 'repeat_st'), "'or'": 137, "'..'": 128, "'until'": (27, 4, 'repeat_st'), 'T.name': (27, 4, 'repeat_st'), "'/'": 126, "'-'": 124, "'for'": (27, 4, 'repeat_st'), "'if'": (27, 4, 'repeat_st'), "'~='": 135, "'local'": (27, 4, 'repeat_st'), "'+'": 129, "'<'": 130}, {}, ['exp', 'repeat_st']), ({"'=='": (73, 3), "';'": (73, 3), "'<='": (73, 3), "'%'": (73, 3), "'end'": (73, 3), 'T.long_string': (73, 3), "'return'": (73, 3), "'function'": (73, 3), "'^'": (73, 3), "'elseif'": (73, 3), 'T.short_string': (73, 3), "','": (73, 3), "'('": (73, 3), "'.'": (73, 3), "'do'": (73, 3), "'break'": (73, 3), "'*'": (73, 3), "'while'": (73, 3), "'>'": (73, 3), '__end_of_input__': (73, 3), "':'": (73, 3), "'>='": (73, 3), "'{'": (73, 3), "'else'": (73, 3), "'and'": (73, 3), "'repeat'": (73, 3), "'or'": (73, 3), "'..'": (73, 3), "'until'": (73, 3), 'T.name': (73, 3), "'/'": (73, 3), "'-'": (73, 3), "'['": (73, 3), "'for'": (73, 3), "'if'": (73, 3), "'~='": (73, 3), "'local'": (73, 3), "'+'": (73, 3), "'<'": (73, 3)}, {}, ['variable_ref']), ({"'=='": (108, 3, 'adjusted_exp'), "';'": (108, 3, 'adjusted_exp'), "'<='": (108, 3, 'adjusted_exp'), "'%'": (108, 3, 'adjusted_exp'), "'end'": (108, 3, 'adjusted_exp'), 'T.long_string': (108, 3, 'adjusted_exp'), "'return'": (108, 3, 'adjusted_exp'), "'function'": (108, 3, 'adjusted_exp'), "'^'": (108, 3, 'adjusted_exp'), "'elseif'": (108, 3, 'adjusted_exp'), 'T.short_string': (108, 3, 'adjusted_exp'), "','": (108, 3, 'adjusted_exp'), "'('": (108, 3, 'adjusted_exp'), "'while'": (108, 3, 'adjusted_exp'), "'>='": (108, 3, 'adjusted_exp'), "'break'": (108, 3, 'adjusted_exp'), "'*'": (108, 3, 'adjusted_exp'), "'>'": (108, 3, 'adjusted_exp'), '__end_of_input__': (108, 3, 'adjusted_exp'), "':'": (108, 3, 'adjusted_exp'), "'do'": (108, 3, 'adjusted_exp'), "'{'": (108, 3, 'adjusted_exp'), "'else'": (108, 3, 'adjusted_exp'), "'and'": (108, 3, 'adjusted_exp'), "'repeat'": (108, 3, 'adjusted_exp'), "'or'": (108, 3, 'adjusted_exp'), "'..'": (108, 3, 'adjusted_exp'), "'until'": (108, 3, 'adjusted_exp'), 'T.name': (108, 3, 'adjusted_exp'), "'/'": (108, 3, 'adjusted_exp'), "'-'": (108, 3, 'adjusted_exp'), "'['": (108, 3, 'adjusted_exp'), "'for'": (108, 3, 'adjusted_exp'), "'if'": (108, 3, 'adjusted_exp'), "'~='": (108, 3, 'adjusted_exp'), "'local'": (108, 3, 'adjusted_exp'), "'+'": (108, 3, 'adjusted_exp'), "'<'": (108, 3, 'adjusted_exp')}, {}, ['adjusted_exp']), ({"'>='": 133, "'^'": 123, "'=='": 134, "'/'": 126, "'or'": 137, "'-'": 124, "'<='": 131, "'%'": 127, "'and'": 136, "'+'": 129, "'>'": 132, "'~='": 135, "'*'": 125, "']'": 251, "'..'": 128, "'<'": 130}, {}, ['exp', 'subscript_exp']), ({"'end'": (11, 0, 'end_scope')}, {11: 252}, ['function_body']), ({"'return'": (85, 3), 'T.name': (85, 3), "'end'": (85, 3), "'function'": (85, 3), "'else'": (85, 3), '__end_of_input__': (85, 3), "'='": (85, 3), "'local'": (85, 3), "'in'": (85, 3), "';'": (85, 3), "'elseif'": (85, 3), "'for'": (85, 3), "'('": (85, 3), "'repeat'": (85, 3), "'do'": (85, 3), "'break'": (85, 3), "'if'": (85, 3), "'while'": (85, 3), "'until'": (85, 3)}, {}, ['name_list']), ({"'return'": (25, 4, 'local_assign_st'), 'T.name': (25, 4, 'local_assign_st'), "'end'": (25, 4, 'local_assign_st'), "'function'": (25, 4, 'local_assign_st'), "'else'": (25, 4, 'local_assign_st'), '__end_of_input__': (25, 4, 'local_assign_st'), "';'": (25, 4, 'local_assign_st'), "'local'": (25, 4, 'local_assign_st'), "'for'": (25, 4, 'local_assign_st'), "'('": (25, 4, 'local_assign_st'), "'repeat'": (25, 4, 'local_assign_st'), "'do'": (25, 4, 'local_assign_st'), "'break'": (25, 4, 'local_assign_st'), "'elseif'": (25, 4, 'local_assign_st'), "'if'": (25, 4, 'local_assign_st'), "'while'": (25, 4, 'local_assign_st'), "'until'": (25, 4, 'local_assign_st')}, {}, ['local_assign_st']), ({"'return'": (26, 4, 'local_function_decl_st'), 'T.name': (26, 4, 'local_function_decl_st'), "'end'": (26, 4, 'local_function_decl_st'), "'function'": (26, 4, 'local_function_decl_st'), "'else'": (26, 4, 'local_function_decl_st'), '__end_of_input__': (26, 4, 'local_function_decl_st'), "';'": (26, 4, 'local_function_decl_st'), "'local'": (26, 4, 'local_function_decl_st'), "'for'": (26, 4, 'local_function_decl_st'), "'('": (26, 4, 'local_function_decl_st'), "'repeat'": (26, 4, 'local_function_decl_st'), "'do'": (26, 4, 'local_function_decl_st'), "'break'": (26, 4, 'local_function_decl_st'), "'elseif'": (26, 4, 'local_function_decl_st'), "'if'": (26, 4, 'local_function_decl_st'), "'while'": (26, 4, 'local_function_decl_st'), "'until'": (26, 4, 'local_function_decl_st')}, {}, ['local_function_decl_st']), ({"'end'": 253, "'elseif'": 256, "'else'": 254}, {48: 255}, ['if_st']), ({"'return'": (28, 5, 'while_st'), 'T.name': (28, 5, 'while_st'), "'end'": (28, 5, 'while_st'), "'function'": (28, 5, 'while_st'), "'else'": (28, 5, 'while_st'), '__end_of_input__': (28, 5, 'while_st'), "'local'": (28, 5, 'while_st'), "';'": (28, 5, 'while_st'), "'elseif'": (28, 5, 'while_st'), "'for'": (28, 5, 'while_st'), "'('": (28, 5, 'while_st'), "'repeat'": (28, 5, 'while_st'), "'do'": (28, 5, 'while_st'), "'break'": (28, 5, 'while_st'), "'if'": (28, 5, 'while_st'), "'while'": (28, 5, 'while_st'), "'until'": (28, 5, 'while_st')}, {}, ['while_st']), ({"'=='": (86, 4, 'subscript_exp'), "';'": (86, 4, 'subscript_exp'), "'<='": (86, 4, 'subscript_exp'), "'%'": (86, 4, 'subscript_exp'), "'end'": (86, 4, 'subscript_exp'), 'T.long_string': (86, 4, 'subscript_exp'), "'return'": (86, 4, 'subscript_exp'), "'function'": (86, 4, 'subscript_exp'), "'^'": (86, 4, 'subscript_exp'), "'elseif'": (86, 4, 'subscript_exp'), "','": (86, 4, 'subscript_exp'), "'('": (86, 4, 'subscript_exp'), 'T.short_string': (86, 4, 'subscript_exp'), "'>='": (86, 4, 'subscript_exp'), "'break'": (86, 4, 'subscript_exp'), "'*'": (86, 4, 'subscript_exp'), "'while'": (86, 4, 'subscript_exp'), "'>'": (86, 4, 'subscript_exp'), '__end_of_input__': (86, 4, 'subscript_exp'), "':'": (86, 4, 'subscript_exp'), "'do'": (86, 4, 'subscript_exp'), "'{'": (86, 4, 'subscript_exp'), "'else'": (86, 4, 'subscript_exp'), "'and'": (86, 4, 'subscript_exp'), "'repeat'": (86, 4, 'subscript_exp'), "'or'": (86, 4, 'subscript_exp'), "'..'": (86, 4, 'subscript_exp'), "'until'": (86, 4, 'subscript_exp'), 'T.name': (86, 4, 'subscript_exp'), "'/'": (86, 4, 'subscript_exp'), "'-'": (86, 4, 'subscript_exp'), "'['": (86, 4, 'subscript_exp'), "'for'": (86, 4, 'subscript_exp'), "'if'": (86, 4, 'subscript_exp'), "'~='": (86, 4, 'subscript_exp'), "'local'": (86, 4, 'subscript_exp'), "'+'": (86, 4, 'subscript_exp'), "'<'": (86, 4, 'subscript_exp')}, {}, ['subscript_exp']), ({"'end'": 270}, {}, ['function_body']), ({"'return'": (24, 5, 'if_st'), 'T.name': (24, 5, 'if_st'), "'end'": (24, 5, 'if_st'), "'function'": (24, 5, 'if_st'), "'else'": (24, 5, 'if_st'), '__end_of_input__': (24, 5, 'if_st'), "'local'": (24, 5, 'if_st'), "';'": (24, 5, 'if_st'), "'elseif'": (24, 5, 'if_st'), "'for'": (24, 5, 'if_st'), "'('": (24, 5, 'if_st'), "'repeat'": (24, 5, 'if_st'), "'do'": (24, 5, 'if_st'), "'break'": (24, 5, 'if_st'), "'if'": (24, 5, 'if_st'), "'while'": (24, 5, 'if_st'), "'until'": (24, 5, 'if_st')}, {}, ['if_st']), ({"'return'": (7, 0, 'begin_scope'), 'T.name': (7, 0, 'begin_scope'), "'end'": (7, 0, 'begin_scope'), "'function'": (7, 0, 'begin_scope'), "'local'": (7, 0, 'begin_scope'), "'for'": (7, 0, 'begin_scope'), "'('": (7, 0, 'begin_scope'), "'repeat'": (7, 0, 'begin_scope'), "'do'": (7, 0, 'begin_scope'), "'break'": (7, 0, 'begin_scope'), "'while'": (7, 0, 'begin_scope'), "'if'": (7, 0, 'begin_scope')}, {33: 271, 7: 107}, ['if_st']), ({"'elseif'": 274, "'else'": 273, "'end'": 272}, {}, ['if_st']), ({'T.name': 57, "'true'": 103, "'#'": 99, "'false'": 102, 'T.var_args': 84, "'-'": 98, "'{'": 81, "'not'": 100, "'('": 60, "'nil'": 101, 'T.hex_number': 105, "'function'": 55, 'T.decimal_number': 104, 'T.long_string': 83, 'T.short_string': 82}, {40: 54, 45: 275, 59: 58, 62: 59, 66: 61, 69: 62, 70: 63, 71: 64, 72: 65, 73: 66, 75: 67, 76: 68, 77: 69, 78: 70, 79: 71, 80: 72, 81: 73, 82: 74, 83: 75, 84: 76, 86: 77, 87: 78, 88: 79, 89: 80, 97: 85, 98: 86, 99: 87, 100: 88, 101: 89, 102: 90, 103: 91, 104: 92, 105: 93, 108: 94, 110: 95, 111: 96, 112: 97}, ['if_st']), ({"'return'": 11, 'T.name': 31, "'end'": (5, 0, 'block'), "'function'": 28, "'local'": 30, "'for'": 26, "'('": 37, "'repeat'": 32, "'do'": 25, "'break'": 12, "'while'": 33, "'if'": 29}, {5: 276, 8: 6, 10: 7, 12: 8, 13: 9, 14: 10, 18: 13, 19: 14, 20: 15, 21: 16, 22: 17, 23: 18, 24: 19, 25: 20, 26: 21, 27: 22, 28: 23, 30: 24, 40: 27, 57: 34, 59: 35, 62: 36, 69: 38, 70: 39, 73: 40, 86: 41, 87: 42, 88: 43, 89: 44, 108: 45}, ['for_step_st']), ({'T.name': 57, "'true'": 103, "'#'": 99, "'false'": 102, 'T.var_args': 84, "'-'": 98, "'{'": 81, "'not'": 100, "'('": 60, "'nil'": 101, 'T.hex_number': 105, "'function'": 55, 'T.decimal_number': 104, 'T.long_string': 83, 'T.short_string': 82}, {16: 277, 29: 53, 40: 54, 45: 56, 59: 58, 62: 59, 66: 61, 69: 62, 70: 63, 71: 64, 72: 65, 73: 66, 75: 67, 76: 68, 77: 69, 78: 70, 79: 71, 80: 72, 81: 73, 82: 74, 83: 75, 84: 76, 86: 77, 87: 78, 88: 79, 89: 80, 97: 85, 98: 86, 99: 87, 100: 88, 101: 89, 102: 90, 103: 91, 104: 92, 105: 93, 108: 94, 110: 95, 111: 96, 112: 97}, ['for_in_st']), ({"'end'": (33, 3, 'scope'), "'elseif'": (33, 3, 'scope'), "'else'": (33, 3, 'scope')}, {}, ['scope']), ({"':'": (87, 1), "'{'": (87, 1), "'('": (87, 1), "'['": (87, 1), 'T.long_string': (87, 1), 'T.short_string': (87, 1)}, {}, ['prefix_exp']), ({"':'": (89, 1), "'{'": (89, 1), "','": (57, 3), "'('": (89, 1), "'['": (89, 1), "'='": (57, 3), 'T.long_string': (89, 1), 'T.short_string': (89, 1)}, {}, ['prefix_exp', 'var_list']), ({"'>='": 133, "'^'": 123, "'=='": 134, "'/'": 126, "'or'": 137, "'-'": 124, "'<='": 131, "'%'": 127, "'and'": 136, "'+'": 129, "'>'": 132, "'~='": 135, "'*'": 125, "']'": 278, "'..'": 128, "'<'": 130}, {}, ['exp', 'subscript_exp']), ({"':'": (108, 3, 'adjusted_exp'), "'{'": (108, 3, 'adjusted_exp'), "'('": (108, 3, 'adjusted_exp'), "'['": (108, 3, 'adjusted_exp'), 'T.long_string': (108, 3, 'adjusted_exp'), 'T.short_string': (108, 3, 'adjusted_exp')}, {}, ['adjusted_exp']), ({"'{'": (73, 3), "':'": (73, 3), "'['": (73, 3), "','": (73, 3), "'('": (73, 3), "'.'": (73, 3), "'='": (73, 3), 'T.long_string': (73, 3), 'T.short_string': (73, 3)}, {}, ['variable_ref']), ({'T.var_args': 215, 'T.name': 212}, {74: 279}, ['_parameter_list']), ({'T.name': 57, "'true'": 103, "'#'": 99, "'false'": 102, 'T.var_args': 84, "'-'": 98, "'{'": 81, "'not'": 100, "'('": 60, "'nil'": 101, 'T.hex_number': 105, "'function'": 55, 'T.decimal_number': 104, 'T.long_string': 83, 'T.short_string': 82}, {40: 54, 45: 280, 59: 58, 62: 59, 66: 61, 69: 62, 70: 63, 71: 64, 72: 65, 73: 66, 75: 67, 76: 68, 77: 69, 78: 70, 79: 71, 80: 72, 81: 73, 82: 74, 83: 75, 84: 76, 86: 77, 87: 78, 88: 79, 89: 80, 97: 85, 98: 86, 99: 87, 100: 88, 101: 89, 102: 90, 103: 91, 104: 92, 105: 93, 108: 94, 110: 95, 111: 96, 112: 97}, ['for_steps']), ({"'('": (42, 3, 'function_name')}, {}, ['function_name']), ({"'^'": 123, "'>'": 132, "'>='": 133, "'=='": 134, "'/'": 126, "'~='": 135, "'-'": 124, "';'": (109, 3, 'field'), "','": (109, 3, 'field'), "'<='": 131, "'%'": 127, "'..'": 128, "'or'": 137, "'and'": 136, "'}'": (109, 3, 'field'), "'*'": 125, "'+'": 129, "'<'": 130}, {}, ['exp', 'field']), ({"'='": 281}, {}, ['field']), ({"'=='": (43, 7, 'function_body'), "';'": (43, 7, 'function_body'), "'<='": (43, 7, 'function_body'), "'%'": (43, 7, 'function_body'), "'end'": (43, 7, 'function_body'), "']'": (43, 7, 'function_body'), "'return'": (43, 7, 'function_body'), "'function'": (43, 7, 'function_body'), "'^'": (43, 7, 'function_body'), "'elseif'": (43, 7, 'function_body'), "','": (43, 7, 'function_body'), "'('": (43, 7, 'function_body'), "'while'": (43, 7, 'function_body'), "'>='": (43, 7, 'function_body'), "'break'": (43, 7, 'function_body'), "'*'": (43, 7, 'function_body'), "'>'": (43, 7, 'function_body'), '__end_of_input__': (43, 7, 'function_body'), "'do'": (43, 7, 'function_body'), "'else'": (43, 7, 'function_body'), "'and'": (43, 7, 'function_body'), "'repeat'": (43, 7, 'function_body'), "'or'": (43, 7, 'function_body'), "'..'": (43, 7, 'function_body'), "'until'": (43, 7, 'function_body'), 'T.name': (43, 7, 'function_body'), "'then'": (43, 7, 'function_body'), "'/'": (43, 7, 'function_body'), "'-'": (43, 7, 'function_body'), "')'": (43, 7, 'function_body'), "'for'": (43, 7, 'function_body'), "'if'": (43, 7, 'function_body'), "'~='": (43, 7, 'function_body'), "'local'": (43, 7, 'function_body'), "'}'": (43, 7, 'function_body'), "'+'": (43, 7, 'function_body'), "'<'": (43, 7, 'function_body')}, {}, ['function_body']), ({"'end'": 282}, {}, ['if_st']), ({"'return'": (24, 6, 'if_st'), 'T.name': (24, 6, 'if_st'), "'end'": (24, 6, 'if_st'), "'function'": (24, 6, 'if_st'), "'else'": (24, 6, 'if_st'), '__end_of_input__': (24, 6, 'if_st'), "'local'": (24, 6, 'if_st'), "';'": (24, 6, 'if_st'), "'elseif'": (24, 6, 'if_st'), "'for'": (24, 6, 'if_st'), "'('": (24, 6, 'if_st'), "'repeat'": (24, 6, 'if_st'), "'do'": (24, 6, 'if_st'), "'break'": (24, 6, 'if_st'), "'if'": (24, 6, 'if_st'), "'while'": (24, 6, 'if_st'), "'until'": (24, 6, 'if_st')}, {}, ['if_st']), ({"'return'": (7, 0, 'begin_scope'), 'T.name': (7, 0, 'begin_scope'), "'end'": (7, 0, 'begin_scope'), "'function'": (7, 0, 'begin_scope'), "'local'": (7, 0, 'begin_scope'), "'for'": (7, 0, 'begin_scope'), "'('": (7, 0, 'begin_scope'), "'repeat'": (7, 0, 'begin_scope'), "'do'": (7, 0, 'begin_scope'), "'break'": (7, 0, 'begin_scope'), "'while'": (7, 0, 'begin_scope'), "'if'": (7, 0, 'begin_scope')}, {33: 283, 7: 107}, ['if_st']), ({'T.name': 57, "'true'": 103, "'#'": 99, "'false'": 102, 'T.var_args': 84, "'-'": 98, "'{'": 81, "'not'": 100, "'('": 60, "'nil'": 101, 'T.hex_number': 105, "'function'": 55, 'T.decimal_number': 104, 'T.long_string': 83, 'T.short_string': 82}, {40: 54, 45: 284, 59: 58, 62: 59, 66: 61, 69: 62, 70: 63, 71: 64, 72: 65, 73: 66, 75: 67, 76: 68, 77: 69, 78: 70, 79: 71, 80: 72, 81: 73, 82: 74, 83: 75, 84: 76, 86: 77, 87: 78, 88: 79, 89: 80, 97: 85, 98: 86, 99: 87, 100: 88, 101: 89, 102: 90, 103: 91, 104: 92, 105: 93, 108: 94, 110: 95, 111: 96, 112: 97}, ['if_st']), ({"'>='": 133, "'^'": 123, "'then'": 285, "'=='": 134, "'/'": 126, "'or'": 137, "'-'": 124, "'<='": 131, "'%'": 127, "'and'": 136, "'+'": 129, "'~='": 135, "'*'": 125, "'<'": 130, "'..'": 128, "'>'": 132}, {}, ['exp', 'if_st']), ({"'end'": (11, 0, 'end_scope')}, {11: 286}, ['for_step_st']), ({"'do'": 287}, {}, ['for_in_st']), ({"':'": (86, 4, 'subscript_exp'), "'{'": (86, 4, 'subscript_exp'), "','": (86, 4, 'subscript_exp'), "'('": (86, 4, 'subscript_exp'), "'['": (86, 4, 'subscript_exp'), "'='": (86, 4, 'subscript_exp'), 'T.long_string': (86, 4, 'subscript_exp'), 'T.short_string': (86, 4, 'subscript_exp')}, {}, ['subscript_exp']), ({"')'": (74, 3)}, {}, ['_parameter_list']), ({"'^'": 123, "'=='": 134, "'/'": 126, "'>='": 133, "'-'": 124, "','": 288, "'<='": 131, "'%'": 127, "'~='": 135, "'and'": 136, "'+'": 129, "'>'": 132, "'or'": 137, "'*'": 125, "'..'": 128, "'<'": 130}, {}, ['exp', 'for_steps']), ({'T.name': 57, "'true'": 103, "'#'": 99, "'false'": 102, 'T.var_args': 84, "'-'": 98, "'{'": 81, "'not'": 100, "'('": 60, "'nil'": 101, 'T.hex_number': 105, "'function'": 55, 'T.decimal_number': 104, 'T.long_string': 83, 'T.short_string': 82}, {40: 54, 45: 289, 59: 58, 62: 59, 66: 61, 69: 62, 70: 63, 71: 64, 72: 65, 73: 66, 75: 67, 76: 68, 77: 69, 78: 70, 79: 71, 80: 72, 81: 73, 82: 74, 83: 75, 84: 76, 86: 77, 87: 78, 88: 79, 89: 80, 97: 85, 98: 86, 99: 87, 100: 88, 101: 89, 102: 90, 103: 91, 104: 92, 105: 93, 108: 94, 110: 95, 111: 96, 112: 97}, ['field']), ({"'return'": (24, 7, 'if_st'), 'T.name': (24, 7, 'if_st'), "'end'": (24, 7, 'if_st'), "'function'": (24, 7, 'if_st'), "'else'": (24, 7, 'if_st'), '__end_of_input__': (24, 7, 'if_st'), "'local'": (24, 7, 'if_st'), "';'": (24, 7, 'if_st'), "'elseif'": (24, 7, 'if_st'), "'for'": (24, 7, 'if_st'), "'('": (24, 7, 'if_st'), "'repeat'": (24, 7, 'if_st'), "'do'": (24, 7, 'if_st'), "'break'": (24, 7, 'if_st'), "'if'": (24, 7, 'if_st'), "'while'": (24, 7, 'if_st'), "'until'": (24, 7, 'if_st')}, {}, ['if_st']), ({"'end'": 290}, {}, ['if_st']), ({"'^'": 123, "'then'": 291, "'=='": 134, "'/'": 126, "'>='": 133, "'-'": 124, "'<='": 131, "'%'": 127, "'~='": 135, "'and'": 136, "'+'": 129, "'>'": 132, "'or'": 137, "'*'": 125, "'..'": 128, "'<'": 130}, {}, ['exp', 'if_st']), ({"'return'": (7, 0, 'begin_scope'), 'T.name': (7, 0, 'begin_scope'), "'end'": (7, 0, 'begin_scope'), "'function'": (7, 0, 'begin_scope'), "'else'": (7, 0, 'begin_scope'), "'elseif'": (7, 0, 'begin_scope'), "'local'": (7, 0, 'begin_scope'), "'for'": (7, 0, 'begin_scope'), "'('": (7, 0, 'begin_scope'), "'repeat'": (7, 0, 'begin_scope'), "'do'": (7, 0, 'begin_scope'), "'break'": (7, 0, 'begin_scope'), "'while'": (7, 0, 'begin_scope'), "'if'": (7, 0, 'begin_scope')}, {33: 292, 7: 107}, ['if_st']), ({"'end'": 293}, {}, ['for_step_st']), ({"'return'": 11, 'T.name': 31, "'end'": (5, 0, 'block'), "'function'": 28, "'local'": 30, "'for'": 26, "'('": 37, "'repeat'": 32, "'do'": 25, "'break'": 12, "'while'": 33, "'if'": 29}, {5: 294, 8: 6, 10: 7, 12: 8, 13: 9, 14: 10, 18: 13, 19: 14, 20: 15, 21: 16, 22: 17, 23: 18, 24: 19, 25: 20, 26: 21, 27: 22, 28: 23, 30: 24, 40: 27, 57: 34, 59: 35, 62: 36, 69: 38, 70: 39, 73: 40, 86: 41, 87: 42, 88: 43, 89: 44, 108: 45}, ['for_in_st']), ({'T.name': 57, "'true'": 103, "'#'": 99, "'false'": 102, 'T.var_args': 84, "'-'": 98, "'{'": 81, "'not'": 100, "'('": 60, "'nil'": 101, 'T.hex_number': 105, "'function'": 55, 'T.decimal_number': 104, 'T.long_string': 83, 'T.short_string': 82}, {40: 54, 45: 295, 59: 58, 62: 59, 66: 61, 69: 62, 70: 63, 71: 64, 72: 65, 73: 66, 75: 67, 76: 68, 77: 69, 78: 70, 79: 71, 80: 72, 81: 73, 82: 74, 83: 75, 84: 76, 86: 77, 87: 78, 88: 79, 89: 80, 97: 85, 98: 86, 99: 87, 100: 88, 101: 89, 102: 90, 103: 91, 104: 92, 105: 93, 108: 94, 110: 95, 111: 96, 112: 97}, ['for_steps']), ({"'^'": 123, "'>'": 132, "'=='": 134, "'/'": 126, "'or'": 137, "'-'": 124, "';'": (109, 5, 'field'), "','": (109, 5, 'field'), "'<='": 131, "'~='": 135, "'and'": 136, "'..'": 128, "'>='": 133, "'%'": 127, "'}'": (109, 5, 'field'), "'*'": 125, "'+'": 129, "'<'": 130}, {}, ['exp', 'field']), ({"'return'": (24, 8, 'if_st'), 'T.name': (24, 8, 'if_st'), "'end'": (24, 8, 'if_st'), "'function'": (24, 8, 'if_st'), "'else'": (24, 8, 'if_st'), '__end_of_input__': (24, 8, 'if_st'), "'local'": (24, 8, 'if_st'), "';'": (24, 8, 'if_st'), "'elseif'": (24, 8, 'if_st'), "'for'": (24, 8, 'if_st'), "'('": (24, 8, 'if_st'), "'repeat'": (24, 8, 'if_st'), "'do'": (24, 8, 'if_st'), "'break'": (24, 8, 'if_st'), "'if'": (24, 8, 'if_st'), "'while'": (24, 8, 'if_st'), "'until'": (24, 8, 'if_st')}, {}, ['if_st']), ({"'return'": (7, 0, 'begin_scope'), 'T.name': (7, 0, 'begin_scope'), "'end'": (7, 0, 'begin_scope'), "'function'": (7, 0, 'begin_scope'), "'else'": (7, 0, 'begin_scope'), "'elseif'": (7, 0, 'begin_scope'), "'local'": (7, 0, 'begin_scope'), "'for'": (7, 0, 'begin_scope'), "'('": (7, 0, 'begin_scope'), "'repeat'": (7, 0, 'begin_scope'), "'do'": (7, 0, 'begin_scope'), "'break'": (7, 0, 'begin_scope'), "'while'": (7, 0, 'begin_scope'), "'if'": (7, 0, 'begin_scope')}, {33: 296, 7: 107}, ['if_st']), ({"'end'": (48, 4), "'else'": (48, 4), "'elseif'": (48, 4)}, {}, ['if_st']), ({"'return'": (21, 7, 'for_step_st'), 'T.name': (21, 7, 'for_step_st'), "'end'": (21, 7, 'for_step_st'), "'function'": (21, 7, 'for_step_st'), "'else'": (21, 7, 'for_step_st'), '__end_of_input__': (21, 7, 'for_step_st'), "'local'": (21, 7, 'for_step_st'), "';'": (21, 7, 'for_step_st'), "'elseif'": (21, 7, 'for_step_st'), "'for'": (21, 7, 'for_step_st'), "'('": (21, 7, 'for_step_st'), "'repeat'": (21, 7, 'for_step_st'), "'do'": (21, 7, 'for_step_st'), "'break'": (21, 7, 'for_step_st'), "'if'": (21, 7, 'for_step_st'), "'while'": (21, 7, 'for_step_st'), "'until'": (21, 7, 'for_step_st')}, {}, ['for_step_st']), ({"'end'": (11, 0, 'end_scope')}, {11: 297}, ['for_in_st']), ({"'^'": 123, "'>'": 132, "'>='": 133, "'=='": 134, "'/'": 126, "'or'": 137, "'-'": 124, "','": 298, "'<='": 131, "'%'": 127, "'and'": 136, "'..'": 128, "'~='": 135, "'*'": 125, "'do'": (39, 5, 'for_steps'), "'+'": 129, "'<'": 130}, {}, ['exp', 'for_steps']), ({"'end'": (48, 5), "'elseif'": (48, 5), "'else'": (48, 5)}, {}, ['if_st']), ({"'end'": 299}, {}, ['for_in_st']), ({'T.name': 57, "'true'": 103, "'#'": 99, "'false'": 102, 'T.var_args': 84, "'-'": 98, "'{'": 81, "'not'": 100, "'('": 60, "'nil'": 101, 'T.hex_number': 105, "'function'": 55, 'T.decimal_number': 104, 'T.long_string': 83, 'T.short_string': 82}, {40: 54, 45: 300, 59: 58, 62: 59, 66: 61, 69: 62, 70: 63, 71: 64, 72: 65, 73: 66, 75: 67, 76: 68, 77: 69, 78: 70, 79: 71, 80: 72, 81: 73, 82: 74, 83: 75, 84: 76, 86: 77, 87: 78, 88: 79, 89: 80, 97: 85, 98: 86, 99: 87, 100: 88, 101: 89, 102: 90, 103: 91, 104: 92, 105: 93, 108: 94, 110: 95, 111: 96, 112: 97}, ['for_steps']), ({"'return'": (20, 9, 'for_in_st'), 'T.name': (20, 9, 'for_in_st'), "'end'": (20, 9, 'for_in_st'), "'function'": (20, 9, 'for_in_st'), "'else'": (20, 9, 'for_in_st'), '__end_of_input__': (20, 9, 'for_in_st'), "'local'": (20, 9, 'for_in_st'), "';'": (20, 9, 'for_in_st'), "'elseif'": (20, 9, 'for_in_st'), "'for'": (20, 9, 'for_in_st'), "'('": (20, 9, 'for_in_st'), "'repeat'": (20, 9, 'for_in_st'), "'do'": (20, 9, 'for_in_st'), "'break'": (20, 9, 'for_in_st'), "'if'": (20, 9, 'for_in_st'), "'while'": (20, 9, 'for_in_st'), "'until'": (20, 9, 'for_in_st')}, {}, ['for_in_st']), ({"'>='": 133, "'^'": 123, "'=='": 134, "'/'": 126, "'or'": 137, "'-'": 124, "'<='": 131, "'%'": 127, "'and'": 136, "'+'": 129, "'>'": 132, "'~='": 135, "'*'": 125, "'do'": (39, 7, 'for_steps'), "'..'": 128, "'<'": 130}, {}, ['exp', 'for_steps']))


if __name__ == "__main__":
    main(sys.argv)

# vim: set shiftwidth=4 expandtab softtabstop=8 :
