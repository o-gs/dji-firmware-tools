#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" Wireshark Dissectors parser with Markdown text output.

Parses LUA files with Wireshark Dissectors of DUML protocol.
Uses the information to create Markdown style documentation of each packet.
"""

# Copyright (C) 2016,2017 Mefistotelis <mefistotelis@gmail.com>
# Copyright (C) 2018 Original Gangsters <https://dji-rev.slack.com/>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import print_function
__version__ = "0.0.1"
__author__ = "Mefistotelis @ Original Gangsters"
__license__ = "GPL"

import sys
import re
import os
import enum
import numbers
import hashlib
import binascii
import argparse
import configparser
import itertools
from ctypes import *
from time import gmtime, strftime, strptime
from calendar import timegm
from Crypto.Cipher import AES

import lrparsing
import lua52

class ValueSim(enum.Enum): 
    # Simple, basic types
    Nop = 1
    Unknown = 2
    Number = 3 # Just a specific numeric value; 1 param: the value
    Logic = 4 # A specific logic value; 1 param: true or false
    VariableRef = 5 # A reference to a variable; 1 param: name of the variable
    String = 6 # A text string; 1 param: the character string
    MathExpr = 7 # Math expression; each param is either operation/sign or name/value (if str then treated as variable ref or operator/sign, if number then as number); ends with ValueConv.No
    # Complex types - after second analysis
    ArraySlice = 10 # Part sliced from any array; 3 params: array,start,size
    ArraySliceConv = 11 # Part sliced from any array, then converted using a standard function; 4 params: array,start,size,conv_func_name
    ArrayPktWhole = 12 # Slice from whole input packet; 3 params: start,size,conv_func
    ArrayPktPayload = 13 # Slice from payload part of the input packet; 3 params: start,size,conv_func
    LenPktWhole = 15 # Length of the whole input packet, no params
    LenPktPayload = 16 # Length of the payload part of input packet, no params
    ObjTreeItem = 20 # Wireshark TreeItem object, no params (TODO maybe place items inside?)
    ObjPInfo = 21 # Wireshark PInfo object, no params
    Format = 30 # string.format()
    RShift = 41
    Floor = 43
    BAnd = 45

class ValueConv(enum.Enum):
    No = 1 # No conversion func
    Len = 2
    Int = 3
    UInt = 4
    LE_Int = 5
    LE_UInt = 6

ValueSimCompoundList = [ValueSim.ArrayPktWhole, ValueSim.ArrayPktPayload, ValueSim.ArraySlice]
ValueSimCompoundExpr = [ValueSim.MathExpr]
ValueSimLogicOperator = ['==', '~=', 'and', 'or']
ValueSimLogicTrueFalse = ['true', 'false']

def eprint(*args, **kwargs):
  print(*args, file=sys.stderr, **kwargs)

def lua_get_assign_st_full_name(assign_st, lua_fname):
    leaf_expr = assign_st
    lua_line = lua_get_file_line(leaf_expr)
    for expr1 in leaf_expr:
        if (not isinstance(expr1, tuple)) or (expr1[0].name != 'var_list'):
            continue
        leaf_expr = expr1
        break
    for expr2 in leaf_expr:
        if (not isinstance(expr2, tuple)) or (expr2[0].name != 'var'):
            continue
        leaf_expr = expr2
        break
    for expr3 in leaf_expr:
        if (not isinstance(expr3, tuple)):
            continue
        if (expr3[0].name != 'variable_ref') and (expr3[0].name != 'name_list'):
            continue
        leaf_expr = expr3
        break
    leaf_name = ''
    for expr4 in leaf_expr:
        if (not isinstance(expr4, tuple)):
            continue
        if (expr4[0].name != 'T.name') and (expr4[0].name != "'.'"):
            continue
        leaf_name += str(expr4[1])
    if (len(leaf_name) < 1):
        eprint("{:s}:{:d}: Warning: Could not get full name in assign statement".format(lua_fname,lua_line))
        for expr1 in assign_st: #!!!!!!!!!!!!!!!!
            print(expr1)
    return leaf_name

def lua_exp_to_integer(expr, lua_fname, ignore_fail=False):
    leaf_expr = expr
    lua_line = lua_get_file_line(leaf_expr)
    for expr1 in leaf_expr:
        if (not isinstance(expr1, tuple)) or (expr1[0].name != 'number'):
            continue
        leaf_expr = expr1
    leaf_val = ''
    for expr1 in leaf_expr:
        if (not isinstance(expr1, tuple)):
            continue
        if (expr1[0].name == 'T.hex_number'):
            leaf_val = expr1[1]
        if (expr1[0].name == 'T.decimal_number'):
            leaf_val = expr1[1]
    if not isinstance(leaf_val, str):
        if not ignore_fail:
            eprint("{:s}:{:d}: Warning: While getting numeric param, expected final leaf to be string".format(lua_fname,lua_line))
        return None
    elif (len(leaf_val) < 1):
        if not ignore_fail:
            eprint("{:s}:{:d}: Warning: While getting numeric param, could not get final leaf string".format(lua_fname,lua_line))
        return None
    return int(leaf_val,0)

def lua_exp_to_truefalse(expr, lua_fname, ignore_fail=False):
    leaf_expr = expr
    lua_line = lua_get_file_line(leaf_expr)
    for expr1 in leaf_expr:
        if (not isinstance(expr1, tuple)) or (expr1[0].name != 'constant'):
            continue
        leaf_expr = expr1
    leaf_val = ''
    for expr1 in leaf_expr:
        if (not isinstance(expr1, tuple)):
            continue
        if (expr1[0].name == 'true'):
            leaf_val = True
        if (expr1[0].name == 'false'):
            leaf_val = False
    if not isinstance(leaf_val, bool):
        if not ignore_fail:
            eprint("{:s}:{:d}: Warning: While getting bool param, expected final leaf to be 'true' or 'false'".format(lua_fname,lua_line))
        return None
    return leaf_val

def lua_exp_variable_ref_to_string(expr, lua_fname, ignore_fail=False):
    leaf_expr = expr
    lua_line = lua_get_file_line(leaf_expr)
    for expr1 in leaf_expr:
        if (not isinstance(expr1, tuple)) or (expr1[0].name != 'prefix_exp'):
            continue
        leaf_expr = expr1
    for expr1 in leaf_expr:
        if (not isinstance(expr1, tuple)) or (expr1[0].name != 'var'):
            continue
        leaf_expr = expr1
    for expr1 in leaf_expr:
        if (not isinstance(expr1, tuple)) or (expr1[0].name != 'variable_ref'):
            continue
        leaf_expr = expr1
    leaf_val = ''
    for expr1 in leaf_expr:
        if (not isinstance(expr1, tuple)):
            continue
        if (expr1[0].name == 'T.name'):
            leaf_val = expr1[1]
    if not isinstance(leaf_val, str):
        if not ignore_fail:
            eprint("{:s}:{:d}: Warning: Could not get to variable ref name".format(lua_fname,lua_line))
        return None
    return leaf_val

def lua_exp_textname_to_string(expr, lua_fname):
    leaf_expr = expr
    lua_line = lua_get_file_line(leaf_expr)
    for expr1 in leaf_expr:
        if (not isinstance(expr1, tuple)) or (expr1[0].name != 'prefix_exp'):
            continue
        leaf_expr = expr1
    for expr1 in leaf_expr:
        if (not isinstance(expr1, tuple)) or (expr1[0].name != 'string'):
            continue
        leaf_expr = expr1
    leaf_val = ''
    for expr1 in leaf_expr:
        if (not isinstance(expr1, tuple)):
            continue
        if (expr1[0].name == 'T.short_string'):
            leaf_val = expr1[1]

    if not isinstance(leaf_val, str):
        eprint("{:s}:{:d}: Warning: Could not get to text name in list assignment".format(lua_fname,lua_line))
    leaf_val = str(leaf_val)
    if (leaf_val.startswith('"') or leaf_val.startswith("'")) and \
       (leaf_val.endswith('"')   or leaf_val.endswith("'")):
        leaf_val = leaf_val[1:-1]
    return leaf_val

def lua_get_file_line(expr):
    if (isinstance(expr[0], lrparsing.Token)):
        return expr[3]
    lua_line = -1
    for expr1 in expr:
        if (not isinstance(expr1, tuple)):
            continue
        lua_line = lua_get_file_line(expr1)
        if lua_line >= 0:
            break
    return lua_line

def lua_adjusted_exp_to_math_expr(expr, body_locals, lua_fname, ignore_fail=False):
    leaf_expr = expr
    lua_line = lua_get_file_line(leaf_expr)
    for expr1 in leaf_expr:
        if (not isinstance(expr1, tuple)) or (expr1[0].name != 'prefix_exp'):
            continue
        leaf_expr = expr1
    for expr1 in leaf_expr:
        if (not isinstance(expr1, tuple)) or (expr1[0].name != 'adjusted_exp'):
            continue
        leaf_expr = expr1
    # There should be one 'exp' inside, wraped with '(' ')'
    for expr1 in leaf_expr:
        if (not isinstance(expr1, tuple)) or (expr1[0].name != 'exp'):
            continue
        return lua_exp_to_math_expr(expr1, body_locals, lua_fname, ignore_fail)
    if not ignore_fail:
        eprint("{:s}:{:d}: Warning: No 'exp' found in given leaf".format(lua_fname,lua_line))
    return None

def lua_exp_to_math_expr(expr, body_locals, lua_fname, ignore_fail=False):
    """ Returns flat math expression list from given tree
    """
    leaf_expr = expr
    lua_line = lua_get_file_line(leaf_expr)
    leaf_val = [ ]
    if (expr[0].name == 'exp'):
        leaf_val += lua_exp_to_math_expr(expr[1], body_locals, lua_fname, ignore_fail)
        for expr1 in expr[2:]:
            if (isinstance(expr1[0], lrparsing.Token)):
                # here we catch '-' but also '/'
                leaf_val.append(expr1[1])
            elif (expr1[0].name == 'exp'):
                leaf_val += lua_exp_to_math_expr(expr1, body_locals, lua_fname, ignore_fail)
            else:
                eprint("{:s}:{:d}: Warning: Member of 'exp' in math expression was not recognized".format(lua_fname,lua_line))
        pass

    elif (expr[0].name == 'prefix_exp'):
        var_found = False
        if not var_found:
            var_out = lua_adjusted_exp_to_math_expr(expr, body_locals, lua_fname, ignore_fail)
            if var_out is not None:
                leaf_val += var_out
                var_found = True
        if not var_found:
            var_out = lua_exp_variable_ref_to_string(expr, lua_fname, ignore_fail)
            if len(var_out) > 0:
                if var_out not in body_locals:
                    leaf_val += [ var_out ]
                elif body_locals[var_out][0] in [ ValueSim.MathExpr ]:
                    leaf_val += body_locals[var_out][1:-1]
                elif body_locals[var_out][0] in [ ValueSim.Number ]:
                    leaf_val += body_locals[var_out][1:]
                elif body_locals[var_out][0] in [ ValueSim.LenPktWhole, ValueSim.LenPktPayload ]:
                    leaf_val += [ body_locals[var_out][0] ]
                else:
                    leaf_val += [ var_out ]
                var_found = True
        if not var_found:
            var_out = lua_exp_to_integer(expr, lua_fname, ignore_fail=True)
            if isinstance(var_out, numbers.Number):
                leaf_val += [ var_out ]
                var_found = True
        if not var_found:
            var_out = lua_get_function_call_sim(expr, body_locals, lua_fname)
            if var_out is not None:
                leaf_val += var_out
                var_found = True
        if not var_found:
            eprint("{:s}:{:d}: Warning: Operand in 'prefix_exp' was not recognized".format(lua_fname,lua_line))

    elif (expr[0].name == 'number'):
        var_out = lua_exp_to_integer(expr, lua_fname, ignore_fail=True)
        if isinstance(var_out, numbers.Number):
            leaf_val += [ var_out ]

    elif (expr[0].name == 'constant'):
        var_out = lua_exp_to_truefalse(expr, lua_fname, ignore_fail=True)
        if isinstance(var_out, bool):
            leaf_val += [ var_out ]

    else:
        eprint("{:s}:{:d}: Warning: Operand in math expression was not recognized".format(lua_fname,lua_line))
        print(expr)#!!!!!!!!!!
    return leaf_val

def simplify_math_expr(val_list, lua_fname):
    out_list = [ ]
    number_op = None
    number_val = 0
    within_calls = 0
    out_math_chunks = 0
    for var_out in val_list:
        # Ignore statements which are part of compound calls (where argument position matters)
        if var_out in ValueSimCompoundList or var_out in ValueSimCompoundExpr:
            within_calls += 1
        if isinstance(var_out, ValueConv):
            within_calls -= 1
        if within_calls > 0:
            out_list += [ var_out ]
            out_math_chunks += 1
            continue
        # Do the processing
        if isinstance(var_out, str) and (var_out in [ "'+'", '-' ]):
            number_op = var_out
        elif isinstance(var_out, numbers.Number):
            if (number_op == '-'):
                number_val -= var_out
            else:
                number_val += var_out
            number_op = None
        elif var_out in ValueSimLogicOperator:
            # logic operator should end the simplification
            if (number_val > 0) and (out_math_chunks > 0):
                out_list += [ "'+'", number_val ]
            elif (number_val < 0):
                out_list += [ '-', -number_val ]
            elif (out_math_chunks <= 0):
                out_list += [ 0 ]
            out_math_chunks = 0
            out_list += [ var_out ]
            continue
        else:
            if number_op is not None:
                out_list += [ number_op ]
                out_math_chunks += 1
                number_op = None
            out_list += [ var_out ]
            out_math_chunks += 1
    if (number_val > 0) and (out_math_chunks > 0):
        out_list += [ "'+'", number_val ]
    elif (number_val < 0):
        out_list += [ '-', -number_val ]
    elif (out_math_chunks <= 0):
        out_list += [ 0 ]
    # Now check for known expessions
    if out_list == [ ValueSim.LenPktWhole, '-', 13 ]:
        return [ ValueSim.LenPktPayload ]
    return out_list

def first_expr_length(val_list, lua_fname):
    expr_len = 0
    within_calls = 0
    for var_out in val_list:
        # Ignore statements which are part of compound calls (where argument position matters)
        if var_out in ValueSimCompoundList or var_out in ValueSimCompoundExpr:
            within_calls += 1
        if isinstance(var_out, ValueConv):
            within_calls -= 1
        if within_calls > 0:
            expr_len += 1
            continue
        # Add one to include the ValueConv
        return expr_len + 1
    return 0

def lua_get_assign_st_val_enum_list(assign_st, lua_fname, expect_text=False):
    leaf_list = {}
    leaf_expr = assign_st
    for expr1 in leaf_expr:
        if (not isinstance(expr1, tuple)) or (expr1[0].name != 'exp_list'):
            continue
        leaf_expr = expr1
    for expr1 in leaf_expr:
        if (not isinstance(expr1, tuple)) or (expr1[0].name != 'exp'):
            continue
        leaf_expr = expr1
    for expr1 in leaf_expr:
        if (not isinstance(expr1, tuple)) or (expr1[0].name != 'table_constructor'):
            continue
        leaf_expr = expr1
    # Now go through enum fields
    for expr1 in leaf_expr:
        if (not isinstance(expr1, tuple)):
            continue
        if (expr1[0].name != 'field'):
            continue
        field_val = None
        field_name = ''
        for expr2 in expr1:
            if (not isinstance(expr2, tuple)) or (expr2[0].name != 'exp'):
                continue
            if field_val is None:
                field_val = lua_exp_to_integer(expr2, lua_fname)
            else:
                if (expect_text):
                    field_name = lua_exp_textname_to_string(expr2, lua_fname)
                else:
                    field_name = lua_exp_variable_ref_to_string(expr2, lua_fname)

        leaf_list[field_val] = field_name if len(field_name) > 0 else 'Unknown'
    return leaf_list

def lua_get_function_decl_st_name(expr, lua_fname):
    leaf_name = ''
    leaf_expr = expr
    lua_line = lua_get_file_line(leaf_expr)
    for expr1 in leaf_expr:
        if (not isinstance(expr1, tuple)):
            continue
        if (expr1[0].name != 'function_decl_st') and (expr1[0].name != 'local_function_decl_st'):
            continue
        leaf_expr = expr1
    is_function = False
    for expr1 in leaf_expr:
        if (not isinstance(expr1, tuple)):
            continue
        if (expr1[0].name == "'function'"):
            is_function = True
            continue
        if (expr1[0].name != 'function_name'):
            continue
        leaf_expr = expr1
    for expr1 in leaf_expr:
        if (not isinstance(expr1, tuple)):
            continue
        if (expr1[0].name != 'variable_ref'):
            continue
        leaf_expr = expr1
    for expr1 in leaf_expr:
        if (not isinstance(expr1, tuple)):
            continue
        if (expr1[0].name == "'local'") or (expr1[0].name == "'function'"):
            continue
        elif (expr1[0].name == 'T.name') or (expr1[0].name == "'.'"):
            if (is_function):
                leaf_name += str(expr1[1])
            else:
                eprint("Warning: Found name tags not preceded by 'function'")
        elif (expr1[0].name == 'function_body'):
            break
        else:
            eprint("{:s}:{:d}: Warning: Unexpected expression in function declaration name: '{:s}'".format(lua_fname,lua_line,expr1[0].name))
    return leaf_name

def lua_get_function_decl_st_args(expr, lua_fname):
    leaf_list = []
    leaf_expr = expr
    for expr1 in leaf_expr:
        if (not isinstance(expr1, tuple)):
            continue
        if (expr1[0].name != 'function_decl_st') and (expr1[0].name != 'local_function_decl_st'):
            continue
        leaf_expr = expr1
    for expr1 in leaf_expr:
        if (not isinstance(expr1, tuple)) or (expr1[0].name != 'function_body'):
            continue
        leaf_expr = expr1
    for expr1 in leaf_expr:
        if (not isinstance(expr1, tuple)) or (expr1[0].name != 'parameter_list'):
            continue
        leaf_expr = expr1
    for expr1 in leaf_expr:
        if (not isinstance(expr1, tuple)) or (expr1[0].name != 'T.name'):
            continue
        leaf_list.append(expr1[1])
    return leaf_list

def lua_get_function_decl_st_body(expr, lua_fname):
    leaf_expr = expr
    for expr1 in leaf_expr:
        if (not isinstance(expr1, tuple)):
            continue
        if (expr1[0].name != 'function_decl_st') and (expr1[0].name != 'local_function_decl_st'):
            continue
        leaf_expr = expr1
    for expr1 in leaf_expr:
        if (not isinstance(expr1, tuple)) or (expr1[0].name != 'function_body'):
            continue
        leaf_expr = expr1
    for expr1 in leaf_expr:
        if (not isinstance(expr1, tuple)) or (expr1[0].name != 'block'):
            continue
        leaf_expr = expr1
    return leaf_expr

def lua_get_function_call_name(expr, lua_fname):
    leaf_name = ''
    leaf_expr = expr
    # simplified tree structure when used as real function call:
    # 1: (prefix_exp (function_call (prefix_exp (var (variable_ref (T.name) ) ) ) (function_args) ) )
    # 2: (prefix_exp (function_call (prefix_exp (function_call (prefix_exp (var (variable_ref (T.name) ) ) )
    #     (function_args ('(') (exp_list (exp) (',') (exp) ) (')') ) ) ) (':') (T.name) (function_args ('(') (')') ) ) )

    # We have two 'prefix_exp' - one inside and one outside of 'function_call'
    # if this is high level prefix_exp, we should enter it to find the prefix_exp we need
    # in case of tree structure 2, we need to do this 2 times
    for retry in range(2):
        for expr1 in leaf_expr:
            if (not isinstance(expr1, tuple)):
                continue
            if (expr1[0].name == 'prefix_exp'):
                if (expr1[1][0].name == 'function_call'):
                    leaf_expr = expr1[1]
                    break
            elif (expr1[0].name == 'function_call'):
                leaf_expr = expr1
                break
            else:
                break # 'prefix_exp' and 'function_call' are first; if soething else is found, no need to search further

    lua_line = lua_get_file_line(leaf_expr)

    # Here our leaf_expr should be a 'function_call'
    for expr1 in leaf_expr:
        if (not isinstance(expr1, tuple)):
            continue
        if (expr1[0].name == 'prefix_exp'):
            leaf_expr = expr1
            break
        else:
            eprint("{:s}:{:d}: Warning: Unexpected '{:s}' near 'prefix_exp' when getting call name".format(lua_fname, lua_line, expr1[0].name))

    # leaf_expr is now the 'prefix_exp' inside 'function_call'
    for expr1 in leaf_expr:
        if (not isinstance(expr1, tuple)):
            continue
        if (expr1[0].name == 'var'):
            leaf_expr = expr1
            break
        else:
            eprint("{:s}:{:d}: Warning: Unexpected '{:s}' near 'var' when getting call name".format(lua_fname, lua_line, expr1[0].name))
    for expr1 in leaf_expr:
        if (not isinstance(expr1, tuple)) or (expr1[0].name != 'variable_ref'):
            continue
        leaf_expr = expr1
    leaf_val = ''
    for expr1 in leaf_expr:
        if (not isinstance(expr1, tuple)):
            continue
        if (expr1[0].name == 'T.name'):
            leaf_val = expr1[1]
    if not isinstance(leaf_val, str):
        eprint("{:s}:{:d}: Warning: Could not get to variable ref when getting call name".format(lua_fname, lua_line))
    leaf_val = str(leaf_val)
    return leaf_val

def lua_get_function_call_args(call_name, expr, lua_fname):
    """ Gets function args list from given function_call expression.
     If there is a method call after the main function call, it is ignored.
     Ie for "payload(offset,1):le_uint()" - this only analyses the part before ":".
    """
    leaf_list = []
    leaf_expr = expr
    # simplified tree structure visible in lua_get_function_call_name()

    # We have two 'prefix_exp' - one inside and one outside of 'function_call'
    # if this is high level prefix_exp, we should enter it to find the prefix_exp we need
    # in case of tree structure 2, we need to do this 2 times
    for retry in range(2):
        for expr1 in leaf_expr:
            if (not isinstance(expr1, tuple)):
                continue
            if (expr1[0].name == 'prefix_exp'):
                if (expr1[1][0].name == 'function_call'):
                    leaf_expr = expr1[1]
                    break
            elif (expr1[0].name == 'function_call'):
                leaf_expr = expr1
                break
            else:
                break # 'prefix_exp' and 'function_call' are first; if soething else is found, no need to search further

    lua_line = lua_get_file_line(leaf_expr)

    # Here our leaf_expr should be a 'function_call'
    for expr1 in leaf_expr:
        if (not isinstance(expr1, tuple)):
            continue
        if (expr1[0].name == 'function_args'):
            leaf_expr = expr1
            break
        elif (expr1[0].name == 'prefix_exp'):
            pass # ignore prefix_exp at this level as it leads to name
        elif (expr1[0].name == 'variable_ref'):
            return None # if we have only variable_ref at this point, then this is really just a variable reference, without args; ie. "payload"
        elif (expr1[0].name == "':'"):
            return None # if we have ':' at this point, then this is a variable reference with no args but with conversion; ie. "payload:len()"
        else:
            eprint("{:s}:{:d}: Warning: Unexpected {:s} near 'function_args' when getting '{:s}' call args".format(lua_fname, lua_line, expr1[0].name, call_name))
    # Lets support enum/table declaration in the same call; it only differs in having 'table_constructor'
    for expr1 in leaf_expr:
        if (not isinstance(expr1, tuple)):
            continue
        if (expr1[0].name == 'table_constructor'):
            leaf_expr = expr1
            break
        else:
            pass # table_constructor is there only for enum/table, everything is ok if it's missing
    for expr1 in leaf_expr:
        if (not isinstance(expr1, tuple)):
            continue
        if (expr1[0].name == 'exp_list'):
            leaf_expr = expr1
        elif (expr1[0].name == "'('") or (expr1[0].name == "')'"):
            pass
        else:
            eprint("{:s}:{:d}: Warning: Unexpected {:s} near 'exp_list' when getting '{:s}' call args".format(lua_fname, lua_line, expr1[0].name, call_name))
    for expr1 in leaf_expr:
        if (not isinstance(expr1, tuple)):
            continue
        if (expr1[0].name == 'exp'):
            leaf_list.append(expr1)
        elif (expr1[0].name == "','"):
            pass
        else:
            eprint("{:s}:{:d}: Warning: Unexpected {:s} near 'exp' when getting '{:s}' call args".format(lua_fname, lua_line, expr1[0].name, call_name))
    return leaf_list

def lua_get_function_call_conv_name(expr, lua_fname):
    """ Gets function call finishing converter name - the method name after ":", if any.
    Ie for "payload(offset,1):le_uint()" - this only returns the name after ":".
    """
    # simplified structure when used: (prefix_exp (function_call  (prefix_exp (var (variable_ref (T.name) ) ) ) (':') (T.name) (function_args) ) )
    # find 'function_call'
    leaf_expr = expr
    leaf_check = None
    for expr1 in leaf_expr:
        if (not isinstance(expr1, tuple)):
            continue
        if (expr1[0].name == 'prefix_exp'):
            leaf_check = expr1[1]
        elif (expr1[0].name == 'function_call'):
            leaf_check = expr1
        elif (expr1[0].name == 'function_args'):
            leaf_check = None
            break
        else:
            break # there may be other function_args after this, ie. after ':'; need to break
    if leaf_check is not None:
        leaf_expr = leaf_check

    # find convertion call within 'function_call'
    leaf_allow = False
    leaf_check = None
    lua_line = lua_get_file_line(leaf_expr)
    for expr1 in leaf_expr:
        if (not isinstance(expr1, tuple)):
            continue
        if (expr1[0].name == "':'"):
            leaf_allow = True
        elif (expr1[0].name == 'T.name'):
            if (leaf_allow):
                leaf_check = [ expr1 ]
                break
        else:
            continue
    if leaf_check is None:
        return ''
    leaf_expr = leaf_check
    leaf_val = ''
    for expr1 in leaf_expr:
        if (not isinstance(expr1, tuple)):
            continue
        if (expr1[0].name == 'T.name'):
            leaf_val = expr1[1]
    if not isinstance(leaf_val, str):
        eprint("{:s}:{:d}: Warning: Could not get to finisher function name".format(lua_fname,lua_line))
    leaf_val = str(leaf_val)
    return leaf_val

def lua_get_exp_value(local_name, exp_block, body_locals, lua_fname):
    """ Converts one 'exp' tag subtree to ValueSim
    """
    lua_line = lua_get_file_line(exp_block)
    if exp_block[0].name == 'exp':
        # If there is only one operand in 'exp', then it might be a simple type
        if len(exp_block) == 2:
            # Check for simple string type
            var_out = lua_exp_variable_ref_to_string(exp_block[1], lua_fname, ignore_fail=True)
            if len(var_out) > 0:
                if var_out not in body_locals:
                    return [ValueSim.VariableRef, var_out]
                else:
                    return body_locals[var_out]
            var_out = lua_exp_to_integer(exp_block[1], lua_fname, ignore_fail=True)
            # Check for simple numeric type
            if isinstance(var_out, numbers.Number):
                return [ValueSim.Number, var_out]
            var_out = lua_exp_to_truefalse(exp_block[1], lua_fname, ignore_fail=True)
            # Check for simple numeric type
            if isinstance(var_out, bool):
                return [ValueSim.Logic, var_out]
        # If this is not a simple type, check if it is math equation
        var_out = lua_exp_to_math_expr(exp_block, body_locals, lua_fname, ignore_fail=True)
        if isinstance(var_out, list):
            var_out = simplify_math_expr(var_out, lua_fname)
            if len(var_out) == 1 and isinstance(var_out[0], ValueSim):
                return var_out
            if len(var_out) == 1 and isinstance(var_out[0], numbers.Number):
                return [ValueSim.Number] + var_out
            if len(var_out) > 0 and first_expr_length(var_out, lua_fname) == len(var_out):
                return var_out
            return [ValueSim.MathExpr] + var_out + [ValueConv.No]
        eprint("{:s}:{:d}: Error: Content of 'exp' not recognized".format(lua_fname,lua_line))
        #print("nn "+str(exp_block[1]))
    else:
        eprint("{:s}:{:d}: Error: Expected 'exp' to get value, got '{:s}'".format(lua_fname,lua_line,exp_block[0].name))
    return None

def lua_get_exp_value_opt(local_name, exp_block, body_locals, lua_fname):
    """ Converts any 'exp' to ValueSim, optimizing it
    """
    var_out = lua_get_exp_value(local_name, exp_block, body_locals, lua_fname)

    if var_out == [ ValueSim.ArrayPktWhole, 0, ValueSim.LenPktWhole, ValueConv.Len ]:
        var_out = [ ValueSim.LenPktWhole ]
    elif var_out == [ ValueSim.ArrayPktPayload, 0, ValueSim.LenPktPayload, ValueConv.Len ]:
        var_out = [ ValueSim.LenPktPayload ]
    return var_out

def lua_get_function_param_opt(func_name, arg_expr, body_locals, lua_fname):
    """ Converts one argument of a function call to ValueSim, optimizing it
    """
    value_sim = lua_get_exp_value_opt("call:"+func_name, arg_expr, body_locals, lua_fname)
    return value_sim

def lua_get_exp_value_sim(local_name, exp_block, body_locals, lua_fname):
    """ Simulates value within 'exp' tag.
    """
    lua_line = lua_get_file_line(exp_block)
    value_sim = lua_get_exp_value_opt(local_name, exp_block, body_locals, lua_fname)
    if (value_sim is None):
        eprint("{:s}:{:d}: Error: could not recognize '{:s}' value for simulation".format(lua_fname,lua_line,exp_block[0].name))
        value_sim = [ ValueSim.Nop ]
    return value_sim

def lua_func_convert_recognize(val_func_conv,val_func):
    if val_func_conv == "len":
        return ValueConv.Len
    elif val_func_conv == "int":
        return ValueConv.Int
    elif val_func_conv == "uint":
        return ValueConv.UInt
    elif val_func_conv == "le_int":
        return ValueConv.LE_Int
    elif val_func_conv == "le_uint":
        return ValueConv.LE_UInt
    elif len(val_func_conv) < 1:
        return ValueConv.No
    else:
        return None

def lua_get_function_call_sim(expr, body_locals, lua_fname):
    # Check if we have function call
    leaf_expr = expr
    lua_line = lua_get_file_line(leaf_expr)
    for expr1 in leaf_expr:
        if (not isinstance(expr1, tuple)):
            continue
        if (expr1[0].name == 'prefix_exp'):
            leaf_expr = expr1
            break
    got_function_call = False
    for expr1 in leaf_expr:
        if (not isinstance(expr1, tuple)):
            continue
        if (expr1[0].name == 'function_call'):
            leaf_expr = expr1
            got_function_call = True
            break
    if not got_function_call:
        return None

    # assumed structure: call_name(call_args):convert_name()
    val_func = lua_get_function_call_name(expr, lua_fname)
    val_func_args_exp = lua_get_function_call_args(val_func, expr, lua_fname)
    val_func_conv = lua_get_function_call_conv_name(expr, lua_fname)

    # Convert args to a simpler form
    val_func_args = []
    if (val_func_args_exp is not None):
        for arg_expr in val_func_args_exp:
            val_func_args.append(lua_get_function_param_opt(val_func, arg_expr, body_locals, lua_fname))
    elif (val_func_conv is not None):
        if (val_func_conv != 'len'):
            # Having a call which does only conversion is only usual for 'len' converter; other ones would be suspicious
            print("{:s}:{:d}: Info: Call to '{:s}' with convert only ('{:s}')".format(lua_fname,lua_line,val_func,val_func_conv))
        pass
    else:
        eprint("{:s}:{:d}: Error: Call without args '{:s}'".format(lua_fname,lua_line,val_func))

    value_sim = [ ValueSim.Nop ]
    if val_func is not None:
        # Now recognize known items
        if val_func in body_locals:
            val_local = body_locals[val_func]
            val_local_type = val_local[0]

            if (val_local_type in ValueSimCompoundList) and (len(val_func_args) >= 2):
                if val_local[3] != ValueConv.No:
                    eprint("{:s}:{:d}: Warning: Array slice after convertion in '{:s}'".format(lua_fname,lua_line,val_func))
                # We have an array to cut slice from
                val_array_start = val_func_args[0]
                val_array_size = val_func_args[1]
                # Check if we should switch from whole packet to payload part
                if val_local_type == ValueSim.ArrayPktWhole and val_array_start[0] == ValueSim.Number and isinstance(val_local[1], numbers.Number) and val_local[1] + val_array_start[1] >= 11:
                    val_local_type = ValueSim.ArrayPktPayload
                    val_array_start = val_local[1] + val_array_start[1] - 11
                elif val_array_start[0] == ValueSim.Number and isinstance(val_local[1], numbers.Number):
                    val_array_start = val_local[1] + val_array_start[1]
                else:
                    eprint("{:s}:{:d}: Warning: Unexpected array start in '{:s}'".format(lua_fname,lua_line,val_func))
                    val_array_start = val_local[1]
                # Find out the length
                if val_array_size[0] == ValueSim.Number and isinstance(val_local[2], numbers.Number):
                    val_array_size = val_local[2] + val_array_size[1]
                elif val_array_size[0] == ValueSim.Number and val_local[2] in [ ValueSim.LenPktPayload, ValueSim.LenPktWhole ]:
                    val_array_size = val_array_size[1]
                elif val_array_size[0] == ValueSim.LenPktPayload and val_local[2] in [ ValueSim.LenPktPayload, ValueSim.LenPktWhole ]:
                    val_array_size = val_array_size[0]
                elif val_array_size[0] == ValueSim.LenPktWhole and val_local[2] in [ ValueSim.LenPktPayload, ValueSim.LenPktWhole ]:
                    val_array_size = val_local[2]
                else:
                    print("XXX !!! " + val_func + " " + str(val_local[2]) + " " + str(val_array_size))#TODO debug
                    eprint("{:s}:{:d}: Warning: Unexpected array size in '{:s}'".format(lua_fname,lua_line,val_func))
                    val_array_size = val_local[2]
                if len(val_func_args) >= 3:
                    eprint("{:s}:{:d}: Warning: Extra args in '{:s}'".format(lua_fname,lua_line,val_func))
                # Set convertion
                val_array_conv = lua_func_convert_recognize(val_func_conv,val_func)
                if val_array_conv is None:
                    eprint("{:s}:{:d}: Warning: Unexpected conversion '{:s}' in '{:s}'".format(lua_fname,lua_line,val_func_conv,val_func))
                    val_array_conv = val_local[3]
                # All done - add the entry
                value_sim[0] = val_local_type
                value_sim.append(val_array_start)
                value_sim.append(val_array_size)
                value_sim.append(val_array_conv)
            elif (val_local_type in ValueSimCompoundList) and (len(val_func_args) == 0):
                val_array_start = val_local[1]
                val_array_size = val_local[2]
                val_array_conv = lua_func_convert_recognize(val_func_conv,val_func)
                if val_array_conv is None:
                    eprint("{:s}:{:d}: Warning: Unexpected conversion '{:s}' in '{:s}'".format(lua_fname,lua_line,val_func_conv,val_func))
                    val_array_conv = val_local[3]
                # All done - add the entry
                value_sim[0] = val_local_type
                value_sim.append(val_array_start)
                value_sim.append(val_array_size)
                value_sim.append(val_array_conv)
            else:
                eprint("{:s}:{:d}: Warning: Unexpected local used, '{:s}'".format(lua_fname,lua_line,val_func))
        elif val_func == "rshift":
            #eprint("{:s}: Error: Call '{}' UNFINNISHED".format(lua_fname,val_func))#TODO debug
            value_sim[0] = ValueSim.RShift
        elif val_func == "floor":
            #eprint("{:s}: Error: Call '{}' UNFINNISHED".format(lua_fname,val_func))#TODO debug
            value_sim[0] = ValueSim.Floor
        elif val_func == "band":
            #eprint("{:s}: Error: Call '{}' UNFINNISHED".format(lua_fname,val_func))#TODO debug
            value_sim[0] = ValueSim.BAnd
        elif val_func == "format":
            #eprint("{:s}: Error: Call '{}' UNFINNISHED".format(lua_fname,val_func))#TODO debug
            value_sim[0] = ValueSim.Format
        else:
            eprint("{:s}:{:d}: Error: Call '{}' is not known function or local array slice".format(lua_fname,lua_line,val_func))
    return value_sim

def lua_get_assign_st_value_sim(local_name, assign_st, body_locals, lua_fname):
    """ Simulates value within assign statement
    """
    leaf_expr = assign_st
    leaf_found = 0
    lua_line = lua_get_file_line(leaf_expr)
    # if we are on 'assign_st' or 'local_assign_st' (we should), there is an 'exp_list' inside storing our value
    if (leaf_expr[0].name != 'assign_st') and (leaf_expr[0].name != 'local_assign_st'):
        eprint("{:s}:{:d}: Warning: Expected 'assign_st' to be passed for getting value".format(lua_fname,lua_line))
    for expr1 in leaf_expr:
        if (not isinstance(expr1, tuple)) or (expr1[0].name != 'exp_list'):
            continue
        leaf_expr = expr1
        leaf_found = leaf_found + 1
        break
    if (leaf_found != 1):
        eprint("{:s}:{:d}: Info: Declaration without assignment".format(lua_fname,lua_line))
        return None
    # now enter inside 'exp_list'; it should have one entry
    for expr1 in leaf_expr:
        if (not isinstance(expr1, tuple)) or (expr1[0].name != 'exp'):
            continue
        leaf_expr = expr1
        leaf_found = leaf_found + 1
    if (leaf_found != 2):
        eprint("{:s}:{:d}: Warning: Expected 2 travels down into 'exp_list'/'exp', got {:d} before getting value".format(lua_fname,lua_line,leaf_found))
    value_sim = lua_get_exp_value_sim(local_name, leaf_expr, body_locals, lua_fname)
    #print(value_sim)
    return value_sim

def lua_get_if_st_condition(if_st, body_locals, lua_fname):
    expr1 = if_st
    lua_line = lua_get_file_line(expr1)
    if (expr1[0].name == 'if_st'):
        expr1 = if_st[2]
    else:
        eprint("{:s}:{:d}: Warning: Expected 'if_st' to be passed for getting condition".format(lua_fname,lua_line))
    value_sim = lua_get_exp_value_sim("if_statement", expr1, body_locals, lua_fname)
    #print("{:s}:{:d}: Debug: Condition in 'if_st' is: {:s}".format(lua_fname,lua_line,str(value_sim)))
    return value_sim

def lua_function_call_dofile_to_string(expr, lua_fname):
    leaf_expr = expr
    is_dofile_call = False
    lua_line = lua_get_file_line(leaf_expr)
    call_name = lua_get_function_call_name(leaf_expr, lua_fname)
    if (call_name == 'dofile'):
        is_dofile_call = True
        leaf_expr = lua_get_function_call_args(call_name, leaf_expr, lua_fname)
        #print(leaf_expr)
    # For confirmed "dofile" call, return first parameter (which is file name)
    if not is_dofile_call:
        return ''
    if len(leaf_expr) != 1:
        eprint("{:s}:{:d}: Warning: Expected dofile() to have exactly one argument".format(lua_fname,lua_line))
    for expr1 in leaf_expr:
        if (not isinstance(expr1, tuple)) or (expr1[0].name != 'exp'):
            continue
        leaf_expr = expr1
    for expr1 in leaf_expr:
        if (not isinstance(expr1, tuple)) or (expr1[0].name != 'string'):
            continue
        leaf_expr = expr1
    leaf_val = ''
    for expr1 in leaf_expr:
        if (not isinstance(expr1, tuple)):
            continue
        if (expr1[0].name == 'T.short_string'):
            leaf_val = expr1[1]
    #print(leaf_val)
    if not isinstance(leaf_val, str):
        eprint("{:s}:{:d}: Warning: Could not get to string file name in dofile() call".format(lua_fname,lua_line))
    leaf_val = str(leaf_val)
    if (leaf_val.startswith('"') or leaf_val.startswith("'")) and \
       (leaf_val.endswith('"')   or leaf_val.endswith("'")):
        leaf_val = leaf_val[1:-1]
    return leaf_val

def lua_block_body_get_conditional_statements(block_expr,body_locals,lua_fname):
    condition_list = []
    for expr2 in block_expr:
        if (not isinstance(expr2, tuple)):
            continue
        lua_line = lua_get_file_line(expr2)
        # Simulate every command in the dissector, make note of things for which we have flags
        #TODO define flags, when simulation works
        if (expr2[0].name == 'function_call_st'):
            # Function calls don't have conditional clauses in our dissectors, and no need to simulate them - skip
            got_call = 0
            for expr3 in expr2:
                 if (not isinstance(expr3, tuple)) or (expr3[0].name != 'function_call'):
                    continue
                 got_call += 1
            if got_call != 1:
                eprint("{:s}:{:d}: Warning: Unexpected content of function_call_st, count of function_call is {:d}".format(lua_fname,lua_line,got_call))
            continue # no need for further processing
        elif (expr2[0].name == 'assign_st') or (expr2[0].name == 'local_assign_st'):
            # Assignment statements don't have conditional clauses in our dissectors, so just simulate them
            # The assigned locals can be later used in conditional statements, so we're storing them for later
            local_name = lua_get_assign_st_full_name(expr2, lua_fname)
            local_val = lua_get_assign_st_value_sim(local_name, expr2, body_locals, lua_fname)
            body_locals[local_name] = local_val
            continue # no need for further processing
        elif (expr2[0].name == 'if_st'):
            #TODO implement
            local_cond = lua_get_if_st_condition(expr2, body_locals, lua_fname)
            expr3 = expr2[4] # select 'scope'
            expr3 = expr3[2] # select 'block'; within it, each line will be wrapped into 'statememnt'
            # copy locals for the sub-block
            subblock_locals = body_locals.copy()
            for expr4 in expr3:
                # Our block body should only have statements
                if (not isinstance(expr4, tuple)) or (expr4[0].name != 'statement'):
                    continue
                lua_block_body_get_conditional_statements(expr4,subblock_locals,lua_fname) # recurrence
            condition_list += [ local_cond ]
            #TODO implement conditions storing, here or below
            continue
        elif (expr2[0].name == 'while_st'):
            continue #TODO implement 'while'
        else:
            eprint("{:s}:{:d}: Warning: Unexpected expression in function body: '{:s}'".format(lua_fname,lua_line,expr2[0].name))
            #print(str(expr2)[:200])
        #TODO in case of 'if' or 'while', store the condition
    return condition_list


def lua_function_body_get_conditional_statements(func):
    """ Parses dissector and returns flag information on its content, like what conditional statements are inside
    """
    lua_fname = func['fname']
    lua_line = func['fline']
    body_locals = {}
    if len(func['args']) != 4:
        eprint("{:s}:{:d}: Warning: Unexpected dissector function params count: {:d} instead of 4".format(lua_fname,lua_line,len(func['args'])))
    var_name = func['args'][0] # 'pkt_length'
    body_locals[var_name] = [ ValueSim.LenPktWhole ]
    var_name = func['args'][1] # 'buffer'
    body_locals[var_name] = [ ValueSim.ArrayPktWhole, 0, ValueSim.LenPktWhole, ValueConv.No ]
    var_name = func['args'][2] # 'pinfo'
    body_locals[var_name] = [ ValueSim.ObjPInfo ]
    var_name = func['args'][3] # 'subtree'
    body_locals[var_name] = [ ValueSim.ObjTreeItem ]
    for var_name in func['args']:
        if var_name not in body_locals.keys():
            body_locals[var_name] = ValueSim.Unknown
    for expr1 in func['body']:
        # Our function body should only have statements
        if (not isinstance(expr1, tuple)) or (expr1[0].name != 'statement'):
            continue
        lua_block_body_get_conditional_statements(expr1,body_locals,lua_fname)
    return []

def switch_negating_conditions(cond_val, cond_n):
    cond_real = cond_val.copy()
    i = 0
    while (i < cond_n):
        #TODO switch conditions which negate each other
        i += 1
    i = cond_n + 1
    while (i < len(cond_real)):
        #TODO switch conditions which negate each other
        i += 1
    return cond_real

def gen_conditions_combination(cond):
    """ Generator which gives all possible combinations of conditions
    """
    cond_val = []
    cond_n = 0
    #TODO generate first cond_val; no conditions met, then switch conditions which negate previous ones
    while (cond_n < len(cond_val)):
        yield switch_negating_conditions(cond_val, cond_n)
        if (cond_val[cond_n].met):
            cond_n += 1
        # generate next cond_val - change value at cond_n, yeld with conditions which negate each other switched
        cond_val[cond_n].met = not cond_val[cond_n].met
    yield switch_negating_conditions(cond_val, cond_n)

def markdown_print_duml_main(po, duml_spec):
    md_main_file = po.md_path + 'README.md'
    if os.path.exists(md_main_file):
        os.remove(md_main_file)
    fh = open(md_main_file, 'w')
    print("| cmdset | description |",file=fh)
    print("|---:|:------------|",file=fh)
    full_cmdset_list = duml_spec['DJI_DUMLv1_CMD_DISSECT'].copy()
    full_cmdset_list.update(duml_spec['DJI_DUMLv1_CMD_TEXT'])
    full_cmdset_list.update(duml_spec['DJI_DUMLv1_CMD_SET_TEXT'])
    for cmdset, desc_set in full_cmdset_list.items():
        if cmdset in duml_spec['DJI_DUMLv1_MDFILES']:
            md_files = duml_spec['DJI_DUMLv1_MDFILES'][cmdset]
        else:
            md_files = {}
        if -1 in md_files:
            md_cmd_file = md_files[-1] # we store cmdset file name at index -1
        else:
            md_cmd_file = ''
        if len(md_cmd_file) > 0:
            print("| {:02x} | [[Command Set: {:s}\|{:s}]] |".format(cmdset, desc_set, md_cmd_file),file=fh)
        else:
            print("| {:02x} | Command Set: {:s} |".format(cmdset, desc_set),file=fh)
    fh.close()
    return

def markdown_print_duml_cmdset(po, duml_spec, cmdset):
    if cmdset in duml_spec['DJI_DUMLv1_MDFILES']:
        md_files = duml_spec['DJI_DUMLv1_MDFILES'][cmdset]
    else:
        md_files = {}
    if not -1 in md_files:
        return
    md_cmd_file = po.md_path + md_files[-1] # we store cmdset file name at index -1
    if os.path.exists(md_cmd_file):
        os.remove(md_cmd_file)
    fh = open(md_cmd_file, 'w')

    if cmdset in duml_spec['DJI_DUMLv1_CMD_TEXT']:
        desc_set = duml_spec['DJI_DUMLv1_CMD_SET_TEXT'][cmdset]
    else: # Should never happen
        eprint("Warning: No DJI_DUMLv1_CMD_SET_TEXT entry for cmdset={:d}".format(cmdset))
        desc_set = duml_spec['DJI_DUMLv1_CMD_TEXT'][cmdset]

    print("# Command Set {:02x}: {:s}\n".format(cmdset, desc_set, md_cmd_file),file=fh)

    print("Command Sets are used to group commands in the DUML protocol. Command Set and Command ID are needed to identify packet type and decode payload.\n",file=fh)

    if cmdset in duml_spec['DJI_DUMLv1_CMD_TEXT_LIST']:
        print("| cmd | description |",file=fh)
        print("|---:|:------------|",file=fh)
        for cmd in sorted(duml_spec['DJI_DUMLv1_CMD_TEXT_LIST'][cmdset]):
            desc_cmd = duml_spec['DJI_DUMLv1_CMD_TEXT_LIST'][cmdset][cmd]
            if cmd in md_files:
                print("| {:02x} | [[{:s}\|{:s}]] |".format(cmd, desc_cmd, md_files[cmd]),file=fh)
            else:
                print("| {:02x} | {:s} |".format(cmd, desc_cmd),file=fh)
    fh.close()
    return

def markdown_print_duml_cmdid(po, duml_spec, cmdset, cmd):
    if cmdset in duml_spec['DJI_DUMLv1_MDFILES']:
        md_files = duml_spec['DJI_DUMLv1_MDFILES'][cmdset]
    else:
        md_files = {}
    if not cmd in md_files:
        return
    md_cmd_file = po.md_path + md_files[cmd]
    if os.path.exists(md_cmd_file):
        os.remove(md_cmd_file)
    fh = open(md_cmd_file, 'w')

    #print(md_cmd_file)
    #TODO make printing the packet structure

    fh.close()
    return

def lua_parse_file(po, grammar, lua_file):
    """ Returns 3 lists with trees of specific items.
    Each resulting tree has input file name appended to top item.
    """
    # Prepare lists for parsed branches
    lua_assign_st = []
    lua_function_decl_st = []
    lua_function_call = []
    lua_fname = os.path.basename(lua_file.name)
    # Read file content
    if (po.verbose > 0):
        print("{}: Parsing {}".format(po.lua.name,lua_fname))
    lua_file_content = lua_file.read()
    lua_file_tree = grammar.parse(lua_file_content)
    #print(grammar.repr_parse_tree(lua_file_tree))
    for expr0 in lua_file_tree:
        if not isinstance(expr0, tuple):
            continue
        for expr1 in expr0:
            if (not isinstance(expr1, tuple)) or (expr1[0].name != 'statement'):
                continue
            for expr2 in expr1:
                if (not isinstance(expr2, tuple)):
                    continue
                if (expr2[0].name == 'assign_st'):
                    lua_assign_st.append( expr2 + (lua_fname,) )
                elif (expr2[0].name == 'local_assign_st'):
                    lua_assign_st.append( expr2 + (lua_fname,) )
                elif (expr2[0].name == 'function_decl_st'):
                    lua_function_decl_st.append( expr2 + (lua_fname,) )
                elif (expr2[0].name == 'local_function_decl_st'):
                    lua_function_decl_st.append( expr2 + (lua_fname,) )
                else:
                    for expr3 in expr2:
                        if (not isinstance(expr3, tuple)):
                            continue
                        lua_function_call.append( expr3 + (lua_fname,) )
    return lua_assign_st, lua_function_decl_st, lua_function_call

def lua_parse_main(po, lua_main):
    # Parse LUA language grammar into a tree
    if (po.verbose > 0):
        print("{}: Parser grammar generation".format(lua_main.name))
    grammar = lua52.Lua52Grammar
    try:
        grammar.pre_compile_grammar(grammar.pre_compiled)
        # warning - compiling the grammar might lead to an issue, better stay at pre-compiled
        #grammar.compile_grammar()
    except:
        try:
            print(grammar.repr_grammar())
            print()
            print(grammar.repr_productions())
            print()
            print(grammar.repr_parse_table())
        finally:
            raise
    assert not grammar.unused_rules(), grammar.unused_rules()
    # Prepare lists for parsed branches
    lua_assign_st, lua_function_decl_st, lua_function_call = lua_parse_file(po, grammar, lua_main)
    for expr1 in lua_function_call:
        lua_fname = expr1[-1]
        lua_subfile_name = lua_function_call_dofile_to_string(expr1, lua_fname)
        if len(lua_subfile_name) > 0:
            with open(po.lua_path + lua_subfile_name, 'r') as lua_subfile:
                sub_assign_st, sub_function_decl_st, sub_function_call = lua_parse_file(po, grammar, lua_subfile)
            lua_assign_st += sub_assign_st
            lua_function_decl_st += sub_function_decl_st
            lua_function_call += sub_function_call
  
    duml_spec = {}
    duml_spec['DJI_DUMLv1_CMD_TEXT'] = []
    duml_spec['DJI_DUMLv1_CMD_DISSECT'] = []
    # Find info on command sets
    for assign_st in lua_assign_st:
        lua_fname = assign_st[-1]
        assign_st_name = lua_get_assign_st_full_name(assign_st, lua_fname)
        if (assign_st_name == 'DJI_DUMLv1_CMD_SET_TEXT'):
            duml_spec['DJI_DUMLv1_CMD_SET_TEXT'] = lua_get_assign_st_val_enum_list(assign_st, lua_fname, expect_text=True)
        if (assign_st_name == 'DJI_DUMLv1_CMD_TEXT'):
            duml_spec['DJI_DUMLv1_CMD_TEXT'] = lua_get_assign_st_val_enum_list(assign_st, lua_fname)
        if (assign_st_name == 'DJI_DUMLv1_CMD_DISSECT'):
            duml_spec['DJI_DUMLv1_CMD_DISSECT'] = lua_get_assign_st_val_enum_list(assign_st, lua_fname)
    # Find info on commands
    duml_spec['DJI_DUMLv1_CMD_TEXT_LIST'] = {}
    duml_spec['DJI_DUMLv1_CMD_DISSECT_LIST'] = {}
    for assign_st in lua_assign_st:
        lua_fname = assign_st[-1]
        assign_st_name = lua_get_assign_st_full_name(assign_st, lua_fname)
        if (assign_st_name in duml_spec['DJI_DUMLv1_CMD_TEXT'].values()):
            for n_cmdset, n_assign_st_name in duml_spec['DJI_DUMLv1_CMD_TEXT'].items():
                if (assign_st_name == n_assign_st_name):
                    cmdset = n_cmdset
            val_enum_list = lua_get_assign_st_val_enum_list(assign_st, lua_fname, expect_text=True)
            if len(val_enum_list) > 0:
                duml_spec['DJI_DUMLv1_CMD_TEXT_LIST'][cmdset] = val_enum_list
            continue
        if (assign_st_name in duml_spec['DJI_DUMLv1_CMD_DISSECT'].values()):
            for n_cmdset, n_assign_st_name in duml_spec['DJI_DUMLv1_CMD_DISSECT'].items():
                if (assign_st_name == n_assign_st_name):
                    cmdset = n_cmdset
            val_enum_list = lua_get_assign_st_val_enum_list(assign_st, lua_fname)
            if len(val_enum_list) > 0:
                duml_spec['DJI_DUMLv1_CMD_DISSECT_LIST'][cmdset] = val_enum_list
    # Prepare dissector functions
    duml_spec['DJI_DUMLv1_CMD_DISSECT_FUNCT'] = {}
    for function_decl_st in lua_function_decl_st:
        func = {}
        func['fname'] = function_decl_st[-1]
        func['fline'] = lua_get_file_line(function_decl_st)
        func['name'] = lua_get_function_decl_st_name(function_decl_st, func['fname'])
        func['args'] = lua_get_function_decl_st_args(function_decl_st, func['fname'])
        func['body'] = lua_get_function_decl_st_body(function_decl_st, func['fname'])
        func_is_dissector = False
        for cmdset, cmd_enum_list in duml_spec['DJI_DUMLv1_CMD_DISSECT_LIST'].items():
            for cmd, dissect_func_name in cmd_enum_list.items():
                if (func['name'] == dissect_func_name):
                    func_is_dissector = True
        if (func_is_dissector):
            #TODO make main program flow, based on comments
            # recognize conditions in any conditional clauses within the function
            func_cond = lua_function_body_get_conditional_statements(func)
            # simulate the dissector with all condition combinations
            for func_cond_val in gen_conditions_combination(func_cond):
                pass
            #TODO if results are different, we should include variants in the output
        else:
            print("{:s}:{:d}: Info: Function marked as not dissector: {:s}".format(func['fname'],func['fline'],func['name']))
            #print(function_decl_st[:100])
        #print(func['name'] + "(" + str(func['args'])+ ")")
        #print(func['body'])
        duml_spec['DJI_DUMLv1_CMD_DISSECT_FUNCT'][func['name']] = func
    # Prepare file names for command sets and commands
    duml_spec['DJI_DUMLv1_MDFILES'] = {}
    for cmdset, desc_set in duml_spec['DJI_DUMLv1_CMD_TEXT_LIST'].items():
        md_cmd_file = str(duml_spec['DJI_DUMLv1_CMD_TEXT'][cmdset])
        if md_cmd_file.endswith('_CMD_TEXT'):
                md_cmd_file = 'CMDSET_' + md_cmd_file[:-9]
        if md_cmd_file.endswith('_UART'):
                md_cmd_file = md_cmd_file[:-5]
        md_fnames = { }
        md_fnames[-1] = '{:s}.md'.format(md_cmd_file)
        if cmdset in duml_spec['DJI_DUMLv1_CMD_DISSECT_LIST']: # only create files which have a list to go inside
            for cmd in duml_spec['DJI_DUMLv1_CMD_DISSECT_LIST'][cmdset].keys():
                md_fnames[cmd] = '{:s}_CMD_{:02X}.md'.format(md_cmd_file,cmd)
        duml_spec['DJI_DUMLv1_MDFILES'][cmdset] = md_fnames

    markdown_print_duml_main(po, duml_spec)
    for cmdset in duml_spec['DJI_DUMLv1_MDFILES'].keys():
        markdown_print_duml_cmdset(po, duml_spec, cmdset)

    for cmdset in duml_spec['DJI_DUMLv1_MDFILES'].keys():
        for cmd in duml_spec['DJI_DUMLv1_MDFILES'][cmdset].keys():
            if (cmd < 0):
                continue
            markdown_print_duml_cmdid(po, duml_spec, cmdset, cmd)

    return

def main():
    """ Main executable function.

    Its task is to parse command line options and call a function which performs requested command.
    """
    # Parse command line options

    parser = argparse.ArgumentParser(description=__doc__)

    parser.add_argument("-v", "--verbose", action="count", default=0,
          help="increases verbosity level; max level is set by -vvv")

    subparser = parser.add_mutually_exclusive_group(required=True)

    subparser.add_argument("-l", "--lua", type=argparse.FileType('r'),
          help="name of the input LUA file, 'dji-dumlv1-proto.lua'")

    subparser.add_argument("--version", action='version', version="%(prog)s {version} by {author}"
            .format(version=__version__,author=__author__),
          help="display version information and exit")

    po = parser.parse_args();

    po.lua_path = './'
    if po.lua is not None and len(os.path.dirname(po.lua.name)) > 0:
        po.lua_path = os.path.dirname(po.lua.name) + '/'
    po.md_path = './duml/'

    if po.lua is not None:

        if (po.verbose > 0):
          print("{}: Opened for parse".format(po.lua.name))

        lua_parse_main(po,po.lua)

    else:

        raise NotImplementedError('Unsupported command.')

if __name__ == "__main__":
    try:
        main()
    except Exception as ex:
        eprint("Error: "+str(ex))
        raise
        sys.exit(10)
