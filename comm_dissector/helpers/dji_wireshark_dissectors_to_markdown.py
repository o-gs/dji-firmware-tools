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
    VariableRef = 4 # A reference to a variable; 1 param: name of the variable
    String = 5 # A text string; 1 param: the character string
    MathExpr = 6 # Math expression; each param is either operation/sign or name/value (if str then treated as variable ref or operator/sign, if number then as number)
    # Complex types - after second analysis
    ArraySlice = 10 # Part sliced from any array; 3 params: array,start,size
    ArraySliceConv = 11 # Part sliced from any array, then converted using a standard function; 4 params: array,start,size,conv_func_name
    # TODO we really need these?
    ArrayPktWhole = 12 # Whole input packet, no params
    ArrayPktPayload = 13 # Payload part of the input packet, no params
    LenPktWhole = 14 # Length of the whole input packet, no params
    LenPktPayload = 15 # Length of the payload part of input packet, no params
    ObjTreeItem = 16 # Wireshark TreeItem object, no params (TODO maybe place items inside?)
    ObjPInfo = 17 # Wireshark PInfo object, no params


def eprint(*args, **kwargs):
  print(*args, file=sys.stderr, **kwargs)

def lua_get_assign_st_full_name(assign_st, lua_fname):
    leaf_expr = assign_st
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
        eprint("{:s}: Warning: Could not get full name in assign statement".format(lua_fname))
        for expr1 in assign_st:
            print(expr1)
    return leaf_name

def lua_exp_to_integer(expr, lua_fname, ignore_fail=False):
    leaf_expr = expr
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
            eprint("{:s}: Warning: While getting numeric param, expected final leaf to be string".format(lua_fname))
        return None
    elif (len(leaf_val) < 1):
        if not ignore_fail:
            eprint("{:s}: Warning: While getting numeric param, could not get final leaf string".format(lua_fname))
        return None
    return int(leaf_val,0)

def lua_exp_variable_ref_to_string(expr, lua_fname, ignore_fail=False):
    leaf_expr = expr
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
            eprint("{:s}: Warning: Could not get to variable ref name".format(lua_fname))
        return None
    return leaf_val

def lua_exp_textname_to_string(expr, lua_fname):
    leaf_expr = expr
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
        eprint("{:s}: Warning: Could not get to text name in list assignment".format(lua_fname))
    leaf_val = str(leaf_val)
    if (leaf_val.startswith('"') or leaf_val.startswith("'")) and \
       (leaf_val.endswith('"')   or leaf_val.endswith("'")):
        leaf_val = leaf_val[1:-1]
    return leaf_val

# Returns flat math expression list from given tree
def lua_exp_to_math_expr(expr, body_locals, lua_fname, ignore_fail=False):
    leaf_expr = expr
    leaf_val = [ ]
    if (expr[0].name == 'exp'):
        leaf_val += lua_exp_to_math_expr(expr[1], body_locals, lua_fname, ignore_fail)
        for expr1 in expr[2:]:
            if (isinstance(expr1[0], lrparsing.Token)):
                leaf_val.append(expr1[1])
            elif (expr1[0].name == 'exp'):
                leaf_val += lua_exp_to_math_expr(expr1, body_locals, lua_fname, ignore_fail)
            else:
                eprint("{:s}: Warning: Member of 'exp' in math expression was not recognized".format(lua_fname))
                #print("pp "+str(expr1[0]))
        pass
    elif (expr[0].name == 'prefix_exp'):
        var_out = lua_exp_variable_ref_to_string(expr, lua_fname, ignore_fail=True)
        if len(var_out) > 0:
            if var_out not in body_locals:
                leaf_val += [ var_out ]
            elif body_locals[var_out][0] in [ ValueSim.Number, ValueSim.MathExpr ]:
                leaf_val += body_locals[var_out][1:]
            elif body_locals[var_out][0] in [ ValueSim.LenPktWhole, ValueSim.LenPktPayload ]:
                leaf_val += [ body_locals[var_out][0] ]
            else:
                leaf_val += [ var_out ]
        var_out = lua_exp_to_integer(expr, lua_fname, ignore_fail=True)
        if isinstance(var_out, numbers.Number):
            leaf_val += [ var_out ]
    elif (expr[0].name == 'number'):
        var_out = lua_exp_to_integer(expr, lua_fname, ignore_fail=True)
        if isinstance(var_out, numbers.Number):
            leaf_val += [ var_out ]
    else:
        eprint("{:s}: Warning: Operand in math expression was not recognized".format(lua_fname))
        #print("oo "+str(expr)+" "+str(type(expr[0])))
    return leaf_val

def simplify_math_expr(val_list, lua_fname):
    out_list = [ ]
    number_op = None
    number_val = 0
    for var_out in val_list:
        if isinstance(var_out, str) and (var_out in [ "'+'", '-' ]):
            number_op = var_out
        elif isinstance(var_out, numbers.Number):
            if (number_op == '-'):
                number_val -= var_out
            else:
                number_val += var_out
            number_op = None
        else:
            if number_op is not None:
                out_list += [ number_op ]
                number_op = None
            out_list += [ var_out ]
    if (number_val > 0):
        out_list += [ "'+'", number_val ]
    elif (number_val < 0):
        out_list += [ '-', -number_val ]
    # Now check for known expessions
    if out_list == [ ValueSim.LenPktWhole, '-', 13 ]:
        return [ ValueSim.LenPktPayload ]
    return out_list

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

def lua_get_function_decl_st_name(expr):
    leaf_name = ''
    leaf_expr = expr
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
            eprint("Warning: Unexpected expression in function declaration name: '{:s}'".format(expr1[0].name))
    return leaf_name

def lua_get_function_decl_st_args(expr):
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

def lua_get_function_decl_st_body(expr):
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
    if got_function_call:
        for expr1 in leaf_expr:
            if (not isinstance(expr1, tuple)):
                continue
            if (expr1[0].name == 'prefix_exp'):
                leaf_expr = expr1
                break
            else:
                eprint("{:s}: Warning: Unexpected expression near prefix_exp: {:s}".format(lua_fname, expr1[0].name))
    for expr1 in leaf_expr:
        if (not isinstance(expr1, tuple)):
            continue
        if (expr1[0].name == 'var'):
            leaf_expr = expr1
            break
        else:
            eprint("{:s}: Warning: Unexpected expression near var: {:s}".format(lua_fname, expr1[0].name))
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
        eprint("{:s}: Warning: Could not get to variable ref name".format(lua_fname))
    leaf_val = str(leaf_val)
    return leaf_val

# Gets function args list from given function_call expression.
# If there is a method call after the main function call, it is ignored.
# Ie for "payload(offset,1):le_uint()" - this only analyses the part before ":".
def lua_get_function_call_args(expr, lua_fname):
    leaf_list = []
    leaf_expr = expr
    # We have two prefix_exp - at function_args leval, and above level
    # Check if there are function_args at current level; if no, then this
    # is high level prefix_exp which we should enter to find function_args
    leaf_check = None
    for expr1 in leaf_expr:
        if (not isinstance(expr1, tuple)):
            continue
        if (expr1[0].name == 'prefix_exp'):
            leaf_check = expr1[1]
        elif (expr1[0].name == 'function_args'):
            leaf_check = None
            break
        else:
            break # there may be other function_args after this, ie. after ':'; need to break
    if leaf_check is not None:
        leaf_expr = leaf_check
    for expr1 in leaf_expr:
        if (not isinstance(expr1, tuple)):
            continue
        if (expr1[0].name == 'function_args'):
            leaf_expr = expr1
            break
        elif (expr1[0].name == 'prefix_exp'):
            pass # ignore prefix_exp at this level as it leads to name
        elif (expr1[0].name == 'variable_ref'):
            return None # if we have only variable_ref at this point, then this is really just a variable reference, without args; ie. "payload:len()"
        else:
            #if leaf_check is not None:
            #    for expr9 in leaf_check:
            #        print("xx "+str(expr9)[:1000])
            #for expr9 in expr:
            #    print("yy "+str(expr9)[:1000])
            eprint("{:s}: Warning: Unexpected expression near function_args: {:s}".format(lua_fname, expr1[0].name))
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
            #if leaf_check is not None:
            #    for expr9 in leaf_check:
            #        print("tt "+str(expr9)[:1000])
            #for expr9 in expr:
            #    print("uu "+str(expr9)[:1000])
            eprint("{:s}: Warning: Unexpected expression near exp_list: {:s}".format(lua_fname, expr1[0].name))
            #for expr1 in expr:
            #    print(str(expr1)[:1000])
    for expr1 in leaf_expr:
        if (not isinstance(expr1, tuple)):
            continue
        if (expr1[0].name == 'exp'):
            leaf_list.append(expr1)
        elif (expr1[0].name == "','"):
            pass
        else:
            eprint("{:s}: Warning: Unexpected expression near exp: {:s}".format(lua_fname, expr1[0].name))
    #for expr1 in leaf_list:
    #    print("X "+str(len(expr1))+" "+str(expr1))
    return leaf_list

# Gets function call finishing converter name - the method name after ":", if any.
# Ie for "payload(offset,1):le_uint()" - this only returns the name after ":".
def lua_get_function_call_conv_name(expr, lua_fname):
    leaf_expr = expr
    leaf_allow = False
    leaf_check = None
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
        eprint("{:s}: Warning: Could not get to finisher function name".format(lua_fname))
    leaf_val = str(leaf_val)
    return leaf_val

# Converts one argument of a function call to ValueSim
def lua_get_function_param(arg_expr, body_locals, lua_fname):
    if arg_expr[0].name == 'exp':
        var_out = lua_exp_variable_ref_to_string(arg_expr[1], lua_fname, ignore_fail=True)
        if len(var_out) > 0:
            if var_out not in body_locals:
                return [ValueSim.VariableRef, var_out]
            else:
                return body_locals[var_out]
        var_out = lua_exp_to_integer(arg_expr[1], lua_fname, ignore_fail=True)
        if isinstance(var_out, numbers.Number):
            return [ValueSim.Number, var_out]
        # If this is not a simple type, check if it is math equation
        var_out = lua_exp_to_math_expr(arg_expr, body_locals, lua_fname, ignore_fail=True)
        if isinstance(var_out, list):
            var_out = simplify_math_expr(var_out, lua_fname)
            if len(var_out) == 1 and isinstance(var_out[0], ValueSim):
                return var_out
            return [ValueSim.MathExpr] + var_out
        eprint("{:s}: Error: Content of 'exp' not recognized".format(lua_fname))
        #print("nn "+str(arg_expr[1]))
    else:
        eprint("{:s}: Error: param not recognized".format(lua_fname))
    return None

def lua_get_assign_st_value_sim(local_name, assign_st, body_locals, lua_fname):
    value_sim = [ ValueSim.Nop ]
    leaf_expr = assign_st
    for expr1 in leaf_expr:
        if (not isinstance(expr1, tuple)) or (expr1[0].name != 'exp_list'):
            continue
        leaf_expr = expr1
    for expr1 in leaf_expr:
        if (not isinstance(expr1, tuple)) or (expr1[0].name != 'exp'):
            continue
        leaf_expr = expr1

    #print(local_name)
    val_number = None
    val_operator = []
    val_func = None
    val_func_args = None
    val_func_conv = None
    for expr1 in leaf_expr:
        if (not isinstance(expr1, tuple)):
            continue
        if (expr1[0].name == 'number'):
            if val_number is None:
                val_number = lua_exp_to_integer(expr1, lua_fname)
            else:
                eprint("{:s}: Error: too comlex, already got 'number' when 'number' came".format(lua_fname))
        elif (expr1[0].name == 'prefix_exp'):
            for expr2 in expr1:
                if (not isinstance(expr2, tuple)):
                    continue
                if (expr2[0].name != 'function_call'):
                    continue
                # assumed structure: call_name(call_args):convert_name()
                val_func = lua_get_function_call_name(expr2, lua_fname)
                val_func_args_exp = lua_get_function_call_args(expr2, lua_fname)
                val_func_conv = lua_get_function_call_conv_name(expr2, lua_fname)
                val_func_args = []
                # Convert args to a simpler form
                if (val_func_args_exp is not None):
                    for arg_expr in val_func_args_exp:
                        val_func_args.append(lua_get_function_param(arg_expr, body_locals, lua_fname))
                else:
                    eprint("{:s}: Error: Call without args '{:s}'".format(lua_fname,val_func))
                #print(val_func+": "+str(val_func_args)[:64] + ": " + str(val_func_conv))
        else:
            #print(str(expr1)[:1000])
            pass
    if val_func is not None:
        # Now recognize known items
        if val_func in body_locals:
            val_array_start = None
            val_array_size = None
            if body_locals[val_func][0] in [ValueSim.ArrayPktWhole, ValueSim.ArrayPktPayload, ValueSim.ArraySlice]:
                for arg_expr in val_func_args:
                    print("XXX !!! " + val_func + str(arg_expr))
                    pass # TODO - convert to ArraySlice
            else:
                eprint("{:s}: Warning: Unexpected local used, '{:s}'".format(lua_fname,val_func))

            if len(val_func_args) == 2:
                #print(str(val_func_args[0]) + " " + str(val_func_args[1]))
                #for expr3 in val_func_args[0]:
                #    print(expr3)
                #TODO
                val_array_start = 1
                val_array_size = 1
            else:
                eprint("{:s}: Error: Array args size {:d} is not supported".format(lua_fname,len(val_func_args)))

            if (val_array_start is not None) and (val_array_size is not None):
                value_sim[0] = ValueSim.ArraySlice
                value_sim.append(val_func)
                value_sim.append(val_array_start)
                value_sim.append(val_array_size)
            else:
                eprint("{:s}: Error: Array args not recognized for '{:s}'".format(lua_fname,val_func))
        else:
            eprint("{:s}: Error: Function call expected to be local array slice".format(lua_fname))
    #TODO
    elif val_number is not None:
        value_sim[0] = ValueSim.Number
        value_sim.append(val_number)
    #print(value_sim)
    return value_sim

def lua_function_call_dofile_to_string(expr, lua_fname):
    leaf_expr = expr
    is_dofile_call = False
    call_name = lua_get_function_call_name(leaf_expr, lua_fname)
    if (call_name == 'dofile'):
        is_dofile_call = True
        leaf_expr = lua_get_function_call_args(leaf_expr, lua_fname)
        #print(leaf_expr)
    # For confirmed "dofile" call, return first parameter (which is file name)
    if not is_dofile_call:
        return ''
    if len(leaf_expr) != 1:
        eprint("{:s}: Warning: Expected dofile() to have exactly one argument".format(lua_fname))
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
        eprint("{:s}: Warning: Could not get to string file name in dofile() call".format(lua_fname))
    leaf_val = str(leaf_val)
    if (leaf_val.startswith('"') or leaf_val.startswith("'")) and \
       (leaf_val.endswith('"')   or leaf_val.endswith("'")):
        leaf_val = leaf_val[1:-1]
    return leaf_val

def lua_function_body_get_conditional_statements(func):
    body_locals = {}
    if len(func['args']) != 4:
        eprint("Warning: Unexpected dissector function params count: {:d} instead of 4".format(len(func['args'])))
    var_name = func['args'][0] # 'pkt_length'
    body_locals[var_name] = [ ValueSim.LenPktWhole ]
    var_name = func['args'][1] # 'buffer'
    body_locals[var_name] = [ ValueSim.ArrayPktWhole ]
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
        for expr2 in expr1:
            if (not isinstance(expr2, tuple)):
                continue
            if (expr2[0].name == 'function_call_st'):
                for expr3 in expr2:
                     if (not isinstance(expr3, tuple)) or (expr3[0].name != 'function_call'):
                        continue
                continue #TODO
            elif (expr2[0].name == 'assign_st') or (expr2[0].name == 'local_assign_st'):
                local_name = lua_get_assign_st_full_name(expr2, func['fname'])
                local_val = lua_get_assign_st_value_sim(local_name, expr2, body_locals, func['fname'])
                body_locals[local_name] = local_val
                continue #TODO
            elif (expr2[0].name == 'if_st'):
                continue #TODO
            elif (expr2[0].name == 'while_st'):
                continue #TODO
            else:
                eprint("Warning: Unexpected expression in function body: '{:s}'".format(expr2[0].name))
                #print(str(expr2)[:200])
    return {}

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
    #TODO

    fh.close()
    return

# Returns 3 lists with trees of specific items.
# Each resulting tree has input file name appended to top item.
def lua_parse_file(po, grammar, lua_file):
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
        func['name'] = lua_get_function_decl_st_name(function_decl_st)
        func['args'] = lua_get_function_decl_st_args(function_decl_st)
        func['body'] = lua_get_function_decl_st_body(function_decl_st)
        func_is_dissector = False
        for cmdset, cmd_enum_list in duml_spec['DJI_DUMLv1_CMD_DISSECT_LIST'].items():
            for cmd, dissect_func_name in cmd_enum_list.items():
                if (func['name'] == dissect_func_name):
                    func_is_dissector = True
        if (func_is_dissector):
            func_cond = lua_function_body_get_conditional_statements(func)
            #TODO
        else:
            print("{:s}: Info: Function marked as not dissector: {:s}".format(func['fname'],func['name']))
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
          help="name of the input LUA file")

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
