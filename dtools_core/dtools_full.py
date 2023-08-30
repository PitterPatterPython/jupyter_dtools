#!/usr/bin/python

# Base imports for all integrations, only remove these at your own risk!
import json
import sys
import os
import time
import pandas as pd
from collections import OrderedDict
import re
from integration_core import Integration
import datetime
from IPython.core.magic import (Magics, magics_class, line_magic, cell_magic, line_cell_magic)
from IPython.core.display import HTML
import domaintools
from io import StringIO

from dtools_core._version import __desc__

from jupyter_integrations_utility.batchquery import df_expand_col
# Your Specific integration imports go here, make sure they are in requirements!
import jupyter_integrations_utility as jiu
#import IPython.display
from IPython.display import display_html, display, Javascript, FileLink, FileLinks, Image
import ipywidgets as widgets

@magics_class
class Dtools(Integration):
    # Static Variables
    # The name of the integration
    name_str = "dtools"
    instances = {}
    custom_evars = ["dtools_conn_default", "dtools_verify_ssl", "dtools_rate_limit"]
    # These are the variables in the opts dict that allowed to be set by the user. These are specific to this custom integration and are joined
    # with the base_allowed_set_opts from the integration base

    # These are the variables in the opts dict that allowed to be set by the user. These are specific to this custom integration and are joined
    # with the base_allowed_set_opts from the integration base
    custom_allowed_set_opts = ["dtools_conn_default", "dtools_verify_ssl", "dtools_rate_limit"]


    help_text = ""
    help_dict = {}
    myopts = {}
    myopts['dtools_conn_default'] = ["default", "Default instance to connect with"]
    myopts['dtools_verify_ssl'] = [True, "Verify integrity of SSL"]
    myopts['dtools_rate_limit'] = [True, "Limit rates based on domain tools user configuration"]

    apis = {
            "iris_enrich": None,
            "available_api_calls": "list",
            "account_information": "listprod",
            "iris_investigate": "kargs",
            "domain_profile": "singledom",
            "hosting_history": "singledom",
            "parsed_whois": "singledom",
            "reverse_whois": "queryargs",
            "whois_history": "queryargs_hist", 
            }


    # Class Init function - Obtain a reference to the get_ipython()
    def __init__(self, shell, debug=False, *args, **kwargs):
        super(Dtools, self).__init__(shell, debug=debug)
        self.debug = debug

        #Add local variables to opts dict
        for k in self.myopts.keys():
            self.opts[k] = self.myopts[k]

        self.load_env(self.custom_evars)
        self.parse_instances()
#######################################



    def retCustomDesc(self):
        return __desc__


    def customHelp(self, curout):
        n = self.name_str
        mn = self.magic_name
        m = "%" + mn
        mq = "%" + m
        table_header = "| Magic | Description |\n"
        table_header += "| -------- | ----- |\n"
        out = curout
        qexamples = []
        qexamples.append(["myinstance", "iris-enrich\ndomains=google.com,microsoft.com", "Run a Domain Tools query for iris-enrich"])
        qexamples.append(["", "iris-enrich\ndomains=google.com,yahoo.com", "Run a Domain Tools iris-enrich query"])
        out += self.retQueryHelp(qexamples)

        return out

    def customAuth(self, instance):
        result = -1
        inst = None
        if instance not in self.instances.keys():
            result = -3
            print("Instance %s not found in instances - Connection Failed" % instance)
        else:
            inst = self.instances[instance]
        if inst is not None:

            if inst['options'].get('useproxy', 0) == 1:
                myproxies = self.get_proxy_str(instance)
            else:
                myproxies = None

            inst['session'] = None
            mypass = ""
            if inst['enc_pass'] is not None:
                mypass = self.ret_dec_pass(inst['enc_pass'])
                inst['connect_pass'] = ""

            ssl_verify = self.opts['dtools_verify_ssl'][0]
            if isinstance(ssl_verify, str) and ssl_verify.strip().lower() in ['true', 'false']:
                if ssl_verify.strip().lower() == 'true':
                    ssl_verify = True
                else:
                    ssl_verify = False
            elif isinstance(ssl_verify, int) and ssl_verify in [0, 1]:
                if ssl_verify == 1:
                    ssl_verify = True
                else:
                    ssl_verify = False



            if myproxies is None:
                inst['session'] = domaintools.API(inst['user'], mypass, verify_ssl=self.opts['dtools_verify_ssl'][0], rate_limit=self.opts['dtools_rate_limit'][0])
            else:
                inst['session'] = domaintools.API(inst['user'], mypass, proxy_url=myproxies, verify_ssl=self.opts['dtools_verify_ssl'][0], rate_limit=self.opts['dtools_rate_limit'][0])

            try:
                api_calls = inst['session'].available_api_calls()
                inst['available_apis'] = api_calls
                inst['available_apis'].append('available_api_calls')
                if self.debug:
                    print("Available APIs:")
                    for a in api_calls:
                        print(a)


                original_stdout = sys.stdout
                sys.stdout = StringIO()
                help(inst['session'])
                help_text = sys.stdout.getvalue()
                sys.stdout = original_stdout
                self.help_text = help_text
                self.parse_help_text()



                result = 0
            except Exception as e:
                e_err = str(e)
                if e_err.find("The credentials you entered do not match an active account.") >= 0:
                    print("Bad Credentials, please try again")
                    result = -1
                else:
                    print(f"Unknown Error: {e_err}")
                    result = -2

        return result


    def parse_query(self, query):

        q_items = query.split("\n")
        end_point = q_items[0].strip()
        if len(q_items) > 1:
            end_point_vars = q_items[1].strip()
        else:
            end_point_vars = None

        return end_point, end_point_vars

    def validateQuery(self, query, instance):
        bRun = True
        bReRun = False

        if self.instances[instance]['last_query'] == query:
            # If the validation allows rerun, that we are here:
            bReRun = True
        # Example Validation

        # Warn only - Don't change bRun
        # Basically, we print a warning but don't change the bRun variable and the bReRun doesn't matter

        inst = self.instances[instance]
        ep, ep_vars = self.parse_query(query)

        if ep not in inst['available_apis'] + ['help']:
            print(f"Endpoint: {ep} not in available APIs: {inst['available_apis']}")
            bRun = False
            if bReRun:
                print("Submitting due to rerun")
                bRun = True
        if ep not in list(self.apis.keys()) + ['help']:
            print(f"Endpoint: {ep} data transform not defined - Rerun at your own risk")
            bRun = False
            if bReRun:
                print(f"Running endpoint: {ep} with default (none) transform - Errors may occur")
                bRun = True
        return bRun


    def call_help(self, help_call, instance):
        if help_call is None or help_call == "":
            print(f"{'Available API':<25}{'Transform':<10}")
            print("----------------------------------------")
            print(f"{'all':<25}{'NA':<10}")
            for x in self.instances[instance]['available_apis']:
                bTransform = False
                if x in self.apis:
                    bTransform = True
                print(f"{x:<25}{bTransform:<10}")

        elif help_call == "all":
            print("All Help Methods")
            print("")
            print(f"{'Method':<50}{'Available':<10}{'Transform':<10}")
            print("--------------------------------------------------------------------")
            for x in self.help_dict.keys():
                bAvail = False
                bTransform = False
                if x in self.apis:
                    bTransform = True
                if x in self.instances[instance]['available_apis']:
                    bAvail = True
                print(f"{x:<50}{bAvail:<10}{bTransform:<10}")
        elif help_call not in self.help_dict:
            print(f"Provided help {help_call} not in help dictionary")
        else:
            print("************")
            print("Domain Tools Help")
            print("")
            print(f"{'Method: ':<12}{help_call}")
            print(f"{'Example: ':<12}{self.help_dict[help_call]['title']}")
            print("")
            print("\n".join(self.help_dict[help_call]['help']))
            print("")

    def customQuery(self, query, instance, reconnect=True):
        ep, ep_data = self.parse_query(query)
        ep_api = self.apis.get(ep, None)
        if self.debug:
            print(f"Query: {query}")
            print(f"Endpoint: {ep}")
            print(f"Endpoint Data: {ep_data}")
            print(f"Endpoint API Transform: {ep_api}")

        mydf = None
        status = ""
        str_err = ""
        if ep == "help":
            self.call_help(ep_data, instance)
            return mydf, "Success - No Results"


        if ep == 'iris_enrich':
            ep_data = ep_data.replace("'", "")

        try:
            if ep_api is None:
                myres = self.instances[instance]['session'].__getattribute__(ep)(ep_data).response().get('results', [])
            elif ep_api == "list":
                myres = self.instances[instance]['session'].__getattribute__(ep)()
            elif ep_api == "listprod":
                myres = self.instances[instance]['session'].__getattribute__(ep)().response().get('products', [])
            elif ep_api == "singledom":
                myres = [self.instances[instance]['session'].__getattribute__(ep)(ep_data).response()]
            elif ep_api == "kargs":
                arg_lines = ep_data.split("\n")
                these_args = {}
                for l in arg_lines:
                    if l.find("=") >= 0:
                        l_i = l.split("=")
                        these_args[l_i[0].strip()] = l_i[1].strip()
                    else:
                        print(f"No = in {l} not processing as arg")
                if self.debug:
                    for k, v in these_args.items():
                        print(f"{k} - {v}")
                myres = self.instances[instance]['session'].__getattribute__(ep)(**these_args).response().get('results', [])
            elif ep_api.find("queryargs") == 0:
                arg_lines = ep_data.split("\n")
                these_args = {}
                these_args['query'] = arg_lines[0]
                for l in arg_lines[1:]:
                    if l.find("=") >= 0:
                        l_i = l.split("=")
                        these_args[l_i[0].strip()] = l_i[1].strip()
                    else:
                        print(f"No = in {l} not processing as arg")
                if self.debug:
                    for k, v in these_args.items():
                        print(f"{k} - {v}")
                if ep_api == "queryargs":
                    myres = self.instances[instance]['session'].__getattribute__(ep)(**these_args).response().get('results', [])
                elif ep_api == "queryargs_hist":
                    myres = self.instances[instance]['session'].__getattribute__(ep)(**these_args).response().get('history', [])


            if myres is not None:
                if ep_api is None or ep_api in ['singledom', 'kargs', 'queryargs', 'listprod', 'queryargs_hist']:
                    mydf = pd.DataFrame(myres)
                    str_err = "Success"
                elif ep_api in ["list"]:
                    mydf = pd.DataFrame({ep: myres})
                    str_err = "Success"
                else:
                    print(f"Currently, transform {ep_api} is not supported") 
                    mydf = None
                    str_err = "Failure - Non-Supported Transform"
            else:
                mydf = None
                str_err = "Success - No Results"
        except Exception as e:
            mydf = None
            str_err = str(e)

        if str_err.find("Success") >= 0:
            pass
        else:
            status = "Failure - query_error: " + str_err

        return mydf, status


    def parse_help_text(self):

        help_lines = self.help_text.split("\n")
        bmethods = False
        methods_dict = {}
        method = ""
        method_name = ""
        method_text = []
        inmethod = False
        for l in help_lines:
            if l.find(" |  -------------------------") == 0:
                if inmethod:
                    methods_dict[method_name] = {"title": method, "help": method_text}
                    method = ""
                    method_name = ""
                    method_text = []
                    inmethod = False
                bmethods = False
            if bmethods:
                if l.strip() == "|":
                    continue
                f_l = l.replace(" |  ", "")
                if f_l[0] != ' ':
                    inmethod = True
                    if inmethod:
                        if method_name.strip() != "":
                            if method_name == "__init__":
                                method_name = "API"
                            methods_dict[method_name] = {"title": method, "help": method_text}
                            method = ""
                            method_name = ""
                            method_text = []
                    method = f_l
                    method_name = method.split("(")[0]
                else:
                    if inmethod:
                        method_text.append(f_l)
            if l.find("|  Methods defined here:") >= 0:
                bmethods = True
        self.help_dict = methods_dict

    # This is the magic name.
    @line_cell_magic
    def dtools(self, line, cell=None):
        if cell is None:
            line = line.replace("\r", "")
            line_handled = self.handleLine(line)
            if self.debug:
                print("line: %s" % line)
                print("cell: %s" % cell)
            if not line_handled: # We based on this we can do custom things for integrations. 
                if line.lower() == "testintwin":
                    print("You've found the custom testint winning line magic!")
                else:
                    print("I am sorry, I don't know what you want to do with your line magic, try just %" + self.name_str + " for help options")
        else: # This is run is the cell is not none, thus it's a cell to process  - For us, that means a query
            self.handleCell(cell, line)

##############################











