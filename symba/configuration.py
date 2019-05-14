"""
A SymbaConfig is charged with the task of parsing
configuration files into FunctionSignatures,
generating TriggerSources accordingly.
For more information about the syntax
of configuration files, ask the author.
HAHAHAHAHAHA
"""
import json

from collections import namedtuple
from symba.source import GenericModel

# TODO: add constraints to the game.
# Using namedtuples instead of classes because no methods, just sweet records.
sig = namedtuple('FunctionSignature', ['name', 'params'])
param = namedtuple('FunctionParam', ['type', 'name', 'inject', 'length'])


class SymbaConfig(object):

    def __init__(self, config_file):
        """[summary]
        Parses input JSON, generates TriggerSources
        and load them into the symba object,
        ready for analysis.
        Arguments:
            symba {Symba} -- The Symba analysis object where triggers will be loaded.
            config_file {str} -- A configuration file to load function signatures from.
        """
        self.config_file = config_file
        self.signatures = []
        self.models = []
        self._parse_json()

        for sig in self.signatures:
            self.models.append(GenericModel(sig))

    def _parse_json(self):
        with open(self.config_file, 'r') as f:
            d = json.load(f)
        for func in d['functions']:
            params = [param(**p) for p in func['params']]
            self.signatures.append(sig(func['name'], params))
