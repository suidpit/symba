from symba.configuration import SymbaConfig
from symba import analysis
from sys import argv

symba = analysis.Symba(argv[1])

# Extract trigger conditions from the executable
conditions = symba.analyse()
