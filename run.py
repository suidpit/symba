from symba import analysis
from sys import argv

symba = analysis.Symba(argv[1])

# Loads symba with analysis information
symba.analyse()
