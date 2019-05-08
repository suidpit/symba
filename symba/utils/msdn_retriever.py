import argparse
import requests

from bs4 import BeautifulSoup

parser = argparse.ArgumentParser(
    description="Easy retrieval of MSDN docs into symba configs.",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter)

parser.add_argument(
    'url_file',
    action='store',
    help='Name of file containing a list of MSDN URL to import.')
parser.add_argument(
    '--config-outfile',
    dest='out-config',
    action='store',
    help='Name of file which should be generated with symba configs.',
    default='out')

args = parser.parse_args()

with open(args.url_file, 'r') as f:
    msdns = [url.strip() for url in f]

for msdn in msdns:
    r = requests.get(msdn)
    from IPython import embed; embed()
