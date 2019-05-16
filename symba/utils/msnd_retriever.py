import json
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
    dest='outconfig',
    action='store',
    help='Name of file which should be generated with symba configs.',
    default='out')

args = parser.parse_args()

with open(args.url_file, 'r') as f:
    msdns = [url.strip() for url in f]

out = {}
out['functions'] = []
# Matter of time and readability man
functions = out['functions']

for msdn in msdns:
    soup = BeautifulSoup(requests.get(msdn).text, 'html.parser')
    code = soup.find('code').get_text().split('\n')[:-2]

    # Shall we begin? Let's parse this code!

    function_name = code[0].split()[1][:-1]
    params = []

    for i, param in enumerate(code[1:]):
        t = param.split()[0]
        # Last argument is the only one without ','
        n = param.split()[1] if i == (len(code[1:]) - 1) else param.split()[1][:-1]
        params.append({'type': t, 'name': n, 'inject': False, 'length': "<DEFAULT>"})
    functions.append({'name': function_name, 'params': params})

with open(f"{args.outconfig}.json", 'w') as f:
    json.dump(out, f, indent=2)
