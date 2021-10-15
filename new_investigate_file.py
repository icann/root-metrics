#!/usr/bin/env python3
import gzip, pickle, pprint, sys

''' For debugging input files that are found to have issues '''

if not len(sys.argv) > 1:
	exit("Arguments are a pickle.gz file, and optionally a record, to investigate")
in_file = sys.argv[1]
get_resp = None
if len(sys.argv) = 3:
	get_resp = int(sys.argv[2])
with gzip.open(in_file, mode="rb") as f:
	in_pickle = f.read()
in_obj = pickle.loads(in_pickle)
resp_count = 0
print("There are {} responses".format(len(in_obj["r"])))
for this_response in in_obj["r"]:
	resp_count += 1
	if get_resp == None:
		print(resp_count)
		pprint.pprint(this_response, compact=False)
	elif get_resp == resp_count:
		print(resp_count)
		pprint.pprint(this_response, compact=False)
