#!/usr/bin/env python3
import gzip, os, pickle, pprint, sys

''' For debugging input files that are found to have issues '''

if not len(sys.argv) == 2:
	exit("Argument is a filename_record value from the record_info database")
this_arg = sys.argv[1]
try:
	(this_datetime, this_vp, this_recno_str) = this_arg.split("-")
except:
	exit("The argument must be in the form yyyymmddhhmm-nnn-mm")
this_dir = f"/home/metrics/Incoming/{this_vp}/Output"
if not os.path.exists(this_dir):
	exit(f"Could not find {this_dir}")
in_file = f"{this_dir}/{this_datetime}-{this_vp}.pickle.gz"
if not os.path.exists(in_file):
	exit(f"Could not find {in_file}")
try:
	this_recno = int(this_recno_str)
except:
	exit(f"{this_arg} does not end with an integer")
	
with gzip.open(in_file, mode="rb") as f:
	in_pickle = f.read()
in_obj = pickle.loads(in_pickle)
if len(in_obj['r']) < this_recno:
	exit(f"The structure in {in_file} has {len(in_obj['r'])} records, which is less than the last argument, {this_recno}")
	
resp_count = 0
for this_response in in_obj["r"]:
	resp_count += 1
	if this_recno == resp_count:
		pprint.pprint(this_response, compact=True, width=180)
		break
