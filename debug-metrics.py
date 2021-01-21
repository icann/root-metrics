#!/usr/bin/env python3
""" Small tool for debugging correctness failures """

import gzip, os, pickle, sys, yaml

if len(sys.argv) == 1:
	exit("Need to give an argument in the form of '202011060425-505-60'. Exiting.")
this_rec = sys.argv[1]
# 202011060425-505-60
file_name = this_rec[:-3] + ".pickle.gz"
in_rec_num = this_rec[-2:]

n1 = "/home/metrics/Incoming/{}".format(file_name)
n2 = "/home/metrics/Incoming/{}/{}".format(file_name[0:6], file_name)
if os.path.exists(n1):
	full_file = n1
elif os.path.exists(n2):
	full_file = n2
else:
	exit("{} and {} did not exist. Exiting.".format(n1, n2))

print("Reading {}".format(full_file))
# Ungz it
try:
	with gzip.open(full_file, mode="rb") as pf:
		in_pickle = pf.read()
except Exception as e:
	exit("Could not unzip {}: '{}'".format(full_file, e))
# Unpickle it
try:
	in_obj = pickle.loads(in_pickle)
except Exception as e:
	exit("Could not unpickle {}: '{}'".format(full_file, e))
# Sanity check the record
if not ("d" in in_obj) and ("e" in in_obj) and ("r" in in_obj) and ("s" in in_obj) and ("v" in in_obj):
	exit("Object in {} did not contain keys d, e, r, s, and v".format(full_file))

r = in_obj["r"][int(in_rec_num) - 1]
print("{}   {}   {}".format(r[0], r[1], r[2]))
rmd = yaml.load(r[6])[0]["message"]["response_message_data"]
rmd_keys = list(rmd.keys())
for this_key in rmd_keys:
	if not "SECTION" in this_key:
		print("{:>10} {}".format(this_key, rmd[this_key]))
	else:
		if this_key == "OPT_PSEUDOSECTION":
			continue
		if len(rmd[this_key]) == 1:
			print("\n{}\n{}".format(this_key, rmd[this_key][0]))
		else:
			rmd_out = ""
			for this_rr in rmd[this_key]:
				if len(this_rr) < 100:
					rmd_out += "{}\n".format(this_rr)
				else:
					rmd_out += "{} ... {}\n".format(this_rr[:97], this_rr[-8:])
			print("\n{}\n{}".format(this_key, rmd_out))
	

