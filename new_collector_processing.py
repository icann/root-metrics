#!/usr/bin/env python3

''' Do all tasks on the collector to get data from the VPs, process it, and put the results in the database tables '''
# Run as the metrics user
# Three-letter items in square brackets (such as [xyz]) refer to parts of rssac-047.md

import argparse, datetime, glob, gzip, logging, os, pickle, psycopg2, socket, subprocess, tempfile, time
from pathlib import Path
from concurrent import futures
from collections import namedtuple

###############################################################

def run_tests_only():
	# Used to run local tests, then exit.
	log("Running tests instead of a real run")
	# Sanity check that you are in the Tests directory
	for this_check in [ "make_tests.py", "p-dot-soa", "root_name_and_types.pickle" ]:
		if not os.path.exists(this_check):
			exit("Did not find {} for running under --test. Exiting.".format(this_check))
	# Test the positives
	p_count = 0
	for this_test_file in sorted(Path(".").glob("p-*")):
		p_count += 1
		this_id = os.path.basename(this_test_file)
		this_resp_pickle = pickle.dumps(open(this_test_file, mode="rb"))
		this_response = ("test", process_one_correctness_array(["", [ "test" ], this_resp_pickle]))
		if this_response:
			log("Expected pass, but got failure, on {}\n{}\n".format(this_id, this_response))
	# Test the negatives
	n_count = 0
	# Collect the negative responses to put in a file
	n_responses = {}
	for this_test_file in sorted(Path(".").glob("n-*")):
		n_count += 1
		this_id = os.path.basename(this_test_file)
		in_lines = open(this_test_file, mode="rt").read().splitlines()
		n_responses[this_id] = {}
		n_responses[this_id]["desc"] = in_lines[0]
		this_resp_pickle = pickle.dumps(open(this_test_file, mode="rt"))
		this_response = ("test", process_one_correctness_array(["", [ "test" ], this_resp_pickle]))
		if not this_response:
			log("Expected failure, but got pass, on {}".format(this_id))
		else:
			n_responses[this_id]["resp"] = this_response
	log("Finished testing {} positive and {} negative tests".format(p_count, n_count))
	tests_results_file = "results.txt"
	out_f = open(tests_results_file, mode="wt")
	for this_id in n_responses:
		out_f.write("\n{}\n".format(n_responses[this_id]["desc"]))
		for this_line in n_responses[this_id]["resp"].splitlines():
			out_f.write("{}\n".format(this_line))
	out_f.close()
	die("Wrote out testing log as {}".format(tests_results_file))

###############################################################

def get_files_from_one_vp(this_vp):
	##################### Remove this before deploying #####################
	##### die("Was about to get_files_from_one_vp for {}".format(this_vp))
	########################################################################

	# Used to rsync files from VPs under multiprocessing into incoming_dir; retuns error messages
	(vp_number, _) = this_vp.split(".", maxsplit=1)
	pull_to_dir = f"{incoming_dir}/{vp_number}"
	if not os.path.exists(pull_to_dir):
		try:
			os.mkdir(pull_to_dir)
		except:
			die(f"Could not create {pull_to_dir}")
	# rsync from the VP
	for this_dir in ("Output", "Logs"):
		try:
			p = subprocess.run(f"rsync -av --timeout=5 metrics@{vp_number}.mtric.net:{this_dir} {pull_to_dir}/", shell=True, capture_output=True, text=True, check=True)
		except Exception as e:
			return f"For {vp_number}, failed to rsync {this_dir}: {e}"
		# Keep the log
		try:
			log_f = open(f"{pull_to_dir}/rsync-log.txt", mode="at")
			log_f.write(p.stdout)
			log_f.close()
		except:
			die(f"Could not write to log {pull_to_dir}/{vp_number}/rsync-log.txt") 
	return ""

###############################################################
def process_one_incoming_file(full_file_name):
	# Process an incoming file, and move it when done
	#   Returns nothing
	#   File-level errors cause "die", record-level errors cause "alert" and skipping the record
	
	# Open the database so that we can define the insert function
	conn = psycopg2.connect(dbname="metrics", user="metrics")
	conn.set_session(autocommit=True)

	# First define a function to insert records into one of the two databases
	def insert_from_template(this_update_cmd_string, this_update_values):
		try:
			curi = conn.cursor()
		except:
			alert("Could not get a cursor inside insert_from_template")
			return
		try:
			curi.execute(this_update_cmd_string, this_update_values)
		except Exception as e:
			alert("Could not insert with '{}' / '{}': '{}'".format(this_update_cmd_string, this_update_values, e))
		curi.close()
		return

	# Check for wrong type of file
	if not full_file_name.endswith(".pickle.gz"):
		alert("Found {} that did not end in .pickle.gz".format(full_file_name))
		return
	
	short_file_name = os.path.basename(full_file_name).replace(".pickle.gz", "")
	
	# Check if it is already in 
	
	# See if this file has already been processed
	cur = conn.cursor()
	cur.execute("select count(*) from files_gotten where filename_short = %s", (short_file_name, ))
	if cur.rowcount == -1:
		alert(f"Got rowcount of -1 for {short_file_name}; skipping this file")
		conn.close()
		return
	files_gotten_check = cur.fetchone()
	if files_gotten_check[0] > 0:
		alert(f"Found exiting instance of {short_file_name} in files_gotten; removing {full_file_name}")
		conn.close()
		try:
			os.remove(full_file_name)
		except:
			die(f"Could not remove {full_file_name} after finding {short_file_name} in files_gotten")
		return
	# Insert the short file name into the files_gotten database
	insert_string = "insert into files_gotten (filename_short, retrieved_at) values (%s, %s);"
	insert_values = (short_file_name, datetime.datetime.now(datetime.timezone.utc))
	insert_from_template(insert_string, insert_values)
	cur.close()
	
	# Un-gzip it
	try:
		with gzip.open(full_file_name, mode="rb") as pf:
			in_pickle = pf.read()
	except Exception as e:
		die(f"Could not unzip {full_file_name}: {e}")
	# Unpickle it
	try:
		in_obj = pickle.loads(in_pickle)
	except Exception as e:
		die(f"Could not unpickle {full_file_name}: {e}")
	# Sanity check the record
	if not ("v" in in_obj) and ("d" in in_obj) and ("e" in in_obj) and ("r" in in_obj) and ("s" in in_obj):
		alert(f"Object in {full_file_name} did not contain keys d, e, r, s, and v")
	
	# Update the metadata
	update_string = "update files_gotten set processed_at=%s, version=%s, delay=%s, elapsed=%s where filename_short=%s"
	update_vales = (datetime.datetime.now(datetime.timezone.utc), in_obj["v"], in_obj["d"], in_obj["e"], short_file_name) 
	insert_from_template(update_string, update_vales)

	# Get the derived date and VP name from the file name
	(file_date_text, _) = short_file_name.split("-")
	try:
		file_date = datetime.datetime(int(file_date_text[0:4]), int(file_date_text[4:6]), int(file_date_text[6:8]),\
			int(file_date_text[8:10]), int(file_date_text[10:12]))
	except Exception as e:
		conn.close()
		die("Could not split the file name '{}' into a datetime: '{}'".format(short_file_name, e))

	# Log the route information from in_obj["s"]
	if not in_obj.get("s"):
		alert("File {} did not have a route information record".format(full_file_name))
	else:
		update_string = "insert into route_info (filename_short, date_derived, route_string) values (%s, %s, %s)"
		update_values = (short_file_name, file_date, in_obj["s"]) 
		try:
			cur = conn.cursor()
			cur.execute(update_string, update_values)
			cur.close()
		except Exception as e:
			alert("Could not insert into route_info for {}: '{}'".format(short_file_name, e))

	# Named tuple for the record templates
	template_names_raw = "filename_record date_derived target internet transport ip_addr record_type query_elapsed timeout soa_found " \
		+ "recent_soas is_correct failure_reason source_pickle"
	# Change spaces to ", "
	template_names_with_commas = template_names_raw.replace(" ", ", ")
	# List of "%s, " for Postgres "insert" commands; remove trailing ", "
	percent_s_string = str("%s, " * len(template_names_raw.split(" ")))[:-2]
	# Create the template
	insert_values_template = namedtuple("insert_values_template", field_names=template_names_with_commas)
	
	# Go throught each response item
	response_count = 0
	for this_resp in in_obj["r"]:
		response_count += 1
		# Each record is "S" for an SOA record or "C" for a correctness test
		#   Sanity test that the type is S or C
		if not this_resp["test_type"] in ("S", "C"):
			alert("Found a response type {}, which is not S or C, in record {} of {}".format(this_resp["test_type"], response_count, full_file_name))
			continue
		insert_template = "insert into record_info ({}) values ({})".format(template_names_with_commas, percent_s_string)
		# Note that the default value for is_correct is "?" so that the test for "has correctness been checked" can still be against "y" or "n", which is set below
		insert_values = insert_values_template(filename_record=f"{short_file_name}-{response_count}", date_derived=file_date, \
			target=this_resp["target"], internet=this_resp["internet"], transport=this_resp["transport"], ip_addr=this_resp["ip_addr"], record_type=this_resp["test_type"], \
			query_elapsed=0.0, timeout="", soa_found="", recent_soas=[], is_correct="?", failure_reason="", source_pickle=b"")
		# If the response code is wrong, treat it as a timeout; use the response code as the timeout message
		#   For "S" records   [ppo]
		#   For "C" records   [ote]
		this_response_code = this_resp.get("rcode")
		if not ((insert_values.record_type == "S" and this_response_code in ["NOERROR"]) or (insert_values.record_type == "C" and this_response_code in ["NOERROR", "NXDOMAIN"])):
			insert_values = insert_values._replace(timeout=this_response_code)
			insert_from_template(insert_template, insert_values)
			continue

		# What is left is the normal responses
		#   For these, leave the timeout as ""
		if not this_resp.get("query_elapsed"):
			alert("Found a message without query_elapsed in record {} of {}".format(response_count, full_file_name))
			continue
		insert_values = insert_values._replace(query_elapsed=this_resp["query_elapsed"])  # [aym]
		if insert_values.record_type == "S":
			if this_resp.get("answer") == None or len(this_resp["answer"]) == 0:
				alert("Found a message of type 'S' without an answer in record {} of {}".format(response_count, full_file_name))
				continue
			# This chooses only the first SOA record
			this_soa_record = this_resp["answer"][0]["rdata"][0]
			soa_record_parts = this_soa_record.split(" ")
			this_soa = soa_record_parts[6]
			insert_values = insert_values._replace(soa_found=this_soa)
		if insert_values.record_type == "C":
			# The correctness response contains the pickle of the whole response; to save space, don't do this for "S" records
			insert_values = insert_values._replace(source_pickle=pickle.dumps(this_resp))
			# Set is_correct to "?" so it can be checked later
			insert_values = insert_values._replace(is_correct="?")
		# Write out this record
		insert_from_template(insert_template, insert_values)
		continue
	# End of response items loop

	cur.close()
	return

###############################################################

def check_for_signed_rr(list_of_records_from_section, name_of_rrtype):
	# Part of correctness checking
	#   See if there is a record in the list of the given RRtype, and make sure there is also an RRSIG for that RRtype
	found_rrtype = False
	for this_full_record in list_of_records_from_section:
		rec_qtype = this_full_record["rdtype"]
		if rec_qtype == name_of_rrtype:
			found_rrtype = True
			break
	if not found_rrtype:
		return "No record of type {} was found in that section".format(name_of_rrtype)
	found_rrsig = False
	for this_full_record in list_of_records_from_section:
		rec_qtype = this_full_record["rdtype"]
		if rec_qtype == "RRSIG":
			found_rrsig = True
			break
	if not found_rrsig:
		return "One more more records of type {} were found in that section, but there was no RRSIG".format(name_of_rrtype)
	return ""
	
###############################################################

def process_one_correctness_array(tuple_of_type_and_filename_record):
	# request_type is "test" or "normal"
	#    For "normal", process one filename_record
	#    For "test", process one id/pickle_blob pair
	# Normally, this function returns nothing because it is writing the results into the record_info database
	#    However, if the type is "test", the function does not write into the database but instead returns the results as text
	(request_type, this_filename_record) = tuple_of_type_and_filename_record
	conn = psycopg2.connect(dbname="metrics", user="metrics")
	conn.set_session(autocommit=True)
	if request_type == "normal":
		try:
			cur = conn.cursor()
			cur.execute("select timeout, source_pickle from record_info where filename_record = %s", (this_filename_record, ))
		except Exception as e:
			alert("Unable to start check correctness on '{}': '{}'".format(this_filename_record, e))
			return
		this_found = cur.fetchall()
		cur.close()
		if len(this_found) > 1:
			alert(f"When checking correctness on {this_filename_record}, found {len(this_found)} records")
			return
		(this_timeout, this_resp_pickle) = this_found[0]
	elif request_type == "test":
		(this_timeout, this_resp_pickle) = this_found[0]
	else:
		alert(f"While running process_one_correctness_array on {this_filename_record}, got unknown first argument {request_type}")
		return

	# Before trying to load the pickled data, first see if it is a timeout; if so, set is_correct but move on [lbl]
	if not this_timeout == "":
		if opts.test:
			return "Timeout '{}' [lbl]".format(this_timeout)
		else:
			try:
				cur = conn.cursor()
				cur.execute("update record_info set (is_correct, failure_reason) = (%s, %s) where filename_record = %s", ("y", "timeout", this_filename_record))
				cur.close()
			except Exception as e:
				alert("Could not update record_info for timed-out {}: '{}'".format(this_filename_record, e))
			return
	
	# Get the pickled object		
	try:
		resp = pickle.loads(this_resp_pickle)
	except Exception as e:
		alert("Could not unpickle in record_info for {}: '{}'".format(this_filename_record, e))
		return
	
	# root_to_check is one of the roots from the 48 hours preceding the record
	if opts.test:
		try:
			root_to_check = pickle.load(open("root_name_and_types.pickle", mode="rb"))
		except:
			exit("While running under --test, could not find and unpickle 'root_name_and_types.pickle'. Exiting.")
	else:
		# Get the starting date from the file name, then pick all zone files whose names have that date or the date from the two days before
		start_date = datetime.date(int(this_filename_record[0:4]), int(this_filename_record[4:6]), int(this_filename_record[6:8]))
		start_date_minus_one = start_date - datetime.timedelta(days=1)
		start_date_minus_two = start_date - datetime.timedelta(days=2)
		soa_matching_date_files = []
		for this_start in [start_date, start_date_minus_one, start_date_minus_two]:
			soa_matching_date_files.extend(glob.glob(str(Path(f"{saved_matching_dir}/{this_start.strftime('%Y%m%d')}" + "*.matching.pickle"))))
		# See if any of the matching files are not listed in the recent_soas field in the record; if so, try the highest one
		soa_matching_date_files = sorted(soa_matching_date_files, reverse=True)
		if len(soa_matching_date_files) == 0:
			alert(f"Found no SOA matching files for {this_filename_record} with dates starting {start_date.strftime('%Y%m%d')}")
			return
		try:
			cur = conn.cursor()
			cur.execute("select recent_soas from record_info where filename_record = %s", (this_filename_record, ))
		except Exception as e:
			alert("Unable to select recent_soas in correctness on '{}': '{}'".format(this_filename_record, e))
			return
		this_found = cur.fetchall()
		cur.close()
		if len(this_found) > 1:
			alert("When checking recent_soas in corrrectness on '{}', found more than one record: '{}'".format(this_filename_record, this_found))
			return
		found_recent_soas = this_found[0]
		root_file_to_check = ""
		for this_file in soa_matching_date_files:
			this_soa = os.path.basename(this_file)[0:8]
			if this_soa in found_recent_soas:
				continue
			else:
				root_file_to_check = this_file
				soa_file_used_for_testing = os.path.basename(this_file)[0:10]
		if root_file_to_check == "":
			try:
				cur = conn.cursor()
				cur.execute("update record_info set (is_correct, failure_reason) = (%s, %s) where filename_record = %s", \
					("n", "Tried with all SOAs for 48 hours", this_filename_record))
				cur.close()
			except Exception as e:
				alert(f"Could not update record_info after end of SOAs in correctness checking after processing record {this_filename_record}: {e}")
			return

		# Try to read the file	
		soa_f = open(root_file_to_check, mode="rb")
		try:
			root_to_check = pickle.load(soa_f)
		except:
			alert(f"Could not unpickle root file {root_file_to_check} while processing {this_filename_record} for correctness")
			return
	
	# failure_reasons holds an expanding set of reasons
	#   It is checked at the end of testing, and all "" entries eliminted
	#   If it is empty, then all correctness tests passed
	failure_reasons = []

	# Check that each of the RRsets in the Answer, Authority, and Additional sections match RRsets found in the zone [vnk]
	#   This check does not include any RRSIG RRsets that are not named in the matching tests below. [ygx]
	# This check does not include any EDNS0 NSID RRset [pvz]
	# After this check is done, we no longer need to check RRsets from the answer against the root zone
	for this_section_name in [ "answer", "authority", "additional" ]:
		if resp.get(this_section_name):
			rrsets_for_checking = {}
			for this_full_record in resp[this_section_name]:
				rec_qname = this_full_record["name"]
				rec_qtype = this_full_record["rdtype"]
				if rec_qtype == "RRSIG":  # [ygx]
					continue
				this_key = f"{rec_qname}/{rec_qtype}"
				rec_rdata = this_full_record["rdata"]
				if not this_key in rrsets_for_checking:
					rrsets_for_checking[this_key] = set()
				for this_rdata_record in rec_rdata:
					rrsets_for_checking[this_key].add(this_rdata_record.upper())
			for this_rrset_key in rrsets_for_checking:
				if not this_rrset_key in root_to_check:
					failure_reasons.append(f"{this_rrset_key} was in the {this_section_name} section in the response, but not the root [vnk]")
				else:
					if not len(rrsets_for_checking[this_rrset_key]) == len(root_to_check[this_rrset_key]):
						failure_reasons.append("RRset {} in {} in response has a different length than {} in root zone [vnk]".\
							format(rrsets_for_checking[this_rrset_key], this_section_name, root_to_check[this_rrset_key]))
						continue
					if not rrsets_for_checking[this_rrset_key] == (root_to_check[this_rrset_key]).upper():
						# Before giving up, see if it is a mismatch in the text for IPv6 addresses
						#   First see if they are sets of one; if not, this will be a normal mismatch failure
						if len(rrsets_for_checking[this_rrset_key]) != 1 or len(root_to_check[this_rrset_key]) != 1:
							pass
						else:
							resp_val = rrsets_for_checking[this_rrset_key].pop()
							root_val = root_to_check[this_rrset_key].pop()
							try:
								resp_ipv6 = socket.inet_pton(socket.AF_INET6, resp_val)
								root_ipv6 = socket.inet_pton(socket.AF_INET6, root_val)
								if resp_ipv6 == root_ipv6:
									continue
							except:
								failure_reasons.append("RRset value '{}' in {} in response is different than '{}' in root zone [vnk]".\
									format(resp_val, this_section_name, root_val))
								continue
						failure_reasons.append("RRset value '{}' in {} in response is different than '{}' in root zone [vnk]".\
							format(rrsets_for_checking[this_rrset_key], this_section_name, root_to_check[this_rrset_key]))

	# Check that each of the RRsets that are signed have their signatures validated. [yds]
	#   Send all the records in each section to the function that checks for validity
	if opts.test:
		recent_soa_root_filename = "root_zone.txt"
	else:
		recent_soa_root_filename = f"{saved_root_zone_dir}/{soa_file_used_for_testing}.root.txt"
	if not os.path.exists(recent_soa_root_filename):
		alert("Could not find {} for correctness validation, so skipping".format(recent_soa_root_filename))
	else:
		for this_section_name in [ "answer", "authority", "additional" ]:
			if not resp.get(this_section_name):
				continue
			this_section_rrs = []
			for this_rec_in_section in resp[this_section_name]:
				this_section_rrs.extend(this_rec_in_section["rdata"])
			# Only act if this section has an RRSIG
			rrsigs_over_rrtypes = set()
			for this_in_rr_text in this_section_rrs:
				# The following splits into 5 parts to expose the first field of RRSIGs
				rr_parts = this_in_rr_text.split(" ", maxsplit=5)
				if len(rr_parts) > 3:
					if rr_parts[3] == "RRSIG":
						rrsigs_over_rrtypes.add(rr_parts[4])
			if len(rrsigs_over_rrtypes) > 0:
				validate_f = tempfile.NamedTemporaryFile(mode="wt")
				validate_fname = validate_f.name
				# Go through each record, and only save the RRSIGs and the records they cover
				for this_in_rr_text in this_section_rrs:
					rr_parts = this_in_rr_text.split(" ", maxsplit=4)
					if (rr_parts[3] == "RRSIG") or (rr_parts[3] in rrsigs_over_rrtypes):
						validate_f.write(this_in_rr_text+"\n")
				validate_f.seek(0)
				validate_p = subprocess.run("{}/getdns_validate -s {} {}".format(target_dir, recent_soa_root_filename, validate_fname),
					shell=True, text=True, check=True, capture_output=True)
				validate_output = validate_p.stdout.splitlines()[0]
				(validate_return, _) = validate_output.split(" ", maxsplit=1)
				if not validate_return == "400":
					failure_reasons.append("Validating {} in {} got error of '{}' [yds]".format(this_section_name, this_filename_record, validate_return))
				validate_f.close()
	
	# Check that all the parts of the resp structure are correct, based on the type of answer
	#   Only look at the first record in the question section
	question_record = resp["question"][0]
	this_qname = question_record["name"]
	this_qtype = question_record["rdtype"]
	if resp["rcode"] == "NOERROR":
		if (this_qname != ".") and (this_qtype == "NS"):  # Processing for TLD / NS [hmk]
			# The header AA bit is not set. [ujy]
			if "AA" in resp["flags"]:
				failure_reasons.append("AA bit was set [ujy]")
			# The Answer section is empty. [aeg]
			if resp.get("answer"):
				failure_reasons.append("Answer section was not empty [aeg]")
			# The Authority section contains the entire NS RRset for the query name. [pdd]
			if not resp.get("authority"):
				failure_reasons.append("Authority section was empty [pdd]")
			root_ns_for_qname = root_to_check["{}/NS".format(this_qname)]
			auth_ns_for_qname = set()
			for this_rec in resp["authority"]:
				rec_qtype = this_full_record["rdtype"]
				rec_rdata = this_full_record["rdata"]
				if not rec_qtype == "RRSIG":  # [ygx]
					if rec_qtype == "NS":
						auth_ns_for_qname.update(rec_rdata)
			if not auth_ns_for_qname == root_ns_for_qname:
				failure_reasons.append("NS RRset in Authority was '{}', but NS from root was '{}' [pdd]".format(auth_ns_for_qname, root_ns_for_qname))
			# If the DS RRset for the query name exists in the zone: [hue]
			if root_to_check.get("{}/DS".format(this_qname)):
				# The Authority section contains the signed DS RRset for the query name. [kbd]
				this_resp = check_for_signed_rr(resp["authority"], "DS")
				if this_resp:
					failure_reasons.append("{} [kbd]".format(this_resp))
			else:  # If the DS RRset for the query name does not exist in the zone: [fot]
				# The Authority section contains no DS RRset. [bgr]
				for this_rec in resp["authority"]:
					rec_qtype = this_full_record["rdtype"]
					if rec_qtype == "DS":
						failure_reasons.append("Found DS in Authority section [bgr]")
						break
				# The Authority section contains a signed NSEC RRset covering the query name. [mkl]
				has_covering_nsec = False
				for this_rec in resp["authority"]:
					rec_qname = this_full_record["name"]
					rec_qtype = this_full_record["rdtype"]
					if rec_qtype == "NSEC":
						if rec_qname == this_qname:
							has_covering_nsec = True
							break
				if not has_covering_nsec:
					failure_reasons.append("Authority section had no covering NSEC record [mkl]")
			# Additional section contains at least one A or AAAA record found in the zone associated with at least one NS record found in the Authority section. [cjm]
			#    Collect the NS records from the Authority section
			found_NS_recs = []
			for this_rec in resp["authority"]:
				rec_qtype = this_full_record["rdtype"]
				rec_rdata = this_full_record["rdata"]
				if rec_qtype == "NS":
					found_NS_recs.extend(rec_rdata)
			found_qname_of_A_AAAA_recs = []
			for this_rec in resp["additional"]:
				rec_qname = this_full_record["name"]
				rec_qtype = this_full_record["rdtype"]
				if rec_qtype in ("A", "AAAA"):
					found_qname_of_A_AAAA_recs.append(rec_qname)
			found_A_AAAA_NS_match = False
			for a_aaaa_qname in found_qname_of_A_AAAA_recs:
					if a_aaaa_qname in found_NS_recs:
						found_A_AAAA_NS_match = True
						break
			if not found_A_AAAA_NS_match:
				failure_reasons.append("No QNAMEs from A and AAAA in Additional {} matched NS from Authority {} [cjm]".format(found_qname_of_A_AAAA_recs, found_NS_recs))
		elif (this_qname != ".") and (this_qtype == "DS"):  # Processing for TLD / DS [dru]
			# The header AA bit is set. [yot]
			if not "AA" in resp["flags"]:
				failure_reasons.append("AA bit was not set [yot]")
			# The Answer section contains the signed DS RRset for the query name. [cpf]
			if not resp.get("answer"):
				failure_reasons.append("Answer section was empty [cpf]")
			else:
				# Make sure the DS is for the query name
				for this_rec in resp["answer"]:
					rec_qname = this_full_record["name"]
					rec_qtype = this_full_record["rdtype"]
					if rec_qtype == "DS":
						if not rec_qname == this_qname:
							failure_reasons.append("DS in Answer section had QNAME {} instead of {} [cpf]".format(rec_qname, this_qname))
				this_resp = check_for_signed_rr(resp["answer"], "DS")
				if this_resp:
					failure_reasons.append("{} [cpf]".format(this_resp))
			# The Authority section is empty. [xdu]
			if resp.get("authority"):
				failure_reasons.append("Authority section was not empty [xdu]")
			# The Additional section is empty. [mle]
			if resp.get("additional"):
				failure_reasons.append("Additional section was not empty [mle]")
		elif (this_qname == ".") and (this_qtype == "SOA"):  # Processing for . / SOA [owf]
			# The header AA bit is set. [xhr]
			if not "AA" in resp["flags"]:
				failure_reasons.append("AA bit was not set [xhr]")
			# The Answer section contains the signed SOA record for the root. [obw]
			this_resp = check_for_signed_rr(resp["answer"], "SOA")
			if this_resp:
				failure_reasons.append("{} [obw]".format(this_resp))
			# The Authority section contains the signed NS RRset for the root. [ktm]
			if not resp.get("authority"):
				failure_reasons.append("The Authority section was empty [ktm]")
			else:
				this_resp = check_for_signed_rr(resp["authority"], "NS")
				if this_resp:
					failure_reasons.append("{} [ktm]".format(this_resp))
		elif (this_qname == ".") and (this_qtype == "NS"):  # Processing for . / NS [amj]
			# The header AA bit is set. [csz]
			if not "AA" in resp["flags"]:
				failure_reasons.append("AA bit was not set [csz]")
			# The Answer section contains the signed NS RRset for the root. [wal]
			this_resp = check_for_signed_rr(resp["answer"], "NS")
			if this_resp:
				failure_reasons.append("{} [wal]".format(this_resp))
			# The Authority section is empty. [eyk]
			if resp.get("authority"):
				failure_reasons.append("Authority section was not empty [eyk]")
		elif (this_qname == ".") and (this_qtype == "DNSKEY"):  # Processing for . / DNSKEY [djd]
			# The header AA bit is set. [occ]
			if not "AA" in resp["flags"]:
				failure_reasons.append("AA bit was not set [occ]")
			# The Answer section contains the signed DNSKEY RRset for the root. [eou]
			this_resp = check_for_signed_rr(resp["answer"], "DNSKEY")
			if this_resp:
				failure_reasons.append("{} [eou]".format(this_resp))
			# The Authority section is empty. [kka]
			if resp.get("authority"):
				failure_reasons.append("Authority section was not empty [kka]")
			# The Additional section is empty. [jws]
			if resp.get("additional"):
				failure_reasons.append("Additional section was not empty [jws]")
		else:
			failure_reasons.append("Not matched: when checking NOERROR statuses, found unexpected name/type of {}/{}".format(this_qname, this_qtype))
	elif resp["rcode"] == "NXDOMAIN":  # Processing for negative responses [vcu]
		# The header AA bit is set. [gpl]
		if not "AA" in resp["flags"]:
			failure_reasons.append("AA bit was not set [gpl]")
		# The Answer section is empty. [dvh]
		if resp.get("answer"):
			failure_reasons.append("Answer section was not empty [dvh]")
		# The Authority section contains the signed . / SOA record. [axj]
		if not resp.get("authority"):
			failure_reasons.append("Authority section was empty [axj]")
		else:
			# Make sure the SOA record is for .
			for this_rec in resp["authority"]:
				rec_qname = this_full_record["name"]
				rec_qtype = this_full_record["rdtype"]
				if rec_qtype == "SOA":
					if not rec_qname == ".":
						failure_reasons.append("SOA in Authority section had QNAME {} instead of '.' [vcu]".format(rec_qname))
			this_resp = check_for_signed_rr(resp["authority"], "SOA")
			if this_resp:
				failure_reasons.append("{} [axj]".format(this_resp))
			# The Authority section contains a signed NSEC record covering the query name. [czb]
			#   Note that the query name might have multiple labels, so only compare against the last label
			this_qname_TLD = this_qname.split(".")[-2] + "."
			nsec_covers_query_name = False
			nsecs_in_authority = []
			for this_rec in resp["authority"]:
				rec_qname = this_full_record["name"]
				rec_qtype = this_full_record["rdtype"]
				rec_rdata = this_full_record["rdata"]
				if rec_qtype == "NSEC":
					# Just looking at the first NSEC record
					nsec_parts = rec_rdata[0].split(" ")
					nsec_parts_covered = nsec_parts[0]
					# Sorting against "." doesn't work, so instead use the longest TLD that could be in the root zone
					if nsec_parts_covered == ".":
						nsec_parts_covered = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
					nsecs_in_authority.append("{}|{}".format(rec_qname, nsec_parts_covered))
					# Make a list of the three strings, then make sure the original QNAME is in the middle
					test_sort = sorted([rec_qname, nsec_parts_covered, this_qname_TLD])
					if test_sort[1] == this_qname_TLD:
						nsec_covers_query_name = True
						break
			if not nsec_covers_query_name:
				failure_reasons.append("NSECs in Authority '{}' did not cover qname '{}' [czb]".format(nsecs_in_authority, this_qname))
			# The Authority section contains a signed NSEC record with owner name “.” proving no wildcard exists in the zone. [jhz]
			nsec_with_owner_dot = False
			for this_rec in resp["authority"]:
				rec_qname = this_full_record["name"]
				rec_qtype = this_full_record["rdtype"]
				if rec_qtype == "NSEC":
					if rec_qname == ".":
						nsec_with_owner_dot = True
						break;
			if not 	nsec_with_owner_dot:
				failure_reasons.append("Authority section did not contain a signed NSEC record with owner name '.' [jzh]")
		# The Additional section is empty. [trw]
		if resp.get("additional"):
			failure_reasons.append("Additional section was not empty [trw]")
	else:
		failure_reasons.append("Response had a status other than NOERROR and NXDOMAIN")
	
	# See if the results were all positive
	#    Remove all entries which are blank
	pared_failure_reasons = []
	for this_element in failure_reasons:
		if not this_element == "":
			pared_failure_reasons.append(this_element)
	failure_reason_text = "\n".join(pared_failure_reasons)
	if failure_reason_text == "":
		make_is_correct = "y"
	else:
		make_is_correct = "n"	
	if opts.test:
		return failure_reason_text
	else:
		try:
			cur = conn.cursor()
			cur.execute("update record_info set (is_correct, failure_reason) = (%s, %s) where filename_record = %s", \
				(make_is_correct, failure_reason_text, this_filename_record))
			cur.close()
		except Exception as e:
			alert("Could not update record_info in correctness checking after processing record {}: '{}'".format(this_filename_record, e))
		return

###############################################################

if __name__ == "__main__":
	# Get the base for the log directory
	log_dir = f"{str(Path('~').expanduser())}/Logs"
	if not os.path.exists(log_dir):
		os.mkdir(log_dir)
	# Set up the logging and alert mechanisms
	log_file_name = f"{log_dir}/log.txt"
	alert_file_name = f"{log_dir}/alert.txt"
	vp_log = logging.getLogger("logging")
	vp_log.setLevel(logging.INFO)
	log_handler = logging.FileHandler(log_file_name)
	log_handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
	vp_log.addHandler(log_handler)
	vp_alert = logging.getLogger("alerts")
	vp_alert.setLevel(logging.CRITICAL)
	alert_handler = logging.FileHandler(alert_file_name)
	alert_handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
	vp_alert.addHandler(alert_handler)
	def log(log_message):
		vp_log.info(log_message)
	def alert(alert_message):
		vp_alert.critical(alert_message)
		log(alert_message)
	def die(error_message):
		vp_alert.critical(error_message)
		log("Died with '{}'".format(error_message))
		exit()
	
	limit_size = 1000
	
	this_parser = argparse.ArgumentParser()
	this_parser.add_argument("--test", action="store_true", dest="test",
		help="Run tests on requests; must be run in the Tests directory")
	this_parser.add_argument("--source", action="store", dest="source", default="vps",
		help="Specify 'vps' or 'skip' to say where to pull recent files")
	this_parser.add_argument("--limit", action="store_true", dest="limit",
		help="Limit procesing to {} items".format(limit_size))
	
	opts = this_parser.parse_args()
	if opts.limit:
		log("Limiting record processing to {} records".format(limit_size))

	# Make sure opts.source is "vps" or "skip"
	if not opts.source in ("vps", "skip"):
		die('The value for --source must be "vps" or "skip"')

	# Where the binaries are
	target_dir = "/home/metrics/Target"	
	# Where to store the incoming files comeing from the vantage points
	incoming_dir = f"{str(Path('~').expanduser())}/Incoming"
	if not os.path.exists(incoming_dir):
		os.mkdir(incoming_dir)
	# Where to save things long-term
	output_dir = f"{str(Path('~').expanduser())}/Output"
	if not os.path.exists(output_dir):
		os.mkdir(output_dir)
	# Subdirectories of log directory for root zones
	saved_root_zone_dir = "{}/RootZones".format(output_dir)
	if not os.path.exists(saved_root_zone_dir):
		os.mkdir(saved_root_zone_dir)
	saved_matching_dir = "{}/RootMatching".format(output_dir)
	if not os.path.exists(saved_matching_dir):
		os.mkdir(saved_matching_dir)

	###############################################################

	# Tests can be run outside the normal cron job. Exits when done.
	#   This is only run from the command line, not from cron.
	if opts.test:
		run_tests_only()
		exit()

	###############################################################

	log("Started overall collector processing")
	
	###############################################################
	
	# First active step is to copy new files to the collector

	if opts.source == "vps":
		# Get the list of VPs
		log("Started pulling from VPs")
		vp_list_filename = f"{str(Path('~').expanduser())}/vp_list.txt"
		try:
			all_vps = open(vp_list_filename, mode="rt").read().splitlines()
		except Exception as e:
			die("Could not open {} and split the lines: '{}'".format(vp_list_filename, e))
		# Make sure we have trusted each one
		known_hosts_set = set()
		known_host_lines = open(f"{str(Path('~').expanduser())}/.ssh/known_hosts", mode="rt").readlines()
		for this_line in known_host_lines:
			known_hosts_set.add(this_line.split(" ")[0])
		for this_vp in all_vps:
			if not this_vp in known_hosts_set:
				try:
					subprocess.run("ssh-keyscan -4 -t rsa {} >> ~/.ssh/known_hosts".format(this_vp), shell=True, capture_output=True, check=True)
					log("Added {} to known_hosts".format(this_vp))
				except Exception as e:
					die("Could not run ssh-keyscan on {}: {}".format(this_vp, e))
		with futures.ProcessPoolExecutor() as executor:
			for (this_vp, this_ret) in zip(all_vps, executor.map(get_files_from_one_vp, all_vps)):
				if not this_ret == "":
					alert(this_ret)
		log("Finished pulling from VPs; got files from {} VPs".format(len(all_vps)))
	
	elif opts.source == "skip":
		# Don't do any source gathering
		log("Skipped getting sources because opts.source was 'skip'")

	###############################################################

	# Go through the files in incoming_dir
	log(f"Started going through {incoming_dir}")
	all_files = [ str(x) for x in Path(f"{incoming_dir}").glob("**/*.pickle.gz") ]
	# If limit is set, use only the first few
	if opts.limit:
		all_files = all_files[0:limit_size]
	processed_incoming_count = 0
	processed_incoming_start = time.time()
	with futures.ProcessPoolExecutor() as executor:
		for (this_file, _) in zip(all_files, executor.map(process_one_incoming_file, all_files)):
			processed_incoming_count += 1
	log("Finished processing {} files in Incoming in {} seconds".format(processed_incoming_count, int(time.time() - processed_incoming_start)))

	###############################################################

	# Now that all the measurements are in, go through all records in record_info where is_correct is "?"
	#   This is done separately in order to catch all earlier attempts where there was not a good root zone file to compare
	#   This does not log or alert; that is left for a different program checking when is_correct is not "?"

	# Iterate over the records where is_correct is "?"
	try:
		conn = psycopg2.connect(dbname="metrics", user="metrics")
		cur = conn.cursor()
		cur.execute("select filename_record from record_info where record_type = 'C' and is_correct = '?'")
	except Exception as e:
		conn.close()
		die("Unable to start processing correctness with 'select' request: '{}'".format(e))
	initial_correct_to_check = cur.fetchall()
	conn.close()
	# Make a list of tuples with the filename_record
	full_correctness_list = []
	for this_initial_correct in initial_correct_to_check:
		full_correctness_list.append(("normal", this_initial_correct[0]))
	# If limit is set, use only the first few
	if opts.limit:
		full_correctness_list = full_correctness_list[0:limit_size]
	log("Started correctness checking on {} found".format(len(full_correctness_list)))
	processed_correctness_count = 0
	processed_correctness_start = time.time()
	with futures.ProcessPoolExecutor() as executor:
		for (this_correctness, _) in zip(full_correctness_list, executor.map(process_one_correctness_array, full_correctness_list, chunksize=1000)):
			processed_correctness_count += 1
	log("Finished correctness checking {} files in {} seconds".format(processed_correctness_count, int(time.time() - processed_correctness_start)))
	
	###############################################################
	
	# STILL TO DO: Validation in correctness checking
	
	###############################################################
	
	log("Finished overall collector processing")	
	exit()
