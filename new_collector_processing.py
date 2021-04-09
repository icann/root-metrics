#!/usr/bin/env python3

''' Do all tasks on the collector to get data from the VPs, process it, and put the results in the database tables '''
# Run as the metrics user
# Three-letter items in square brackets (such as [xyz]) refer to parts of rssac-047.md

import argparse, datetime, glob, gzip, logging, os, pickle, psycopg2, socket, subprocess, shutil, tempfile, time, yaml
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
	for this_test_file in sorted(glob.glob("p-*")):
		p_count += 1
		this_id = os.path.basename(this_test_file)
		this_resp_pickle = pickle.dumps(yaml.load(open(this_test_file, mode="rb")))
		this_response = ("test", process_one_correctness_array(["", [ "test" ], this_resp_pickle]))
		if this_response:
			log("Expected pass, but got failure, on {}\n{}\n".format(this_id, this_response))
	# Test the negatives
	n_count = 0
	# Collect the negative responses to put in a file
	n_responses = {}
	for this_test_file in sorted(glob.glob("n-*")):
		n_count += 1
		this_id = os.path.basename(this_test_file)
		in_lines = open(this_test_file, mode="rt").read().splitlines()
		n_responses[this_id] = {}
		n_responses[this_id]["desc"] = in_lines[0]
		this_resp_pickle = pickle.dumps(yaml.load(open(this_test_file, mode="rt")))
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
	die("Was about to get_files_from_one_vp for {}".format(this_vp))
	########################################################################

	# Used to pull files from VPs under multiprocessing; retuns the number of files pulled from this VP
	pulled_count = 0
	# Make a batch file for sftp that gets the directory
	dir_batch_filename = "{}/{}-dirbatchfile.txt".format(batch_dir, this_vp)
	dir_f = open(dir_batch_filename, mode="wt")
	dir_f.write("cd transfer/Output\ndir -1\n")
	dir_f.close()
	# Execuite sftp with the directory batch file
	try:
		p = subprocess.run("sftp -b {} transfer@{}".format(dir_batch_filename, this_vp), shell=True, capture_output=True, text=True, check=True)
	except Exception as e:
		log("Getting directory for {} ended with '{}'".format(dir_batch_filename, e))
		return pulled_count
	dir_lines = p.stdout.splitlines()

	conn = psycopg2.connect(dbname="metrics", user="metrics")
	conn.set_session(autocommit=True)
	
	# Get the filenames that end in .gz; some lines will be other cruft such as ">"
	for this_filename in dir_lines:
		if not this_filename.endswith(".gz"):
			continue
		# Create an sftp batch file for each file to get
		get_batch_filename = "{}/{}-getbatchfile.txt".format(batch_dir, this_vp)
		get_f = open(get_batch_filename, mode="wt")
		# Get the file
		get_cmd = "get transfer/Output/{} {}\n".format(this_filename, incoming_dir)
		get_f.write(get_cmd)
		get_f.close()
		try:
			p = subprocess.run("sftp -b {} transfer@{}".format(get_batch_filename, this_vp), shell=True, capture_output=True, text=True, check=True)
		except Exception as e:
			conn.close()
			die("Running get for {} ended with '{}'".format(this_filename, e))
		# Create an sftp batch file for each file to move
		move_batch_filename = "{}/{}-movebatchfile.txt".format(batch_dir, this_vp)
		move_f = open(move_batch_filename, mode="wt")
		# Get the file
		move_cmd = "rename transfer/Output/{0} transfer/AlreadySeen/{0}\n".format(this_filename)
		move_f.write(move_cmd)
		move_f.close()
		try:
			p = subprocess.run("sftp -b {} transfer@{}".format(move_batch_filename, this_vp), shell=True, capture_output=True, text=True, check=True)
		except Exception as e:
			conn.close()
			die("Running rename for {} ended with '{}'".format(this_filename, e))
		pulled_count += 1
		try:
			cur = conn.cursor()
			cur.execute("insert into files_gotten (filename_full, retrieved_at) values (%s, %s);", (this_filename, datetime.datetime.now(datetime.timezone.utc)))
			cur.close()
		except Exception as e:
			conn.close()
			die("Could not insert '{}' into files_gotten: '{}'".format(this_filename, e))
	conn.close()
	return pulled_count

###############################################################
def process_one_incoming_file(full_file):
	# Process an incoming file, and move it when done
	#   Returns nothing
	#   File-level errors cause "die", record-level errors cause "alert" and skipping the record
	
	# Check for bad file
	if not full_file.endswith(".pickle.gz"):
		alert("Found {} that did not end in .pickle.gz".format(full_file))
		return
	short_file = os.path.basename(full_file).replace(".pickle.gz", "")
	# Ungz it
	try:
		with gzip.open(full_file, mode="rb") as pf:
			in_pickle = pf.read()
	except Exception as e:
		die("Could not unzip {}: '{}'".format(full_file, e))
	# Unpickle it
	try:
		in_obj = pickle.loads(in_pickle)
	except Exception as e:
		die("Could not unpickle {}: '{}'".format(full_file, e))
	# Sanity check the record
	if not ("d" in in_obj) and ("e" in in_obj) and ("r" in in_obj) and ("s" in in_obj) and ("v" in in_obj):
		alert("Object in {} did not contain keys d, e, r, s, and v".format(full_file))

	# Move the file to ~/Originals/yyyymm so it doesn't get processed again
	year_from_short_file = short_file[0:4]
	month_from_short_file = short_file[4:6]
	original_dir_target = os.path.expanduser("~/Originals/{}{}".format(year_from_short_file, month_from_short_file))
	if not os.path.exists(original_dir_target):
		try:
			os.mkdir(original_dir_target)
		except Exception as e:
			log("Could not create {} but it might already have just been created; continuing".format(original_dir_target))
	try:
		shutil.move(full_file, original_dir_target)
	except Exception as e:
		die("Could not move {} to {}: '{}'".format(full_file, original_dir_target, e))

	conn = psycopg2.connect(dbname="metrics", user="metrics")
	conn.set_session(autocommit=True)

	# Function to insert records into one of the two databases
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

	# See if this file has already been processed
	this_pickle_gz = short_file + ".pickle.gz"
	cur = conn.cursor()
	cur.execute("select count(*) from files_gotten where filename_full = %s", (this_pickle_gz, ))
	if cur.rowcount == -1:
		alert("Got rowcount of -1 for {}; skipping this file".format(this_pickle_gz))
		conn.close()
		return
	files_gotten_check = cur.fetchone()
	if files_gotten_check[0] > 1:
		alert("Found mulitple instances of {} in files_gotten; ignoring this new one".format(short_file))
		conn.close()
		return
	# If the file is not there, probably due to rsyncing from c01
	insert_string = "insert into files_gotten (filename_full, retrieved_at) values (%s, %s);"
	insert_values = (this_pickle_gz, datetime.datetime.now(datetime.timezone.utc))
	insert_from_template(insert_string, insert_values)
	cur.close()
	
	# Update the metadata
	update_string = "update files_gotten set processed_at=%s, version=%s, delay=%s, elapsed=%s where filename_full=%s"
	update_vales = (datetime.datetime.now(datetime.timezone.utc), in_obj["v"], in_obj["d"], in_obj["e"], this_pickle_gz) 
	insert_from_template(update_string, update_vales)

	# Get the derived date and VP name from the file name
	(file_date_text, _) = short_file.split("-")
	try:
		file_date = datetime.datetime(int(file_date_text[0:4]), int(file_date_text[4:6]), int(file_date_text[6:8]),\
			int(file_date_text[8:10]), int(file_date_text[10:12]))
	except Exception as e:
		conn.close()
		die("Could not split the file name '{}' into a datetime: '{}'".format(short_file, e))

	# Log the route information from in_obj["s"]
	if not in_obj.get("s"):
		alert("File {} did not have a route information record".format(full_file))
	else:
		update_string = "insert into route_info (filename, date_derived, route_string) values (%s, %s, %s)"
		update_values = (short_file, file_date, in_obj["s"]) 
		try:
			cur = conn.cursor()
			cur.execute(update_string, update_values)
			cur.close()
		except Exception as e:
			alert("Could not insert into route_info for {}: '{}'".format(short_file, e))

	# Named tuple for the record templates
	template_names_raw = "filename_record date_derived rsi internet transport ip_addr record_type prog_elapsed dig_elapsed timeout soa_found " \
		+ "is_correct failure_reason source_pickle"
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
		if not this_resp[4] in ("S", "C"):
			alert("Found a response type {}, which is not S or C, in record {} of {}".format(this_resp[4], response_count, full_file))
			continue
		insert_template = "insert into record_info ({}) values ({})".format(template_names_with_commas, percent_s_string)
		# Note that the default value for is_correct is "?" so that the test for "has correctness been checked" can still be against "y" or "n", which is set below
		insert_values = insert_values_template(filename_record="{}-{}".format(short_file, response_count), date_derived=file_date, \
			rsi=this_resp[0], internet=this_resp[1], transport=this_resp[2], ip_addr=this_resp[3], record_type=this_resp[4], prog_elapsed=this_resp[5], \
			dig_elapsed=0.0, timeout="", soa_found="", is_correct="?", failure_reason="", source_pickle=b"")

		# If what was supposed to be YAML is an empty string, it means that dig could not get a route to the server
		#   In this case, make it a timeout, and don't fill in any other data [dfl] [dks]
		if len(this_resp[6]) == 0:
			insert_values = insert_values._replace(timeout="empty_yaml")
			insert_from_template(insert_template, insert_values)
			continue
			
		# Get it out of YAML and do basic sanity checks
		#   BIND sometimes puts out bad YAML by having colons at the end of unquoted strings for IPv6 addresses in AAAA records
		#   If so, add a "0" on those lines
		in_yaml_lines = this_resp[6].splitlines()
		for (line_number, this_line) in enumerate(in_yaml_lines):
			if len(this_line) > 0 and this_line.lstrip()[0] == "-" and this_line.rstrip().endswith(":"):
				in_yaml_lines[line_number] = in_yaml_lines[line_number] + "0"
		in_yaml_fixed = "\n".join(in_yaml_lines)
		try:
			this_resp_obj = yaml.load(in_yaml_fixed)
		except Exception as e:
			alert("Could not interpret YAML from {} of {}: '{}'".format(response_count, full_file, e))
			continue
		if not this_resp_obj[0].get("type"):
			alert("Found no dig type in record {} of {}".format(response_count, full_file))
			continue
		if not this_resp_obj[0]["type"] in ("MESSAGE", "DIG_ERROR"):
			alert("Found an unexpected dig type {} in record {} of {}".format(this_resp_obj[0]["type"], response_count, full_file))
			continue
		if not this_resp_obj[0].get("message"):
			alert("Found no message in record {} of {}".format(response_count, full_file))
			continue

		# All DIG_ERROR responses should say "timed out" or "communications error" in the message
		if this_resp_obj[0]["type"] == "DIG_ERROR":
			if not (("timed out" in this_resp_obj[0]["message"]) or ("communications error" in this_resp_obj[0]["message"])):
				alert("Found unexpected dig error message '{}' in record {} of {}".format(this_resp_obj[0]["message"], response_count, full_file))
				continue
			insert_values = insert_values._replace(timeout="dig_error")
			insert_from_template(insert_template, insert_values)
			continue

		# If the response code is wrong, treat it as a timeout; use the response code as the timeout message
		#   For "S" records   [ppo]
		#   For "C" records   [ote]
		this_response_code = this_resp_obj[0]["message"]["response_message_data"]["status"]
		if not ((insert_values.record_type == "S" and this_response_code in ("NOERROR")) or (insert_values.record_type == "C" and this_response_code in ("NOERROR", "NXDOMAIN"))):
			insert_values = insert_values._replace(timeout=this_response_code)
			insert_from_template(insert_template, insert_values)
			continue

		# What is left is the normal responses
		#   For these, leave the timeout as ""
		if (not this_resp_obj[0]["message"].get("response_time")) or (not this_resp_obj[0]["message"].get("query_time")):
			alert("Found a message of type 'S' without response_time or query_time in record {} of {}".format(response_count, full_file))
			continue
		dig_elapsed_as_delta = this_resp_obj[0]["message"]["response_time"] - this_resp_obj[0]["message"]["query_time"]  # [aym]
		insert_values = insert_values._replace(dig_elapsed=datetime.timedelta.total_seconds(dig_elapsed_as_delta))
		if insert_values.record_type == "S":
			if not this_resp_obj[0]["message"].get("response_message_data").get("ANSWER_SECTION"):
				alert("Found a message of type 'S' without an answer in record {} of {}".format(response_count, full_file))
				continue
			this_soa_record = this_resp_obj[0]["message"]["response_message_data"]["ANSWER_SECTION"][0]
			soa_record_parts = this_soa_record.split(" ")
			this_soa = soa_record_parts[6]
			insert_values = insert_values._replace(soa_found=this_soa)
		if insert_values.record_type == "C":
			# The correctness response contains the pickle of the YAML; to save space, don't do this for "S" records
			insert_values = insert_values._replace(source_pickle=pickle.dumps(this_resp_obj))
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
		(rec_qname, _, _, rec_qtype, rec_rdata) = this_full_record.split(" ", maxsplit=4)
		if rec_qtype == name_of_rrtype:
			found_rrtype = True
			break
	if not found_rrtype:
		return "No record of type {} was found in that section".format(name_of_rrtype)
	found_rrsig = False
	for this_full_record in list_of_records_from_section:
		(rec_qname, _, _, rec_qtype, rec_rdata) = this_full_record.split(" ", maxsplit=4)
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
			alert("When checking corrrectness on '{}', found more than one record: '{}'".format(this_filename_record, this_found))
			return
		(this_timeout, this_resp_pickle) = this_found[0]
	elif request_type == "test":
		(this_timeout, this_resp_pickle) = this_found[0]
	else:
		alert("While running process_one_correctness_array on {}, got unknown first argument '{}'".format(this_filename_record, request_type))
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
		this_resp_obj = pickle.loads(this_resp_pickle)
	except Exception as e:
		alert("Could not unpickle in record_info for {}: '{}'".format(this_filename_record, e))
		return
	# Pick out the response message
	try:
		resp = this_resp_obj[0]["message"]["response_message_data"]
	except:
		alert("Could not get the response_message_data from the first message in {}".format(this_filename_record))
		return

	# Use this to finish checking; it appears in two places in the outer function
	#   The outer function needs to return after this call
	def update_database_when_finished(failure_reason_text, this_filename_record):
		out_result = "n" if len(failure_reason_text) > 0 else "y"
		try:
			cur = conn.cursor()
			cur.execute("update record_info set (is_correct, failure_reason) = (%s, %s) where filename_record = %s", (out_result, failure_reason_text, this_filename_record))
			cur.close()
		except Exception as e:
			alert("Could not update record_info in correctness checking after processing record {} as incorrect: '{}'".format(this_filename_record, e))
		return

	# Store the list of SOAs and files as tuples in soas_to_test
	if opts.test:
		soas_to_test = [ ("TEST-SOA", "root_name_and_types.pickle") ] 
	else:
		# Get the starting date from the file name, then pick all zone files whose names have that date or the date from the two days before
		start_date = datetime.date(int(this_filename_record[0:4]), int(this_filename_record[4:6]), int(this_filename_record[6:8]))
		start_date_minus_one = start_date - datetime.timedelta(days=1)
		start_date_minus_two = start_date - datetime.timedelta(days=2)
		matched_date_files = []
		# Note that a single date will have multiple SOAs, so add the files as groups
		for this_start in [start_date, start_date_minus_one, start_date_minus_two]:
			matched_date_files.extend(glob.glob("{}/{}*.matching.pickle".format(saved_matching_dir, this_start.strftime("%Y%m%d"))))
		if len(matched_date_files) == 0:
			alert("There were no matched files for start date {}".format(start_date))
			return
		# Store the list of SOAs in descending order by SOA
		soas_to_test = []
		for this_matched_file in sorted(matched_date_files, reverse=True):
			soas_to_test.append( ((os.path.basename(this_matched_file))[0:10], this_matched_file) )
			
	# Loop over the SOAs
	per_soa_results = {}
	for (this_soa, this_root_file) in soas_to_test:
		# Try to read the file	
		soa_f = open(this_root_file, mode="rb")
		try:
			root_to_check = pickle.load(soa_f)
		except:
			if opts.test:
				exit("While running under --test, could not find and unpickle 'root_name_and_types.pickle'. Exiting.")
			else:
				alert("Could not unpickle {} while processing {} for correctness".format(this_root_file, this_filename_record))
				return

		# failure_reasons holds an expanding set of reasons fore each run
		#   If it is empty, then all correctness tests passed
		# Start with no failure reasons
		failure_reasons = []

		# Check that all the parts of the resp structure are correct, based on the type of answer
		question_record = resp["QUESTION_SECTION"][0]
		(this_qname, _, this_qtype) = question_record.split(" ")
		if not resp["status"] in ("NOERROR", "NXDOMAIN"):
			failure_reasons.append("Response had a status other than NOERROR and NXDOMAIN")

		elif resp["status"] == "NOERROR":  # Process for positive responses
			if (this_qname != ".") and (this_qtype == "NS"):  # Processing for TLD / NS [hmk]
				# The header AA bit is not set. [ujy]
				if "aa" in resp["flags"]:
					failure_reasons.append("AA bit was set [ujy]")
				# The Answer section is empty. [aeg]
				if resp.get("ANSWER_SECTION"):
					failure_reasons.append("Answer section was not empty [aeg]")
				# The Authority section contains the entire NS RRset for the query name. [pdd]
				if not resp.get("AUTHORITY_SECTION"):
					failure_reasons.append("Authority section was empty [pdd]")
				root_ns_for_qname = root_to_check["{}/NS".format(this_qname)]
				auth_ns_for_qname = set()
				for this_rec in resp["AUTHORITY_SECTION"]:
					(rec_qname, _, _, rec_qtype, rec_rdata) = this_rec.split(" ", maxsplit=4)
					if rec_qtype == "NS":
						auth_ns_for_qname.add(rec_rdata)
				if not auth_ns_for_qname == root_ns_for_qname:
					failure_reasons.append("NS RRset in Authority was '{}', but NS from root was '{}' [pdd]".format(auth_ns_for_qname, root_ns_for_qname))
				# If the DS RRset for the query name exists in the zone: [hue]
				if root_to_check.get("{}/DS".format(this_qname)):
					# The Authority section contains the signed DS RRset for the query name. [kbd]
					this_resp = check_for_signed_rr(resp["AUTHORITY_SECTION"], "DS")
					if this_resp:
						failure_reasons.append("{} [kbd]".format(this_resp))
				else:  # If the DS RRset for the query name does not exist in the zone: [fot]
					# The Authority section contains no DS RRset. [bgr]
					for this_rec in resp["AUTHORITY_SECTION"]:
						(rec_qname, _, _, rec_qtype, _) = this_rec.split(" ", maxsplit=4)
						if rec_qtype == "DS":
							failure_reasons.append("Found DS in Authority section [bgr]")
							break
					# The Authority section contains a signed NSEC RRset covering the query name. [mkl]
					has_covering_nsec = False
					for this_rec in resp["AUTHORITY_SECTION"]:
						(rec_qname, _, _, rec_qtype, rec_rdata) = this_rec.split(" ", maxsplit=4)
						if rec_qtype == "NSEC":
							if rec_qname == this_qname:
								has_covering_nsec = True
								break
					if not has_covering_nsec:
						failure_reasons.append("Authority section had no covering NSEC record [mkl]")
				# Additional section contains at least one A or AAAA record found in the zone associated with at least one NS record found in the Authority section. [cjm]
				#    Collect the NS records from the Authority section
				found_NS_recs = []
				for this_rec in resp["AUTHORITY_SECTION"]:
					(rec_qname, _, _, rec_qtype, rec_rdata) = this_rec.split(" ", maxsplit=4)
					if rec_qtype == "NS":
						found_NS_recs.append(rec_rdata)
				found_qname_of_A_AAAA_recs = []
				for this_rec in resp["ADDITIONAL_SECTION"]:
					(rec_qname, _, _, rec_qtype, rec_rdata) = this_rec.split(" ", maxsplit=4)
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
				if not "aa" in resp["flags"]:
					failure_reasons.append("AA bit was not set [yot]")
				# The Answer section contains the signed DS RRset for the query name. [cpf]
				if not resp.get("ANSWER_SECTION"):
					failure_reasons.append("Answer section was empty [cpf]")
				else:
					# Make sure the DS is for the query name
					for this_rec in resp["ANSWER_SECTION"]:
						(rec_qname, _, _, rec_qtype, _) = this_rec.split(" ", maxsplit=4)
						if rec_qtype == "DS":
							if not rec_qname == this_qname:
								failure_reasons.append("DS in Answer section had QNAME {} instead of {} [cpf]".format(rec_qname, this_qname))
					this_resp = check_for_signed_rr(resp["ANSWER_SECTION"], "DS")
					if this_resp:
						failure_reasons.append("{} [cpf]".format(this_resp))
				# The Authority section is empty. [xdu]
				if resp.get("AUTHORITY_SECTION"):
					failure_reasons.append("Authority section was not empty [xdu]")
				# The Additional section is empty. [mle]
				if resp.get("ADDITIONAL_SECTION"):
					failure_reasons.append("Additional section was not empty [mle]")
			elif (this_qname == ".") and (this_qtype == "SOA"):  # Processing for . / SOA [owf]
				# The header AA bit is set. [xhr]
				if not "aa" in resp["flags"]:
					failure_reasons.append("AA bit was not set [xhr]")
				# The Answer section contains the signed SOA record for the root. [obw]
				this_resp = check_for_signed_rr(resp["ANSWER_SECTION"], "SOA")
				if this_resp:
					failure_reasons.append("{} [obw]".format(this_resp))
				# The Authority section contains the signed NS RRset for the root. [ktm]
				if not resp.get("AUTHORITY_SECTION"):
					failure_reasons.append("The Authority section was empty [ktm]")
				else:
					this_resp = check_for_signed_rr(resp["AUTHORITY_SECTION"], "NS")
					if this_resp:
						failure_reasons.append("{} [ktm]".format(this_resp))
			elif (this_qname == ".") and (this_qtype == "NS"):  # Processing for . / NS [amj]
				# The header AA bit is set. [csz]
				if not "aa" in resp["flags"]:
					failure_reasons.append("AA bit was not set [csz]")
				# The Answer section contains the signed NS RRset for the root. [wal]
				this_resp = check_for_signed_rr(resp["ANSWER_SECTION"], "NS")
				if this_resp:
					failure_reasons.append("{} [wal]".format(this_resp))
				# The Authority section is empty. [eyk]
				if resp.get("AUTHORITY_SECTION"):
					failure_reasons.append("Authority section was not empty [eyk]")
			elif (this_qname == ".") and (this_qtype == "DNSKEY"):  # Processing for . / DNSKEY [djd]
				# The header AA bit is set. [occ]
				if not "aa" in resp["flags"]:
					failure_reasons.append("AA bit was not set [occ]")
				# The Answer section contains the signed DNSKEY RRset for the root. [eou]
				this_resp = check_for_signed_rr(resp["ANSWER_SECTION"], "DNSKEY")
				if this_resp:
					failure_reasons.append("{} [eou]".format(this_resp))
				# The Authority section is empty. [kka]
				if resp.get("AUTHORITY_SECTION"):
					failure_reasons.append("Authority section was not empty [kka]")
				# The Additional section is empty. [jws]
				if resp.get("ADDITIONAL_SECTION"):
					failure_reasons.append("Additional section was not empty [jws]")
			else:
				failure_reasons.append("Not matched: when checking NOERROR statuses, found unexpected name/type of {}/{}".format(this_qname, this_qtype))
	
		elif resp["status"] == "NXDOMAIN":  # Processing for negative responses [vcu]
			# The header AA bit is set. [gpl]
			if not "aa" in resp["flags"]:
				failure_reasons.append("AA bit was not set [gpl]")
			# The Answer section is empty. [dvh]
			if resp.get("ANSWER_SECTION"):
				failure_reasons.append("Answer section was not empty [dvh]")
			# The Authority section contains the signed . / SOA record. [axj]
			if not resp.get("AUTHORITY_SECTION"):
				failure_reasons.append("Authority section was empty [axj]")
			else:
				# Make sure the SOA record is for .
				for this_rec in resp["AUTHORITY_SECTION"]:
					(rec_qname, _, _, rec_qtype, _) = this_rec.split(" ", maxsplit=4)
					if rec_qtype == "SOA":
						if not rec_qname == ".":
							failure_reasons.append("SOA in Authority section had QNAME {} instead of '.' [vcu]".format(rec_qname))
				this_resp = check_for_signed_rr(resp["AUTHORITY_SECTION"], "SOA")
				if this_resp:
					failure_reasons.append("{} [axj]".format(this_resp))
				# The Authority section contains a signed NSEC record covering the query name. [czb]
				#   Note that the query name might have multiple labels, so only compare against the last label
				this_qname_TLD = this_qname.split(".")[-2] + "."
				nsec_covers_query_name = False
				nsecs_in_authority = []
				for this_rec in resp["AUTHORITY_SECTION"]:
					(rec_qname, _, _, rec_qtype, rec_rdata) = this_rec.split(" ", maxsplit=4)
					if rec_qtype == "NSEC":
						nsec_parts = rec_rdata.split(" ")
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
				for this_rec in resp["AUTHORITY_SECTION"]:
					(rec_qname, _, _, rec_qtype, rec_rdata) = this_rec.split(" ", maxsplit=4)
					if rec_qtype == "NSEC":
						if rec_qname == ".":
							nsec_with_owner_dot = True
							break;
				if not 	nsec_with_owner_dot:
					failure_reasons.append("Authority section did not contain a signed NSEC record with owner name '.' [jzh]")
			# The Additional section is empty. [trw]
			if resp.get("ADDITIONAL_SECTION"):
				failure_reasons.append("Additional section was not empty [trw]")

		# Check that each of the RRsets in the Answer, Authority, and Additional sections match RRsets found in the zone [vnk]
		#   This check does not include any RRSIG RRsets that are not named in the matching tests below. [ygx]
		# This check does not include any OPT RRset found in the Additional section because "dig +yaml" does not put them in the Additional section [pvz]
		# After this check is done, we no longer need to check RRsets from the answer against the root zone
		for this_section_name in [ "ANSWER_SECTION", "AUTHORITY_SECTION", "ADDITIONAL_SECTION" ]:
			if resp.get(this_section_name):
				# Gather the non-RRSIG RRsets in this section
				rrsets_for_checking = {}
				for this_full_record in resp[this_section_name]:
					# There is an error in BIND 9.16.1 and .2 where this_full_record might be a dict instead of a str. If so, ignore it. #######
					if isinstance(this_full_record, dict):
						alert("Found record with a dict in id {}, {} {}".format(this_filename_record, this_section_name, this_full_record))
						return
					(rec_qname, _, _, rec_qtype, rec_rdata) = this_full_record.split(" ", maxsplit=4)
					if not rec_qtype == "RRSIG":  # [ygx]
						this_key = "{}/{}".format(rec_qname, rec_qtype)
						rrsets_for_checking.setdefault(this_key, set()).add(rec_rdata)
				# Check each qname/qtype pair that was found in the section
				for this_rrset_key in rrsets_for_checking:
					# See if the qname/qtype is in the root
					if not this_rrset_key in root_to_check:
						failure_reasons.append("'{}' was in '{}' in the response but not the root [vnk]".format(this_rrset_key, this_section_name))
					else:
						# See if the length of the sets is not the same
						if not len(rrsets_for_checking[this_rrset_key]) == len(root_to_check[this_rrset_key]):
							failure_reasons.append("RRset '{}' in {} in response has a different length than '{}' in root zone [vnk]".\
								format(rrsets_for_checking[this_rrset_key], this_section_name, root_to_check[this_rrset_key]))
							continue
						# If the data is the same, that's good; continue on
						if rrsets_for_checking[this_rrset_key] == root_to_check[this_rrset_key]:
							continue
						else:
							# Before giving up, see if it is a mismatch in the text for IPv6 addresses
							#  Normalize IPv6 strings with socket.inet_ntop(socket.AF_INET6, (socket.inet_pton(socket.AF_INET6, this_rdata)))
							if this_rrset_key.endswith("/AAAA"):
								checking_aaaa = set()
								for this_rdata in rrsets_for_checking[this_rrset_key]:
									try:
										checking_aaaa.add(socket.inet_ntop(socket.AF_INET6, (socket.inet_pton(socket.AF_INET6, this_rdata))))
									except:
										alert("Found a bad AAAA record '{}' in {} in {}, so cannot continue checking this record".format(this_rdata, this_filename_record, this_section_name))
										continue
								root_aaaa = set()
								for this_rdata in root_to_check[this_rrset_key]:
									try:
										root_aaaa.add(socket.inet_ntop(socket.AF_INET6, (socket.inet_pton(socket.AF_INET6, this_rdata))))
									except:
										alert("Found a bad AAAA record '{}' in {}, so cannot continue checking this record".format(this_rdata, this_root_file))
										continue
								for this_aaa_from_checking in checking_aaaa:
									if not this_aaa_from_checking in root_aaaa:
										failure_reasons.append("AAAA RRset value '{}' in {} in response is different than any AAAA RRset '{}' in root zone [vnk]".\
											format(this_aaa_from_checking, this_section_name, root_aaaa))
										continue
							else:
								failure_reasons.append("Non-AAAA RRset value '{}' in {} in response is different than '{}' in root zone [vnk]".\
									format(rrsets_for_checking[this_rrset_key], this_section_name, root_to_check[this_rrset_key]))

		# If there are any errors, stop here instead of also trying the validation
		if len(failure_reasons) == 0:
			# Check that each of the RRsets that are signed have their signatures validated. [yds]
			#   Send all the records in each section to the function that checks for validity
			################################################################################################################
			#   Due to unexplainable errors coming from getdns_validate, validation is temporarily turned off
			################################################################################################################
			if True:
				pass
			else:
				if opts.test:
					recent_soa_root_filename = "root_zone.txt"
				else:
					recent_soa_root_filename = "{}/{}.root.txt".format(saved_root_zone_dir, this_soa)
				if not os.path.exists(recent_soa_root_filename):
					alert("Could not find {} for correctness validation, so skipping".format(recent_soa_root_filename))
				else:
					for this_section_name in [ "ANSWER_SECTION", "AUTHORITY_SECTION", "ADDITIONAL_SECTION" ]:
						this_section_rrs = resp.get(this_section_name, [])
						# Only act if this section has an RRSIG
						rrsigs_over_rrtypes = set()
						for this_in_rr_text in this_section_rrs:
							# The following splits into 5 parts to expose the first field of RRSIGs
							rr_parts = this_in_rr_text.split(" ", maxsplit=5)
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
								input_file_contents = open(validate_fname, "rt").read()
								failure_reasons.append("Validating {} in {} with {} gave code {} [yds]\n{}"\
									.format(this_section_name, this_filename_record, recent_soa_root_filename, validate_return, input_file_contents))
							validate_f.close()

		# If there no errors, we're done, no need to try other SOAs
		if len(failure_reasons) == 0:
			if opts.test:
				return ""
			else:
				update_database_when_finished("", this_filename_record)
				return

		# Here if there were errors. If there are still more entries in soas_to_test, they will be tried; otherwise, it will fall off to a validation failure
		per_soa_results[this_soa] = failure_reasons
			
	# Here if went through all the SOAs and got a validation failure for the last SOA tested
	highest_failure_soa = max(per_soa_results.keys())
	#   Because the SOAs were tried in reverse order, this_soa is the highest SOA in the list
	failure_reason_text = "{}\n".format("\n".join(per_soa_results[highest_failure_soa]))
	failure_reason_text += "Failed in SOA {}".format(highest_failure_soa)
	failure_reason_text += " after trying in all SOAs ({})".format(" ".join([ x[0] for x in soas_to_test]))
	debug("Correctness failure for {}\n{}".format(this_filename_record, failure_reason_text))
	for this_soa in per_soa_results:
		debug("{}: {}".format(this_soa, per_soa_results[this_soa]))
	# If running tests, return regardless
	if opts.test:
		return failure_reason_text
	else:
		update_database_when_finished(failure_reason_text, this_filename_record)
		return
	


###############################################################

if __name__ == "__main__":
	# Get the base for the log directory
	log_dir = "{}/Logs".format(os.path.expanduser("~"))
	if not os.path.exists(log_dir):
		os.mkdir(log_dir)
	# Set up the logging and alert mechanisms
	log_file_name = "{}/collector-log.txt".format(log_dir)
	vp_log = logging.getLogger("logging")
	vp_log.setLevel(logging.INFO)
	log_handler = logging.FileHandler(log_file_name)
	log_handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
	vp_log.addHandler(log_handler)
	alert_file_name = "{}/collector-alert.txt".format(log_dir)
	vp_alert = logging.getLogger("alerts")
	vp_alert.setLevel(logging.CRITICAL)
	alert_handler = logging.FileHandler(alert_file_name)
	alert_handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
	vp_alert.addHandler(alert_handler)
	debug_file_name = "{}/collector-debug.txt".format(log_dir)
	vp_debug = logging.getLogger("debug")
	vp_debug.setLevel(logging.DEBUG)
	debug_handler = logging.FileHandler(debug_file_name)
	debug_handler.setFormatter(logging.Formatter("%(message)s"))
	vp_debug.addHandler(debug_handler)
	def log(log_message):
		vp_log.info(log_message)
	def alert(alert_message):
		vp_alert.critical(alert_message)
		log(alert_message)
	def debug(debug_message):
		vp_debug.debug(debug_message + "\n")
	def die(error_message):
		vp_alert.critical(error_message)
		log("Died with '{}'".format(error_message))
		exit()
	
	limit_size = 10000
	
	this_parser = argparse.ArgumentParser()
	this_parser.add_argument("--test", action="store_true", dest="test",
		help="Run tests on requests; must be run in the Tests directory")
	this_parser.add_argument("--source", action="store", dest="source", default="skip",
		help="Specify 'vps' or 'c01' or 'skip' to say where to pull recent files")
	this_parser.add_argument("--limit", action="store_true", dest="limit",
		help="Limit procesing to {} items".format(limit_size))
	
	opts = this_parser.parse_args()
	if opts.limit:
		log("Limiting record processing to {} files".format(limit_size))

	# Make sure opts.source is "vps" or "c01" or "skip"
	if not opts.source in ("vps", "c01", "skip"):
		die('The value for --source must be "vps" or "c01" or "skip"')

	# Where the binaries are
	target_dir = "/home/metrics/Target"	
	# Where to store the incoming files comeing from the vantage points
	incoming_dir = os.path.expanduser("~/Incoming")
	if not os.path.exists(incoming_dir):
		os.mkdir(incoming_dir)
	# Where to put the processed vantage point files after processing them; they are segregated by month
	originals_dir = os.path.expanduser("~/Originals")
	if not os.path.exists(originals_dir):
		os.mkdir(originals_dir)
	# Where to save things long-term
	output_dir = os.path.expanduser("~/Output")
	if not os.path.exists(output_dir):
		os.mkdir(output_dir)
	# Subdirectories of log directory for root zones
	saved_root_zone_dir = "{}/RootZones".format(output_dir)
	if not os.path.exists(saved_root_zone_dir):
		os.mkdir(saved_root_zone_dir)
	saved_matching_dir = "{}/RootMatching".format(output_dir)
	if not os.path.exists(saved_matching_dir):
		os.mkdir(saved_matching_dir)
	# Where to put the SFTP batch files
	batch_dir = os.path.expanduser("{}/Batches".format(output_dir))
	if not os.path.exists(batch_dir):
		os.mkdir(batch_dir)
	
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
	#   opts.source is either c01 (to rsync from c01.mtric.net) or vps (to pull from vps)

	if opts.source == "c01":
		log("Running rsync from c01")
		rsync_start = time.time()
		rsync_files_cmd = 'rsync -av -e "ssh -l root -i /home/metrics/.ssh/metrics_id_rsa" root@c01.mtric.net:/home/metrics/Originals/ /home/metrics/FromC01'
		rsync_actual = subprocess.run(rsync_files_cmd, shell=True, capture_output=True, text=True)
		pickle_count = 0
		for this_line in rsync_actual.stdout.splitlines():
			if ".pickle.gz" in this_line:
				pickle_count += 1
		log("Rsync of vantage point files got {} files in {} seconds, return code {}".format(pickle_count, int(time.time() - rsync_start), rsync_actual.returncode))
		# Get the RootMatching files
		rsync_start = time.time()
		rsync_matching_cmd = 'rsync -av -e "ssh -l root -i /home/metrics/.ssh/metrics_id_rsa" root@c01.mtric.net:/home/metrics/Output/RootMatching/ /home/metrics/Output/RootMatching'
		rsync_root_matching = subprocess.run(rsync_matching_cmd, shell=True, capture_output=True, text=True)
		pickle_count = 0
		for this_line in rsync_root_matching.stdout.splitlines():
			if ".matching.pickle" in this_line:
				pickle_count += 1
		log("Rsync of RootMatching got {} files in {} seconds, return code {}".format(pickle_count, int(time.time() - rsync_start), rsync_root_matching.returncode))
		# Get the RootZones files
		rsync_start = time.time()
		rsync_zones_cmd = 'rsync -av -e "ssh -l root -i /home/metrics/.ssh/metrics_id_rsa" root@c01.mtric.net:/home/metrics/Output/RootZones/ /home/metrics/Output/RootZones'
		rsync_root_zones = subprocess.run(rsync_zones_cmd, shell=True, capture_output=True, text=True)
		pickle_count = 0
		for this_line in rsync_root_zones.stdout.splitlines():
			if ".root.txt" in this_line:
				pickle_count += 1
		log("Rsync of RootZones got {} files in {} seconds, return code {}".format(pickle_count, int(time.time() - rsync_start), rsync_root_zones.returncode))
				
	elif opts.source == "vps":
		# On each VP, find the files in /sftp/transfer/Output and get them one by one
		#   For each file, after getting, move it to /sftp/transfer/AlreadySeen
		# Get the list of VPs
		log("Started pulling from VPs")
		vp_list_filename = os.path.expanduser("~/vp_list.txt")
		try:
			all_vps = open(vp_list_filename, mode="rt").read().splitlines()
		except Exception as e:
			die("Could not open {} and split the lines: '{}'".format(vp_list_filename, e))
		# Make sure we have trusted each one
		known_hosts_set = set()
		known_host_lines = open(os.path.expanduser("~/.ssh/known_hosts"), mode="rt").readlines()
		for this_line in known_host_lines:
			known_hosts_set.add(this_line.split(" ")[0])
		for this_vp in all_vps:
			if not this_vp in known_hosts_set:
				try:
					subprocess.run("ssh-keyscan -4 -t rsa {} >> ~/.ssh/known_hosts".format(this_vp), shell=True, capture_output=True, check=True)
					log("Added {} to known_hosts".format(this_vp))
				except Exception as e:
					die("Could not run ssh-keyscan on {}: {}".format(this_vp, e))
		total_pulled = 0
		with futures.ProcessPoolExecutor() as executor:
			for (this_vp, pulled_count) in zip(all_vps, executor.map(get_files_from_one_vp, all_vps)):
				if pulled_count:
					total_pulled += pulled_count
		log("Finished pulling from VPs; got {} files from {} VPs".format(total_pulled, len(all_vps)))
	
	elif opts.source == "skip":
		# Don't do any source gathering
		log("Skipped getting sources because opts.source was 'skip'")

	###############################################################

	# Go through the files in ~/Incoming
	log("Started going through ~/Incoming")
	all_files = list(glob.glob("{}/*.pickle.gz".format(incoming_dir)))
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
	##### # If limit is set, use only the first few
	##### if opts.limit:
	#####	full_correctness_list = full_correctness_list[0:limit_size]
	log("Started correctness checking on {} found".format(len(full_correctness_list)))
	processed_correctness_count = 0
	processed_correctness_start = time.time()
	with futures.ProcessPoolExecutor() as executor:
		for (this_correctness, _) in zip(full_correctness_list, executor.map(process_one_correctness_array, full_correctness_list, chunksize=1000)):
			processed_correctness_count += 1
	log("Finished correctness checking {} records in {} seconds".format(processed_correctness_count, int(time.time() - processed_correctness_start)))
	
	###############################################################
	
	# STILL TO DO: Validation in correctness checking
	
	###############################################################
	
	log("Finished overall collector processing")	
	exit()
