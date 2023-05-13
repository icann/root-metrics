#!/usr/bin/env python3

''' Do all tasks on the collector to process the data from the VPs and put the results in the database tables '''
# Run as the metrics user
# Three-letter items in square brackets (such as [xyz]) refer to parts of rssac-047.md

import argparse, datetime, glob, gzip, logging, os, pickle, psycopg2, time
import dns.dnssec, dns.ipv6, dns.rdata, dns.rrset
from pathlib import Path
from concurrent import futures
from collections import namedtuple

###############################################################

def run_tests_only():
	# Run just the tests locally, then exit.
	debug("Running tests instead of a real run")
	try:
		test_dir = f"{str(Path('~').expanduser())}/repo/Tests"
		os.chdir(test_dir)
	except:
		exit(f"Could not chdir to {test_dir}")
	# Sanity check that you are in the Tests directory
	for this_check in [ "make_tests.py", "p-dot-soa", "n-ffr" ]:
		if not os.path.exists(this_check):
			exit(f"Did not find {this_check} for running under --test. Exiting.")
	# Test the positives
	p_count = 0
	for this_test_file in sorted(Path(".").glob("p-*")):
		p_count += 1
		this_id = os.path.basename(this_test_file)
		this_resp_pickle = open(this_test_file, mode="rb").read()
		this_response = process_one_correctness_tuple(("test", this_resp_pickle))
		if this_response:
			debug(f"Expected pass, but got failure, on {this_id}\n{this_response}\n")
	# Test the negatives
	n_count = 0
	# Collect the negative responses to put in a file
	n_responses = {}
	for this_test_file in sorted(Path(".").glob("n-*")):
		n_count += 1
		this_id = os.path.basename(this_test_file)
		this_resp_pickle = open(this_test_file, mode="rb").read()
		this_response = process_one_correctness_tuple(("test", this_resp_pickle))
		if not this_response:
			debug(f"Expected failure, but got success, on {this_id}")
		else:
			n_responses[this_id] = {}
			this_resp_full = pickle.loads(this_resp_pickle)
			n_responses[this_id]["desc"] = this_resp_full["test-desc"]
			n_responses[this_id]["resp"] = this_response
	debug(f"Finished testing {p_count} positive and {n_count} negative tests")
	tests_results_file = "results.txt"
	out_f = open(tests_results_file, mode="wt")
	for this_id in sorted(n_responses):
		out_f.write(f"\n{this_id} -- {n_responses[this_id]['desc']}\n")
		for this_line in n_responses[this_id]["resp"].splitlines():
			out_f.write(f"   {this_line}\n")
	out_f.close()
	debug(f"Wrote out testing log as {tests_results_file}")

###############################################################
def process_one_incoming_file(full_file_name):
	# Process an incoming file
	#   Returns nothing
	
	# Open the database so that we can define the insert function
	with psycopg2.connect(dbname="metrics", user="metrics") as conn:
		conn.set_session(autocommit=True)
		# First define a function to insert records into one of the two databases
		def insert_from_template(this_cmd_string, this_values):
			with conn.cursor() as curi:
				try:
					curi.execute(this_cmd_string, this_values)
				except Exception as e:
					alert(f"Failed to execute '{this_cmd_string}' on '{this_values}': '{e}'")
				return

		# Check for wrong type of file
		if not full_file_name.endswith(".pickle.gz"):
			alert(f"Found {full_file_name} that did not end in .pickle.gz")
			return
	
		# Sometimes ones slip in that are empty
		if os.path.getsize(full_file_name) == 0:
			alert(f"File {full_file_name} had zero length")
			return
		# Un-gzip it
		try:
			with gzip.open(full_file_name, mode="rb") as pf:
				in_pickle = pf.read()
		except Exception as e:
			alert(f"Could not unzip {full_file_name}: {e}")
			return
		# Unpickle it
		try:
			in_obj = pickle.loads(in_pickle)
		except Exception as e:
			alert(f"Could not unpickle {full_file_name}: {e}")
			return
		# Sanity check the record
		if not ("v" in in_obj) and ("d" in in_obj) and ("e" in in_obj) and ("l" in in_obj) and ("r" in in_obj):
			alert(f"Object in {full_file_name} did not contain keys d, e, l, r, and v")
			return
	
		# Update the metadata
		short_file_name = os.path.basename(full_file_name).replace(".pickle.gz", "")
		insert_files_string = "insert into files_gotten (processed_at, version, delay, elapsed, filename_short) values (%s, %s, %s, %s, %s)"
		insert_files_values = (datetime.datetime.now(datetime.timezone.utc), in_obj["v"], in_obj["d"], in_obj["e"], short_file_name) 
		insert_from_template(insert_files_string, insert_files_values)

		# Get the derived date and VP name from the file name
		(file_date_text, _) = short_file_name.split("-")
		try:
			file_date = datetime.datetime(int(file_date_text[0:4]), int(file_date_text[4:6]), int(file_date_text[6:8]),\
				int(file_date_text[8:10]), int(file_date_text[10:12]))
		except Exception as e:
			alert(f"Could not split the file name {short_file_name} into a datetime: {e}")
			return

		# Named tuple for the record templates
		template_names_raw = "filename_record date_derived target internet transport ip_addr record_type query_elapsed timeout soa_found " \
			+ "likely_soa is_correct failure_reason"
		# Change spaces to ", "
		template_names_with_commas = template_names_raw.replace(" ", ", ")
		# List of "%s, " for Postgres "insert" commands; remove trailing ", "
		percent_s_string = str("%s, " * len(template_names_raw.split(" ")))[:-2]
		# Create the template
		insert_values_template = namedtuple("insert_values_template", field_names=template_names_with_commas)
	
		# Go through each response item
		response_count = 0
		for this_resp in in_obj["r"]:
			response_count += 1  # response_count is 1-based, not 0-based
			# Each record is "S" for an SOA record or "C" for a correctness test
			#   Sanity test that the type is S or C
			if not this_resp["test_type"] in ("S", "C"):
				alert(f"Found a response type {this_resp['test_type']}, which is not S or C, in record {response_count} of {full_file_name}")
				continue
			short_name_and_count = f"{short_file_name}-{response_count}"
			insert_template = f"insert into record_info ({template_names_with_commas}) values ({percent_s_string})"
			insert_values = insert_values_template(filename_record=short_name_and_count, date_derived=file_date, \
				target=this_resp["target"], internet=this_resp["internet"], transport=this_resp["transport"], ip_addr=this_resp["ip_addr"], record_type=this_resp["test_type"], \
				query_elapsed=0.0, timeout=this_resp["timeout"], soa_found="", likely_soa=in_obj["l"], is_correct="", failure_reason="")
			# If there is already something in timeout, just insert this record
			if this_resp["timeout"]:
				insert_values = insert_values._replace(is_correct="y")
				insert_from_template(insert_template, insert_values)
				continue
			# If the response code is wrong, treat it as a timeout; use the response code as the timeout message
			#   For "S" records   [ppo]
			#   For "C" records   [ote]
			this_response_code = this_resp.get("rcode")
			if not ((insert_values.record_type == "S" and this_response_code in ["NOERROR"]) or (insert_values.record_type == "C" and this_response_code in ["NOERROR", "NXDOMAIN"])):
				insert_values = insert_values._replace(timeout=this_response_code)
				insert_values = insert_values._replace(is_correct="y")
				insert_from_template(insert_template, insert_values)
				continue
			# What is left is responses that didn't time out
			if not this_resp.get("query_elapsed"):
				alert(f"Found a message without query_elapsed in record {response_count} of {full_file_name}")
				continue
			insert_values = insert_values._replace(query_elapsed=this_resp["query_elapsed"])  # [aym]
			if insert_values.record_type == "S":
				if this_resp.get("answer") == None or len(this_resp["answer"]) == 0:
					alert(f"Found a message of type 'S' without an answer in record {response_count} of {full_file_name}")
					continue
				# Set is_correct to "s" because correctness is not being checked for record_type = s
				insert_values = insert_values._replace(is_correct="s")
				# This chooses only the first SOA record; there really should only be one SOA record in the response
				this_soa_record = this_resp["answer"][0]["rdata"][0]
				soa_record_parts = this_soa_record.split(" ")
				this_soa = soa_record_parts[2]
				insert_values = insert_values._replace(soa_found=this_soa)
			elif insert_values.record_type == "C":
				with open(f"{saved_response_dir}/{short_name_and_count}", mode="wb") as f_out:
					pickle.dump(this_resp, f_out)
				# Make is_correct "t" for correctness tests that times out, otherwise mark it as "?" so that it gets checked
				if this_resp["timeout"]:
					insert_values = insert_values._replace(is_correct="t")
				else:
					insert_values = insert_values._replace(is_correct="?")
			# Write out this record
			insert_from_template(insert_template, insert_values)
	return

###############################################################

def check_for_signed_rr(list_of_records_from_section, name_of_rrtype):
	# Part of correctness checking
	#   See if there is a record in the list of the given RRtype, and make sure there is also an RRSIG for that RRtype
	found_rrtype = False
	for this_rec_dict in list_of_records_from_section:
		rec_qtype = this_rec_dict["rdtype"]
		if rec_qtype == name_of_rrtype:
			found_rrtype = True
			break
	if not found_rrtype:
		return f"No record of type {name_of_rrtype} was found in that section"
	found_rrsig = False
	for this_rec_dict in list_of_records_from_section:
		rec_qtype = this_rec_dict["rdtype"]
		if rec_qtype == "RRSIG":
			found_rrsig = True
			break
	if not found_rrsig:
		return f"One more more records of type {name_of_rrtype} were found in that section, but there was no RRSIG"
	return ""
	
###############################################################

def process_one_correctness_tuple(in_tuple):
	# Tuple is (request_type, tuple of (filename_record, timeout, likely_soa, is_correct)
	# request_type is "test" or "normal"
	#    For "normal", process one filename_record
	#    For "test", process one id/pickle_blob pair
	# For test type "normal" return a tuple that is handed to Postgres as a command; otherwise return an empty string (usually after an alert)
	#    However, if the type is "test", the function does not write into the database but instead returns the results as text
	(request_type, record_tuple) = in_tuple
	if not request_type in ("normal", "test"):
		alert(f"While running process_one_correctness_tuple on {in_tuple}, got unknown first argument {request_type}")
		return
	(in_filename_record, this_timeout, this_soa_to_check, this_is_correct) = record_tuple
	if request_type == "normal":
		# Get the pickled response
		with open(f"{saved_response_dir}/{in_filename_record}", mode="rb") as f_in:
			this_resp_pickle = f_in.read()
		# Before trying to load the pickled data, first see if it is a timeout; if so, set is_correct but move on [lbl]
		if not this_timeout == "":
			return ("update record_info set (is_correct, failure_reason) = (%s, %s) where filename_record = %s", ("y", "timeout", in_filename_record))
		# Get the pickled object		
		try:
			resp = pickle.loads(this_resp_pickle)
		except Exception as e:
			alert(f"Could not unpickle the response in {in_filename_record}: {e}")
			return
	else:  # For tests
		this_timeout = ""
		# Unpickle the object to get the values
		try:
			resp = pickle.loads(in_filename_record)
		except:
			alert("Could not unpickle this test.")
			return
		test_name = resp["test-on"]
		if test_name[0] == "p":
			this_is_correct = "y"
		elif test_name[0] == "n":
			this_is_correct = "n"
		else:
			alert(f"In {test_name}, the first letter was not 'p' or 'n'.")
			return
		# Change in_filename_record in tests to be the test ID so that errors come out more readable
		in_filename_record = test_name
		this_soa_to_check = ""			

	#  Get the question
	#   Only look at the first record in the question section; it is completely unclear what to do if the the question section has more records
	question_record_dict = resp["question"][0]
	this_qname = question_record_dict["name"]
	this_qtype = question_record_dict["rdtype"]

	# roots_to_check holds all the contents of roots to check in this round
	#   For type "C" and is_correct "?", it is just the root associated with	likely_soa
	#   For type "C" and is_correct "r", it is just the roots for 48 hours before likely_soa, and the SOA after
	#   For type "test", it is the fixed root
	roots_to_check = []
	# The root is known is known for opts.test; for the normal checking, it is the likely_soa
	if opts.test:
		try:
			roots_to_check.append(pickle.load(open("root_name_and_types.pickle", mode="rb")))
		except:
			alert("While running under --test, could not find and unpickle 'root_name_and_types.pickle'. Exiting.")
			return
	elif this_is_correct == "?":
		one_root_file = f"{saved_matching_dir}/{this_soa_to_check}.matching.pickle"
		if not os.path.exists(one_root_file):
			# Just return, leacing the is_correct as "?" so it will get caught on the next run
			debug(f"When checking correctness on {in_filename_record}, could not find root file {one_root_file}")
			return
		# Try to read the file	
		with open(one_root_file, mode="rb") as root_contents_f:
			try:
				roots_to_check.append(pickle.load(root_contents_f))
			except:
				alert(f"Could not unpickle root file {one_root_file} while processing {in_filename_record} for correctness the first time")
				return
	elif this_is_correct == "r":
		# Get the starting date from the file name, then pick all zone files whose names have that date or the date from the 48 hours before [xog]
		start_date = datetime.date(int(in_filename_record[0:4]), int(in_filename_record[4:6]), int(in_filename_record[6:8]))
		start_date_minus_one = start_date - datetime.timedelta(days=1)
		start_date_minus_two = start_date - datetime.timedelta(days=2)
		soa_matching_date_files = []
		for this_start in [start_date, start_date_minus_one, start_date_minus_two]:
			soa_matching_date_files.extend(glob.glob(str(Path(f"{saved_matching_dir}/{this_start.strftime('%Y%m%d')}" + "*.matching.pickle"))))
		# Also get the root zone with the SOA after this_soa_to_check
		soa_already_checked = f"{saved_matching_dir}/{this_soa_to_check}.matching.pickle"
		all_matching_files = sorted(glob.glob(str(Path(f"{saved_matching_dir}/*.matching.pickle"))))
		try:
			this_root_by_soa = all_matching_files.index(soa_already_checked)
		except:
			alert(f"When looking for the root after {soa_already_checked}, could not even find {soa_already_checked}")
			return
		try:
			next_soa_to_check = all_matching_files[this_root_by_soa + 1]
			soa_matching_date_files.add(next_soa_to_check)
		except:
			pass  # This indicates that this_root_by_soa was the last file in the directory
		# Try to read the files
		for this_root_file in soa_matching_date_files:
			try:
				with open(this_root_file, mode="rb") as root_contents_f:
					try:
						roots_to_check.append(pickle.load(root_contents_f))
					except:
						alert(f"Could not unpickle root file {this_root_file} while retrying processing of {in_filename_record} for correctness")
						return
			except Exception as e:
				alert(f"When processing {this_root_file} among {soa_matching_date_files} in {in_filename_record}, got {e}")
				return
	else:
		alert(f"Got unexpected value for is_correct, {this_is_correct}, in {in_filename_record}")
		return

	# Go through the correctness checking against each root, stopping if you get one root for which everything is correct
	for this_root_to_check in roots_to_check:
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
				for this_rec_dict in resp[this_section_name]:
					rec_qname = this_rec_dict["name"]
					rec_qtype = this_rec_dict["rdtype"]
					if rec_qtype == "RRSIG":  # [ygx]
						continue
					this_key = f"{rec_qname}/{rec_qtype}"
					rec_rdata = this_rec_dict["rdata"]
					if not this_key in rrsets_for_checking:
						rrsets_for_checking[this_key] = set()
					for this_rdata_record in rec_rdata:
						rrsets_for_checking[this_key].add(this_rdata_record)
				for this_rrset_key in rrsets_for_checking:
					if not this_rrset_key in this_root_to_check:
						failure_reasons.append(f"{this_rrset_key} was in the {this_section_name} section in the response, but not the root [vnk]")
					else:
						z_short = rrsets_for_checking[this_rrset_key]
						r_short = this_root_to_check[this_rrset_key]
						if not len(rrsets_for_checking[this_rrset_key]) == len(this_root_to_check[this_rrset_key]):
							failure_reasons.append(f"{this_rrset_key} in {this_section_name} in the response has {len(z_short)} members instead of {len(r_short)} in root zone;" +
								f" {z_short} instead of {r_short} [vnk]")
							continue
						# Need to match case, so uppercase all the records in both sets
						#   It is OK to do this for any type that is not displayed as Base64, and RRSIG is already excluded by [ygx]
						#   But don't change case on DNSKEY
						for this_comparator in [rrsets_for_checking[this_rrset_key], this_root_to_check[this_rrset_key]]:
							for this_rdata in this_comparator.copy():
								this_comparator.remove(this_rdata)
								if this_rrset_key.endswith("/DNSKEY"):
									(d_flags, d_prot, d_alg, d_key) = this_rdata.split(" ", maxsplit=3)
									d_key = d_key.replace(" ", "")
									this_rdata = f"{d_flags} {d_prot} {d_alg} {d_key}"
									this_comparator.add(this_rdata)
								elif this_rrset_key.endswith("/AAAA"):
									this_comparator.add(dns.ipv6.inet_ntoa(dns.ipv6.inet_aton(this_rdata)))
								else:
									this_comparator.add(this_rdata.upper())
						if not rrsets_for_checking[this_rrset_key] == this_root_to_check[this_rrset_key]:
							failure_reasons.append(f"Set of RRset value {z_short} in {this_section_name} in response is different than {r_short} in root zone [vnk]")

		# Check that each of the RRsets that are signed have their signatures validated. [yds]
		#    Make these calls shorter
		class_in = dns.rdataclass.from_text("IN")
		# Get the ./DNSKEY records for this root
		root_rdataset = dns.rdataset.Rdataset(class_in, dns.rdatatype.from_text("DNSKEY"))
		for this_root_dnskey in this_root_to_check["./DNSKEY"]:
			root_rdataset.add(dns.rdata.from_text(class_in, dns.rdatatype.from_text("DNSKEY"), this_root_dnskey))
		root_keys_for_matching = { dns.name.from_text("."): root_rdataset }
		# Check each section for signed records
		for this_section_name in [ "answer", "authority", "additional" ]:
			if resp.get(this_section_name):
				signed_rrsets = {}
				# Find the RRSIG records to know what is signed
				for this_rec_dict in resp[this_section_name]:
					rec_qname = this_rec_dict["name"]
					rec_qtype = this_rec_dict["rdtype"]
					rec_rdata = this_rec_dict["rdata"]
					if rec_qtype == "RRSIG":
						(first_field, _) = rec_rdata[0].split(" ", maxsplit=1)
						signed_rrsets[f"{rec_qname}&{first_field}"] = []
				# Make an RRset of the records that were signed, an RRset of those RRSIGS, and then validate
				for signed_rrset_id in signed_rrsets:
					(rec_qname, rec_qtype) = signed_rrset_id.split("&")
					signed_rrset = dns.rrset.RRset(dns.name.from_text(rec_qname), class_in, dns.rdatatype.from_text(rec_qtype))
					rrsig_rrset = dns.rrset.RRset(dns.name.from_text(rec_qname), class_in, dns.rdatatype.from_text("RRSIG"))
					for this_rec_dict in resp[this_section_name]:
						if (this_rec_dict["name"] == rec_qname) and (this_rec_dict["rdtype"] == rec_qtype):
							for this_signed_rdata in this_rec_dict["rdata"]:
								signed_rrset.add(dns.rdata.from_text(class_in, dns.rdatatype.from_text(rec_qtype), this_signed_rdata))
						elif (this_rec_dict["name"] == rec_qname) and (this_rec_dict["rdtype"] == "RRSIG"):
							for this_rrsig_rdata in this_rec_dict["rdata"]:
								(first_field, _) = this_rrsig_rdata.split(" ", maxsplit=1)
								if first_field == rec_qtype:
									rrsig_rrset.add(dns.rdata.from_text(class_in, dns.rdatatype.from_text("RRSIG"), this_rrsig_rdata))
					try:
						pass ########################################################################## Temporarily not validating #####################################
						######################## dns.dnssec.validate(signed_rrset, rrsig_rrset, root_keys_for_matching) ################################################
					except Exception as e:
						failure_reasons.append(f"Validating {rec_qname}/{rec_qtype} in {this_section_name} in {in_filename_record} failed. [yds]")
						die(f"Validation failure: signed_rrset {signed_rrset}, rrsig_rrset {rrsig_rrset}, root_keys_for_matching {root_keys_for_matching}")

		# Check that all the parts of the resp structure are correct, based on the type of answer
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
				root_ns_for_qname = this_root_to_check[f"{this_qname}/NS"]
				auth_ns_for_qname = set()
				for this_rec_dict in resp["authority"]:
					if this_rec_dict["rdtype"] == "NS":
						for this_ns in this_rec_dict["rdata"]:
							auth_ns_for_qname.add(this_ns.upper())
				if not auth_ns_for_qname == root_ns_for_qname:
					failure_reasons.append(f"NS RRset in Authority was {auth_ns_for_qname}, but NS from root was {root_ns_for_qname} [pdd]")
				# If the DS RRset for the query name exists in the zone: [hue]
				if this_root_to_check.get(f"{this_qname}/DS"):
					# The Authority section contains the signed DS RRset for the query name. [kbd]
					this_resp = check_for_signed_rr(resp["authority"], "DS")
					if this_resp:
						failure_reasons.append(f"{this_resp} [kbd]")
				else:  # If the DS RRset for the query name does not exist in the zone: [fot]
					# The Authority section contains no DS RRset. [bgr]
					for this_rec_dict in resp["authority"]:
						rec_qtype = this_rec_dict["rdtype"]
						if rec_qtype == "DS":
							failure_reasons.append("Found DS in Authority section [bgr]")
							break
					# The Authority section contains a signed NSEC RRset with an owner name matching the QNAME and with the DS type omitted from the Type Bit Maps field [mkl]
					has_covering_nsec = False
					for this_rec_dict in resp["authority"]:
						rec_qtype = this_rec_dict["rdtype"]
						if rec_qtype == "NSEC":
							rec_qname = this_rec_dict["name"]
							if rec_qname == this_rec_dict["name"]:
								rec_rdata = this_rec_dict["rdata"][0]
								(next_name, type_bit_map) = rec_rdata.split(" ", maxsplit=1)
								nsec_types = type_bit_map.split(" ")
								if not "DS" in nsec_types:
									has_covering_nsec = True
								break
					if not has_covering_nsec:
						failure_reasons.append("Authority section had no covering NSEC record [mkl]")
				# Additional section contains at least one A or AAAA record found in the zone associated with at least one NS record found in the Authority section. [cjm]
				#    Collect the NS records from the Authority section
				found_NS_recs = set()
				for this_rec_dict in resp["authority"]:
					rec_qtype = this_rec_dict["rdtype"]
					if rec_qtype == "NS":
						for this_ns in this_rec_dict["rdata"]:
							found_NS_recs.add(this_ns.upper())
				found_qname_of_A_AAAA_recs = set()
				for this_rec_dict in resp["additional"]:
					rec_qtype = this_rec_dict["rdtype"]
					if rec_qtype in ("A", "AAAA"):
						found_qname_of_A_AAAA_recs.add((this_rec_dict["name"]).upper())
				found_A_AAAA_NS_match = False
				for a_aaaa_qname in found_qname_of_A_AAAA_recs:
						if a_aaaa_qname in found_NS_recs:
							found_A_AAAA_NS_match = True
							break
				if not found_A_AAAA_NS_match:
					failure_reasons.append(f"No QNAMEs from A and AAAA in Additional {found_qname_of_A_AAAA_recs} matched NS from Authority {found_NS_recs} [cjm]")
			elif (this_qname != ".") and (this_qtype == "DS"):  # Processing for TLD / DS [dru]
				# The header AA bit is set. [yot]
				if not "AA" in resp["flags"]:
					failure_reasons.append("AA bit was not set [yot]")
				# The Answer section contains the signed DS RRset for the query name. [cpf]
				if not resp.get("answer"):
					failure_reasons.append("Answer section was empty [cpf]")
				else:
					# Make sure the DS is for the query name
					for this_rec_dict in resp["answer"]:
						rec_qname = this_rec_dict["name"]
						rec_qtype = this_rec_dict["rdtype"]
						if rec_qtype == "DS":
							if not rec_qname == this_qname:
								failure_reasons.append(f"DS in Answer section had QNAME {rec_qname} instead of {this_qname} [cpf]")
					this_resp = check_for_signed_rr(resp["answer"], "DS")
					if this_resp:
						failure_reasons.append(f"{this_resp} [cpf]")
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
					failure_reasons.append(f"{this_resp} [obw]")
				# The Authority section contains the signed NS RRset for the root, or is empty. [ktm]
				#   The "or is empty" is added in v2.
				if not resp.get("authority"):
					debug(f"The Authority section was empty in {in_filename_record}")
				else:
					this_resp = check_for_signed_rr(resp["authority"], "NS")
					if this_resp:
						failure_reasons.append(f"{this_resp} [ktm]")
			elif (this_qname == ".") and (this_qtype == "NS"):  # Processing for . / NS [amj]
				# The header AA bit is set. [csz]
				if not "AA" in resp["flags"]:
					failure_reasons.append("AA bit was not set [csz]")
				# The Answer section contains the signed NS RRset for the root. [wal]
				this_resp = check_for_signed_rr(resp["answer"], "NS")
				if this_resp:
					failure_reasons.append(f"{this_resp} [wal]")
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
					failure_reasons.append(f"{this_resp} [eou]")
				# The Authority section is empty. [kka]
				if resp.get("authority"):
					failure_reasons.append("Authority section was not empty [kka]")
				# The Additional section is empty. [jws]
				if resp.get("additional"):
					failure_reasons.append("Additional section was not empty [jws]")
			else:
				debug(f"NOERROR on {this_qname}/{this_qtype} in {in_filename_record}")
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
				for this_rec_dict in resp["authority"]:
					rec_qname = this_rec_dict["name"]
					rec_qtype = this_rec_dict["rdtype"]
					if rec_qtype == "SOA":
						if not rec_qname == ".":
							failure_reasons.append(f"SOA in Authority section had QNAME {rec_qname} instead of '.' [vcu]")
				this_resp = check_for_signed_rr(resp["authority"], "SOA")
				if this_resp:
					failure_reasons.append(f"{this_resp} [axj]")
				# The Authority section contains a signed NSEC record whose owner name would appear before the QNAME and whose Next Domain Name field
				#   would appear after the QNAME according to the canonical DNS name order defined in RFC4034, proving no records for QNAME exist in the zone. [czb]
				#   Note that the query name might have multiple labels, so only compare against the last label
				this_qname_TLD = this_qname.split(".")[-2] + "."
				nsec_covers_query_name = False
				nsecs_in_authority = set()
				for this_rec_dict in resp["authority"]:
					rec_qtype = this_rec_dict["rdtype"]
					if rec_qtype == "NSEC":
						# Just looking at the first NSEC record
						rec_qname = this_rec_dict["name"]
						rec_rdata = this_rec_dict["rdata"][0]
						(next_name, _) = rec_rdata.split(" ", maxsplit=1)  # Ignore the type_bit_map
						# Sorting against "." doesn't work, so instead use the longest TLD that could be in the root zone
						if next_name == ".":
							next_name = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
						nsecs_in_authority.add(f"{rec_qname}|{next_name}")
						# Make a list of the three strings, then make sure the original QNAME is in the middle
						test_sort = sorted([rec_qname, next_name, this_qname_TLD])
						if test_sort[1] == this_qname_TLD:
							nsec_covers_query_name = True
							break
				if not nsec_covers_query_name:
					failure_reasons.append(f"NSECs in Authority {nsecs_in_authority} did not cover qname {this_qname} [czb]")
				# The Authority section contains a signed NSEC record with owner name “.” proving no wildcard exists in the zone. [jhz]
				nsec_with_owner_dot = False
				for this_rec_dict in resp["authority"]:
					rec_qname = this_rec_dict["name"]
					rec_qtype = this_rec_dict["rdtype"]
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
		# Determine the new value if is_correct
		if failure_reason_text == "":
			new_is_correct = "y"
		elif this_is_correct == "?":
			new_is_correct = "r"	
		elif this_is_correct == "r":
			new_is_correct = "n"
			soas_checked = []
			for this_file in soa_matching_date_files:
				soas_checked.append(this_file.replace(f"{saved_matching_dir}/", "").replace(".matching.pickle", ""))
			failure_reason_text += f"\nCorrectness was first tested against {this_soa_to_check} and then later against {' '.join(soas_checked)}"
		# If this was a test, just return the failure_reason_text
		if opts.test:
			return failure_reason_text
		# Here if it is not a test. Enter the new value in the database, and stop if it is a "y"
		if new_is_correct == "y":
			return("update record_info set (is_correct, failure_reason) = (%s, %s) where filename_record = %s", \
				(new_is_correct, failure_reason_text, in_filename_record))
	# Here at the end of the loop over the roots to check
	return("update record_info set (is_correct, failure_reason) = (%s, %s) where filename_record = %s", \
		(new_is_correct, failure_reason_text, in_filename_record))

###############################################################

if __name__ == "__main__":
	# Get the base for the log directory
	log_dir = f"{str(Path('~').expanduser())}/Logs"
	if not os.path.exists(log_dir):
		os.mkdir(log_dir)
	# Set up the logging and alert mechanisms
	log_file_name = f"{log_dir}/log.txt"
	alert_file_name = f"{log_dir}/alert.txt"
	debug_file_name = f"{log_dir}/debug.txt"
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
	vp_debug = logging.getLogger("debugs")
	vp_debug.setLevel(logging.CRITICAL)
	debug_handler = logging.FileHandler(debug_file_name)
	debug_handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
	vp_debug.addHandler(debug_handler)
	def log(log_message):
		vp_log.info(log_message)
	def alert(alert_message):
		vp_alert.critical(alert_message)
		log(alert_message)
	def debug(debug_message):
		vp_debug.critical(debug_message)
	def die(error_message):
		vp_alert.critical(error_message)
		log(f"Died with '{error_message}'")
		exit()
	
	limit_size = 10
	
	this_parser = argparse.ArgumentParser()
	this_parser.add_argument("--test", action="store_true", dest="test",
		help="Run tests on requests; must be run in the Tests directory")
	this_parser.add_argument("--debug", action="store_true", dest="debug",
		help=f"Limit procesing to {limit_size} correctness items and run single-threaded")
	
	opts = this_parser.parse_args()

	# Where to store the incoming files comeing from the vantage points
	incoming_dir = f"{str(Path('~').expanduser())}/Incoming"
	if not os.path.exists(incoming_dir):
		os.mkdir(incoming_dir)
	# Where to save things long-term
	output_dir = f"{str(Path('~').expanduser())}/Output"
	if not os.path.exists(output_dir):
		os.mkdir(output_dir)
	# Subdirectories of log directory for root zones
	saved_root_zone_dir = f"{output_dir}/RootZones"
	if not os.path.exists(saved_root_zone_dir):
		os.mkdir(saved_root_zone_dir)
	saved_matching_dir = f"{output_dir}/RootMatching"
	if not os.path.exists(saved_matching_dir):
		os.mkdir(saved_matching_dir)
	saved_response_dir = f"{output_dir}/Responses"
	if not os.path.exists(saved_response_dir):
		os.mkdir(saved_response_dir)

	###############################################################

	# Tests can be run outside the normal cron job. Exits when done.
	#   This is only run from the command line, not from cron.
	if opts.test:
		run_tests_only()
		exit()

	###############################################################

	log("Started collector processing")

	###############################################################

	# Go through the files in incoming_dir
	processed_incoming_start = time.time()
	all_files = { os.path.basename(x).replace(".pickle.gz", ""): str(x) for x in Path(f"{incoming_dir}").glob("**/*.pickle.gz") }
	# Compare this list to the list of those already processed
	with psycopg2.connect(dbname="metrics", user="metrics") as conn:
		with conn.cursor() as cur:
			cur.execute("select filename_short from files_gotten")
			this_fetch = cur.fetchall()
			all_in_db = list(this_fetch)
	for this_db_tuple in all_in_db:
		this_db_name = this_db_tuple[0]
		if this_db_name in all_files:
			all_files.pop(this_db_name)
	log(f"Found {len(all_files)} files on disk, {len(all_in_db)} files in the database, left with {len(all_files)} files after culling")
	all_full_files = all_files.values()
	processed_incoming_count = 0
	with futures.ProcessPoolExecutor() as executor:
		for (this_file, _) in zip(all_full_files, executor.map(process_one_incoming_file, all_full_files)):
			processed_incoming_count += 1
	log(f"Finished processing {processed_incoming_count} incoming files in {int(time.time() - processed_incoming_start)} seconds")

	###############################################################

	# Now that all the measurements are in, go through all records in record_info where is_correct is "?"
	#   This finds record_type = "C" records that have not been evaluated yet
	#   This does not log or alert

	def do_correctness(in_correct_type):
		corr_start_time = time.time()
		processed_correctness_count = 0
		with psycopg2.connect(dbname="metrics", user="metrics") as conn:
			conn.set_session(autocommit=True)
			with conn.cursor() as cur:
				cur.execute(f"select filename_record, timeout, likely_soa, is_correct from record_info where record_type = 'C' and is_correct = '{in_correct_type}'")
				correct_to_check = cur.fetchall()
		# Make a list of tuples with the filename_record
		full_correctness_list = []
		for this_initial_correct in correct_to_check:
			full_correctness_list.append(("normal", this_initial_correct))
		log(f"Found {len(full_correctness_list)} '{in_correct_type}' records")
		with psycopg2.connect(dbname="metrics", user="metrics") as conn:
			conn.set_session(autocommit=True)
			with conn.cursor() as cur:
				if opts.debug:
					log(f"Limiting to {limit_size} records")
					for this_correctness in full_correctness_list[0:limit_size]:
						this_ret = process_one_correctness_tuple(this_correctness)
						processed_correctness_count += 1
						if this_ret:
							if not len(this_ret) == 2:
								alert(f"Got a bad correctness return of {this_ret}")
							else:
								try:
									cur.execute(this_ret[0], this_ret[1])
								except Exception as e:
									alert(f"Could not execute {this_ret}: {e}")					
				else:
					with futures.ProcessPoolExecutor() as executor:
						for (this_correctness, this_ret) in zip(full_correctness_list, executor.map(process_one_correctness_tuple, full_correctness_list)):
							processed_correctness_count += 1
							if this_ret:
								if not len(this_ret) == 2:
									alert(f"Got a bad correctness return of {this_ret}")
								else:
									try:
										cur.execute(this_ret[0], this_ret[1])
									except Exception as e:
										alert(f"Could not execute {this_ret}: {e}")
		log(f"Finished correctness checking {processed_correctness_count} '{in_correct_type}' records in {int(time.time() - corr_start_time)} seconds")

	# There might be some records with is_correct that is "r" from the last run. Do them first.
	for correct_type in ["r", "?"]:
		do_correctness(correct_type)

	exit()
