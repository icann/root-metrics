#!/usr/bin/env python3

''' Gets the root zone '''
# Run as the metrics user under cron, every 15 minutes

import argparse, logging, os, pickle, re, requests
from pathlib import Path
################### import dns.ipv6
import dns.rdata

def cleanup(text_from_zone_file):
	''' Clean up the text by collapsing whitespaces and removing comments '''
	# Turn tabs into spaces
	text_from_zone_file = re.sub("\t", " ", text_from_zone_file)
	# Turn runs of spaces into a single space
	text_from_zone_file = re.sub(" +", " ", text_from_zone_file)
	# Get the output after removing comments
	out_root_text = ""
	# Remove the comments
	for this_line in text_from_zone_file.splitlines():
		if not this_line.startswith(";"):
			out_root_text += this_line + "\n"
	return out_root_text

def get_names_and_types(in_text):
	''' Takes a string that is the root zone, returns a dict of name/type: rdata '''
	root_name_and_types = {}
	for this_line in in_text.splitlines():
		(this_name, _, _, this_type, this_rdata) = this_line.split(" ", maxsplit=4)
		this_key = "{}/{}".format(this_name, this_type)
		if not this_key in root_name_and_types:
			root_name_and_types[this_key] = set()
		if this_type == "AAAA" or "DNSKEY":
			####################### this_rdata = dns.ipv6.inet_ntoa(dns.ipv6.inet_aton(this_rdata))
			this_rdata = dns.rdata.to_text(dns.rdata.from_text(this_rdata))
		root_name_and_types[this_key].add(this_rdata)
	return root_name_and_types

def find_soa(in_dict):
	''' Returns an SOA or dies if it cannot find it '''
	try:
		this_soa_record = list(in_dict[("./SOA")])[0]
	except:
		die("The root zone just received didn't have an SOA record.")
	try:
		this_soa = this_soa_record.split(" ")[2]
	except Exception as e:
		die("Splitting the SOA from the root zone just received failed with '{}'".format(e))
	return this_soa

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
		log(f"Died with '{error_message}'")
		exit()
	
	this_parser = argparse.ArgumentParser()
	this_parser.add_argument("--redo", action="store_true", dest="redo",
		help="Redo all the processing in the output directory")
	opts = this_parser.parse_args()

	# Where to save things long-term
	output_dir = f"{str(Path('~').expanduser())}/Output"
	if not os.path.exists(output_dir):
		os.mkdir(output_dir)

	log("Started root zone collecting")

	# Subdirectories of ~/Output for root zones
	saved_root_zone_dir = f"{output_dir}/RootZones"
	if not os.path.exists(saved_root_zone_dir):
		os.mkdir(saved_root_zone_dir)
	saved_matching_dir = f"{output_dir}/RootMatching"
	if not os.path.exists(saved_matching_dir):
		os.mkdir(saved_matching_dir)
	
	if opts.redo:
		log("Redoing all the output processing")
		for this_path in Path(saved_root_zone_dir).glob("*.root.txt"):
			with this_path.open(mode="rt") as f:
				new_root_text = cleanup(f.read())
				root_name_and_types = get_names_and_types(new_root_text)
				this_soa = find_soa(root_name_and_types)
				# reate a file of the tuples for matching
				matching_file_name = f"{saved_matching_dir}/{this_soa}.matching.pickle"
				with open(matching_file_name, mode="wb") as out_f:
					pickle.dump(root_name_and_types, out_f)
	else:
		# Get the current root zone
		internic_url = "https://www.internic.net/domain/root.zone"
		try:
			root_zone_request = requests.get(internic_url)
		except Exception as e:
			die(f"Could not do the requests.get on {internic_url}: {e}")
		new_root_text = cleanup(root_zone_request.text)
		root_name_and_types = get_names_and_types(new_root_text)
		this_soa = find_soa(root_name_and_types)

		# Check if this SOA has already been seen
		full_root_file_name = f"{saved_root_zone_dir}/{this_soa}.root.txt"  # [ooy]
		if not os.path.exists(full_root_file_name):
			with open(full_root_file_name, mode="wt") as out_f:
				out_f.write(root_zone_request.text)
			log("Got a root zone with new SOA {}".format(this_soa))
			# Also create a file of the tuples for matching
			matching_file_name = f"{saved_matching_dir}/{this_soa}.matching.pickle"
			with open(matching_file_name, mode="wb") as out_f:
				pickle.dump(root_name_and_types, out_f)

	log("Finished root zone collecting")
	
