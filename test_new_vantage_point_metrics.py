#!/usr/bin/env python3
''' Vantage point measurements probe for RSSAC047 '''

# Three-letter items in square brackets (such as [xyz]) refer to parts of rssac-047.md

import argparse, concurrent.futures, gzip, logging, os, pickle, random, socket, subprocess, time
import dns.edns, dns.flags, dns.message, dns.query, dns.rdatatype
from pathlib import Path

# New class for errors from dnspython queries
class QueryError(Exception):
	pass

# Run one command; to be used under concurrent.futures
def do_one_query(target, internet, ip_addr, transport, query, test_type):
	''' Send one query; return a dict of results '''
	id_string = f"{target}|{internet}|{transport}|{query}|{test_type}"
	r_dict = { "id_string": id_string, "error": "", "target": target, "internet": internet, "ip_addr": ip_addr,
		"transport": transport, "query": query, "test_type": test_type }
	r_dict["timeout"] = ""
	# Sanity checks
	if not internet in ("v4", "v6"):
		raise QueryError(f"Bad internet: {internet} in {id_string}")
	if not transport in ("udp", "tcp"):
		raise QueryError(f"Bad transport: {transport} in {id_string}")
	if not test_type in ("C", "S"):
		raise QueryError(f"Bad test type: {test_type} in {id_string}")
	# Prepare the query
	try:
		(qname, qtype) = query.split("/")
	except:
		raise QueryError(f"Bad query: {query} in {id_string}")
	try:
		qname_processed = dns.name.from_text(qname)
	except:
		raise QueryError(f"Bad qname: {qname} in {id_string}")
	try:
		qtype_processed = dns.rdatatype.from_text(qtype)
	except:
		raise QueryError(f"Unknown qtype: {qtype} in {id_string}")
	q = dns.message.make_query(qname_processed, qtype_processed)
	# Turn off the RD bit
	q.flags &= ~dns.flags.RD
	# Include NSID over EDNS0 [mgj] for both "S" and "C"
	nsid_option = dns.edns.GenericOption(dns.edns.OptionType.NSID, b'')
	# If test_type is "C", set the buffer size to 1220 [rja] and add DO bit
	if test_type == "C":
		q.use_edns(edns=0, payload=1220, ednsflags=dns.flags.DO, options=[nsid_option])
	else:
		q.use_edns(edns=0, options=[nsid_option])
	# Start the return value
	query_start_time = time.time()
	# Choose the transport
	if transport == "udp":
		try:
			r = dns.query.udp(q, ip_addr, timeout=4.0)
			r_dict["query_elapsed"] = time.time() - query_start_time
		except Exception as e:
			if "operation timed out" in str(e):
				r_dict["timeout"] = "UDP timeout"
			else:
				r_dict["error"] = f"UDP query failure: {e}"
			return r_dict
	else:
		try:
			tcp_start_time = time.time()
			if internet == "v4":
				t_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			else:
				t_sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
			t_sock.connect((ip_addr, 53))
			r_dict["tcp_setup"] = time.time() - tcp_start_time
		except Exception as e:
			if "operation timed out" in str(e):
				r_dict["timeout"] = "TCP setup timeout"
			else:
				r_dict["error"] = f"TCP setup failure: {e}"
			return r_dict
		try:
			r = dns.query.tcp(q, None, timeout=4.0, sock=t_sock)
			r_dict["query_elapsed"] = time.time() - query_start_time
			t_sock.close()
		except Exception as e:
			if "operation timed out" in str(e):
				r_dict["timeout"] = "TCP query timeout"
			else:
				r_dict["error"] = f"TCP query failure: {e}"
			return r_dict
	# Collect all the response data
	try:
		r_dict["id"] = r.id
		r_dict["rcode"] = dns.rcode.to_text(r.rcode())
		r_dict["flags"] = dns.flags.to_text(r.flags)
		r_dict["edns"] = {}
		for this_option in r.options:
			r_dict["edns"][this_option.otype.value] = this_option.data
		if test_type == "C":
			get_sections = ("question", "answer", "authority", "additional")
		else:
			get_sections = ("question", "answer")
		for (this_section_number, this_section_name) in enumerate(get_sections):
			r_dict[this_section_name] = []
			for this_rrset in r.section_from_number(this_section_number):
				this_rrset_dict = {"name": this_rrset.name.to_text(), "ttl": this_rrset.ttl, "rdtype": dns.rdatatype.to_text(this_rrset.rdtype), "rdata": []}
				for this_record in this_rrset:
					this_rrset_dict["rdata"].append(this_record.to_text())
				r_dict[this_section_name].append(this_rrset_dict)
	except Exception as e:
		raise QueryError(f"Dict failure; {e} in {id_string}")
	return r_dict

# Main program starts here

if __name__ == "__main__":
	# Get the vantage point identifier from the short-host-name.txt file
	#   This has to be done before setting up logging, so "exit" is needed if it fails
	vp_ident_file_name = "/home/metrics/short-host-name.txt"
	try:
		vp_ident = open(vp_ident_file_name, mode="rt").read().strip()
	except:
		exit(f"Could not read {vp_ident_file_name}. Exiting.")
	if vp_ident == None or vp_ident == "":
		exit(f"The vp_ident gotten from {vp_ident_file_name} was bad: '{vp_ident}'. Exiting.")

	# Get the time string for this run
	start_time_string = time.strftime("%Y%m%d%H%M")

	out_file_id = f"{start_time_string}-{vp_ident}"
	
	# Get the base for the log and alerts directories
	log_dir = f"{os.path.expanduser('~')}/Logs"
	if not os.path.exists(log_dir):
		os.mkdir(log_dir)

	# Set up the logging and alert mechanisms
	#   Requires log_dir to have been defined above 
	log_file_name = f"{log_dir}/log.txt"
	alert_file_name = f"{log_dir}/alert.txt"
	vp_log = logging.getLogger("logging")
	vp_log.setLevel(logging.INFO)
	log_handler = logging.FileHandler(log_file_name)
	log_handler.setFormatter(logging.Formatter("%(created)d %(message)s"))
	vp_log.addHandler(log_handler)
	vp_alert = logging.getLogger("alerts")
	vp_alert.setLevel(logging.CRITICAL)
	alert_handler = logging.FileHandler(alert_file_name)
	alert_handler.setFormatter(logging.Formatter("%(created)d %(message)s"))
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

	# Get the command-line arguments
	this_parser = argparse.ArgumentParser()
	this_parser.add_argument("--verbose",  dest="verbose", action="store_true", 
		help="Make the logging more verbose; not currently used")
	opts = this_parser.parse_args()
	
	# Set the wait time for a random period of up to 60 seconds [fzk]
	wait_first = random.randint(0, 60)
	# List the targets by root server identifier letter and associated IP addresses [yns]
	test_targets= {
		"a": { "v4": ["198.41.0.4"], "v6": ["2001:503:ba3e::2:30"] },
		"b": { "v4": ["199.9.14.201"], "v6": ["2001:500:200::b"] },
		"c": { "v4": ["192.33.4.12"], "v6": ["2001:500:2::c"] },
		"d": { "v4": ["199.7.91.13"], "v6": ["2001:500:2d::d"] },
		"e": { "v4": ["192.203.230.10"], "v6": ["2001:500:a8::e"] },
		"f": { "v4": ["192.5.5.241"], "v6": ["2001:500:2f::f"] },
		"g": { "v4": ["192.112.36.4"], "v6": ["2001:500:12::d0d"] },
		"h": { "v4": ["198.97.190.53"], "v6": ["2001:500:1::53"] },
		"i": { "v4": ["192.36.148.17"], "v6": ["2001:7fe::53"] },
		"j": { "v4": ["192.58.128.30"], "v6": ["2001:503:c27::2:30"] },
		"k": { "v4": ["193.0.14.129"], "v6": ["2001:7fd::1"] },
		"l": { "v4": ["199.7.83.42"], "v6": ["2001:500:9f::42"] },
		"m": { "v4": ["202.12.27.33"], "v6": ["2001:dc3::35"] } }

	# Open the root_auth_file and get qname_qtype_pairs
	root_auth_file = f"{str(Path('~').expanduser())}/Logs/root-auth-rrs.pickle"
	if not os.path.exists(root_auth_file):
		die(f"Could not find {root_auth_file}")
	with open(root_auth_file, mode="rb") as root_f:
		try:
			root_name_and_types = pickle.load(root_f)
		except Exception as e:
			die(f"Could not unpickle {root_auth_file}: {e}")
	qname_qtype_pairs = list(root_name_and_types.keys())

	# Pick one QNAME for correctness to be used later
	#    90% chance of a positive authoritative QNAME/QTYPE, 10% chance of a negative test value
	correctness_candidates = []
	# Choose nine good pairs at random
	while len(correctness_candidates) < 9:
		this_pair = random.choice(qname_qtype_pairs)
		(this_qname, this_qtype) = this_pair.split("/")
		if not ( ((this_qname == ".") and (this_qtype == "SOA")) \
			or ((this_qname == ".") and (this_qtype == "DNSKEY")) \
			or ((this_qname == ".") and (this_qtype == "NS")) \
			or ((this_qname != ".") and (this_qname.count(".") == 1) and (this_qtype == "NS") and (this_qname != "arpa.")) \
			or ((this_qname != ".") and (this_qname.count(".") == 1) and (this_qtype == "DS")) ):
			continue
		# RSSAC047 says that we may use 0x20 mixed case in the QNAME. [zon] This is not done here.
		correctness_candidates.append(f"{this_qname}/{this_qtype}")
	# For the negative test, choose a RAND-NXD
	all_letters = "abcdefghijklmnopqrstuvwxyz"  # [dse]
	ten_random_letters = ""
	for i in range(10):
		ten_random_letters += all_letters[random.randint(0, 25)]
	rand_nxd_tld = f"www.rssac047-test.{ten_random_letters}."  # [hkc]
	correctness_candidates.append(f"{rand_nxd_tld}/A")
	# Pick just one of these ten [yyg]
	this_correctness_test = random.choice(correctness_candidates)
	correctness_tuples = []
	for this_target in test_targets:
		# Pick a random address type [thb]
		rand_v4_v6 = random.choice(["v4", "v6"])
		# Pick a random transport [ogo]
		rand_udp_tcp = random.choice(["udp", "tcp"])
		for this_ip_addr in test_targets[this_target][rand_v4_v6]:
			correctness_tuples.append((this_target, rand_v4_v6, this_ip_addr, rand_udp_tcp, this_correctness_test))
	
	# Sleep a random time
	time.sleep(wait_first)
	
	# Send the dnspython queries for ./SOA
	all_results = []
	commands_clock_start = time.time()
	with concurrent.futures.ThreadPoolExecutor() as executor:
		# Calling sequence for do_one_query() is: target, internet, ip_addr, transport, query, test_type
		returned_futures = {}
		# First launch the correctness tests (C)
		for (this_target, this_internet, this_ip_addr, this_transport, this_q_and_t) in correctness_tuples:
			returned_futures[executor.submit(do_one_query, this_target, this_internet, this_ip_addr, this_transport, this_q_and_t, "C")] = None
		# Then launch the ./SOA queries (S)
		for (this_target, this_dict) in test_targets.items():
			for this_transport in ["udp", "tcp" ]:
				for this_internet in ["v4", "v6" ]:
					returned_futures[executor.submit(do_one_query, this_target, this_internet, this_dict[this_internet][0], this_transport, "./SOA", "S")] = None
		# Collect the results
		for this_future in concurrent.futures.as_completed(returned_futures):
			try:
				this_ret = this_future.result()
			except Exception as e:
				alert(f"Request error: {e}")
			else:
				all_results.append(this_ret)
	
	# Finish with the scamper command to run traceroute-like queries for all targets [vno]
	scamper_output = ""
	scamper_start_time = time.time()
	this_scamper_cmd = "/usr/bin/scamper -i "
	for this_target in test_targets:
		for this_internet in ["v4", "v6"]:
			specify_4_or_6 = "-4" if this_internet == "v4" else "-6"
			for this_ip_addr in test_targets[this_target][this_internet]:
				this_scamper_cmd += f"{this_ip_addr} "
	try:
		command_p = subprocess.run(this_scamper_cmd, shell=True, capture_output=True, text=True, check=True)
	except Exception as e:
		alert(f"Running scamper had the exception '{e}'; continuing.")
	scamper_output = command_p.stdout
	scamper_elapsed = int(time.time() - scamper_start_time)
	if len(scamper_output) == 0:
		alert(f"Running scamper got a zero-length response in {scamper_elapsed} seconds, stderr was '{command_p.stderr}'")
	scamper_output += f"Elapsed was {scamper_elapsed} seconds"

	commands_clock_stop = time.time()

	# Look for timeputs [yve]
	for this_result in all_results:
		if this_result["timeout"]:
			log(f"{out_file_id}\t{this_result['timeout']}\t{this_result['id_string']}")

	# Go through the "S" records in all_results looking for the highest SOA value
	highest_soa = ""
	for this_result in all_results:
		if this_result["test_type"] == "S":
			if this_result.get("answer"):
				this_soa_record = this_result["answer"][0]["rdata"][0]
				soa_record_parts = this_soa_record.split(" ")
				this_soa = soa_record_parts[2]
				if this_soa > highest_soa:
					highest_soa = this_soa
	if highest_soa == "":
		alert("None of the 'S' answers had SOA records in the answers.")
	
	# Save output as a dict
	#   "v": int, version of this program (3 for now)
	#   "d": int, the delay used: wait_first
	#   "e": float, elapsed time for commands: commands_clock_stop - commands_clock_start
	#   "l", text, the likely SOA for the correctness queries
	#   "r": list, the records
	output_dict = {
		"v": 4,
		"d": wait_first,
		"e": int(commands_clock_stop - commands_clock_start),
		"l": highest_soa,
		"r": all_results,
	}

	# Save the data to a file
	output_dir = "/home/metrics/Output"
	try:
		out_run_file_name = f"{output_dir}/{out_file_id}.pickle.gz"
		with gzip.open(out_run_file_name, mode="wb") as gzf:
			gzf.write(pickle.dumps(output_dict))
	except:
		alert(f"Could not create {out_run_file_name}")

	# Save the scamper output to a file
	routing_dir = "/home/metrics/Routing"
	try:
		scamper_file_name = f"{routing_dir}/{out_file_id}-routing.txt"
		with open(scamper_file_name, mode="wt") as scamper_f:
			scamper_f.write(scamper_output)
	except:
		alert(f"Could not create {scamper_file_name}")

	# Log the finish
	log(f"Finished {out_file_id}, {int(commands_clock_stop - commands_clock_start)} seconds elapsed")
	exit()

