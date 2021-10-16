#!/usr/bin/env python3
''' Vantage point measurements probe for RSSAC047 '''

# Three-letter items in square brackets (such as [xyz]) refer to parts of rssac-047.md

import argparse, concurrent.futures, gzip, logging, os, pickle, random, re, requests, socket, subprocess, time
import dns.edns, dns.message, dns.query, dns.rdataclass, dns.rdatatype

# New class for errors from dnspython queries
class QueryError(Exception):
	pass

# Run one command; to be used under concurrent.futures
def do_one_query(target, internet, ip_addr, transport, query, test_type):
	''' Send one ./SOA query over UDP/TPC and v4/v6; return a dict of results '''
	id_string = f"{target}|{internet}|{transport}|{query}|{test_type}"
	r_dict = { "id_string": id_string, "error": "", "target": target, "internet": internet, "ip_addr": ip_addr, "transport": transport, "query": query, "test_type": test_type }
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
	# If test_type is "C", set the buffer size to 1220 [rja] and add DO bit
	#    Include NSID over EDNS0 [mgj] for both "S" and "C"
	nsid_option = dns.edns.GenericOption(dns.edns.OptionType.NSID, b'')
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
			if "operation timed out" in e:
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
			if "operation timed out" in e:
				r_dict["timeout"] = "TCP setup timeout"
			else:
				r_dict["error"] = f"TCP setup failure: {e}"
			return r_dict
		try:
			r = dns.query.tcp(q, None, timeout=4.0, sock=t_sock)
			r_dict["query_elapsed"] = time.time() - query_start_time
			t_sock.close()
		except Exception as e:
			if "operation timed out" in e:
				r_dict["timeout"] = "TCP query timeout"
			else:
				r_dict["error"] = f"TCP query failure: {e}"
			return r_dict
	# Collect all the response data
	try:
		r_dict["id"] = r.id
		r_dict["opcode"] = r.opcode()
		r_dict["rcode"] = r.rcode()
		r_dict["flags"] = dns.flags.to_text(r.flags)
		r_dict["edns"] = {}
		for this_option in r.options:
			r_dict["edns"][this_option.otype.value] = this_option.data
		for (this_section_number, this_section_name) in enumerate(("question", "answer", "authority", "additional")):
			r_dict[this_section_name] = []
			for this_rrset in r.section_from_number(this_section_number):
				this_rrset_dict = {"name": this_rrset.name.to_text(), "ttl": this_rrset.ttl, "class": this_rrset.rdclass, "rdata": []}
				for this_record in this_rrset:
					this_rrset_dict["rdata"].append(this_record.to_text())
				r_dict[this_section_name].append(this_rrset_dict)
	except Exception as e:
		raise QueryError(f"Dict failure; {e} in {id_string}")
	return r_dict

# Make a list candidate RRsets for the correctness testing
def update_rr_list(file_to_write):
	# Returns nothing
	internic_url = "https://www.internic.net/domain/root.zone"
	try:
		r = requests.get(internic_url)
	except Exception as e:
		alert(f"Could not do the requests.get on {internic_url}: '{e}'")
		return
	# Save it as a temp file to use named-compilezone
	temp_latest_zone_name = f"{log_dir}/temp_latest_zone"
	temp_latest_zone_f = open(temp_latest_zone_name, mode="wt")
	temp_latest_zone_f.write(r.text)
	temp_latest_zone_f.close()
	# Give the named-compilezone command, then post-process
	try:
		named_compilezone_p = subprocess.run(f"/home/metrics/Target/sbin/named-compilezone -q -i none -r ignore -o - . '{temp_latest_zone_name}'",\
			shell=True, text=True, check=True, capture_output=True)
	except Exception as e:
		alert(f"named-compilezone failed with '{e}'")
	new_root_text_in = named_compilezone_p.stdout
	# Turn tabs into spaces
	new_root_text_in = re.sub("\t", " ", new_root_text_in)
	# Turn runs of spaces into a single space
	new_root_text_in = re.sub(" +", " ", new_root_text_in)
	# Get the output after removing comments
	new_root_text = ""
	# Remove the comments
	for this_line in new_root_text_in.splitlines():
		if not this_line.startswith(";"):
			new_root_text += f"{this_line}\n"	
	root_name_and_types = {}
	for (line_num, this_line) in enumerate(new_root_text.splitlines()):
		(this_name, _, _, this_type, rdata) = this_line.split(" ", maxsplit=4)
		this_key = f"{this_name}/{this_type}"
		if this_key in root_name_and_types:
			root_name_and_types[this_key].append(rdata)
		else:
			root_name_and_types[this_key] = [ rdata ]
	try:
		this_soa_record = root_name_and_types[("./SOA")][0]
	except:
		die("The root zone just received didn't have an SOA record.")
	try:
		this_soa = this_soa_record.split(" ")[2]
	except Exception as e:
		die(f"Splitting the SOA from the root zone just received failed with '{e}'")
	log(f"Got a new root zone with SOA {this_soa}")
	# Create a new root_auth_file, which has the same qname / qtypes as the processed file but only for authoritative zones
	root_auth_text = ""
	for this_key in root_name_and_types:
		(this_name, this_type) = this_key.split("/")
		# The logic on the following lines comes from [njh] [hmc] [xca] [max] [kmd] [unt]
		if ( ((this_name == ".") and (this_type == "SOA")) \
			or ((this_name == ".") and (this_type == "DNSKEY")) \
			or ((this_name == ".") and (this_type == "NS")) \
			or ((this_name != ".") and (this_name.count(".") == 1) and (this_type == "NS") and (this_name != "arpa.")) \
			or ((this_name != ".") and (this_name.count(".") == 1) and (this_type == "DS")) ):
			root_auth_text += f"{this_key}\n"
	root_auth_out_f = open(file_to_write, mode="wt")
	root_auth_out_f.write(root_auth_text)
	root_auth_out_f.close()
	log(f"Wrote out new {os.path.basename(file_to_write)}")
	return

# Main program starts here

if __name__ == "__main__":
	# Get the vantage point identifier from the short-host-name.txt file
	#   vp_ident of 999 is special: it means this is running on a local computer, probably for testing
	#   This has to be done before setting up logging, so "exit" is needed if it fails
	vp_ident_file_name = "/home/metrics/short-host-name.txt"
	try:
		vp_ident = open(vp_ident_file_name, mode="rt").read().strip()
	except:
		exit(f"Could not read {vp_ident_file_name}. Exiting.")
	if vp_ident == None or vp_ident == "":
		exit(f"The vp_ident gotten from {vp_ident_file_name} was bad: '{vp_ident}'. Exiting.")

	# Get the base for the log and alerts directories
	log_dir = f"{os.path.expanduser('~')}/Logs"
	if not os.path.exists(log_dir):
		os.mkdir(log_dir)
	alerts_dir = f"{log_dir}/Alerts"
	if not os.path.exists(alerts_dir):
		os.mkdir(alerts_dir)

	# Get the time string for this run
	start_time_string = time.strftime("%Y%m%d%H%M")

	# Set up the logging and alert mechanisms
	#   Requires log_dir and vp_ident to have been defined above 
	log_file_name = f"{log_dir}/{vp_ident}-log.txt"
	alert_file_name = f"{log_dir}/{vp_ident}-alert.txt"
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
		# Also write alerts as individual alert files
		p = subprocess.run(f'create-alert.py "{alert_message}"', shell=True, capture_output=True, text=True)
		if len(p.stdout) > 0:
			die(f"Trying to send alert failed with '{p.stderr}")
	def die(error_message):
		vp_alert.critical(error_message)
		log(f"Died with '{error_message}'")
		# Also write alerts as individual alert files
		subprocess.run(f'create-alert.py "{error_message}"', shell=True, capture_output=True, text=True)
		if vp_ident == "999":
			print(f"Exiting at {int(time.time())}: {error_message}")
		exit()

	# Log the start
	log(f"Starting run {start_time_string}-{vp_ident}")

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

	# Pick one QNAME for correctness to be used later
	#    90% chance of a positive authoritative QNAME/QTYPE, 10% chance of a negative test value
	correctness_candidates = []
	# Check if root-auth-rrs.txt is recent; if not, get a new one
	root_auth_file = f"{log_dir}/root-auth-rrs.txt"
	# For the first run, create the file
	if not os.path.exists(root_auth_file):
		f = open(root_auth_file, mode="wt")
		f.close()
		# But set this to be modified at the beginning of time so it is immediately updated
		os.utime(root_auth_file, (0,0))
	# See if the file is more than 12 hours old [mow]
	if time.time() - os.stat(root_auth_file).st_mtime > (60 * 60 * 12):
		update_rr_list(root_auth_file)
	try:
		qname_qtype_pairs = open(root_auth_file, mode="rt").read().splitlines()
	except:
		die(f"Could not open {root_auth_file}")
	# Choose nine good pairs at random
	for i in range(9):
		this_pair = random.choice(qname_qtype_pairs)
		(this_qname, this_qtype) = this_pair.split("/")
		# RSSAC047 calls for the use of 0x20 mixed case in the QNAME. [zon] This is not done here because it feels unneccessary,
		#   given that it is already highly unpredictable what queries will be sent.
		#   This is a divergence from RSSAC047.
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
	commands_clock_start = int(time.time())
	with concurrent.futures.ThreadPoolExecutor() as executor:
		# Calling sequence for do_one_query() is: target, internet, ip_addr, transport, query, test_type
		#   query is None for ./SOA, or "<qname>/<qtype>" for correctness
		returned_futures = {}
		# First launch the ./SOA queries (S)
		for (this_target, this_dict) in test_targets.items():
			for this_transport in ["udp", "tcp" ]:
				for this_internet in ["v4", "v6" ]:
					returned_futures[executor.submit(do_one_query, this_target, this_internet, this_dict[this_internet][0], this_transport, "./SOA", "S")] = None
		# Then launch the correctness tests (C)
		for (this_target, this_internet, this_ip_addr, this_transport, this_q_and_t) in correctness_tuples:
			returned_futures[executor.submit(do_one_query, this_target, this_internet, this_ip_addr, this_transport, this_q_and_t, "C")] = None
		# Collect the results
		for this_future in concurrent.futures.as_completed(returned_futures):
			try:
				this_ret = this_future.result()
			except Exception as e:
				log(f"Request error: {e}")
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
		log(f"Running scamper had the exception '{e}'; continuing.")
	scamper_output = command_p.stdout
	scamper_elapsed = int(time.time() - scamper_start_time)
	if len(scamper_output) == 0:
		log(f"Running scamper got a zero-length response in {scamper_elapsed} seconds, stderr was '{command_p.stderr}'")
	scamper_output += f"Elapsed was {scamper_elapsed} seconds"

	commands_clock_stop = int(time.time())

	# Save output as a dict
	#   "v": int, version of this program (2 for now)
	#   "d": int, the delay used: wait_first
	#   "e": float, elapsed time for commands: commands_clock_stop - commands_clock_start
	#   "r": list, the records
	#   "s", text, the output from scamper
	output_dict = {
		"v": 2,
		"d": wait_first,
		"e": commands_clock_stop - commands_clock_start,
		"r": all_results,
		"s": scamper_output
	}
	# Save the output in a file with start_time_string and vp_ident
	output_dir = "/sftp/transfer/Output"
	try:
		out_run_file_name = f"{output_dir}/{start_time_string}-{vp_ident}.pickle.gz"
		with gzip.open(out_run_file_name, mode="wb") as gzf:
			gzf.write(pickle.dumps(output_dict))
			gzf.close()
	except:
		alert(f"Could not create {out_run_file_name}")
	# Log the finish
	log(f"Finishing run, wrote out {os.path.basename(out_run_file_name)}, elapsed was {int(commands_clock_stop - commands_clock_start)} seconds")
	exit()
