#!/usr/bin/env python3
''' Vantage point measurements probe for RSSAC047 '''

# Three-letter items in square brackets (such as [xyz]) refer to parts of rssac-047.md

import argparse, gzip, logging, os, pickle, random, re, requests, subprocess, time
from concurrent import futures

# Run one command; to be used under concurrent.futures
def do_one_command(command_dict):
	''' Takes a command_dict that contains command_dict["command"]; returns (success_bool, elapsed, text) '''
	one_command_start = time.time()
	try:
		command_to_give = command_dict["command"]
	except:
		alert(f"No 'command' in '{command_dict}' in do_one_command.")
	command_p = subprocess.run(command_to_give, shell=True, capture_output=True, text=True, check=False)
	one_command_elapsed = time.time() - one_command_start
	this_command_text = command_p.stdout
	# Return code 9 means timeout
	if command_p.returncode == 9:
		return(True, -1, this_command_text)
	elif not command_p.returncode == 0:
		return (False, one_command_elapsed, f"# Return code {command_p.returncode}\n# Command {command_to_give}\n{this_command_text}")
	elif len(this_command_text) == 0:
		return (False, one_command_elapsed, f"Running '{command_to_give}' got a zero-length response, stderr was '{command_p.stderr}'")
	else:
		return (True, one_command_elapsed, this_command_text)

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

	# Make the list of commands to give on this run
	#   This is a list of dicts. Each dict contains:
	#			"target": target for the query
	#			"internet": "v4" or "v6"
	#			"ip_addr": address for the query
	#			"test_type": "S" for ./SOA, "C" for correctness
	#			"command": the command to give
	all_commands = []
	
	# Notes on using "dig"
	#   Starting in BIND 9.16, dig has a "+yaml" argument that outputs responses in YAML format;
	#      this makes it much easier to parse the output than in earlier versions of BIND.
	#   The reported time for UDP is from query to response, as expected. [tsm]
	#   dig treats connection errors as timeouts [dfl] and are not retried. [dks]  ### Need to check this later
	#   dig uses query source port randomization [uym], query ID randomization [wsb], and query response matching [doh]
	#   Using dig causes some limitations in the implementation:
	#      There is no control of the reported time for TCP. [epp] This may or may not be OK for the final implementation.
  #   The templates below do *not* do DNS cookies [ujj] because they are optional and are not necessarily supported by all instances.
  #      This is a divergence from RSSAC047.
	path_to_dig = "/home/metrics/Target/bin/dig"

	# dot_soa_query_template uses +nodnssec +noauthority +noadditional in order to reduce the size of the responses
	#   The variables to be filled in are path_to_dig, IP address, -4 or -6, and "no" if this is for UDP
	#   It is used many of the measurements [dzn] [hht] [wdo] [zvy] [kzu]
	#   It has +nsid for later identification of instances [mgj]
	#   It has a timeout of 4 seconds [ywz]
	#   It does not allow retries [xyl]
	dot_soa_query_template = "{} +yaml . SOA @{} {} +{}tcp +nodnssec +noauthority +noadditional +bufsize=1220 +nsid +norecurse +time=4 +tries=1"

	# Run the queries for . SOA
	for this_target in test_targets:
		# Sent to both v4 and v6 addresses [jhb]
		for this_internet in ["v4", "v6"]:
			specify_4_or_6 = "-4" if this_internet == "v4" else "-6"
			for this_ip_addr in test_targets[this_target][this_internet]:
				# Send to both UDP and TCP [ykn]
				for this_transport in ["udp", "tcp"]:
					is_tcp_string = "no" if this_transport == "udp" else ""
					# Add the . SOA commands
					this_dig_cmd = dot_soa_query_template.format(path_to_dig, this_ip_addr, specify_4_or_6, is_tcp_string)
					all_commands.append( {
						"target": this_target,
						"internet": this_internet,
						"ip_addr": this_ip_addr,
						"transport": this_transport,
						"test_type": "S",
						"command": this_dig_cmd
					} )

	# The correctness_query_template is only used for correctness measurements
	#   The variables to be filled in are path_to_dig, QNAME, QTYPE, IP address, -4 or -6, and "no" if this is for UDP
	#   It uses +nsid for later identification of instances [mgj]
	#   It uses +dnssec [rhe]
	#   It uses a UDP buffer size of 1220 [rja]
	#   It has a timeout of 4 seconds [twf]
	#   It has +noignore to force a retry if the response has the TC bit set [hjw]
	correctness_query_template = "{} +yaml {} {} @{} {} +{}tcp +dnssec +bufsize=1220 +nsid +norecurse +time=4 +tries=1 +noignore"

	# Create one command for correctness
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
		correctness_candidates.append([this_qname, this_qtype])
	# For the negative test, choose a RAND-NXD
	all_letters = "abcdefghijklmnopqrstuvwxyz"  # [dse]
	ten_random_letters = ""
	for i in range(10):
		ten_random_letters += all_letters[random.randint(0, 25)]
	rand_nxd_tld = f"www.rssac047-test.{ten_random_letters}."  # [hkc]
	correctness_candidates.append([rand_nxd_tld, "A"])
	# Pick just one of these ten [yyg]
	this_correctness_test = random.choice(correctness_candidates)
	for this_target in test_targets:
		# Pick a random address type [thb]
		rand_v4_v6 = random.choice(["v4", "v6"])
		# Pick a random transport [ogo]
		rand_udp_tcp = random.choice(["udp", "tcp"])
		specify_4_or_6 = "-4" if this_internet == "v4" else "-6"
		is_tcp_string = "no" if this_transport == "udp" else ""
		for this_ip_addr in test_targets[this_target][rand_v4_v6]:
			# Add the DNSSEC correctness commands
			this_dig_cmd = correctness_query_template.format(
				path_to_dig,
				this_correctness_test[0],
				this_correctness_test[1],
				this_ip_addr,
				specify_4_or_6,
				is_tcp_string )
			all_commands.append( {
				"target": this_target,
				"internet": this_internet,
				"ip_addr": this_ip_addr,
				"transport": this_transport,
				"test_type": "C",
				"command": this_dig_cmd } )
	
	# Sleep a random time
	time.sleep(wait_first)

	# If the commands are supposed to run in random order, this would be the place to do that
	#   random.shuffle(all_commands)
	
	# Run the dig commands, collecting the text output
	commands_clock_start = int(time.time())
	all_dig_output = []
	with futures.ProcessPoolExecutor() as executor:
		for (this_command, this_ret) in zip(all_commands, executor.map(do_one_command, all_commands)):
			# Check the first argument for True/False
			if this_ret[0]:
				# The record of the command is [ target, internet, transport, ip_addr, test_type, elapsed, dig_output ]
				this_record = [
					this_command["target"], this_command["internet"], this_command["transport"], this_command["ip_addr"], this_command["test_type"],
					this_ret[1], this_ret[2] ]
				all_dig_output.append(this_record)
				# Log timeouts
				if this_record[5] == -1:
					log(f"Timeout for {this_record}")
			else:
				log(this_ret[2])
	
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
	#   "v": int, version of this program (1 for now)
	#   "d": int, the delay used: wait_first
	#   "e": float, elapsed time for commands: commands_clock_stop - commands_clock_start
	#   "r": list, the records
	#   "s", text, the output from scamper
	output_dict = {
		"v": 1,
		"d": wait_first,
		"e": commands_clock_stop - commands_clock_start,
		"r": all_dig_output,
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
