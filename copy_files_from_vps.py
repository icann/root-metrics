#!/usr/bin/env python3

''' Copy the files from the vantage points using rsync '''
# Run as the metrics user
# Three-letter items in square brackets (such as [xyz]) refer to parts of rssac-047.md

import logging, os, subprocess, time
from pathlib import Path
from concurrent import futures

###############################################################

def get_files_from_one_vp(this_vp):

	# Used to rsync files from VPs under multiprocessing into incoming_dir; retuns error messages
	(vp_number, _) = this_vp.split(".", maxsplit=1)
	pull_to_dir = f"{incoming_dir}/{vp_number}"
	if not os.path.exists(pull_to_dir):
		try:
			os.mkdir(pull_to_dir)
		except:
			die(f"Could not create {pull_to_dir}")
	# rsync from the VP
	for this_dir in ("Output", "Routing", "Logs"):
		try:
			p = subprocess.run(f"rsync -av --timeout=5 metrics@{vp_number}.mtric.net:{this_dir} {pull_to_dir}/", shell=True, capture_output=True, text=True, check=True)
		except Exception as e:
			debug(f"For {vp_number}, failed to rsync {this_dir}: {e}")
			return ""
		# Keep the log
		try:
			log_f = open(f"{pull_to_dir}/rsync-log.txt", mode="at")
			log_f.write(p.stdout)
			log_f.close()
		except:
			die(f"Could not write to log {pull_to_dir}/{vp_number}/rsync-log.txt") 
	return ""

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
	saved_root_zone_dir = f"{output_dir}/RootZones"
	if not os.path.exists(saved_root_zone_dir):
		os.mkdir(saved_root_zone_dir)
	saved_matching_dir = f"{output_dir}/RootMatching"
	if not os.path.exists(saved_matching_dir):
		os.mkdir(saved_matching_dir)

	# Get the list of VPs
	vp_list_filename = f"{str(Path('~').expanduser())}/vp_list.txt"
	try:
		all_vps = open(vp_list_filename, mode="rt").read().splitlines()
	except Exception as e:
		die(f"Could not open {vp_list_filename} and split the lines: {e}")
	# Make sure we have trusted each one
	known_hosts_set = set()
	known_host_lines = open(f"{str(Path('~').expanduser())}/.ssh/known_hosts", mode="rt").readlines()
	for this_line in known_host_lines:
		known_hosts_set.add(this_line.split(" ")[0])
	for this_vp in all_vps:
		if not this_vp in known_hosts_set:
			try:
				subprocess.run(f"ssh-keyscan -4 -t rsa {this_vp} >> ~/.ssh/known_hosts", shell=True, capture_output=True, check=True)
				log(f"Added {this_vp} to known_hosts")
			except Exception as e:
				die(f"Could not run ssh-keyscan on {this_vp}: {e}")
	start_time = time.time()
	with futures.ProcessPoolExecutor() as executor:
		for (this_vp, this_ret) in zip(all_vps, executor.map(get_files_from_one_vp, all_vps)):
			if not this_ret == "":
				alert(this_ret)
	log(f"Finished pulling from VPs in {int(time.time()-start_time)} seconds")

	exit()
	