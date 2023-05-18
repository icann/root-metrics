#!/usr/bin/env python3

''' Create reports for RSSAC047 '''
# Run as the metrics user
# Three-letter items in square brackets (such as [xyz]) refer to parts of rssac-047.md

import argparse, datetime, glob, logging, math, os, pickle, psycopg2, statistics
from pathlib import Path

if __name__ == "__main__":
	# Get the base for the log directory
	log_dir = f"{str(Path('~').expanduser())}/Logs"
	if not os.path.exists(log_dir):
		os.mkdir(log_dir)
	# Set up the logging and alert mechanisms
	log_file_name = f"{log_dir}/reports-log.txt"
	alert_file_name = f"{log_dir}/reports-alert.txt"
	debug_file_name = f"{log_dir}/reports-debug.txt"
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
	
	this_parser = argparse.ArgumentParser()
	this_parser.add_argument("--test_date", action="store", dest="test_date",
		help="Give a date as YY-MM-DD-HH-MM-SS to act as today")
	this_parser.add_argument("--lastmonth", action="store_true", dest="lastmonth",
		help="Create a report for the previous month")
	this_parser.add_argument("--thisweek", action="store_true", dest="thisweek",
		help="Create a report for just the current week")
	this_parser.add_argument("--force", action="store_true", dest="force",
		help="Force the monthly report to be recreated if it already exists")
	opts = this_parser.parse_args()
	if not (opts.lastmonth or opts.thisweek):
		die("Need to specify either --lastmonth or --thisweek")

	# Subdirectories of ~/Output for the reports
	output_dir = f"{str(Path('~').expanduser())}/Output"
	if not os.path.exists(output_dir):
		os.mkdir(output_dir)
	monthly_reports_dir = f"{output_dir}/Monthly"
	if not os.path.exists(monthly_reports_dir):
		os.mkdir(monthly_reports_dir)
	weekly_reports_dir = f"{output_dir}/Weekly"
	if not os.path.exists(weekly_reports_dir):
		os.mkdir(weekly_reports_dir)

	report_type = "monthly" if opts.lastmonth else "weekly"
	log(f"Started {report_type} report process")
	
	##############################################################

	# Formats to use	
	strf_day_format = "%Y-%m-%d"
	strf_timestamp_format = "%Y-%m-%d %H:%M:%S"
	strf_fielename_format = "%Y-%m-%d-%H-%M-%S"
	
	if opts.thisweek:
		now = datetime.datetime.utcnow()
		week_ago = now + datetime.timedelta(days=-7)
		report_start_timestamp = week_ago.strftime(strf_timestamp_format)
		report_end_timestamp = now.strftime(strf_timestamp_format)
		new_report_name = f"{weekly_reports_dir}/custom-weekly-ending-{now.strftime(strf_fielename_format)}.txt"
	else:
		# See if a monthly report needs to be written
		if opts.test_date:
			parts = opts.test_date.split("-")
			if not len(parts) == 6:
				die("Must give argument to --test_date as YY-MM-DD-HH-MM-SS")
			try:
				now = datetime.datetime(int(parts[0]), int(parts[1]), int(parts[2]), int(parts[3]), int(parts[4]), int(parts[5]))
			except Exception as e:
				die(f"Could not parse {opts.test_date} into YY-MM-DD-HH-MM-SS: {e}")
			log(f"Using test date of {opts.test_date}, which becomes {now}")
		else:
			now = datetime.datetime.utcnow()
		this_month_number = now.month
		# Math is different if it is currently January
		if not now.month == 1:
			first_of_last_month = now.replace(month=(now.month - 1), day=1, hour=0, minute=0, second=0)
		else:
			first_of_last_month = now.replace(year=(now.year - 1), month=12, day=1, hour=0, minute=0, second=0)
		first_of_last_month_file = first_of_last_month.strftime(strf_day_format)
		end_of_last_month =  now.replace(day=1, hour=0, minute=0, second=0) - datetime.timedelta(seconds=1)  # [ver] [jps]
		log(f"It is now {now.strftime('%Y-%m-%d')}, the first of last month is {first_of_last_month_file}")
		# Look for a report for last month
		all_monthly_reports = glob.glob(f"{monthly_reports_dir}/monthly*.txt")
		for this_report in glob.glob(f"{monthly_reports_dir}/monthly-*.txt"):
			if first_of_last_month_file in this_report:
				if opts.force:
					log(f"Found {this_report}, going to re-create it")
				else:
					log(f"Found {this_report}, so no need to create it")  # [rps]
					exit()
		# Here if a monthly report needs to be made
		report_start_timestamp = first_of_last_month.strftime(strf_timestamp_format)
		report_end_timestamp = end_of_last_month.strftime(strf_timestamp_format)
		new_report_name = f"{monthly_reports_dir}/monthly-{first_of_last_month_file}.txt"
	log(f"About to create {new_report_name} for range {report_start_timestamp} to {report_end_timestamp}")

	##############################################################

	# The list of RSIs might change in the future, so treat this as a list [dlw]
	rsi_list = [ "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m" ]
	# Note that the database uses "target" for the RSIs, which this program uses "rsi"

	# RSS availability and response latency use the value k defined in Section 4.9 of RSSAC-047
	rss_k = math.ceil((len(rsi_list) - 1) * float(2/3))
	
	# The following is used for keeping track of the internet/transport pairs, and the way they are expressed in the report
	report_pairs = { "v4udp": "IPv4 UDP", "v4tcp": "IPv4 TCP", "v6udp": "IPv6 UDP", "v6tcp": "IPv6 TCP" }

	# Make a list of vantage points for the RSS reports
	vp_list_file = f"{str(Path('~').expanduser())}/repo/vp_list.txt"
	if not os.path.exists(vp_list_file):
		die(f"Could not find {vp_list_file}")
	vp_names = []
	with open(vp_list_file, mode="rt") as vp_f:
		for this_line in vp_f:
			(vp_name, _, _) = this_line.split(".")
			vp_names.append(vp_name)
	
	##############################################################

	# Get the records from the database
	with psycopg2.connect(dbname="metrics", user="metrics") as conn:
		with conn.cursor() as cur:
			# Set the dates for the search
			where_date = f"where date_derived between '{report_start_timestamp}' and  '{report_end_timestamp}' "

			# Get all the SOA records for this period
			cur.execute("select filename_record, target, internet, transport, query_elapsed, timeout, soa_found, date_derived from record_info " +
				f"{where_date} and record_type = 'S' order by date_derived")
			soa_recs = cur.fetchall()
	
			# Get all the correctness records for this period
			cur.execute("select filename_record, target, is_correct from record_info " +
				f"{where_date} and record_type = 'C' order by date_derived")
			correctness_recs = cur.fetchall()
			
			# Get all the failed correctness records to report in the additional section
			cur.execute("select filename_record, target, internet, transport, failure_reason from record_info " +
				f"{where_date} and record_type = 'C' and is_correct = 'n' order by date_derived")
			correctness_failures = cur.fetchall()
		
	log(f"Found {len(soa_recs)} SOA records and {len(correctness_recs)} correctness records for {report_start_timestamp} to {report_end_timestamp}")
		
	# Create dicts from the lists so that we can add derived values
	soa_dict = {}
	for x in soa_recs:
		soa_dict[x[0]] = { "rsi": x[1], "internet": x[2], "transport": x[3], "query_elapsed": x[4], "timeout": x[5], "soa_found": x[6], "date_time": x[7]}
		(_, vp, _) = x[0].split("-")
		soa_dict[x[0]]["vp"] = vp

	correctness_dict = {}
	for x in correctness_recs:
		correctness_dict[x[0]] = { "rsi": x[1], "is_correct": x[2]}

	##############################################################
	
	# Set up the RSI lists for the reports
	
	# For RSI availability, for each RSI, each internet/transport pair has two values: number of non-timeouts, and count
	rsi_availability = {}
	# For RSI response latency, for each RSI, each internet/transport pair has two values: list of response latencies, and count
	rsi_response_latency = {}
	# For RSI correctness, for each RSI, there are two values: number of incorrect responses, and count [jof] [lbl]
	rsi_correctness = {}
	# For publication latency, record the datetimes that each SOA is seen for each internet and transport pair
	rsi_publication_latency = {}

	for this_rsi in rsi_list:
		rsi_availability[this_rsi] = { "v4udp": [ 0, 0 ], "v4tcp": [ 0, 0 ], "v6udp": [ 0, 0 ], "v6tcp": [ 0, 0 ] }
		rsi_response_latency[this_rsi] = { "v4udp": [ [], 0 ], "v4tcp": [ [], 0 ], "v6udp": [ [], 0 ], "v6tcp": [ [], 0 ] }
		rsi_publication_latency[this_rsi] = {}
		rsi_correctness[this_rsi] = [ 0, 0 ]

	##############################################################	

	# RSI availability and RSI response latency collation (done at the same time)

	# Measurements for publication latency requires more work because the system has to determine when new SOAs are first seen
	#   soa_first_seen keys are SOAs, values are the date first seen
	soa_first_seen = {}
	for (this_key, this_rec) in sorted(soa_dict.items()):
		int_trans_pair = f"{this_rec['internet']}{this_rec['transport']}"
		# RSI availability [gfa]
		if not this_rec["timeout"]:
			rsi_availability[this_rec["rsi"]][int_trans_pair][0] += 1
		rsi_availability[this_rec["rsi"]][int_trans_pair][1] += 1
		# RSI response latency [fhw]
		if not this_rec["timeout"]:  # [vpa]
			try:
				rsi_response_latency[this_rec["rsi"]][int_trans_pair][0].append(this_rec["query_elapsed"])
				rsi_response_latency[this_rec["rsi"]][int_trans_pair][1] += 1
			except:
				die(f"Found a non-timed-out response that did not have an elapsed time: {this_rec}")
		# Store the date that a SOA was first seen; note that this relies on soa_recs to be ordered by date_derived
		this_soa = this_rec["soa_found"]
		if this_soa and (not this_soa in soa_first_seen):
			soa_first_seen[this_soa] = this_rec["date_time"]

	##############################################################

	# RSI publication latency collation  # [yxn]

	# This must be run after the soa_first_seen dict is filled in
	for this_rsi in rsi_list:
		for this_soa in soa_first_seen:
			rsi_publication_latency[this_rsi][this_soa] = { "v4udp": None, "v4tcp": None, "v6udp": None, "v6tcp": None, "last": None, "latency": 0 }
	# Go through the SOA records again, filling in the fields for internet and transport pairs
	#   Again, this relies on soa_recs to be in date order
	for (this_key, this_rec) in sorted(soa_dict.items()):
		this_rsi = this_rec["rsi"]
		this_soa_found = this_rec["soa_found"]
		# Timed-out responses don't count for publication latency  # [tub]
		if this_rec["timeout"]:
			continue
		int_trans_pair = f"{this_rec['internet']}{this_rec['transport']}"
		# Store the datetimes when each SOA was seen [cnj]
		if this_soa_found:
			# Only add an entry if there is not already one there; this causes only the earliest date_time to be recorded
			if not rsi_publication_latency[this_rsi][this_soa_found][int_trans_pair]:
				rsi_publication_latency[this_rsi][this_soa_found][int_trans_pair] = this_rec["date_time"]
	# Change the "last" entry in the rsi_publication_latency to the time that the SOA was finally seen by all internet/transport pairs
	for this_rsi in rsi_list:
		for this_soa in soa_first_seen:
			for this_pair in report_pairs:
				if not rsi_publication_latency[this_rsi][this_soa]["last"]:
					# Set "last" if it doesn't already exist
					rsi_publication_latency[this_rsi][this_soa]["last"] = rsi_publication_latency[this_rsi][this_soa][this_pair]
				elif rsi_publication_latency[this_rsi][this_soa][this_pair] > rsi_publication_latency[this_rsi][this_soa]["last"]:
					# Reset "last" to the new value if the new value is greater
					rsi_publication_latency[this_rsi][this_soa]["last"] = rsi_publication_latency[this_rsi][this_soa][this_pair]
			# Fill in the "latency" entry by comparing the "last" to the SOA datetime; it is stored as seconds
			rsi_publication_latency[this_rsi][this_soa]["latency"] = (rsi_publication_latency[this_rsi][this_soa]["last"] - soa_first_seen[this_soa]).seconds  # [jtz]
				
	##############################################################

	# RSI correctness collation [ebg]
	#   [0] is the number correct, [1] is the total count

	for (this_key, this_rec) in sorted(correctness_dict.items()):
		if not this_rec["is_correct"] == "n":
			rsi_correctness[this_rec["rsi"]][0] += 1
		rsi_correctness[this_rec["rsi"]][1] += 1
	
	##############################################################
	
	# RSS availability collation
		
	# For RSS availability, for each VP, for each date_time, count the availability in each internet/transport pair, and total count
	rss_availability = {}
	for this_vp in vp_names:
		rss_availability[this_vp] = {}
	# Go through te SOA records recorded earlier
	for (this_key, this_rec) in sorted(soa_dict.items()):
		this_vp = this_rec["vp"]
		this_date_time = this_rec["date_time"]
		if not rss_availability[this_vp].get(this_date_time):
			rss_availability[this_vp][this_date_time] = { "v4udp": [ 0, 0 ], "v4tcp": [ 0, 0 ], "v6udp": [ 0, 0 ], "v6tcp": [ 0, 0 ] }
		int_trans_pair = f"{this_rec['internet']}{this_rec['transport']}"
		if not this_rec["timeout"]:
			rss_availability[this_vp][this_date_time][int_trans_pair][0] += 1  # [egb]
			rss_availability[this_vp][this_date_time][int_trans_pair][1] += 1
				
	##############################################################
	
	# RSS response latency collation

	# For RSS response latency, for each date_time, each internet/transport pair has a list of latencies
	rss_response_latency_in = {}
	rss_latency_intervals = set()
	for (this_key, this_rec) in sorted(soa_dict.items()):  # [spx]
		this_vp = this_rec["vp"]
		this_date_time = this_rec["date_time"]
		this_query_elapsed = this_rec["query_elapsed"]
		rss_latency_intervals.add(this_date_time)
		if not rss_response_latency_in.get(this_date_time):
			rss_response_latency_in[this_date_time] = { "v4udp": [], "v4tcp": [], "v6udp": [], "v6tcp": [] }
		int_trans_pair = f"{this_rec['internet']}{this_rec['transport']}"
		if this_query_elapsed:
			rss_response_latency_in[this_date_time][int_trans_pair].append(this_query_elapsed)  # [bom]
	# Need to remove any empty int_trans_pair because empty lists can't have a median
	for this_latency_measurement_key in rss_response_latency_in:
		for this_date_time in rss_response_latency_in[this_latency_measurement_key]:
			for this_pair in  rss_response_latency_in[this_latency_measurement_key][this_date_time]:
				if this_pair == []:
					this_pair in  rss_response_latency_in[this_latency_measurement_key][this_date_time].pop(this_pair, None)
					debug(f"Removed empty pair for {this_pair} from {rss_response_latency_in[this_latency_measurement_key][this_date_time]}")
	# Reduce each list of latencies to the median of the lowest k latencies in that last
	rss_response_latency_aggregates = {}
	for this_interval in rss_latency_intervals:
		rss_response_latency_aggregates[this_interval] = {}
		for this_pair in report_pairs:
			this_median = statistics.median(rss_response_latency_in[this_interval][this_pair][0:rss_k-1])  # [jbr]
			this_count = len(rss_response_latency_in[this_interval][this_pair])
			rss_response_latency_aggregates[this_interval][this_pair] = [ this_median, this_count ]
			
	##############################################################
	
	# RSS publication latency collation
	
	rss_publication_latency_list = []
	for this_rsi in rsi_list:
		for this_soa in soa_first_seen:
			rss_publication_latency_list.append(rsi_publication_latency[this_rsi][this_soa]["latency"])  # [dbo]

	##############################################################
	
	# RSS correctness collation
	
	rss_correctness_numerator = 0
	rss_correctness_denominator = 0
	for this_rsi in rsi_list:
		rss_correctness_numerator += rsi_correctness[this_rsi][0]
		rss_correctness_denominator += rsi_correctness[this_rsi][1]
	rss_correctness_ratio = rss_correctness_numerator / rss_correctness_denominator  # [ywo]
	rss_correctness_incorrect = rss_correctness_denominator - rss_correctness_numerator

	##############################################################
	
	# Create the report
	
	report_main = []
	report_additional = []
	
	def r_out(in_text, additional=""):
		global report_main
		global report_additional
		if in_text:
			report_main.append(in_text + "\n")
		report_additional.append(in_text + additional + "\n")

	# Start the report text
	r_out(f"Report for {report_start_timestamp} to {report_end_timestamp}")

	# Note the number of measurements for this report
	r_out(f"Number of measurments across all vantage points: {len(soa_dict) + len(correctness_dict)}")
	
	# The report only has "Pass" and "Fail", not the collated metrics [ntt] [cpm]
	
	# RSI reports
	
	# RSI availability report
	rsi_availability_threshold = .96  # [ydw]
	r_out(f"\nRSI Availability\nThreshold is {int(rsi_availability_threshold * 100)}%")  # [vmx]
	for this_rsi in rsi_list:
		r_out(f"  {this_rsi}.root-servers.net:")
		for this_pair in sorted(report_pairs):
			rsi_availability_ratio = rsi_availability[this_rsi][this_pair][0] / rsi_availability[this_rsi][this_pair][1]  # [yah]
			pass_fail_text = "Fail" if rsi_availability_ratio < rsi_availability_threshold else "Pass"
			additional_text = f" -- {(rsi_availability_ratio * 100):>6.2f}%"
			r_out(f"    {report_pairs[this_pair]}: {pass_fail_text} {(rsi_availability[this_rsi][this_pair][1]):>8,} measurements", additional_text)  # [lkd]
	
	# RSI response latency report
	rsi_response_latency_udp_threshold = .250  # [zuc]
	rsi_response_latency_tcp_threshold = .500  # [bpl]
	r_out(f"\nRSI Response Latency\nThreshold for UDP is {rsi_response_latency_udp_threshold:.3f} seconds")
	r_out(f"Threshold for TCP is {rsi_response_latency_tcp_threshold:.3f} seconds")  # [znh]
	for this_rsi in rsi_list:
		r_out(f"  {this_rsi}.root-servers.net:")
		for this_pair in sorted(report_pairs):
			response_latency_median = statistics.median(rsi_response_latency[this_rsi][this_pair][0]) # [mzx]
			if "udp" in this_pair:
				pass_fail_text = "Fail" if response_latency_median > rsi_response_latency_udp_threshold else "Pass"
			else:
				pass_fail_text = "Fail" if response_latency_median > rsi_response_latency_tcp_threshold else "Pass"
			additional_text = f" -- {response_latency_median:.3f} median"
			r_out(f"    {report_pairs[this_pair]}: {pass_fail_text}  {(rsi_response_latency[this_rsi][this_pair][1]):>8,} measurements", additional_text)  # [lxr]
	
	# RSI correctness report
	rsi_correctness_threshold = 100  # ...as percentage [ahw]
	r_out("\nRSI Correctness\nThreshold is 100%")  # [mah]
	for this_rsi in rsi_list:
		r_out(f"  {this_rsi}.root-servers.net:")
		rsi_correctness_percentage = (rsi_correctness[this_rsi][0] / rsi_correctness[this_rsi][1]) * 100  # [skm]
		pass_fail_text = "Fail" if rsi_correctness_percentage < rsi_correctness_threshold else "Pass"
		additional_text = f" -- {rsi_correctness[this_rsi][1] - rsi_correctness[this_rsi][0]:>5,} incorrect, {rsi_correctness_percentage:>6.2f}%"
		r_out(f"    {pass_fail_text}  {rsi_correctness[this_rsi][1]:>10,}  measurements", additional_text)  # [fee]
	
	# RSI publication latency report
	rsi_publication_latency_threshold = 65 * 60 # [fwa]
	r_out(f"\nRSI Publication Latency\nThreshold is {rsi_publication_latency_threshold} seconds")  # [erf]
	for this_rsi in rsi_list:
		r_out(f"  {this_rsi}.root-servers.net:")
		# latency_differences is the delays in publication for this letter
		latency_differences = []
		for this_soa in soa_first_seen:
			if rsi_publication_latency[this_rsi].get(this_soa):
				latency_differences.append(rsi_publication_latency[this_rsi][this_soa]["latency"])  # [kvg] [udz]
		publication_latency_median = statistics.median(latency_differences)  # [yzp]
		pass_fail_text = "Fail" if publication_latency_median > rsi_publication_latency_threshold else "Pass"
		additional_text = f" -- {publication_latency_median:>7.1f} median"
		r_out(f"    {pass_fail_text}  {len(rsi_publication_latency[this_rsi]):>8,} measurements", additional_text)  # [hms]

	# RSS reports
	
	# Report both the derived values and a pass/fail indicator for each RSS metric [nuc]
	
	# RSS availability report
	rss_availability_threshold = .99999  # [wzz]
	r_out(f"\nRSS Availability\nThreshold is {(rss_availability_threshold * 100):>5.3f}%")  # [fdy]
	for this_pair in sorted(report_pairs):
		rss_availability_numerator = 0
		rss_availability_denominator = 0
		this_count = 0
		for this_vp in rss_availability:
			for this_date_time in rss_availability[this_vp]:
				rss_availability_numerator += min(rss_k, rss_availability[this_vp][this_date_time][this_pair][0])
				rss_availability_denominator += rss_k
				this_count += rss_availability[this_vp][this_date_time][this_pair][1]
		this_ratio = rss_availability_numerator / rss_availability_denominator  # [cvf]
		pass_fail_text = "Fail" if this_ratio < rss_availability_threshold else "Pass"
		additional_text = f" -- {rss_availability_numerator:>10,} /{rss_availability_denominator:>10,}"
		r_out(f"  {report_pairs[this_pair]}: {(this_ratio * 100):>7.3f}%, {pass_fail_text}, {this_count:>8,} measurements", additional_text)  # [vxl] [hgm]
		
	# RSS response latency report
	rss_response_latency_udp_threshold = .150  # [uwf]
	rss_response_latency_tcp_threshold = .300  # [lmx]
	r_out(f"\nRSS Response Latency\nThreshold for UDP is {rss_response_latency_udp_threshold:.3f} seconds")
	r_out(f"Threshold for TCP is {rss_response_latency_tcp_threshold:>.3f} seconds")  # [gwm]
	for this_pair in sorted(report_pairs):
		pair_latencies = []
		pair_count = 0
		for this_interval in rss_latency_intervals:
			pair_latencies.append(rss_response_latency_aggregates[this_interval][this_pair][0])
			pair_count += rss_response_latency_aggregates[this_interval][this_pair][1]
		pair_response_latency_median = statistics.median(pair_latencies)
		if "udp" in this_pair:
			pass_fail_text = "Fail" if pair_response_latency_median > rss_response_latency_udp_threshold else "Pass"
		else:
			pass_fail_text = "Fail" if pair_response_latency_median > rss_response_latency_tcp_threshold else "Pass"
		additional_text = f" -- {(statistics.mean(pair_latencies)):.3f} mean"
		r_out(f"  {report_pairs[this_pair]}: {pair_response_latency_median:.3f} median, {pass_fail_text}, {pair_count:>8,} measurements", additional_text)
	
	# RSS correctness report
	rss_correctness_threshold = 1  # [gfh]
	r_out("\nRSS Correctness\nThreshold is 100%")  # [vpj]
	pass_fail_text = "Fail" if rss_correctness_ratio < rss_correctness_threshold else "Pass"  # [udc]
	additional_text = f" -- {rss_correctness_incorrect} incorrect"
	r_out(f"   Entire RSS {(rss_correctness_ratio * 100):.6f}%, {pass_fail_text}, {rss_correctness_denominator:>8,} measurements", additional_text)  # [kea]

	# RSS publication latency
	rss_publication_latency_threshold = 35 * 60  # [zkl]
	r_out(f"\nRSS Publication Latency\nThreshold is {rss_publication_latency_threshold} seconds")  # [tkw]
	rss_publication_latency_median = statistics.median(rss_publication_latency_list)  # [zgb]
	pass_fail_text = "Fail" if rss_publication_latency_median > rss_publication_latency_threshold else "Pass"
	additional_text = f" -- {statistics.mean(rss_publication_latency_list):.3f} mean"
	r_out(f"   Entire RSS {rss_publication_latency_median} median, {pass_fail_text}, {len(rss_publication_latency_list):>8,} measurements", additional_text)  # [daz]

	##############################################################

	# List the correctness failures
	######################## Correctness testing is currently turned off, so this section does not apply
	######################## However, when it does apply, the pickle of the bad replies is now found in saved_response_dir / short_file_name
	"""
	if len(correctness_failures) > 0:
		r_out("", f"\nThere were {len(correctness_failures)} correctness failures during the period:")
		for (filename_record, target, internet, transport, failure_reason) in correctness_failures:
			culled_reasons = []
			this_source = pickle.loads(source_pickle)
			r_out("", f"   {filename_record}: {target} {internet} {transport} for {this_source['question'][0]['name']}/{this_source['question'][0]['rdtype']}:")
			# Get the reasons
			for this_line in failure_reason.splitlines():
				# If this is a . / SOA record, only put out the actual error, not the stuff indicating that we tested against other SOAs
				if this_source["question"][0]["name"] == "." and this_source["question"][0]["rdtype"] == "SOA":
					if this_line.startswith("Set of RRset value {'A.ROOT-SERVERS.NET. NSTLD.VERISIGN-GRS.COM.") or this_line.startswith("Correctness was first tested"):
						continue
				culled_reasons.append(this_line.strip())
			for this_reason in culled_reasons:
				r_out("", f"      {this_reason}")
	else:
		r_out("", "\nThere were no correctness failures during the period.")
	"""
	
	##############################################################

	# Write out the report
	with open(new_report_name, mode="wt") as f_out:
		f_out.write("".join(report_main))
		f_out.write(f"\n{'-'*80}\n")
		f_out.write("".join(report_additional))
	
	log(f"Finished report process, wrote out {new_report_name}")	
	exit()
