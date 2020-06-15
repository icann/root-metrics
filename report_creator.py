#!/usr/bin/env python3

''' Create the monthly reports '''
# Run as the metrics user
# Three-letter items in square brackets (such as [xyz]) refer to parts of rssac-047.md

import argparse, datetime, glob, logging, math, os, psycopg2, statistics

if __name__ == "__main__":
	# Get the base for the log directory
	log_dir = "{}/Logs".format(os.path.expanduser("~"))
	if not os.path.exists(log_dir):
		os.mkdir(log_dir)
	# Set up the logging and alert mechanisms
	log_file_name = "{}/report-log.txt".format(log_dir)
	alert_file_name = "{}/report-alert.txt".format(log_dir)
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
	
	this_parser = argparse.ArgumentParser()
	this_parser.add_argument("--test_date", action="store", dest="test_date",
		help="Give a date as YY-MM-DD-HH-MM-SS to act as today")
	this_parser.add_argument("--force", action="store_true", dest="force",
		help="Force the monthly report to be recreated if it already exists")
	this_parser.add_argument("--debug", action="store_true", dest="debug",
		help="Adds debugging info to the report output")
	opts = this_parser.parse_args()

	# Subdirectories of ~/Output for the reports
	output_dir = os.path.expanduser("~/Output")
	if not os.path.exists(output_dir):
		os.mkdir(output_dir)
	monthly_reports_dir = "{}/Monthly".format(output_dir)
	if not os.path.exists(monthly_reports_dir):
		os.mkdir(monthly_reports_dir)

	log("Started report process")
	
	##############################################################
	
	# See if a monthly report needs to be written
	strf_day_format = "%Y-%m-%d"
	strf_timestamp_format = "%Y-%m-%d %H:%M:%S"
	if opts.test_date:
		parts = opts.test_date.split("-")
		if not len(parts) == 6:
			die("Must give test_date as YY-MM-DD-HH-MM-SS")
		try:
			now = datetime.datetime(int(parts[0]), int(parts[1]), int(parts[2]), int(parts[3]), int(parts[4]), int(parts[5]))
		except Exception as e:
			die("Could not parse {} into YY-MM-DD-HH-MM-SS: {}".format(opts.test_date, e))
		log("Using test date of {}, which becomes '{}'".format(opts.test_date, now))
	else:
		now = datetime.datetime.utcnow()
	this_month_number = now.month
	# Math is different if it is currently January
	if not now.month == 1:
		first_of_last_month = now.replace(month=(now.month - 1), day=1, hour=0, minute=0, second=0)
	else:
		first_of_last_month = now.replace(year=(now.year - 1), month=12, day=1, hour=0, minute=0, second=0)
	first_of_last_month_file = first_of_last_month.strftime(strf_day_format)
	first_of_last_month_timestamp = first_of_last_month.strftime(strf_timestamp_format)
	end_of_last_month =  now.replace(day=1, hour=0, minute=0, second=0) - datetime.timedelta(seconds=1)  # [ver] [jps]
	end_of_last_month_timestamp = end_of_last_month.strftime(strf_timestamp_format)
	log("It is now {}, the first of last month is {}".format(now.strftime("%Y-%m-%d"), first_of_last_month_file))
	# Look for a report for last month
	all_monthly_reports = glob.glob("{}/monthly*.txt".format(monthly_reports_dir))
	for this_report in glob.glob("{}/monthly-*.txt".format(monthly_reports_dir)):
		if first_of_last_month_file in this_report:
			if opts.force:
				log("Found {}, going to re-create it.".format(this_report))
			else:
				log("Found {}, so no need to create it.".format(this_report))  # [rps]
				exit()
	# Here if a monthly report needs to be made
	new_monthly_report_name = "{}/monthly-{}.txt".format(monthly_reports_dir, first_of_last_month_file)
	log("About to create {} for range {} to {}".format(new_monthly_report_name, first_of_last_month_timestamp, end_of_last_month_timestamp))
	# Start the report text
	report_text = "Report for {} to {}\n".format(first_of_last_month_timestamp, end_of_last_month_timestamp)

	##############################################################

	# Keep track of the files seen in order to count the number of measurements across all vantage points
	#   This will be filled in both in looking through the SOA and correctness datasets
	files_seen = set()
	# The list of RSIs might change in the future, so treat this as a list [dlw]
	rsi_list = [ "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m" ]

	# RSS availability and response latency use the value k defined in Section 4.9 of RSSAC-047
	rss_k = math.ceil((len(rsi_list) - 1) * float(2/3))
	
	# The following is used for keeping track of the internet/transport pairs, and the way they are expressed in the report
	report_pairs = { "v4udp": "IPv4 UDP", "v4tcp": "IPv4 TCP", "v6udp": "IPv6 UDP", "v6tcp": "IPv6 TCP" }

	##############################################################

	# Connect to the database
	try:
		conn = psycopg2.connect(dbname="metrics", user="metrics")
	except Exception as e:
		die("Unable to open database: '{}'".format(e))
	try:
		cur = conn.cursor()
	except Exception as e:
		die("Unable to get database cursor: '{}'".format(e))
	
	where_clause = "where date_derived between '{}' and  '{}' ".format(first_of_last_month_timestamp, end_of_last_month_timestamp)

	# Get all the SOA records for this month
	cur.execute("select file_prefix, date_derived, vp, rsi, internet, transport, dig_elapsed, timeout, soa from public.soa_info "\
		+ "{} order by date_derived".format(where_clause))
	soa_recs = cur.fetchall()
	log("Found {} SOA records".format(len(soa_recs)))
	
	# Get all the correctness records for this month
	cur.execute("select file_prefix, date_derived, rsi, is_correct from public.correctness_info {} order by date_derived".format(where_clause))
	correctness_recs = cur.fetchall()
	log("Found {} correctness records".format(len(correctness_recs)))

	# Collect information for the RSS availability
	cur.execute("select vp from public.soa_info {} group by vp".format(where_clause))
	vp_names = set()
	for this_record in cur.fetchall():
		vp_names.add(this_record[0])
	log("Found {} vantage point names".format(len(vp_names)))
	
	cur.close()
	conn.close()

	##############################################################

	# RSI availability and RSI response latency collation (done at the same time)

	# For RSI availability, for each RSI, each internet/transport pair has two values: number of non-timeouts, and count
	# For RSI response latency, for each RSI, each internet/transport pair has two values: list of response latencies, and count
	rsi_availability = {}
	rsi_response_latency = {}
	for this_rsi in rsi_list:
		rsi_availability[this_rsi] = { "v4udp": [ 0, 0 ], "v4tcp": [ 0, 0 ], "v6udp": [ 0, 0 ], "v6tcp": [ 0, 0 ] }
		rsi_response_latency[this_rsi] = { "v4udp": [ [], 0 ], "v4tcp": [ [], 0 ], "v6udp": [ [], 0 ], "v6tcp": [ [], 0 ] }
	# Measurements for publication latency requires more work because the system has to determine when new SOAs are first seen
	#   soa_first_seen keys are SOAs, values are the date first seen
	soa_first_seen = {}
	for this_rec in soa_recs:
		(this_file_prefix, this_date_time, this_vp, this_rsi, this_internet, this_transport, this_dig_elapsed, this_timeout, this_soa) = this_rec
		files_seen.add(this_file_prefix)
		int_trans_pair = this_internet + this_transport
		# RSI availability [gfa]
		if not this_timeout:
			rsi_availability[this_rsi][int_trans_pair][0] += 1
		rsi_availability[this_rsi][int_trans_pair][1] += 1
		# RSI response latency [fhw]
		if not this_timeout:  # [vpa]
			try:
				rsi_response_latency[this_rsi][int_trans_pair][0].append(this_dig_elapsed)
				rsi_response_latency[this_rsi][int_trans_pair][1] += 1
			except:
				die("Found a non-timed-out response that did not have an elapsed time: '{}'".format(this_rec))
		# Store the date that a SOA was first seen; note that this relies on soa_recs to be ordered by date_derived
		if this_soa and (not this_soa in soa_first_seen):
			soa_first_seen[this_soa] = this_date_time

	##############################################################

	# RSI correctness collation [ebg]

	# For RSI correctness, for each RSI, there are two values: number of incorrect responses, and count [jof] [lbl]
	rsi_correctness = {}
	for this_rsi in rsi_list:
		rsi_correctness[this_rsi] = [ 0, 0 ]
	for this_rec in correctness_recs:
		(this_file_prefix, this_date_time, this_rsi, this_correctness) = this_rec
		files_seen.add(this_file_prefix)
		if this_correctness:
			rsi_correctness[this_rsi][0] += 1
		rsi_correctness[this_rsi][1] += 1
		
	##############################################################

	# RSI publication latency collation  # [yxn]

	# This must be run after the soa_first_seen dict is filled in
	# For publication latency, record the datetimes that each SOA is seen for each internet and transport pair
	rsi_publication_latency = {}
	for this_rsi in rsi_list:
		rsi_publication_latency[this_rsi] = {}
		for this_soa in soa_first_seen:
			rsi_publication_latency[this_rsi][this_soa] = { "v4udp": None, "v4tcp": None, "v6udp": None, "v6tcp": None, "last": None, "latency": 0 }
	# Go through the SOA records again, filling in the fields for internet and transport pairs
	#   Again, this relies on soa_recs to be in date order
	for this_rec in soa_recs:
		(this_file_prefix, this_date_time, this_vp, this_rsi, this_internet, this_transport, this_dig_elapsed, this_timeout, this_soa) = this_rec
		# Timed-out responses don't count for publication latency  # [tub]
		if this_timeout:
			continue
		int_trans_pair = this_internet + this_transport
		# Store the datetimes when each SOA was seen [cnj]
		if not rsi_publication_latency[this_rsi][this_soa][int_trans_pair]:
			rsi_publication_latency[this_rsi][this_soa][int_trans_pair] = this_date_time
	# Change the "last" entry in the rsi_publication_latency to the time that the SOA was finally seen by all internet/transport pairs
	for this_rsi in rsi_list:
		for this_soa in soa_first_seen:
			for this_pair in report_pairs:
				if not rsi_publication_latency[this_rsi][this_soa]["last"]:
						rsi_publication_latency[this_rsi][this_soa]["last"] = rsi_publication_latency[this_rsi][this_soa][this_pair]
				elif rsi_publication_latency[this_rsi][this_soa][this_pair] > rsi_publication_latency[this_rsi][this_soa]["last"]:
						rsi_publication_latency[this_rsi][this_soa]["last"] = rsi_publication_latency[this_rsi][this_soa][this_pair]
			# Fill in the "latency" entry by comparing the "last" to the SOA datetime; it is stored as seconds
			rsi_publication_latency[this_rsi][this_soa]["latency"] = (rsi_publication_latency[this_rsi][this_soa]["last"] - soa_first_seen[this_soa]).seconds [jtz]
				
	##############################################################
	
	# RSS availability collation
		
	# For RSS availability, for each VP, for each date_time, count the availability in each internet/transport pair, and total count
	rss_availability = {}
	for this_vp in vp_names:
		rss_availability[this_vp] = {}
	# Go through te SOA records recorded earlier
	for this_rec in soa_recs:
		(this_file_prefix, this_date_time, this_vp, this_rsi, this_internet, this_transport, this_dig_elapsed, this_timeout, this_soa) = this_rec
		if not rss_availability[this_vp].get(this_date_time):
			rss_availability[this_vp][this_date_time] = { "v4udp": [ 0, 0 ], "v4tcp": [ 0, 0 ], "v6udp": [ 0, 0 ], "v6tcp": [ 0, 0 ] }
		int_trans_pair = this_internet + this_transport
		if not this_timeout:
			rss_availability[this_vp][this_date_time][int_trans_pair][0] += 1  # [egb]
			rss_availability[this_vp][this_date_time][int_trans_pair][1] += 1
				
	##############################################################
	
	# RSS response latency collation

	# For RSS response latency, for each date_time, each internet/transport pair has a list of latencies
	rss_response_latency_in = {}
	rss_latency_intervals = set()
	for this_rec in soa_recs:  # [spx]
		(this_file_prefix, this_date_time, this_vp, this_rsi, this_internet, this_transport, this_dig_elapsed, this_timeout, this_soa) = this_rec
		rss_latency_intervals.add(this_date_time)
		if not rss_response_latency_in.get(this_date_time):
			rss_response_latency_in[this_date_time] = { "v4udp": [], "v4tcp": [], "v6udp": [], "v6tcp": [] }
		int_trans_pair = this_internet + this_transport
		if this_dig_elapsed:
			rss_response_latency_in[this_date_time][int_trans_pair].append(this_dig_elapsed)  # [bom]
	# Reduce each list of latencies to the median of the lowest k latencies in that last
	rss_response_latency_aggregates = {}
	for this_interval in rss_latency_intervals:
		rss_response_latency_aggregates[this_interval] = {}
		for this_pair in report_pairs:
			this_median = statistics.median(rss_response_latency_in[this_interval][this_pair][0:rss_k-1])  # [jbr]
			this_count = len(rss_response_latency_in[this_interval][this_pair])
			rss_response_latency_aggregates[this_interval][this_pair] = [ this_median, this_count ]
			
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
	
	# RSS publication latency collation
	
	rss_publication_latency_list = []
	for this_rsi in rsi_list:
		for this_soa in soa_first_seen:
			rss_publication_latency_list.append(rsi_publication_latency[this_rsi][this_soa]["latency"])  # [dbo]

	##############################################################
	
	# Write the monthly report

	# Note the number of measurements for this month
	report_text += "Number of measurments across all vantage points in the month: {}\n".format(len(files_seen))
	
	# The report only has "Pass" and "Fail", not the collated metrics [ntt] [cpm]
	
	# RSI reports
	
	# RSI availability report
	rsi_availability_threshold = .96  # [ydw]
	report_text += "\nRSI Availability\nThreshold is {:.0f}%\n".format(rsi_availability_threshold * 100)  # [vmx]
	for this_rsi in rsi_list:
		report_text += "  {}.root-servers.net:\n".format(this_rsi)
		for this_pair in sorted(report_pairs):
			rsi_availability_ratio = rsi_availability[this_rsi][this_pair][0] / rsi_availability[this_rsi][this_pair][1]  # [yah]
			pass_fail_text = "Fail" if rsi_availability_ratio < rsi_availability_threshold else "Pass"
			debug_text = " -- {:.3f}".format(rsi_availability_ratio) if opts.debug else ""
			report_text += "    {}: {}, {} measurements{}\n"\
				.format(report_pairs[this_pair], pass_fail_text, rsi_availability[this_rsi][this_pair][1], debug_text)  # [lkd]
	
	# RSI response latency report
	rsi_response_latency_udp_threshold = .250  # [zuc]
	rsi_response_latency_tcp_threshold = .500  # [bpl]
	report_text += "\nRSI Response Latency\nThreshold for UDP is {} seconds, threshold for TCP is {} seconds\n"\
		.format(rsi_response_latency_udp_threshold, rsi_response_latency_tcp_threshold)  # [znh]
	for this_rsi in rsi_list:
		report_text += "  {}.root-servers.net:\n".format(this_rsi)
		for this_pair in sorted(report_pairs):
			response_latency_median = statistics.median(rsi_response_latency[this_rsi][this_pair][0]) # [mzx]
			if "udp" in this_pair:
				pass_fail_text = "Fail" if response_latency_median > rsi_response_latency_udp_threshold else "Pass"
			else:
				pass_fail_text = "Fail" if response_latency_median > rsi_response_latency_tcp_threshold else "Pass"
			debug_text = " -- {:.3f} median".format(response_latency_median) if opts.debug else ""
			report_text += "    {}: {}, {} measurements{}\n"\
				.format(report_pairs[this_pair], pass_fail_text, rsi_response_latency[this_rsi][this_pair][1], debug_text)  # [lxr]
	
	# RSI correctness report
	rsi_correctness_threshold = 1  # [ahw]
	report_text += "\nRSI Correctness\nThreshold is 100%\n"  # [mah]
	for this_rsi in rsi_list:
		report_text += "  {}.root-servers.net:\n".format(this_rsi)
		rsi_correctness_ratio = rsi_correctness[this_rsi][0] / rsi_correctness[this_rsi][1]  # [skm]
		pass_fail_text = "Fail" if rsi_correctness_ratio < rsi_correctness_threshold else "Pass"
		debug_text = " -- {} incorrect, {:.4f}".format(rsi_correctness[this_rsi][1] - rsi_correctness[this_rsi][0], rsi_correctness_ratio) if opts.debug else ""
		report_text += "    {}, {} measurements{}\n"\
			.format(pass_fail_text, rsi_correctness[this_rsi][1], debug_text)  # [fee]
	
	# RSI publication latency report
	rsi_publication_latency_threshold = 65 * 60 # [fwa]
	report_text += "\nRSI Publication Latency\nThreshold is {} seconds\n".format(rsi_publication_latency_threshold)  # [erf]
	for this_rsi in rsi_list:
		report_text += "  {}.root-servers.net:\n".format(this_rsi)
		# latency_differences is the delays in publication for this letter
		latency_differences = []
		for this_soa in soa_first_seen:
			if rsi_publication_latency[this_rsi].get(this_soa):
				latency_differences.append(rsi_publication_latency[this_rsi][this_soa]["latency"])  # [kvg] [udz]
		publication_latency_median = statistics.median(latency_differences)  # [yzp]
		pass_fail_text = "Fail" if publication_latency_median > rsi_publication_latency_threshold else "Pass"
		debug_text = " -- {} median".format(publication_latency_median) if opts.debug else ""
		report_text += "    {}, {} measurements{}\n"\
			.format(pass_fail_text, len(rsi_publication_latency[this_rsi]), debug_text)  # [hms]

	# RSS reports
	
	# Report both the derived values and a pass/fail indicator for each RSS metric [nuc]
	
	# RSS availability report
	rss_availability_threshold = .99999  # [wzz]
	report_text += "\nRSS Availability\nThreshold is {:.3f}%\n".format(rss_availability_threshold * 100)  # [fdy]
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
		debug_text = " -- {}/{}".format(rss_availability_numerator, rss_availability_denominator) if opts.debug else ""
		report_text += "  {}: {:.3f}%, {}, {} measurements{}\n"\
			.format(report_pairs[this_pair], this_ratio * 100, pass_fail_text, this_count, debug_text)  # [vxl] [hgm]
		
	# RSS response latency report
	rss_response_latency_udp_threshold = .150  # [uwf]
	rss_response_latency_tcp_threshold = .300  # [lmx]
	report_text += "\nRSS Response Latency\nThreshold for UDP is {} seconds, threshold for TCP is {} seconds\n"\
		.format(rss_response_latency_udp_threshold, rss_response_latency_tcp_threshold)  # [gwm]
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
		debug_text = " -- {:.3f} mean".format(statistics.mean(pair_latencies)) if opts.debug else ""
		report_text += "  {}: {} median, {}, {} measurements{}\n"\
			.format(report_pairs[this_pair], pair_response_latency_median, pass_fail_text, pair_count, debug_text)
	
	# RSS correctness report
	rss_correctness_threshold = 1  # [gfh]
	report_text += "\nRSI Correctness\nThreshold is 100%\n"  # [vpj]
	pass_fail_text = "Fail" if rss_correctness_ratio < rss_correctness_threshold else "Pass"  # [udc]
	debug_text = " -- {} incorrect".format(rss_correctness_incorrect) if opts.debug else ""
	report_text += "   Entire RSS {:.6f}%, {}, {} measurements{}\n"\
		.format(rss_correctness_ratio, pass_fail_text, rss_correctness_denominator, debug_text)  # [kea]

	# RSS publication latency
	rss_publication_latency_threshold = 35 * 60  # [zkl]
	report_text += "\nRSS Publication Latency\nThreshold is {} seconds\n".format(rss_publication_latency_threshold)  # [tkw]
	rss_publication_latency_median = statistics.median(rss_publication_latency_list)  # [zgb]
	pass_fail_text = "Fail" if rss_publication_latency_median > rss_publication_latency_threshold else "Pass"
	debug_text = " -- {:.3f} mean".format(statistics.mean(rss_publication_latency_list)) if opts.debug else ""
	report_text += "   Entire RSS {} median, {}, {} measurements{}\n"\
		.format(rss_publication_latency_median, pass_fail_text, len(rss_publication_latency_list), debug_text)  # [daz]

	##############################################################
	
	# Write out the report
	f_out = open(new_monthly_report_name, mode="wt")
	f_out.write(report_text)
	f_out.close()

	log("Finished report process")	
	exit()
