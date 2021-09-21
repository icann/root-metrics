#!/usr/bin/env python3
""" Program to write alert messages as files in a user's home directory """
import argparse, datetime, os, subprocess, sys

# This program will always either create a file that has a header and the text from the command line and return 0
#   or will return a value of 1 and print a text string 
# The command cab have an argument of --file=<filename> or arguments to be turned into a string

# Get the command-line arguments
this_parser = argparse.ArgumentParser()
this_parser.add_argument("cmd_args", action="store", nargs="*",
	help="Text for the alert")
this_parser.add_argument("--file", action="store", dest="file",
	help="File containing the alert test")
opts = this_parser.parse_args()

body_text = ""
if opts.cmd_args:
	body_text += f"{' '.join(opts.cmd_args)}\n"
if opts.file:
	full_file_name = os.path.expanduser(opts.file)
	if not os.path.exists(full_file_name):
		exit(f"A file argument of {full_file_name} was given, but that file was not found")
	else:
		body_text += open(os.path.expanduser(full_file_name), mode="rt", encoding="latin-1").read()

if len(body_text) == 0:
	body_text = f"Empty alert generated at {datetime.datetime.now().strftime('%Y-%m-%d-%H-%M-%S-%f')}"

out_start = ""

# See if the ~/.alert-info file exists; if so, use it as a header
alert_info_filename = os.path.expanduser("~/.alert-info")
if os.path.exists(alert_info_filename):
	info_content = open(alert_info_filename, mode="rt", encoding="latin-1").read()
	if len(info_content) > 0:
		out_start += f"Header: {info_content}\n"

# Add info from hostname -I
p = subprocess.run("hostname -I", shell=True, capture_output=True, text=True)
addr_string = p.stdout
if addr_string:
	out_start += f"Addresses: {addr_string}\n"

# Make the alerts directory if it does not already exist
alerts_dir = os.path.expanduser("~/Alerts")
if not os.path.exists(alerts_dir):
	try:
		os.mkdir(alerts_dir)
	except:
		sys.exit(f"Could not create {alerts_dir}")

# Construct a file name for this alert
alert_filename = f"{alerts_dir}/alert-{datetime.datetime.now().strftime('%Y-%m-%d-%H-%M-%S-%f')}.txt"
try:
	alert_f = open(alert_filename, mode="wt")
except:
	sys.exit(f"Could not open {alert_filename} for writing")

alert_f.write(out_start)
alert_f.write(body_text)
alert_f.close()
