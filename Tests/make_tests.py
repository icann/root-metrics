#!/usr/bin/env python3
''' Program to make tests for metrics testing '''
import argparse, copy, glob, json, os, re, requests
import dns.edns, dns.flags, dns.message, dns.query, dns.rdatatype
from pathlib import Path

def create_n_file(id, compare_name, desc, in_dict):
	if id in all_n_ids:
		exit(f"Found {id} a second time. Exiting.")
	compare_dict = json.load(open(compare_name, mode="rt"))
	# Check if nothing changed
	if in_dict == compare_dict:
		exit(f"Found unchanged test creation for {id} and {compare_name}. Exiting")
	in_dict["test-desc"] = desc
	in_dict["test-id"] = id
	in_dict["test-on"] = compare_name
	# Write the file
	with open(f"n-{id}", mode="wt") as f:
		json.dump(in_dict, f, indent=1)
	all_n_ids.append(id)

if __name__ == "__main__":
	this_parser = argparse.ArgumentParser()
	# Use IP address of a.root-servers.net as default
	this_parser.add_argument("--addr", dest="addr", default="198.41.0.4",
		help="IP address of root server to get tests from")
	opts = this_parser.parse_args()
	
	tests_dir = Path('~').expanduser() / "repo/Tests"
	if not tests_dir.exists():
		exit(f"Could not find {tests_dir}. Exiting.")
	os.chdir(tests_dir)

	# Make a file of the root names and types for the collector_processing.py program
	# Keep track of all the records in this temporary root zone, both to find the SOA but also to save for later matching comparisons
	# Get the current root zone
	internic_url = "https://www.internic.net/domain/root.zone"
	try:
		root_zone_request = requests.get(internic_url)
	except Exception as e:
		exit(f"Could not do the requests.get on {internic_url}: {e}")
	text_from_zone_file = root_zone_request.text
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
	# Now save the name and types data
	root_name_and_types = {}
	for this_line in out_root_text.splitlines():
		(this_name, _, _, this_type, this_rdata) = this_line.split(" ", maxsplit=4)
		this_key = f"{this_name}/{this_type}"
		if not this_key in root_name_and_types:
			root_name_and_types[this_key] = []
		root_name_and_types[this_key].append(this_rdata)
	with open("root_name_and_types.json", mode="wt") as f_out:
		json.dump(root_name_and_types, f_out, indent=1)

	queries_list = [
		[".", "SOA", "p-dot-soa"],
		[".", "DNSKEY", "p-dot-dnskey"],
		[".", "NS", "p-dot-ns"],
		["www.rssac047-test.zyxwvutsrqp.", "A", "p-neg"],
		["us.", "DS", "p-tld-ds"],
		["us.", "NS", "p-tld-ns"],
		["cm.", "NS", "p-tld-ns-no-ds"]
	]
	# If the name for p-neg above is changed, the covering name in the test in [czb] below needs to be changed as well

	for (in_qname, in_type, out_filename) in queries_list:
		q = dns.message.make_query(dns.name.from_text(in_qname), dns.rdatatype.from_text(in_type))
		# Turn off the RD bit
		q.flags &= ~dns.flags.RD
		# Add NSID
		nsid_option = dns.edns.GenericOption(dns.edns.OptionType.NSID, b'')
		q.use_edns(edns=0, payload=1220, ednsflags=dns.flags.DO, options=[nsid_option])
		r = dns.query.udp(q, opts.addr, timeout=4.0)
		r_dict = { "test-on": out_filename }
		r_dict["id"] = r.id
		r_dict["rcode"] = dns.rcode.to_text(r.rcode())
		r_dict["flags"] = dns.flags.to_text(r.flags)
		r_dict["edns"] = {}
		for this_option in r.options:
			r_dict["edns"][this_option.otype.value] = this_option.to_text()
		get_sections = ("question", "answer", "authority", "additional")
		for (this_section_number, this_section_name) in enumerate(get_sections):
			r_dict[this_section_name] = []
			for this_rrset in r.section_from_number(this_section_number):
				this_rrset_dict = {"name": this_rrset.name.to_text(), "ttl": this_rrset.ttl, "rdtype": dns.rdatatype.to_text(this_rrset.rdtype), "rdata": []}
				for this_record in this_rrset:
					this_rrset_dict["rdata"].append(this_record.to_text())
				r_dict[this_section_name].append(this_rrset_dict)
		with open(out_filename, mode="wt") as out_f:
			json.dump(r_dict, out_f, indent=1)
		
	# Delete all the negative files before re-creating them
	for this_to_delete in glob.glob("n-*"):
		try:
			os.unlink(this_to_delete)
		except:
			exit(f"Stopping early because can't delete {this_to_delete}. Exiting.")

	# Read all the positive files into memory
	p_dicts = {}
	for (_, _, this_file) in queries_list:
		p_dicts[this_file] = json.load(open(this_file, mode="rt"))

	# Keep track of the IDs to make sure we don't accidentally copy one
	all_n_ids = []

	##########

	# Whenever possible, create test cases that do not also cause validation failures

	##########

	# All of the RRsets in the Answer, Authority, and Additional sections match RRsets found in the zone. [vnk]
	#   Add and change records in Answer (although this will always fail due to DNSSEC validation)
	#   Add and change unsigned records in Authority
	#   Add and change unsigned records in Addtional
	#   Note that deleting records is not covered here because that can't be tested

	# Add a new record to Answer
	id = "ffr"
	compare_name = "p-dot-ns"
	desc = "Start with p-dot-ns, add z.root-servers.net to Answer; will have DNSSEC validation failure"
	this_dict = copy.deepcopy(p_dicts[compare_name])
	made_change = False
	for this_r in this_dict["answer"]:
		if this_r["name"] == "." and this_r["rdtype"] == "NS":
			this_r["rdata"].append("z.root-servers.net.")
			made_change = True
	if not made_change:
		exit(f"Did not make a change when processing {id} -- {desc}. Exiting.")
	create_n_file(id, compare_name, desc, this_dict)
	
	# Change a record in Answer
	id = "vpn"
	compare_name = "p-dot-ns"
	desc = "Start with p-dot-ns, change a.root-server.net to z.root-servers.net in Answer; will have DNSSEC validation failure"
	this_dict = copy.deepcopy(p_dicts[compare_name])
	made_change = False
	for this_r in this_dict["answer"]:
		if this_r["name"] == "." and this_r["rdtype"] == "NS":
			this_r["rdata"].remove("a.root-servers.net.")
			this_r["rdata"].append("z.root-servers.net.")
			made_change = True
	if not made_change:
		exit(f"Did not make a change when processing {id} -- {desc}. Exiting.")
	create_n_file(id, compare_name, desc, this_dict)

	# Add a new record to Authority 
	id = "zoc"
	compare_name = "p-tld-ns"
	desc = "Start with p-tld-ns, add z.cctld.us to Authority; use NS because it is unsigned"
	this_dict = copy.deepcopy(p_dicts[compare_name])
	made_change = False
	for this_r in this_dict["authority"]:
		if this_r["name"] == "us." and this_r["rdtype"] == "NS":
			this_r["rdata"].append("z.cctld.us.")
			made_change = True
	if not made_change:
		exit(f"Did not make a change when processing {id} -- {desc}. Exiting.")
	create_n_file(id, compare_name, desc, this_dict)

	# Change a record in Authority
	id = "gye"
	compare_name = "p-tld-ns"
	desc = "Start with p-tld-ns, change x.cctld.us to z.cctld.us in Authority; use NS because it is unsigned"
	this_dict = copy.deepcopy(p_dicts[compare_name])
	made_change = False
	for this_r in this_dict["authority"]:
		if this_r["name"] == "us." and this_r["rdtype"] == "NS":
			this_r["rdata"].remove("x.cctld.us.")
			this_r["rdata"].append("z.cctld.us.")
			made_change = True
	if not made_change:
		exit(f"Did not make a change when processing {id} -- {desc}. Exiting.")
	create_n_file(id, compare_name, desc, this_dict)
	
	# Add a new record to Additional
	id = "rse"
	compare_name = "p-tld-ns"
	desc = "Start with p-tld-ns, add an A for x.cctld.us in Additional"
	this_dict = copy.deepcopy(p_dicts[compare_name])
	made_change = False
	for this_r in this_dict["additional"]:
		if this_r["name"] == "x.cctld.us." and this_r["rdtype"] == "A":
			this_r["rdata"].append("37.209.194.99")
			made_change = True
	if not made_change:
		exit(f"Did not make a change when processing {id} -- {desc}. Exiting.")
	create_n_file(id, compare_name, desc, this_dict)

	# Change a record in Additional
	id = "ykm"
	compare_name = "p-tld-ns"
	desc = "Start with p-tld-ns, change A for x.cctld.us in Addtional"
	this_dict = copy.deepcopy(p_dicts[compare_name])
	made_change = False
	for this_r in this_dict["additional"]:
		if this_r["name"] == "x.cctld.us." and this_r["rdtype"] == "A":
			this_r["rdata"].remove("37.209.194.15")
			this_r["rdata"].append("37.209.194.99")
			made_change = True
	if not made_change:
		exit(f"Did not make a change when processing {id} -- {desc}. Exiting.")
	create_n_file(id, compare_name, desc, this_dict)
	
	##########

	# All RRsets that are signed have their signatures validated. [yds]
	#   Change the RRSIGs in different ways

	# Change the RDATA
	id = "uuc"
	compare_name = "p-tld-ds"
	desc = "Start with p-tld-ds, change the DS RData in the Answer; causes validation failure"
	this_dict = copy.deepcopy(p_dicts[compare_name])
	made_change = False
	for this_r in this_dict["answer"]:
		if this_r["name"] == "us." and this_r["rdtype"] == "DS":
			us_ds_rdata_l = this_r["rdata"][0].rsplit(maxsplit=1)
			if len(us_ds_rdata_l) != 2 or len(us_ds_rdata_l[1]) < 6:
				exit(f"In uuc, malformed us. DS rdata {this_r['rdata'][0]}. Exiting.")
			this_r["rdata"][0] = us_ds_rdata_l[0] + ' abcdef' + us_ds_rdata_l[1][6:]
			made_change = True
	if not made_change:
		exit(f"Did not make a change when processing {id} -- {desc}. Exiting.")
	create_n_file(id, compare_name, desc, this_dict)

	# Change the signature value itself
	id = "gut"
	compare_name = "p-tld-ds"
	desc = "Start with p-tld-ds, change the RRSIG RData in the Answer; causes validation failure"
	this_dict = copy.deepcopy(p_dicts[compare_name])
	made_change = False
	for this_r in this_dict["answer"]:
		if this_r["name"] == "us." and this_r["rdtype"] == "RRSIG":
			this_r["rdata"][0] = this_r["rdata"][0].replace("W", "X")
			made_change = True
	if not made_change:
		exit(f"Did not make a change when processing {id} -- {desc}. Exiting.")
	create_n_file(id, compare_name, desc, this_dict)

	##########

	# For positive responses with QNAME = <TLD> and QTYPE = NS, a correct result requires all of the following: [hmk]
	#   Use p-tld-ns

	# The header AA bit is not set. [ujy]
	id = "xpa"
	compare_name = "p-tld-ns"
	desc = "Start with p-tld-ns, set the AA bit"
	this_dict = copy.deepcopy(p_dicts[compare_name])
	this_dict["flags"] += " AA"
	create_n_file(id, compare_name, desc, this_dict)

	# The Answer section is empty. [aeg]
	id = "aul"
	compare_name = "p-tld-ns"
	desc = "Start with p-tld-ns, create a bogus Answer section with the NS records" 
	this_dict = copy.deepcopy(p_dicts[compare_name])
	for this_r in this_dict["additional"]:
		this_dict["answer"].append(this_r)
	create_n_file(id, compare_name, desc, this_dict)

	# The Authority section contains the entire NS RRset for the query name. [pdd]
	id = "mbh"
	compare_name = "p-tld-ns"
	desc = "Start with p-tld-ns, remove NS x.cctld.us. from the Authority section" 
	this_dict = copy.deepcopy(p_dicts[compare_name])
	made_change = False
	for this_r in this_dict["authority"]:
		if this_r["name"] == "us." and this_r["rdtype"] == "NS":
			this_r["rdata"].remove("x.cctld.us.")
			made_change = True
	if not made_change:
		exit(f"Did not make a change when processing {id} -- {desc}. Exiting.")
	create_n_file(id, compare_name, desc, this_dict)

	# If the DS RRset for the query name exists in the zone: [hue]
	#   The Authority section contains the signed DS RRset for the query name. [kbd]
	id = "csl"
	compare_name = "p-tld-ns"
	desc = "Start with p-tld-ns, remove one of the DS records from the Authority section; will cause validation failure" 
	this_dict = copy.deepcopy(p_dicts[compare_name])
	made_change = False
	for this_r in this_dict["authority"]:
		if this_r["name"] == "us." and this_r["rdtype"] == "DS":
			this_r["rdata"].pop()
			made_change = True
	if not made_change:
		exit(f"Did not make a change when processing {id} -- {desc}. Exiting.")
	create_n_file(id, compare_name, desc, this_dict)

	# If the DS RRset for the query name does not exist in the zone: [fot]
	#   The Authority section contains no DS RRset. [bgr]
	#   The Authority section contains a signed NSEC RRset covering the query name. [mkl]
	id = "jke"
	compare_name = "p-tld-ns-no-ds"
	desc = "Start with p-tld-ns-no-ds, add a DS records to the Authority section" 
	this_dict = copy.deepcopy(p_dicts[compare_name])
	this_dict["authority"].append({ 'name': 'cm.',
		'rdata': ['21364 8 1 260d0461242bcf8f05473a08b05ed01e6fa59b9c', '21364 8 2 b499cfa7b54d25fde1e6fe93076fb013daa664da1f26585324740a1e6ebdab26'],
    'rdtype': 'DS', 'ttl': 86400 })
	create_n_file(id, compare_name, desc, this_dict)

	id = "gpn"
	compare_name = "p-tld-ns-no-ds"
	desc = "Start with p-tld-ns-no-ds, remove the NSEC and its RRSIG from the Authority section" 
	this_dict = copy.deepcopy(p_dicts[compare_name])
	new_authority = []
	made_change = False
	for this_r in this_dict["authority"]:
		if this_r["rdtype"] in ("NSEC", "RRSIG"):
			made_change = True
			continue
		else:
			new_authority.append(this_r)
	if not made_change:
		exit(f"Did not make a change when processing {id} -- {desc}. Exiting.")
	this_dict["authority"] = copy.deepcopy(new_authority)
	create_n_file(id, compare_name, desc, this_dict)

	# The Additional section contains at least one A or AAAA record found in the zone associated with at least one NS record found in the Authority section. [cjm]
	id = "fvg"
	compare_name = "p-tld-ns"
	desc = "Start with p-tld-ns, remove all the glue records and add a fake one" 
	this_dict = copy.deepcopy(p_dicts[compare_name])
	this_dict["additional"] = [{'name': 'no-an-ns.of.us.', 'rdata': ['10.10.10.1'], 'rdtype': 'A', 'ttl': 172800}]
	create_n_file(id, compare_name, desc, this_dict)

	##########

	# For positive responses where QNAME = <TLD> and QTYPE = DS, a correct result requires all of the following: [dru]
	#   Use p-tld-ds

	# The header AA bit is set. [yot]
	id = "ttr"
	compare_name = "p-tld-ds"
	desc = "Start with p-tld-ds, remove the AA bit"
	this_dict = copy.deepcopy(p_dicts[compare_name])
	this_dict["flags"] = this_dict["flags"].replace(" AA", "").replace("AA ", "")
	create_n_file(id, compare_name, desc, this_dict)

 	# The Answer section contains the signed DS RRset for the query name. [cpf]
	id = "zjs"
	compare_name = "p-tld-ds"
	desc = "Start with p-tld-ds, remove the one DS record in the Answer section; validation will fail"
	this_dict = copy.deepcopy(p_dicts[compare_name])
	made_change = False
	for this_r in this_dict["answer"]:
		if this_r["name"] == "us." and this_r["rdtype"] == "DS":
			this_r["rdata"].pop()
			made_change = True
	if not made_change:
		exit(f"Did not make a change when processing {id} -- {desc}. Exiting.")
	create_n_file(id, compare_name, desc, this_dict)

	# The Authority section is empty. [xdu]
	id = "rpr"
	compare_name = "p-tld-ds"
	desc = "Start with p-tld-ds, add an Authority section with an NS record"
	this_dict = copy.deepcopy(p_dicts[compare_name])
	this_dict["authority"] = [ {'name': 'us.', 'rdata': ['k.cctld.us.', 'x.cctld.us.', 'b.cctld.us.', 'y.cctld.us.', 'w.cctld.us.', 'f.cctld.us.'], 'rdtype': 'NS', 'ttl': 172800} ]
	create_n_file(id, compare_name, desc, this_dict)
			
	# The Additional section is empty. [mle]
	id = "ekf"
	compare_name = "p-tld-ds"
	desc = "Start with p-tld-ds, add an Additonal section with an AAAA record"
	this_dict = copy.deepcopy(p_dicts[compare_name])
	this_dict["additional"] = [ {'name': 'x.cctld.us.', 'rdata': ['2001:dcd:2::15'], 'rdtype': 'AAAA', 'ttl': 172800} ]
	create_n_file(id, compare_name, desc, this_dict)

	##########

	# For positive responses for QNAME = . and QTYPE = SOA, a correct result requires all of the following: [owf]
	#   Use p-dot-soa

	# The header AA bit is set. [xhr]
	id = "apf"
	compare_name = "p-dot-soa"
	desc = "Start with p-dot-soa, remove the AA bit"
	this_dict = copy.deepcopy(p_dicts[compare_name])
	this_dict["flags"] = this_dict["flags"].replace(" AA", "").replace("AA ", "")
	create_n_file(id, compare_name, desc, this_dict)

	# The Answer section contains the signed SOA record for the root. [obw]
	id = "jjg"
	compare_name = "p-dot-soa"
	desc = "Start with p-dot-soa, remove the SOA from Answer section; this will fail validation"
	this_dict = copy.deepcopy(p_dicts[compare_name])
	new_answer = []
	made_change = False
	for this_r in this_dict["answer"]:
		if this_r["rdtype"] in ("SOA", "RRSIG"):
			made_change = True
			continue
		else:
			new_answer.append(this_r)
	if not made_change:
		exit(f"Did not make a change when processing {id} -- {desc}. Exiting.")
	this_dict["answer"] = copy.deepcopy(new_answer)
	create_n_file(id, compare_name, desc, this_dict)

	# The Authority section contains the signed NS RRset for the root. [ktm]
	id = "mtg"
	compare_name = "p-dot-soa"
	desc = "Start with p-dot-soa, remove a.root-servers.net. from the NS record the Authority section; this will fail validation"
	this_dict = copy.deepcopy(p_dicts[compare_name])
	made_change = False
	for this_r in this_dict["authority"]:
		if this_r["rdtype"] == "NS":
			this_r["rdata"].remove("a.root-servers.net.")
			made_change = True
	if not made_change:
		exit(f"Did not make a change when processing {id} -- {desc}. Exiting.")
	create_n_file(id, compare_name, desc, this_dict)

	##########

	# For positive responses for QNAME = . and QTYPE = NS, a correct result requires all of the following: [amj]
	#   Use p-dot-ns

	# The header AA bit is set. [csz]
	id = "kuc"
	compare_name = "p-dot-ns"
	desc = "Start with p-dot-ns, remove the AA bit"
	this_dict = copy.deepcopy(p_dicts[compare_name])
	this_dict["flags"] = this_dict["flags"].replace(" AA", "").replace("AA ", "")
	create_n_file(id, compare_name, desc, this_dict)

	# The Answer section contains the signed NS RRset for the root. [wal]
	id = "oon"
	compare_name = "p-dot-ns"
	desc = "Start with p-dot-ns, remove a.root-servers.net. from the Answer section; this will fail validation"
	this_dict = copy.deepcopy(p_dicts[compare_name])
	made_change = False
	for this_r in this_dict["answer"]:
		if this_r["rdtype"] == "NS":
			this_r["rdata"].remove("a.root-servers.net.")
			made_change = True
	if not made_change:
		exit(f"Did not make a change when processing {id} -- {desc}. Exiting.")
	create_n_file(id, compare_name, desc, this_dict)

	# The Authority section is empty. [eyk]
	id = "hmp"
	compare_name = "p-dot-ns"
	desc = "Start with p-dot-ns, add an Authority section with an A record for a.root-servers.net."
	this_dict = copy.deepcopy(p_dicts[compare_name])
	this_dict["authority"] = [ {'name': 'a.root-servers.net.', 'rdata': ['198.41.0.4'], 'rdtype': 'A', 'ttl': 518400} ]
	create_n_file(id, compare_name, desc, this_dict)
	
	##########

	# For positive responses for QNAME = . and QTYPE = DNSKEY, a correct result requires all of the following: [djd]
	#   Use p-dot-dnskey

	# The header AA bit is set. [occ]
	id = "kbc"
	compare_name = "p-dot-dnskey"
	desc = "Start with p-dot-dnskey, remove the AA bit"
	this_dict = copy.deepcopy(p_dicts[compare_name])
	this_dict["flags"] = this_dict["flags"].replace(" AA", "").replace("AA ", "")
	create_n_file(id, compare_name, desc, this_dict)

	# The Answer section contains the signed DNSKEY RRset for the root. [eou]
	id = "nsz"
	compare_name = "p-dot-dnskey"
	desc = "Start with p-dot-dnskey, remove one of the DNSKEY records; this will fail validation "
	this_dict = copy.deepcopy(p_dicts[compare_name])
	made_change = False
	for this_r in this_dict["answer"]:
		if this_r["rdtype"] == "DNSKEY":
			this_r["rdata"] = this_r["rdata"][1:]
			made_change = True
	if not made_change:
		exit(f"Did not make a change when processing {id} -- {desc}. Exiting.")
	this_dict["answer"] = copy.deepcopy(new_answer)
	create_n_file(id, compare_name, desc, this_dict)

	# The Authority section is empty. [kka]
	id = "coh"
	compare_name = "p-dot-dnskey"
	desc = "Start with p-dot-dnskey, add an Authority section with an NS record for a.root-servers.net."
	this_dict = copy.deepcopy(p_dicts[compare_name])
	this_dict["authority"] = [ {'name': 'a.root-servers.net.', 'rdata': ['198.41.0.4'], 'rdtype': 'A', 'ttl': 518400} ]
	create_n_file(id, compare_name, desc, this_dict)

	# The Additional section is empty. [jws]
	id = "nnd"
	compare_name = "p-dot-dnskey"
	desc = "Start with p-dot-dnskey, add an Additional section with an A record for a.root-servers.net."
	this_dict = copy.deepcopy(p_dicts[compare_name])
	this_dict["additional"] = [ {'name': 'a.root-servers.net.', 'rdata': ['198.41.0.4'], 'rdtype': 'A', 'ttl': 518400} ]
	create_n_file(id, compare_name, desc, this_dict)
	
	##########

	# For negative responses, a correct result requires all of the following: [vcu]
	#   Use p-neg

		# The header AA bit is set. [gpl]
	id = "ymb"
	compare_name = "p-neg"
	desc = "Start with p-neg, remove the AA bit"
	this_dict = copy.deepcopy(p_dicts[compare_name])
	this_dict["flags"] = this_dict["flags"].replace(" AA", "").replace("AA ", "")
	create_n_file(id, compare_name, desc, this_dict)

	# The Answer section is empty. [dvh]
	id = "njw"
	compare_name = "p-neg"
	desc = "Start with p-neg, create an Answer section with an A record"
	this_dict = copy.deepcopy(p_dicts[compare_name])
	this_dict["answer"] = [ {'name': 'www.rssac047-test.zyxwvutsrqp.', 'rdata': ['10.10.10.10'], 'rdtype': 'A', 'ttl': 518400} ]
	create_n_file(id, compare_name, desc, this_dict)

	# The Authority section contains the signed . / SOA record. [axj]
	id = "pho"
	compare_name = "p-neg"
	desc = "Start with p-neg, remove the SOA record and its RRSIG"
	this_dict = copy.deepcopy(p_dicts[compare_name])
	new_authority = []
	made_change = False
	for this_r in this_dict["authority"]:
		if (this_r["name"] == "." and this_r["rdtype"] == "SOA"):
			made_change = True
			continue
		elif (this_r["name"] == "." and this_r["rdtype"] == "RRSIG"):
			if this_r["rdata"][0].startswith("SOA"):
				made_change = True
				continue
		else:
			new_authority.append(this_r)
	if not made_change:
		exit(f"Did not make a change when processing {id} -- {desc}. Exiting.")
	this_dict["authority"] = copy.deepcopy(new_authority)
	create_n_file(id, compare_name, desc, this_dict)

	# The Authority section contains a signed NSEC record covering the query name. [czb]
	id = "czb"
	compare_name = "p-neg"
	desc = "Start with p-neg, remove the NSEC record covering the query"
	this_dict = copy.deepcopy(p_dicts[compare_name])
	new_authority = []
	made_change = False
	for this_r in this_dict["authority"]:
		###### Important note: the .zw here was chosen because that is the that would precede the query name "www.rssac047-test.zyxwvutsrqp" given in queries_list
		###### If the negative name in queries_list is changed, this needs to be changed too
		if (this_r["name"] == "zw." and this_r["rdtype"] == "NSEC") or (this_r["name"] == "zw." and this_r["rdtype"] == "RRSIG"):
			made_change = True
			continue
		else:
			new_authority.append(this_r)
	if not made_change:
		exit(f"Did not make a change when processing {id} -- {desc}. Exiting.")
	this_dict["authority"] = copy.deepcopy(new_authority)
	create_n_file(id, compare_name, desc, this_dict)

	# The Authority section contains a signed NSEC record with owner name “.” proving no wildcard exists in the zone. [jhz]
	id = "pdu"
	compare_name = "p-neg"
	desc = "Start with p-neg, remove the NSEC record covering the . and its RRSIG"
	this_dict = copy.deepcopy(p_dicts[compare_name])
	new_authority = []
	made_change = False
	for this_r in this_dict["authority"]:
		if (this_r["name"] == "." and this_r["rdtype"] == "NSEC") or (this_r["name"] == "." and this_r["rdtype"] == "RRSIG"):
			made_change = True
			continue
		else:
			new_authority.append(this_r)
	if not made_change:
		exit(f"Did not make a change when processing {id} -- {desc}. Exiting.")
	this_dict["authority"] = copy.deepcopy(new_authority)
	create_n_file(id, compare_name, desc, this_dict)

	# The Additional section is empty. [trw]
	id = "anj"
	compare_name = "p-neg"
	desc = "Start with p-neg, add an Additonal section with an A record"
	this_dict = copy.deepcopy(p_dicts[compare_name])
	this_dict["additional"] = [ {'name': 'a.root-servers.net.', 'rdata': ['198.41.0.4'], 'rdtype': 'A', 'ttl': 518400} ]
	create_n_file(id, compare_name, desc, this_dict)
	
	##########

	# Go through all the negative tests, and compare them to the postive ones
	import pprint, subprocess, tempfile
	ret = "\n"
	out_diff_name = "diffs-for-negatives.txt"
	with open(out_diff_name, mode="wt") as f:
		for this_neg in all_n_ids:
			with tempfile.NamedTemporaryFile(mode="wt", delete=False) as neg_file:
				neg_dict = json.load(open(f"n-{this_neg}", mode="rt"))
				neg_file_name = neg_file.name
				neg_file.write(pprint.pformat(neg_dict, indent=1, width=500))
				neg_file.close()
				with tempfile.NamedTemporaryFile(mode="wt", delete=False) as pos_file:
					pos_file_name = pos_file.name
					pos_file.write(pprint.pformat(json.load(open(neg_dict['test-on'], mode="rt")), indent=1, width=500))
					pos_file.close()
					diff_cmd = f"diff {pos_file_name} {neg_file_name}"
					p = subprocess.run(diff_cmd, shell=True, capture_output=True, text=True)
					this_diff = p.stdout
					this_diff = this_diff.replace("\\ No newline at end of file\n", "")
					f.write(f"###{this_neg}###{ret}{this_diff}{ret}")
	exit(f"Saved diffs in {out_diff_name}. Exiting.")
