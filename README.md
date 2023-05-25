# RSSAC047 Initial Implementation

This repository represents an initial implementation of [RSSAC047](https://www.icann.org/en/system/files/files/rssac-047-03feb22-en.pdf) prepared by ICANN org.
This implementation is an initial development, and is presented here so that the community can see how RSSAC047 might be implemented, to get suggestions and code contributions for this code, and to help the [RSSAC Caucus](https://www.icann.org/groups/rssac-caucus) evaluate RSSAC047 for possible future changes.

The repo has a Markdown version of excerpts of [RSSAC047](rssac-047.md) as the file "rssac-047.md". In this file, every requirement is marked with a unique three-letter code in square brackets, and that same code appears in the source code as well as this document. The purpose of doing this it to verify that all requirements from RSSAC047 are implemented, and for readers to be able to more easily find where the requirements are reflected in the implementation.

## Deployment

- Deployed with Ansible
	- In `Ansible` directory in the repo
	- Files that are not part of the distribution are on `Local` directory in the repo
	- Create VPs first with vps_building.yml, then create collector with collector_building.yml
	- Creates users on collector with names transfer-xxx to receive files from the VPs

## Logging and alerts

- Logs are text files kept on VPs and collector
- Alerts are text files, may be monitored by Prometheus/Zabbix/etc. on collector
	- ~/Logs/nnn-alerts.txt on every machine
- All Python scripts have _die_ function that prints to alert logs

## Vantage points

- Each VP should have more than one core if possible
- All are running latest Debian or similar
	- Thus automatically running NTP  `[ugt]`
- All programs run as "metrics" user
- Also has "transfer" user for for the collector to copy data

- `vantage_point_metrics.py`
	- Is run from cron job every 5 minutes on 0, 5, ... `[wyn]` `[mba]` `[wca]`
	- All systems use UTC `[nms]`
	- Use `dig + yaml` from BIND 9.16.3
	- Checks for new root zone every 12 hours
	- Run `scamper` after queries to each source for both IPv4 and IPv6
	- Results of each run are saved as .pickle.gz to /sftp/transfer/Output for later pulling
	- Logs to ~/Logs/nnn-log.txt

## Collector

- Run on a VM with lots of cores and memory
- Running latest Debian or similar
	- Thus automatically running NTP  `[ugt]`
- All programs run as "metrics" user
- Also has "transfer" user for others to copy data

- `get_root_zone.py`
	- Run from cron job every 15 minutes
	- Stores zones in ~/Output/RootZones for every SOA seen

- `collector_processing.py`
	- Run from cron job twice every hour
	- Use sftp to pull from all VPs to ~/Incoming
	- For each .gz file in ~/Incoming
		- Open file, store results in the database
		- Move file to ~/Originals/yyyymm/
	- Find records in the correctness table that have not been checked, and check them
	- Reports why any failure happens

- `report_creator.py`
	- Run from cron job every week, and on the first of each month
	- `--debug` to add debugging info to the report
	- `--force` to recreate a report that already exists
	- `--test_date` to pretend that it is a different date in order to make earlier reports

## Correctness testing

_Important note_: in the current version of the testbed, correctness is not being checked.
The data that could be used for correctness testing is being collected, but the steps from RSSAC047 used to check that data are not being performed.

- `collector_processing.py` contains a twisty maze of code to check the correctness of queries to the root servers from Section 5.3 of RSSAC047
- Clearly, this part needs test cases
- In Tests/, `make_tests.py` makes the set of positive and negative test responses for correctness
- Tests are run manually to check whether the correctness tests in `collector_processing.py` are correct
- In a local setup (not on the root metrics system):
	- Use `make_tests.py --addr` to get test vectors from a server under test
	- Use `make_tests.py --bin_prefix` to indicate where "dig" is
- After setting up the test cases, run `collector_processing.py --test` to execute the tests
	- This uses the normal logging
	- See the full output in Tests/results.txt

