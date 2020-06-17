# RSSAC047 text for creating metrics and analysis implemention

This document extracts some of the text of [RSSAC047](https://www.icann.org/en/system/files/files/rssac-047-12mar20-en.pdf).
Some of the text from RSSAC047 has been removed here, so do not rely on it as a complete copy of that document.
 
The purpose of this document is to mark all text that might be linked to the source code and operational plan for a metrics and analysis implementation of RSSAC047.
The text of this document is basically what is in RSSAC047, but tags are added in every place that something from RSSAC047 might affect implementation.
All tags are given as `[xyz]`, where "xyz" is a unique, randomly selected three-letter string. That bracketed tag "[xyz]" will appear in the implementation code or other documents.

## Preface

{{ elided }}

## Table of Contents

{{ elided }}

## 1 Introduction

{{ elided }}

## 2 Background and Scope

{{ elided }}

## 3 Vantage Points

### 3.1 Number of Vantage Points

The RSSAC recommends that measurements be made from approximately 20 vantage points. `[fdz]` This number has been chosen to strike a balance between two competing goals: coverage and manageability. While more vantage points can increase coverage of the RSS, it also increases complexity and difficulty in managing a large number of systems. As experience is gained in the operation and interpretation of these metrics, a future update may recommend a larger number of vantage points. 

### 3.2 Location of Vantage Points

Vantage points shall be distributed approximately evenly among the five following geographic regions: 

- Africa `[gjr]`
- Asia/Australia/Pacific `[lrr]`
- Europe `[fzt]`
- Latin America/Caribbean Islands `[knk]`
- North America `[vak]`

Vantage points should be located within major metropolitan areas. `[htk]` There should only be one vantage point per major metropolitan area. `[ttz]`

The RSSAC believes that a better long-term plan for the location of the vantage points would be to distribute them by network topology instead of geographic location. RSSAC should begin investigation of implementing such a plan in the future. 

### 3.3 Connectivity and Other Requirements

Vantage points shall be hosted inside data centers with reliable power `[roy]` and diverse connectivity providers. `[ppy]`

The placement of vantage points should be based on the desire to have diverse connectivity providers. Diversity of connectivity providers helps to increase RSS coverage and avoid situations where multiple vantage points all reach the same instance.

Vantage points may be deployed on “bare metal” or virtual machines (VMs). When VMs are utilized, they should provide dedicated IP addresses and a dedicated operating system environment. `[ota]` 

## 4 General Points about Metrics and Measurements

### 4.1 Reporting

The metrics defined in this report shall be reported by the collection system on a monthly basis. `[rps]`

For RSI metrics (Section 5), the collection system reports results for each metric in a given month as either “pass” or “fail.” `[ntt]` An RSI is reported to “pass” the metric when its value meets the appropriate threshold, and reported to “fail” when its value does not meet the threshold. The metric’s measured value is not reported in either reading. `[cpm]` As stated in Section 2.2, these metrics are not designed to make performance comparisons between RSIs. See Section 8.1 for an example of an RSI metrics report.

For RSS metrics (Section 6), the collection system reports the results for each metric in a given month with the measured value, as well as a pass or fail indication. `[nuc]` See Section 8.2 for an example of an RSS metrics report.

### 4.2 Timestamps and Measurement Scheduling

Vantage points and the collection system shall be synchronized to Network Time Protocol (NTP). `[ugt]`

Vantage points run all tests at five-minute intervals. `[wyn]` At the start of each five-minute interval, the measurement software should wait for an amount of time randomly chosen between 0 and 60 seconds. `[fzk]` Thus, measurements from all vantage points start at slightly different times, but still have enough time to complete within the five-minute interval. 

Vantage points store measurements and the collection system reports metrics in Coordinated Universal Time (UTC). `[nms]` The collection system reports of pass or fail for thresholds are always shown for a whole month starting on the first of the month; `[ver]` dates for presentation always start at midnight (0 hours 0 minutes) UTC. `[jps]`

### 4.3 Elapsed Time and Timeouts

Some vantage point measurements have timeouts or are designed to measure elapsed time. This section describes how to calculate elapsed time for individual measurements over differing transports. Unless specified otherwise for individual measurements, the following rules apply:

For connectionless requests (i.e., over UDP) a timer starts immediately after the UDP message has been sent. It stops when the entire response has been received. `[tsm]`

For connection-based requests (e.g., over TCP) a timer starts when the connection is initiated. It stops when the entire DNS response has been received (although not waiting for the TCP connection to close). `[epp]`

__Requirements in this paragraph are not currently implemented.__ Some features such as TCP Fast Open (TFO) reduce connection setup delays. None of those features should be turned on in the measurement platform. `[zbf]` Environments and/or operating systems that do not allow TFO to be disabled should not be used for these measurements, if at all possible. `[jbt]`

### 4.4 Connection Errors

Both connectionless and connection-based transactions may terminate in an error. Some common errors include no route to host, connection refused, and connection reset by peer. For the purposes described in this document, vantage points shall treat such errors as timeouts. `[dfl]` That is, in general, timeouts (including these errors) are not retried by vantage points and are not included in collection system metrics other than availability. `[dks]`

### 4.5 Spoofing Protections

Vantage points must take reasonable steps to prevent acceptance of spoofed responses. Vantage point software must use proper source port randomization, `[uym]` query id randomization, `[wsb]` optional “0x20” mixed case, `[zon]` __NOT DONE IN THE IMPLEMENTATION__ and proper query and response matching. `[doh]` DNS Cookies may be used as a lightweight DNS transaction security mechanism that provides limited protection to DNS servers and clients. `[ujj]`

If vantage points detect malicious or spoofed traffic, such events should be recorded and logged so that manual inspection of measurements can be performed and disregarded if necessary. 

### 4.6 Anycast

The measurements defined in this report are “instance agnostic,” which means they do not target specific anycast instances within a RSI. Thus, the vantage points do not try to force queries to specific instances, rather they should let intermediate routers on the Internet determine which anycast instance of an RSI receives each query and measure the performance of the RSI as a whole.

### 4.7 Measurement Reuse

In some cases, queries and responses for one measurement are used in more than one metric. In specific, the collection system uses the Start of Authority (SOA) query to an instance in the availability, and response latency, and publication latency metrics. `[dzn]`

### 4.8 Unexpected Results

When the collection system observes unexpected measurements or metrics, they may warrant further investigation. Examples of unexpected results may include very high response latency to some or all instances of an RSI, DNSSEC validation failures, and excessive staleness. Investigation and publication of unexpected results is most likely in the best interest of affected parties to understand the reasons for and, if possible, rectify situations that lead to such results.

To aid in debugging unexpected results, all DNS query measurements shall include the Name Server Identifier Option (NSID) option. `[mgj]` Furthermore, vantage points shall record the network route to both IPv4 and IPv6 addresses of each RSI, in every measurement interval, using commonly available tools such as traceroute, tracepath, or mtr. `[vno]` This additional information helps diagnose issues with the monitoring system (for example, if a route local to the monitoring system disappears it will show up in traceroute). The collection and storage of the extra debugging information is not the primary purpose of the vantage point and must not cause interruption or disturbance to measurement gathering. 

If, in the course of collecting and aggregating the measurements from the vantage points, one or more vantage points is clearly impacted by a software or network failure, the collection system can temporarily exclude those vantage points from the threshold calculations. `[raz]` Any such exclusion needs to be described publicly, and the times that the vantage points' data is excluded be clearly stated. `[hnr]`

The collection system can also exclude some measurements from threshold calculations if the RSO can give a reasonable explanation for temporary technical problems that caused a failure to meet a threshold. `[xjv]` Any such exclusion needs to be described publicly, and the times that the data is excluded be clearly stated. `[dew]`

The collection system is allowed to remove vantage points that are not acting in accordance with the goals of measurement. `[ahh]`

RSOs can ask the collection system that anomalies be annotated with information detailing the reason for an outage, or a notice of preventative maintenance. `[bmu]`

### 4.9 Determining the Number of RSIs Required for Reliable Operation of the RSS

{{ elided }}

### 4.10 Potential Effects of Metrics on Independence and Diversity

{{ elided }}

## 5 Root Server Identifier-Related Metrics

The metrics in this section apply to the individual root server identifiers (RSIs). Note that this refers to the DNS name associated with a root server operator that appears in the root zone and root hints file. For example, d.root-servers.net (or sometimes “D-Root”) is the root server identifier associated with the root server managed by the University of Maryland at the time this document was published. Furthermore, note that a single identifier refers to the IPv4 and IPv6 addresses for the corresponding service.

### 5.1 RSI Availability

The purpose of these metrics is to characterize the availability of a single RSI over different transports and address types. The metrics are derived from a set of individual availability measurements taken from multiple locations over a period of time. The metrics have the following names:

- IPv4 UDP Availability
- IPv4 TCP Availability
- IPv6 UDP Availability
- IPv6 TCP Availability

In accordance with the recommendations in this report, it is likely that vantage points will be placed inside data centers some distance away from root server instances. The queries and responses between vantage point and instance traverse through some number of networks, routers, and switches. These intermediate network components, which are not necessarily under an RSO’s control, also factor into the availability measurements. That is, the availability of an RSI at a particular point in time depends not only on the RSI itself, but on the availability of the intermediate networks as well.

__Measurements.__ Measurements shall be made by sending DNS queries of type SOA with QNAME=”.” `[hht]` at five-minute intervals `[mba]` over each of the transports `[ykn]` and address types `[jhb]` to the root server addresses `[yns]`. 

Measurements shall use a timeout value of four seconds. `[ywz]`

For a response with RCODE=0 received within the timeout value, the RSI is considered to have been available over that transport and address. After the timeout value, the query is considered to be timed out and the RSI is considered to have been unavailable over that transport and address. `[yve]` Timed out queries shall not be retried. `[xyl]` Since the query should always result in an RCODE=0 response, responses with any other RCODE are considered to be equivalent to a timeout. `[ppo]`

For every measurement, the vantage point also records the time elapsed between sending the query and receiving the response. `[aym]` This measurement is also used for the measurements in “5.2 RSI Response Latency” and “5.4 RSI Publication Latency.” `[wdo]`

__Aggregation.__ All of the measurements for each transport and address type, from all vantage points, covering a period of one month are aggregated with the other measurements from the same transport and address type. `[gfa]` Availability is calculated as the number of non-timed-out and non-error responses received divided by the number of queries sent, expressed as a percentage. `[yah]`

__Precision.__ The number of aggregated measurements shall convey the metric’s precision. `[lkd]`

__Reporting.__ For each month, the report shall state whether or not each of the aggregated availability metrics meets or does not meet the established threshold. `[vmx]`

__Threshold.__ The recommended threshold for this metric is 96%. `[ydw]` The recommended threshold value was determined by using the formula for simple k-out-of-n parallel availability:

{{ formula elided }}

Given a desired overall system availability of A=99.999% (“five nines”), n = 13, and k = 8, this formula tells us that an individual RSI availability of a = 96 is necessary to meet the desired system availability.

If the number of RSIs were to change in the future, this threshold may need to be adjusted. `[dlw]` The chart below shows the relationship between values of A,a, and n when k=⌈(n-1)*2/3⌉. Note that as the number of RSIs increases, the threshold for RSI availability decreases.

{{ chart elided }}

### 5.2 RSI Response Latency

The purpose of these metrics is to characterize the response latency for a single RSI over different transports and address types. The metrics are derived from a set of individual response latency measurements from multiple locations over a period of time. The metrics have the following names:

- IPv4 UDP Response Latency
- IPv4 TCP Response Latency
- IPv6 UDP Response Latency
- IPv6 TCP Response Latency

__Measurements.__ Measurements are taken from timing of queries and responses made for Section 5.1 "RSI Availability.” `[zvy]` Timed-out queries are not utilized in this metric. `[vpa]`

__Aggregation.__ All of the measurements for each transport and address type, from all vantage points, covering a period of one month are aggregated with the other measurements from the same transport and address type. `[fhw]` Response latency is calculated as the median value of the aggregated latency measurements. `[mzx]`

__Precision.__ The number of aggregated measurements shall convey the metric’s precision. `[lxr]`

__Reporting.__ For each month, the report shall state whether or not each of the aggregated median response latency metrics meets or does not meet the established threshold. `[znh]`

__Threshold.__ The recommended threshold for this metric is 250 milliseconds for UDP `[zuc]` and 500 milliseconds for TCP. `[bpl]` 

The threshold for TCP is twice that for UDP due to TCP connection setup latencies.

### 5.3 RSI Correctness 

The purpose of this metric is to characterize whether or not a single root server instance serves correct responses. Correctness is determined through exact matching against root zone data and DNSSEC validation. The metric is derived from a set of individual correctness measurements from multiple locations over a period of time. The metric has the following name:

- Correctness

The individual measurement responses will be marked either correct or incorrect. `[jof]` It might be difficult to determine whether an incorrect response was actually transmitted by an RSI, or due to an attacker transmitting spoofed responses. For this reason, implementations should follow the advice in Section 4.5 (“Spoofing Protections”) and Section 4.8 (“Unexpected Results”) to both minimize the chance of being affected by malicious traffic and to allow someone to investigate and disregard measurements that may be impacted by spoofing. 

The RSSAC recognizes that there are limitations to this metric because the vantage points are measuring a small number of root server instances, from known source IP addresses, with no detection of on-path attackers. Another potential limitation may arise in cases when root server instances are started up with older versions of the zone saved on disk. Typically, when name servers start up they will use any saved zone data and then quickly check for a newer version from the master server. If a correctness query happens during this short window of time between startup and zone refresh, stale data may be returned. Future improvements in the measurement system may address these and other concerns.

__Measurements.__ Measurements shall be made by sending DNS queries at five-minute intervals to the RSIs. `[wca]` In each interval the transport and address type used for a particular measurement shall be chosen with uniform random probability among all combinations of IPv4/IPv6 `[thb]` and UDP/TCP. `[ogo]` In order to test a variety of responses, the query name and type for a particular measurement are chosen at random as described below.

For all queries, the DNSSEC OK bit is always set, `[rhe]` and the EDNS0 buffer size is set to 1220 when using UDP. `[rja]`

There are two kinds of queries: expected positive and expected negative.

- The expected positive queries are selected from the following RRSets from a recent root zone: `[mow]` ./SOA, `[njh]` ./DNSKEY, `[hmc]` ./NS, `[xca]` <any_TLD>/NS, `[max]` and <any_TLD>/DS. `[kmd]` These measurements do not query non-authoritative data directly. However, any non-authoritative data included in the Additional section of responses will be checked for correctness.
  - At the time this document is published, the ARPA TLD is served by many of the RSIs. From those root servers, an ARPA/NS query will return authoritative data, rather than a referral, and therefore cannot be tested for correctness as described in the checking rules below. Therefore, ARPA/NS must be excluded from the set of expected positive queries above as long as any RSI is serving ARPA authoritatively. `[unt]` Note, however, that ARPA/DS is included because it can be tested for correctness even in this scenario.
- The expected negative queries have a name that contains random letters and a resource record type of A. The names are constructed as “www.rssac047-test.<RAND-NXD>”, `[hkc]` where <RAND-NXD> is formed by 10 ASCII letters chosen at random. `[dse]` Examples of expected negative questions are “www.rssac047-test.twxoozxmew” and “www.rssac047-test.hwzvpicwen”.

When selecting a query to send for this metric, the vantage point chooses queries from the expected positive set with a 90% probability, and from the expected negative set with a 10% probability. `[yyg]`

The rationale for the query styles is:

- Positive responses are the common case and using known authoritative Resource Record sets (RRsets) provides good coverage of the namespace.
- It is impossible to predict situations in which an RSI might provide incorrect responses. Using randomly generated TLDs - which look like typical queries - is a reasonable choice. By examining NSEC records from queries for random names we can identify cases where incorrect data may have been inserted into the root zone.

Measurements shall use a timeout value of four seconds. `[twf]` Responses in which the TC bit is set shall be retried over TCP transport and the timeout restarted. `[hjw]`

__Measuring Correctness.__ For a response received within the timeout value, the measurement records the result as either correct or incorrect. `[lbl]`

The collection system keeps a copy of every root zone file published after it has been set up. `[ooy]` A response is tested against all root zones that were first seen in use in the 48 hours preceding the query until a correct result is returned. `[yhu]` If no correct result is found, an incorrect result is returned. `[xog]`

Correctness checking is based on the actual response data, rather than what was expected. For example, if a query was sent in the expected positive style, but the received response was negative (e.g., NXDOMAIN), matching is performed as a negative response. This is done to handle cases when vantage points might not receive configuration updates for a short period of time.

For all matching testing:

- All of the RRsets in the Answer, Authority, and Additional sections match RRsets found in the zone. `[vnk]` This check does not include any OPT RRset found in the Additional section `[pvz]`, nor does it include any RRSIG RRsets that are not named in the matching tests below. `[ygx]`
- All RRsets that are signed have their signatures validated. `[yds]`

For positive responses with QNAME = <TLD> and QTYPE = NS, a correct result requires all of the following: `[hmk]`

- The header AA bit is not set. `[ujy]`
- The Answer section is empty. `[aeg]`
- The Authority section contains the entire NS RRset for the query name. `[pdd]`
- If the DS RRset for the query name exists in the zone:`[hue]`
  - The Authority section contains the signed DS RRset for the query name. `[kbd]`
- If the DS RRset for the query name does not exist in the zone: `[fot]`
  - The Authority section contains no DS RRset. `[bgr]`
  - The Authority section contains a signed NSEC RRset covering the query name. `[mkl]` __NOT GOOD WORDING HERE__
- The Additional section contains at least one A or AAAA record found in the zone associated with at least one NS record found in the Authority section. `[cjm]`

For positive responses where QNAME = <TLD> and QTYPE = DS, a correct result requires all of the following: `[dru]`

- The header AA bit is set. `[yot]`
- The Answer section contains the signed DS RRset for the query name. `[cpf]`
- The Authority section is empty. `[xdu]`
- The Additional section is empty. `[mle]`

For positive responses for QNAME = . and QTYPE = SOA, a correct result requires all of the following: `[owf]`

- The header AA bit is set. `[xhr]`
- The Answer section contains the signed SOA record for the root. `[obw]`
- The Authority section contains the signed NS RRset for the root. `[ktm]`

For positive responses for QNAME = . and QTYPE = NS, a correct result requires all of the following: `[amj]`

- The header AA bit is set. `[csz]`
- The Answer section contains the signed NS RRset for the root. `[wal]`
- The Authority section is empty. `[eyk]`

For positive responses for QNAME = . and QTYPE = DNSKEY, a correct result requires all of the following: `[djd]`

- The header AA bit is set. `[occ]`
- The Answer section contains the signed DNSKEY RRset for the root. `[eou]`
- The Authority section is empty. `[kka]`
- The Additional section is empty. `[jws]`

For negative responses, a correct result requires all of the following: `[vcu]`

- The header AA bit is set. `[gpl]`
- The Answer section is empty. `[dvh]`
- The Authority section contains the signed . / SOA record. `[axj]`
- The Authority section contains a signed NSEC record covering the query name. `[czb]`
- The Authority section contains a signed NSEC record with owner name “.” proving no wildcard exists in the zone. `[jhz]`
- The Additional section is empty. `[trw]`

__Aggregation.__ All of the measurements covering a period of one month are aggregated together. `[ebg]` Correctness is calculated as the number of correct responses received divided by the total number of responses received, expressed as a percentage. `[skm]`

__Precision.__ The number of aggregated measurements shall convey the metric’s precision. `[fee]`

__Reporting.__ For each month, the report shall state whether or not the RSI’s aggregated correctness meets or does not meet the established threshold. `[mah]`

__Thresholds.__ The recommended threshold for this metric is 100%. `[ahw]` The expectation is that root name servers always serve correct responses.

### 5.4 RSI Publication Latency

The purpose of this metric is to characterize the publication latency for a single RSI, that is, the amount of time taken to publish new versions of the root zone. The metric is derived from a set of individual measurements from multiple locations over a period of time. The metric has the following name:

- Publication Latency

The publication latency metric may also be affected by the situation described in Section 5.3, when name servers first start up with older zone data before the zone has been refreshed from the master server.

__Measurements.__ The metrics are based on the amount of time between publication of a new root zone serial number, and the time the new serial number is observed by each vantage point over all of the transports and address types for each RSI. Rather than make additional SOA queries, this metric reuses the root zone SOA responses received from the response latency measurements from Section 5.2. `[kzu]`

__The following section needs to be changed. It needs to be clear that it is describing metrics, not measurements. It also needs to remove "In each measurement interval" because the metrics are per SOA, not per time interval.__

In each measurement interval, the collection system examines the response latency measurements and calculates the minimum SOA serial value over all of the transports and address types for each vantage point and RSI. `[cnj]` This is because the RSI might return different SOA serials over UDP/TCP and IPv4/IPv6. Timed out and bogus responses must not be used in this calculation. `[tub]`

The collection system needs to know, approximately, when new zones are published by the root zone maintainer. This is accomplished by examining the collective SOA serial responses from all RSIs. `[yxn]`

The collection system then calculates the amount of time elapsed until a given vantage point observes the new serial number in a response from the RSI. `[kvg]` Note that this will always be a multiple of five minutes. For vantage points that observe the new serial number in the same interval as the root zone publication time, the publication latency shall be recorded as zero minutes. `[udz]`

__Aggregation.__ All of the measurements, from all vantage points, covering a period of one month are aggregated together. `[jtz]` Publication latency is calculated as the median value of the aggregated latency measurements. `[yzp]`

Note that the number of aggregated measurements depends on the number of root zones published in the aggregation interval. Most commonly there are two root zones published each day, which would result in at least approximately “sixty times the number of vantage points” measurements each month for each RSI. 

__Precision.__ The number of aggregated measurements shall convey the metric’s precision. `[hms]`

__Reporting.__ For each month, the report shall state whether or not each of the aggregated publication latency metrics meets or does not meet the established threshold. `[erf]`

__Thresholds.__ The recommended threshold for this metric is 65 minutes. `[fwa]` This is based on twice the value of the SOA refresh parameter (which is 30 minutes) plus one five-minute measurement interval. Note that the Root Zone Maintainer’s current distribution system sends out DNS NOTIFY messages from many different locations, to a set of addresses provided by each RSO. Even in situations where NOTIFY messages may not be reliably delivered, the RSO’s systems should be polling for zone updates at least every SOA refresh interval (30 minutes).

## 6 RSS Related Metrics

Whereas the metrics described in Section 5 apply to individual root server identifiers (RSIs), the metrics in this section are designed to evaluate and measure service levels for the entire root server system (RSS). Although there is no single organization that could be held accountable for RSS performance, the RSSAC finds value in measuring and reporting on RSS service levels. Recorded metrics may be useful in understanding long-term RSS behavior. 

### 6.1 RSS Availability

The purpose of this metric is to characterize the availability of the RSS from multiple locations over a period of time.

This metric is derived from the set of RSI availability measurements described in Section 5.1. Since the RSI availability measurements are sent over specific transports and address types, we can describe the RSS availability over those separate transports and address types. The metrics have the following names:

- IPv4 UDP Availability
- IPv4 TCP Availability
- IPv6 UDP Availability
- IPv6 TCP Availability

__Aggregation.__ For each transport and address type, in each measurement interval t, and for each vantage point v, calculate r_(t,v) as the number of RSIs that responded to an availability query (section 5.1). `[egb]` The aggregated RSS availability (for each transport and address type) A is then:

A = (∑ min(k, r_(t,v))) / ∑ k

Where k is the value from Section 4.9, and the sums are taken over all intervals and all vantage points. `[cvf]`

In order for the calculated RSS availability to be anything less than 100%, there must be at least one interval in which at least one vantage point received responses from fewer than k RSIs.

__Aggregation Examples.__ Since the calculation of this metric is more complex than others, here are some fabricated examples that demonstrate how it is calculated. These examples are based on n=13 RSIs, k=8 required for operation, a 30-day month, and 20 vantage points.

Scenarios | Measured Availability | Notes
--- | --- | ---
A month-long attack takes out one RSI entirely. | 100% | All measured r_(t,v)=12, which is greater than k=8.
A month-long attack takes out five RSIs entirely. | 100% | All measured r_(t,v)=8, which is equal to k=8.
A month-long attack takes out six RSIs entirely. | 87.50% | ⅞ because all measured r_(t,v)=7.
A 24-hour attack takes out all RSIs entirely. | 96.66% | 29/30
In one five-minute interval, one vantage point can only reach seven RSIs. | 99.99992% | ((288*30*20*8)-1)/(288*30*20*8)
For two intervals, seven vantage points can reach no RSIs. | 99.9989% | ((288*30*20*8)-14)/(288*30*20*8)

__Precision.__ The number of aggregated measurements shall convey the precision. `[vxl]`

__Reporting.__ For each month, the report shall include the aggregated RSS Availability values for each transport and address type, and whether each meet, or does not meet the established threshold(s). `[fdy]`

__Thresholds.__ The recommended threshold for this metric is 99.999%, based on the rationale for the RSI availability threshold in Section 5.1. `[wzz]`

### 6.2 RSS Response Latency

The purpose of this metric is to characterize the response latency of the RSS from multiple locations over a period of time.

Since the individual RSI response latency measurements are sent over specific transports and address types, we can also report the RSS latency over those separate transports and address types. The metrics have the following names:

- IPv4 UDP Response Latency
- IPv4 TCP Response Latency
- IPv6 UDP Response Latency
- IPv6 TCP Response Latency

__Measurements.__ In this method, the metric is derived from the set of RSI response latency measurements described in Section 5.1. `[spx]`

__Aggregation.__ In each five-minutes measurement interval, find the best k RSI response latencies for each vantage point and for each transport and address type. `[bom]` The aggregated response latency is calculated as the median value of the subset of lowest latencies. `[jbr]`

__The paragraph above should be replaced with:__  Aggregation. For each five-minute measurement interval, and for each each transport and address type, find the median of the lowest k RSI response latencies from the set of vantage points. The aggregated response latency for each each transport and address type is calculated as the median of the medians from the set of five-minute measurement intervals.

__Precision.__ Measurement Count shall be presented to convey the measurement range and precision. `[hgm]`

__Reporting.__ For each month, the report shall include the aggregated RSS Response Latency values for each transport and address type, and whether each meet, or does not meet the established threshold(s). `[gwm]`

__Thresholds.__ The recommended threshold for this metric is 150 milliseconds for UDP `[uwf]` and 300 milliseconds for TCP. `[lmx]`

### 6.3 RSS Correctness

The purpose of this metric is to characterize the correctness of the overall RSS from multiple locations over a period of time. 

The metric is derived from the set of individual RSI correctness measurements described in section 5.3. The metric has the following name:

- Correctness

__Aggregation.__ All of the measurements covering a period of one month are aggregated together. `[udc]` RSS Correctness is calculated as the number of correct responses observed divided by the total number of responses, expressed as a percentage. `[ywo]`

__Precision.__ The number of aggregated measurements shall convey the precision. `[kea]` 

__Reporting.__ For each month, the report shall include the aggregated RSS Correctness values, and whether it meets, or does not meet the established threshold. `[vpj]`

__Thresholds.__ The recommended threshold for this metric is 100%. `[gfh]` The expectation is that the RSS always serves correct responses.

### 6.4 RSS Publication Latency

The purpose of this metric is to characterize the publication latency of the RSS from multiple locations over a period of time. 

The metric is derived from the set of individual RSI publication latency measurements described in Section 5.4. The metric has the following name:

- Publication Latency

__Aggregation.__ All of the measurements covering a period of one month are aggregated together. `[dbo]` Publication Latency is calculated as the median of the aggregated values. `[zgb]`

__Precision.__ The number of aggregated measurements shall convey the precision. `[daz]`

__Reporting.__ For each month, the report shall include the aggregated Publication Latency values, and whether it meets, or does not meet the established threshold. `[tkw]`

__Thresholds.__ The recommended threshold for this metric is 35 minutes. `[zkl]` This is based on the root zone SOA retry value of 30 minutes, plus one five-minute measurement interval. Note that the RSS publication latency threshold is lower than the RSI publication latency threshold because we do not expect that a majority of RSIs to be close to the individual threshold at the same time.

## 7 Summary of Metrics and Thresholds

{{ elided }}

## 8 Recommendations

Recommendation 1: The RSSAC recommends the ICANN Board commission an initial implementation of the measurement system described in this document to gather operational data and experience from actual monitoring of the RSS. The initial implementation should be designed such that it can transform into the official implementation as described in Recommendation 2 below. The insights learned from the implementation will inform future revisions of this document, if necessary.

Recommendation 2: The RSSAC recommends that the official implementation of the metric system must:

a. Meet the minimum requirements specified in Section 3 of this report regarding the number, location, connectivity, and other requirements for the vantage points. `[ccd]`

a. Publish all software related to its operation under an open source license as defined by the Open Source Initiative. `[atl]`

a. Make the raw measurement data available to anyone in the interest of transparency. `[otd]` A third party should be able to use the raw data to verify the computation of these metrics.

a. In its monthly reports, only publish threshold pass or fail indicators for each RSI, not the actual measurements or metrics used to determine the threshold pass or fail values. `[gkr]`

a. Publicly describe its methods for collecting measurements and aggregating metrics, including the topological location of each measurement vantage point. `[uys]` This description should be complete enough for RSOs and DNS researchers to create their own measurement collection systems similar to those used by the official implementation.

a. Share with an RSO the underlying measurements and metrics that resulted in failure any time an RSI fails to pass a threshold test. `[drc]` The shared measurements and metrics must include all measurements from around the time of failure and must include all measured values for all transports and address types. `[lpf]`

Recommendation 3: The RSSAC, in collaboration with ICANN and the Internet community, should consider the following additional work:  

- For a holistic view of RSS performance, it may be desirable or necessary to include measurements for all instances of each RSI. The only reasonable way to provide for such a view would be through self-reporting. In the future, it should be considered to have each RSO perform self-reporting of the defined metrics to eliminate uncertainty of components not under the RSO’s control, and it should probably be tied to an SLA including compensation for the RSO to implement.

- Create a reference data set.

- Explore the financial aspects of increased accountability and how it might relate to these metrics.

- Keeping with the provisions of RSSAC037 and RSSAC038 publish a document that advises any bodies created as part of the ongoing evolution of RSS governance on how they should interpret and act on data from the measurement systems.

- Investigate a better long-term plan for the location of the vantage points. Such a plan would distribute the vantage points by network topology instead of geographic location.

- Whereas the current work is based on a largely empirical model of the RSS, future versions of this document may want to take a more analytical and theoretical modeling approach.

## 9 Example Results

{{ too complicated for Markdown; please see [RSSAC047](https://www.icann.org/en/system/files/files/rssac-047-12mar20-en.pdf) for the full tables }}

## 10 Acknowledgments, Dissents, and Withdrawals

{{ elided }}

## 11 Revision History

{{ elided }}