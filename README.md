# automated_infected_hosts_tickets

## Python script which correlates snort alerts in Splunk with aruba authentication logs in Splunk to automatically create helpdesk tickets for machines which need to be reimaged.

### The code is not very clean because it was written to be used in a specific environment, but it performed with new issues as a cronjob on a daily basis.

### Dependencies:
* Python 2.7
* splunk-sdk

