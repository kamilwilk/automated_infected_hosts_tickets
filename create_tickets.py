import splunklib.results as results
import splunklib.client as client
import csv, operator
import re
import time
import datetime
import smtplib
from email.MIMEMultipart import MIMEMultipart
from email.MIMEBase import MIMEBase
from email.mime.text import MIMEText
from email import Encoders


###############OPTIONS###############
use_threshold = True
threshold = 3
correlation_time = 7200

HOST = ""
PORT = 8089
USERNAME = ""
PASSWORD = ""
####################################

threshold_list = []
ticketed_list = []
manual_review_list = []

tickets_count = 0

def main():
	# Create a Service instance and log in 
	service = client.connect(
		host=HOST,
		port=PORT,
		username=USERNAME,
		password=PASSWORD)

	#Open our CSV files
	with open("trojan-report-results.csv", "wb") as output_report, open("manual_review_report.csv", "wb") as manual_review_report:
		output_wtr = csv.writer(output_report)
		m_r_wtr = csv.writer(manual_review_report)



		#Do our splunk search for virus reports
		kwargs_export = {"output_mode" : "csv",
						  "search_mode": "normal",
						  "field_list" : "_time, dest, event_detail, src",
					  	  "earliest_time": int(time.time()) - 86400,}
		searchquery_export = """search sourcetype=snort "Priority: 1"
AND dest !=X.X.X.X/16 AND dest !=X.X.X.X/8 AND dest !=X.X.X.0/21 AND dest !=X.X.X.X AND dest !=X.X.X.X
AND src !=X.X.X.X AND src !=X.X.X.X AND src !=X.X.X.X AND src !=X.X.X.X
NOT "ET DNS" NOT Possible NOT User-Agent NOT AdWare NOT Potentially NOT BrowseFox NOT IRC NOT Suspicious
| dedup src dest event_detail
| sort src, _time
| table src dest _time event_detail"""
		exportsearch_results = service.jobs.export(searchquery_export, **kwargs_export)
		trojan_results = csv.reader(exportsearch_results)


		#NOTE: Have to try and except IndexError/ValueErrors because Splunk 
		#returns empty fields for no reason in CSV format.

		#Go through each result in virus search
		for t_result in trojan_results:

			#Write header to CSV
			if t_result[0] == "_time":
				t_result.append("mac")
				t_result.append("user")
				t_result.append("auth_time")
				output_wtr.writerow(t_result)

			else:
				src_ip = t_result[3]
				t_time = int(time.mktime(datetime.datetime.strptime(t_result[0], "%Y-%m-%d %H:%M:%S.%f %Z").timetuple()))

				#conduct search for users authed on ip within
				searchquery_export = "search sourcetype=aruba:authmgr 522008 AND " + src_ip
				kwargs_export = {"output_mode" : "csv",
								 "search_mode": "normal",
								 "field_list" : "_indextime, _raw, _time",
								 "earliest_time": t_time - correlation_time,
								 "latest_time": t_time}
				exportsearch_results = service.jobs.export(searchquery_export, **kwargs_export)
				search_results = csv.reader(exportsearch_results)

				for s_result in search_results:
					#Splunk search result has a header for each result
					#might be a better way to ignore it than the check below
					if s_result[0] == "_indextime":
						continue

					s_time = int(s_result[0])

					if ( (t_time > s_time) and (t_time - s_time) < correlation_time):
						t_result.append(find_between(s_result[1], "MAC=", " "))
						t_result.append(find_between(s_result[1], "username=", " "))
						t_result.append(s_result[2])

						if not (use_threshold):
							output_wtr.writerow(t_result)

						else:
							info = [find_between(s_result[1], "username=", " "), t_result[2][0:20]]
							threshold_list.append(info)

							if threshold_list.count(info) == threshold:
								print "Threshold Met"
								output_wtr.writerow(t_result)
								ticketed_list.append(t_result)

							elif threshold_list.count(info) > threshold:
								print "Already Written"

							else:
								print "Threshold Not Met"
								manual_review_list.append(t_result)
						break

		for tr in ticketed_list:
			for mr in manual_review_list:
				if [tr[5],tr[2][0:20]] == [mr[5],mr[2][0:20]]:
					print mr
					manual_review_list.remove(mr)

		m_r_wtr.writerow(["_time", "dest", "event_detail", "src", "mac", "user", "auth_time"])
		for item in manual_review_list:
			m_r_wtr.writerow(item)

	#create_ticket()	
	email_report()

def create_ticket():
	with open("trojan-report-results.csv", "rb") as ticket_report:
		input_rdr = csv.reader(ticket_report)
		next(input_rdr, None)
		for item in input_rdr:

			global tickets_count
			tickets_count += 1
		
			SUBJECT = "Virus Infection"
			EMAIL_FROM = item[5] + "@"
			EMAIL_TO = ""
			EMAIL_SERVER = ""

			msg = MIMEMultipart()
			msg['Subject'] = SUBJECT 
			msg['From'] = EMAIL_FROM
			msg['To'] = EMAIL_TO
			msg_string = """
						
					We regret to inform you that your computer has been infected with a virus.

					User: %s
					MAC: %s
					Time: %s
					Event Detail: %s 
					Source IP: %s
					Destination IP: %s
					


			""" % (item[5], item[4], item[0], item[2], item[3], item[1])
			
			msg.attach( MIMEText(msg_string) )
			server = smtplib.SMTP(EMAIL_SERVER)
			server.sendmail(EMAIL_FROM, EMAIL_TO, msg.as_string())


def email_report():
	print "Emailing report"
	now = datetime.datetime.now()

	SUBJECT = "Infected Hosts Report " + now.strftime("%m-%d-%Y")
	EMAIL_FROM = "pythonscript"
	EMAIL_TO = ["", ""]
	EMAIL_SERVER = ""

	msg = MIMEMultipart()
	msg['Subject'] = SUBJECT 
	msg['From'] = EMAIL_FROM
	msg['To'] = ", ".join(EMAIL_TO)
	msg_string = """
					
				Number of tickets created: %d

		""" % tickets_count

	msg.attach( MIMEText(msg_string) )

	part = MIMEBase('application', "octet-stream")
	part.set_payload(open("trojan-report-results.csv", "rb").read())
	Encoders.encode_base64(part)
	part.add_header('Content-Disposition', 'attachment; filename="trojan-report-results.csv"')

	msg.attach(part)

	part = MIMEBase('application', "octet-stream")
	part.set_payload(open("manual_review_report.csv", "rb").read())
	Encoders.encode_base64(part)
	part.add_header('Content-Disposition', 'attachment; filename="manual_review_report.csv"')


	msg.attach(part)

	server = smtplib.SMTP(EMAIL_SERVER)
	server.sendmail(EMAIL_FROM, EMAIL_TO, msg.as_string())



def find_between( s, first, last ):
	try:
		start = s.index( first ) + len( first )
		end = s.index( last, start )
		return s[start:end]
	except ValueError:
		return ""


if __name__ == "__main__":
    main()

