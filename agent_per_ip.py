#!/usr/bin/python

import sys
import csv
from array import array
import re

global ipfield
global uafield
global trigger_limit
global count
global option
global fname
global arguments
global arguments_percentage

###
##############################################################################
lines = 0


iphead = "Internal IP"		# Used for auto-determining the right column
uahead = "User Agent (Original)"# Like above

# Values below are defaults and can be changed on CLI
# IPfield and UAfield are usually automatically determined

ipfield = 6			# 6 for newer	5/6 for old
uafield = 10			# 10 for newer	12 for old
trigger_limit = 50
count = 5

##############################################################################
thelist = []			# [ { dictIP,[listUA] } ]
arguments = {}			# Dict that holds a count of all UA-elements 
				# after processUA has been called
arguments_percentage = {}	# Dict with percentage of all UA-elements
				# after percentUA has been called
outlier_ua = {}
outlier = {}

##############################################################################
helpmsg = """
Usage: agent_per_ip.py <option> <file>
Options:
--process
\tProcesses a .csv file
--import
\tImports an existing .txt file that
\tis an export of previous processing
"""

##############################################################################
### Main Program starts here

def main():

	try:
		option = sys.argv[1]
		fname = sys.argv[2]
	except Exception,e:
		print helpmsg
		exit(2)

	if option == "--process":
		processcsv(fname)
		storelist(fname)
	if option == "--import":
		loadlist(fname)
	if not option == "--process" and not option == "--import":
		print helpmsg
		exit(2)
	
	processhosts()
	showmenu()


def loadlist(file):
	import json
	global thelist
	sys.stdout.write("Loading...")
	sys.stdout.flush()
	thelist = json.load(open(file))
	print "\t [Done]\n"

def addlist(file):
	import json
	global thelist
	sys.stdout.write("Loading...")
	sys.stdout.flush()
	importlist = json.load(open(file))
	for host in importlist:
		if not any(host['ip'] == d['ip'] for d in thelist):
                        # Host doesn't exist in thelist
                        thelist.append({"ip":host['ip'], "user-agent":host['user-agent']})
                else:
                        # IP is in the array
                        for d in thelist:
                                if d['ip'] == host['ip']:
					for ua in host['user-agent']:
                                        	if not any(a == ua for a in d['user-agent']):
                                                	d['user-agent'].append(ua)

	print "\t [Done]"

def file_size(file):
	sys.stdout.write("Counting lines...")
	sys.stdout.flush()
        lines = file_len(file)
        print "\t [Done]"

def file_len(file):
	with open(file) as f:
		for i, l in enumerate(f):
			pass
	global lines
	lines = i + 1

def processcsv(file):
	file_size(file)
	f = open(file, 'r')
        r = csv.reader(f)
	print "Starting to process the file. May take long!"
	print "This file has",lines,"lines."
	counter = 0
	countertwee = 0
	ten = lines/10
	findfields(r)
        for row in r:
		counter+=1
		if counter > ten:
			countertwee+=1
			done = int(countertwee*10)
			sys.stdout.write("\t%s%% Done\r" %done)
			sys.stdout.flush()
			counter = 0
                process(row)
        f.close()
	print("\t 100% Done\t ")

def processUA(uastring):
	# Start by splitting these
	x = re.split(';|\\(|\\)|,|\\[\\]',uastring)

	for element in x:
		try:	# Element existed: +=1
			s = element.strip()
			arguments[s]=arguments[s]+1
		except Exception,e:
			# element didn't exist: =1
			s = element.strip()
			arguments[s]=1

def process(row):
	if not row.__len__() < 2:
		ipsrc = row[ipfield]
		usragent = row[uafield]
		
		if not any(d['ip'] == ipsrc for d in thelist):
			# IP is not yet in the array
			if re.match('[^\ ]', usragent):
				thelist.append({"ip":ipsrc, "user-agent":[usragent]})
		else:
			# IP is in the array
			for d in thelist:
				if d['ip'] == ipsrc:
					if not any(a == usragent for a in d['user-agent']) and re.match('[^\ ]', usragent):
						d['user-agent'].append(usragent.strip())

def findfields(csv_r):
	head = csv_r.next()
	i=0
	while i < head.__len__():
		if head[i] == iphead:
			print "Automatically determined IP field:",i
			global ipfield
			ipfield = i
		if head[i] == uahead:
			print "Automatically determined UA field:",i
			global uafield
			uafield = i
		i+=1

def storelist(file):
	import json
	file = file+".txt"
	with open(file, 'w+') as f:
		json.dump(thelist, f, ensure_ascii=False)

def storeua(file,abrel):
	import json
	file = file+".csv"
	with open(file, 'w+') as f:
		if abrel == 0:
			print>>f,"User-agent element,Count"
			for ua in arguments:
				print>>f,ua+",",arguments[ua]
		elif abrel == 1:
			print>>f,"User-agent element,Percentage"
			for ua in arguments_percentage:
				print>>f,ua+",",arguments_percentage[ua]
		elif abrel == 2:
			print>>f,"User-agent element,Count,Percentage"
			for ua in arguments:
				for uaa in arguments_percentage:
					if ua == uaa:
						print>>f,ua+",",arguments[ua],",",arguments_percentage[ua]
		else:
			print "Invalid number given"

def percentUA():
	total=0.0
	for q in arguments:
		total += arguments[q]

	for q in arguments:
		pct = arguments[q]/total*100
		arguments_percentage[q] = pct

def genoutliers(count):
	global outlier_ua
	perctmp = arguments_percentage.copy()
	lowest = {}
	i = 0
	# Generate lowest _count_ percentages
	while i < count:
		lowest[i] = min(perctmp.itervalues())
		for k in perctmp:
			if perctmp[k] == lowest[i]:
				perctmp[k] = 100
		i+=1
	
	# Generate list of arguments in lowest 5 percentages
	outlier_ua = {}
	for k in lowest:
		for q in arguments_percentage:
			if arguments_percentage[q] == lowest[k]:
				outlier_ua[q] = lowest[k]

def scorehosts():
	# Generate outliers first
	# Score hosts based on argument_outliers
	global outlier
	outlier = {}
	for k in thelist:
		for l in k['user-agent']:
		        x = re.split(';|\\(|\\)|,|\\[\\]',l)
			for element in x:
				s = element.strip()
				if s in outlier_ua:
					try:	# Value existed
						outlier[k['ip']]+=1
					except Exception,e:
						outlier[k['ip']]=0
						outlier[k['ip']]+=1					

def printoutliers(trigger_limit):
	# Score hosts first
	# Print funny hosts
	for k in outlier:
		if outlier[k] > trigger_limit:
			print "Host: "+k+", score:",outlier[k]

def printhost(ip):
	print "Host",ip,", score:",outlier[ip]

def printua(host):
	for k in thelist:
		if k['ip'] == host:
			for ua in k['user-agent']:
				print ua


#def uaperip():
#	# Unused
#	for d in thelist:
#		if d['user-agent'].__len__() > 4:
#			print "=======",d['ip'],"======="
#			for ua in d['user-agent']:
#				print ua

def processhosts():
	global count
	for d in thelist:
		for useragent in d['user-agent']:
			processUA(useragent)
	percentUA()
	genoutliers(count)
	scorehosts()

def showmenu():
	print (50 * '=')
	print ("1.\t Print outlying hosts")
	print ("2.\t Change trigger percentage")
	print ("3.\t Change trigger threshold")
	print ("4.\t Print user-agents for host")
	print ("5.\t Load additional preprocessed file")
	print ("6.\t Export processed dataset")
	print ("7.\t Export user-agent")
	print ("")
	print ("0.\t Exit")
	print ("")
 
	is_valid=0
 
	while not is_valid :
        	try :
                	choice = int ( raw_input('Enter your choice [0-9] : ') )
                	is_valid = 1 # Escape while loop
        	except ValueError, e :
        	        print ("'%s' is not a valid integer." % e.args[0].split(": ")[1])
 
	# Menu options
	if choice == 1:
		# Print triggered hosts
		global trigger_limit
		print ""
		print (15 * "-"),#
		print ("Outliers"),
		print (15* "-")
		printoutliers(trigger_limit)
		print (40 * "-")
		print ""
		showmenu()

	elif choice == 2:
		# Trigger percentage
		print ("Triggering is done based on the lowest X number of percentages.")
		count = int(raw_input("What number should be used for triggering? (5): "))
		sys.stdout.write("Recalculating...")
		sys.stdout.flush()
		genoutliers(count)
		print "\t[Done]"
		sys.stdout.write("Scoring hosts...")
		scorehosts()
		print "\t[Done]"
		showmenu()
		
	elif choice == 3:
		# Set trigger threshold
		print ("The trigger threshold defines the threshold for hosts to be shown.")
		trigger_limit = int(raw_input("What should the new threshold be? (50) "))
		showmenu()

	elif choice == 4:
		# Show user-agents for single host
		host = raw_input("Host IP: ")
		print (9*"-"), #
		print host, #
		print (9*"-")
		printhost(host)
		printua(host)
		showmenu()

	elif choice == 5:
		# Import processed file
		file = raw_input("File location: ")
		addlist(file)
		processhosts()
		showmenu()

	elif choice == 6:
		# Export complete set
		file = raw_input("Export to (.txt auto-added): ")
		storelist(file)
		sys.stdout.write("Processed set stored as %s.txt\n\n" %file)
		showmenu()

	elif choice == 7:
		# Export UA
		file = raw_input("Export user-agents to (.csv auto-added): ")
		print "\n\nExport as absolute [0] or percentages [1]"
		abrel = int (raw_input("or combined [2]: "))
		storeua(file,abrel)
		sys.stdout.write("User-agents stored as %s.csv\n\n" %file)
		showmenu()

	elif choice == 0:
		# GTFO
		exit(1)

	else:
	        print ("Invalid number. Try again...")
		showmenu()

main()
