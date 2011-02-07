#!/usr/bin/python

#	DNSploit - Python DNS Reconnaissance/Exploit tool
#
#	Copyright Mike Romano 2011
#
#	DNSploit is free software: you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation, either version 3 of the License, or
#	(at your option) any later version.
#
#	DNSploit is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with DNSploit If not, see <http://www.gnu.org/licenses/>.


#Import dnspython libraries and system utilities
from dns.resolver import query
import sys, getopt

#Wordlist for common hosts
bruteHostNames=['accounting','accounts','alpha','apple','banking','blackboard','blog','blog1','blogs','carro','cart','catalog','chart','chat','cisco','correoweb','dc','dev-www','development','dns','download','downloads','drupal','drupal6','email','exch','exchange','file','file01','file1','files','filesrv','finance','firewall','forum','forums','ftp','gallery','gamma','groups','help','home','images','imap','imaps','irc','juniper','life','linux','lists','mail','main','members','microsoft','mon','monitor','mysql','news','ns1','ns2','ns3','omega','online','oracle','partner','partners','people','pop','pops','portal','purchase','radio','remote','sales','search','secure','server','services','shop','smtp','snort','sql','srv','ssh','staff','stream','streaming','sun','support','test','test1','test2','upload','users','video','videos','voice','vpn','web','web-dev','web1','web2','web3','webcam','webct','web-dev','webdev','webmail','wordpress','ww0','www','www-dev','www1','www2','www3','www4','www5','www6','www7','www8','www9']

#Version 
version = "0.2"

def usage():
	print "\nDnsploit "+ version + " by Mike Romano"
	print "Usage: dnsploit <options>\n"
	print "Options:"
	print "-d, --domain 		Set attack domain **REQUIRED**"
	print "-a, --ipv4		Brute Force IPv4 Hosts (A)"
	print "-A, --ipv6		Brute Force IPv6 Hosts (AAAA)"
	print "-c, --cname		Brute Force Aliases (CNAME)"
	print "-s, --service		Dump Service Records (SRV)"
	print "-m, --mail		Dump Mail Records (MX)"
	print "-z, --zone		Start Zone Transfer"
	print "-h, --help		Print this help message"
	print "-x, --all		Run all DNS attacks **Use with caution**"
	print "-w, --wildcard		Check for wildcard only (IPv4 & IPv6)"
	print ""
	print "Example:			"
	print "dnsploit -d mydomain.com -a"
	print "\tThis will run a dictionary brute force IPv4 lookup against mydomain.com"
	print ""

def argParse(argv):
	nsDump = False
	ipv4Dump = False
	ipv6Dump = False
	cnameDump = False
	serviceDump = False
	zoneXfer = False
	mailDump = False
	wildcardCheck = False
	setAll = False
	dom = 'mydomain.org'
	try: 
		opts, args = getopt.getopt(argv, "hnaxAcsmzwd:",["help","ipv4","all","ipv6","domain=","cname","service","mail","zone"])
		for opt, arg in opts:
			if opt in ("-h", "--help"):
				usage()
				sys.exit()
			elif opt in ("-n", "--ns"):
				nsDump = True
			elif opt in ("-a", "--ipv4"):
				ipv4Dump = True
			elif opt in ("-x", "--all"):
				setAll = True
			elif opt in ("-A", "--ipv6"):
				ipv6Dump = True
			elif opt in ("-c", "--cname"):
				cnameDump = True
			elif opt in ("-s", "--service"):
				serviceDump = True
			elif opt in ("-m", "--mail"):
				mailDump = True
			elif opt in ("-z", "--zone"):
				zoneXfer = True
			elif opt in ("-d","--domain"):
				dom = arg
			elif opt in ("-w","--wildcard"):
				wildcardCheck = True	
		return (setAll, nsDump, ipv4Dump, ipv6Dump, cnameDump, serviceDump, mailDump, zoneXfer, dom, wildcardCheck)
	except getopt.GetoptError:
		usage()
		sys.exit(2)


def _random():
	import random
	charset = 'abcdefghijklmnopqrstuvwxyzABDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
	min = 8
	max = 12
	randomString = ''
	for count in xrange(4,5):
		for x in random.sample(charset,random.randint(min,max)):
			randomString+=x
	return randomString
	

def _main(argv):
	
	(setAll, nsDump, ipv4Dump, ipv6Dump, cnameDump, serviceDump, mailDump, zoneXfer, dom, wildcardCheck) = argParse(argv)
	if dom == "mydomain.org":
		print "\n** Domain Not Specified, Please Specify a Domain **\n"
		usage()
		sys.exit(2)
	if setAll == True:
		_nsDump(dom)
		_hostDump(dom)
		_hostDumpv6(dom)
		_cnameDump(dom)
		_serviceDump(dom)
		_mailDump(dom)
		sys.exit(2)
	if wildcardCheck == True:
		_wildcardCheck(dom)
	if nsDump == True:
		_nsDump(dom)
	if ipv4Dump == True:
		_hostDump(dom)
	if ipv6Dump == True:
		_hostDumpv6(dom)
	if cnameDump == True:
		_cnameDump(dom)
	if serviceDump == True:
		_serviceDump(dom)
	if mailDump == True:
		_mailDump(dom)
	if zoneXfer == True:
		print "Zone transfers not supported in this version"
	
def _nsDump(dom):
	try:
		print "\nDumping Nameserver Records (NS)\n"
		for record in query(dom, 'NS'):
			print "\t"+dom, 'NS', record.target
		print "---------------"
	except:
		print "Nameserver Records unavailable\n"	
		print "---------------"
	
def _wildcardCheck(dom):	
		try:
			for record in query(_random()+'.'+domain, 'A'):
				print "\n!!!!! IPv4 Wildcard in place at "+record.address+" !!!!!\n"
		except:
			print "\nIPv4 Wildcard not present\n"
				
		try:
			for record in query(_random()+'.'+domain, 'AAAA'):
				print "\n!!!!! IPv6 Wildcard in place at "+record.address+" !!!!!\n"
		except:
			print "\nIPv6 Wildcard not present\n"
				
def _hostDump(dom):	
	try:
		print "\nDumping IPv4 Hosts (A)\n"		
		for i in bruteHostNames:
			request = str(i)+'.'+str(dom)
			print request	
			try:

				for record in query(request, 'A'):
					print "\t"+request, 'A', record.address
			except:
				print "\n"
		_wildcardCheck(dom)
		print "---------------"
	except:
		print "IPv4 Hosts unavailable\n"
		
		print "---------------"

def _hostDumpv6(dom):
	try:
		print "\nDumping IPv6 Hosts (A)\n"		
		for i in bruteHostNames:
			request = str(i)+'.'+str(dom)
			print request	
			try:
				for record in query(request, 'AAAA'):
					print "\t"+request, 'AAAA', record.address
			except:
				print "\n"
		_wildcardCheck(dom)
		print "---------------"
	except:
		print "IPv6 Hosts unavailable\n"
		
		print "---------------"
	
	
def _cnameDump(dom):
	try:
		print "\nDumping Aliases (CNAME)\n"
	
		for i in bruteHostNames:
			request = str(i)+'.'+str(dom)
			print request
			try:
				for record in query(request, 'CNAME'):
					print "\t"+request, 'CNAME', record.target
			except:
				print "\n"
		print "---------------"
	
	except:
		print "Alias Records unavailable\n"
		
		print "---------------"

def _mailDump(dom):
	try:
		print "\nDumping Mail Records (MX)\n"
		for record in query(dom, 'MX'):
			print dom, 'MX', record.preference, record.exchange
		
		print "---------------"
	
	except:
		print "Mail Records unavailable\n"
		
		print "---------------"
	
def _serviceDump(dom):
	try:
		print "\nDumping Service Records (SRV)\n"
		for record in query(dom,'SRV'):
			print dom, 'SRV', request.target, request.port, request.priority
		
		print "---------------"
	except:
		print "Service Records unavailable\n"
	
		print "---------------"

def _zoneXfer():
	print "zone unavailable"

	
if __name__ == '__main__':
	_main(sys.argv[1:])
