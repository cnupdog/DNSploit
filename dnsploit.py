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
import sys, getopt, dns.zone
from dns import resolver,reversename
from multiprocessing import Process

#Wordlist for common hosts
bruteHostNames=['accounting','accounts','admin','alpha','apple','apps','autodiscover','banking','blackboard','blog','blog1','blogs','campaign','campaigns','carro','cart','catalog','chart','chat','cisco','conference','correoweb','data','database','db','db1','db2','dc','dev','dev-www','developers','development','dns','download','downloads','drupal','drupal6','drupal7','email','exch','exchange','facebook','file','file01','file1','files','filesrv','finance','firewall','forms','forum','forums','ftp','gallery','gamma','groups','help','helpdesk','home','images','imap','imaps','info','irc','juniper','legal','life','linux','lists','mail','main','members','microsoft','mon','monitor','mysql','news','ns1','ns2','ns3','omega','online','oracle','partner','partners','people','pop','pops','portal','project','projects','purchase','radio','remote','sales','search','secure','server','services','sftp','shop','smtp','snort','sql','srv','ssh','staff','stage','staging','stg','storelocator','stream','streaming','sun','support','svn','svn1','test','test1','test2','upload','users','video','videos','voice','vpn','web','web-dev','web1','web2','web3','webcam','webct','web-dev','webdev','webex','webdrive','webmail','wiki','wordpress','ww0','www','www-dev','www1','www2','www3','www4','www5','www6','www7','www8','www9']

#Version 
version = "2.0"

#How to use
def usage():
	print "\nDNSploit "+ version + " by Mike Romano"
	print "Usage: dnsploit <options>\n"
	print "Options:"
	print "-d, --domain 		Set attack domain **REQUIRED**"
	print "-a, --ipv4		Brute Force IPv4 Hosts (A)"
	print "-A, --ipv6		Brute Force IPv6 Hosts (AAAA)"
	print "-c, --cname		Brute Force Aliases (CNAME)"
	print "-s, --service		Dump Service Records (SRV)"
	print "-m, --mail		Dump Mail Records (MX)"
	print "-n, --ns		Dump Name Servers (NS)"
	print "-r, --ptr		Dump Reverse records (PTR)"
	print "-z, --zone		Start Zone Transfer"
	print "-h, --help		Print this help message"
	print "-x, --all		Run all DNS attacks **Use with caution**"
	print "-w, --wildcard		Check for wildcard only (IPv4 & IPv6)"
	print ""
	print "Example:			"
	print "dnsploit -d mydomain.com -a"
	print "\tThis will run a dictionary brute force IPv4 lookup against mydomain.com\n"
	print "dnsploit -d mydomain.com -z 127.0.0.1"
	print "\tThis will attempt to pull the zone file from remote DNS at IP 127.0.0.1\n"
	print "dnsploit -d mydomain.com -r 192.168.1.0/24"
	print "\tThis will attempt to pull all PTR records in the 192.16.1.0 255.255.255.0 subnet"
	print ""

#Initial arguments for what options to execute
def arg_parse(argv):
	nsDump = False
	ipv4Dump = False
	ipv6Dump = False
	cnameDump = False
	serviceDump = False
	remote_host = False
	mailDump = False
	wildcardCheck = False
	setAll = False
	#Default the following values to prevent error
	dom = 'mydomain.org'
	remote_host = '127.0.0.1'
	ptrDump = '127.0.0.1/32'
	try: 
		opts, args = getopt.getopt(argv, "hnaxAcsmz:wr:d:",["help","ipv4","all","ipv6","domain=","cname","service","mail","zone=","ptr="])
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
			elif opt in("-r","--ptr"):
				ptrDump = arg
			elif opt in ("-z", "--zone"):
				remote_host = arg
			elif opt in ("-d","--domain"):
				dom = arg
			elif opt in ("-w","--wildcard"):
				wildcardCheck = True	
		return (setAll, nsDump, ipv4Dump, ipv6Dump, cnameDump, serviceDump, mailDump, remote_host, dom, wildcardCheck, ptrDump)
	except getopt.GetoptError:
		usage()
		sys.exit(2)


def _random():
	#This is used for testing wildcards - if a random string @ domain is present, the odds are high that a wildcard exists
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
	
	(setAll, nsDump, ipv4Dump, ipv6Dump, cnameDump, serviceDump, mailDump, remote_host, dom, wildcardCheck,ptrDump) = arg_parse(argv)
	if dom == "mydomain.org":
		print "\n** Domain Not Specified, Please Specify a Domain **\n"
		usage()
		sys.exit(2)
	if setAll == True:
		ns_dump(dom)
		host_dump(dom)
		host_dump_v6(dom)
		cname_dump(dom)
		service_dump(dom)
		mail_dump(dom)
		sys.exit(2)
	if wildcardCheck == True:
		wildcard_check(dom,'A')
		wildcard_check(dom,'AAAA')
	if nsDump == True:
		ns_dump(dom)
	if ipv4Dump == True:
		host_dump(dom)
	if ipv6Dump == True:
		host_dump_v6(dom)
	if cnameDump == True:
		cname_dump(dom)
	if serviceDump == True:
		service_dump(dom)
	if mailDump == True:
		mail_dump(dom)
	if remote_host != '127.0.0.1':
		zone_xfer(dom,remote_host)
	if ptrDump !='127.0.0.1/32':
		ptr_driver(ptrDump)

#Dump Nameserver Records (NS)
def ns_dump(dom):
	try:
		print "\nDumping Nameserver Records (NS)\n"
		for record in query(dom, 'NS'):
			print "\t"+dom, 'NS', record.target
		print "---------------"
	except:
		print "Nameserver Records unavailable\n"	
		print "---------------"

#Check if Wildcard exists	
def wildcard_check(dom,rec_type):	
	if rec_type=='AAAA':
		ipv = 'IPv6'
	else:
		ipv = 'IPv4'
	try:
		for record in query(_random()+'.'+dom, rec_type):
			print "\n!!!!! "+ipv+" Wildcard in place at "+record.address+" !!!!!\n"
			return record.address
	except:
		print "\n "+ipv+ " Wildcard not present"
		return ""
			
#Check against word list for existing hosts (IPv4 - A records)	
def host_dump(dom):
	
	rec_type = 'A'
	wc_address=wildcard_check(dom,rec_type)
	
		
	print "\nDumping IPv4 Hosts (A)\n"		

	try:
		for i in bruteHostNames:
			proc = Process(target=host_dump_resolver,args=(dom,i,wc_address,rec_type))
			proc.start()
	except:
		print "\n----IPv4 Record unavailable----\n"
		
def host_dump_resolver(dom,i,wc_address,rec_type):
	request = str(i)+'.'+str(dom)
	resolver = dns.resolver.Resolver()	
	resolver.lifetime=2.0
	
	try:	
		answer = resolver.query(request,rec_type)
	
		for record in answer.rrset:
	
			if str(record) == wc_address:
				pass	
			else:
				print request, rec_type, answer.rrset.ttl, record
	except:
		pass	
		
#Check against word list for existing hosts (IPv6 - AAAA records)
def host_dump_v6(dom):
	rec_type = 'AAAA'	
	wc_address=wildcard_check(dom,rec_type)
	print "\nDumping IPv6 Hosts (A)\n"		

	try:
		for i in bruteHostNames:
			proc = Process(target=host_dump_resolver,args=(dom,i,wc_address,rec_type))
			proc.start()
	except:
		print "\n----IPv6 Record unavailable----\n"
		
#Check for alias (CNAME) records
def cname_dump(dom):
	rec_type = 'CNAME'
	wc_address=wildcard_check(dom,'A')

	print "\nDumping Aliases (CNAME)\n"
	try:
		for i in bruteHostNames:
			proc = Process(target=host_dump_resolver,args=(dom,i,wc_address,rec_type))
			proc.start()

	except:
		print "Alias Records unavailable\n"
		
		print "---------------"

#Check for Mail (MX) records
def mail_dump(dom):
	try:
		print "\nDumping Mail Records (MX)\n"
		for record in query(dom, 'MX'):
			print dom, 'MX', record.preference, record.exchange
		
		print "---------------"
	
	except:
		print "Mail Records unavailable\n"
		
		print "---------------"
	
#Check for service SRV records
def service_dump(dom):
	try:
		print "\nDumping Service Records (SRV)\n"
		for record in query(dom,'SRV'):
			print dom, 'SRV', request.target, request.port, request.priority
		
		print "---------------"
	except:
		print "Service Records unavailable\n"
	
		print "---------------"

#Reverse dump - look for PTR records
def ptr_dump(ip):	
	try:
		ptr_addr = reversename.from_address(ip)
		ans= str(resolver.query(ptr_addr,"PTR")[0])
		if ans:
			print ip+"\t"+ans
	except:
		pass

#Attempt zone transfer of domain: dom on host: remote_host
def zone_xfer(dom,remote_host):
	try:
		result_set = dns.zone.from_xfr(dns.query.xfr(remote_host,dom))
		responses = result_set.nodes.keys()
		responses.sort()
		for i in responses:
			try:
				print result_set[i].to_text(i)
			except:
				pass #If a zone file has bad records ignore it and move on
	except:
		print "Zone Transfer Unavailable from host "+remote_host


#PTR Record Support - Brute Force
def ptr_usage():
	print """\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\nWhen brute forcing a set of PTR records, use the following format:
IPADDRESS/SUBNET
As in:  192.168.1.0/24

Invalid addresses and subnet masks will not be accepted\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"""

#Display some messages if the format is not IP/Subnet
def _ip_block_validate(ipblock):
	try:
		block_one = ipblock.split(".")[0]
        	block_two = ipblock.split(".")[1]
        	block_three = ipblock.split(".")[2]
        	block_four = ipblock.split(".")[3].split("/")[0]
        	subnet = ipblock.split("/")[1]
		if int(block_one) > 255 or int(block_one) < 0:
			print "\nOctet ONE is out of range [0-255]\n"
			exit()
		if int(block_two) > 255 or int(block_two) < 0:
			print "\nOctet TWO is out of range [0-255]\n"
			exit()
		if int(block_three) > 255 or int(block_three) < 0:
			print "\nOctet THREE is out of range [0-255]\n"
			exit()
		if int(block_four) > 255 or int(block_four) < 0:
			print "\nOctet FOUR is out of range [0-255]\n"
			exit()
		if int(subnet) > 32 or int(subnet) < 0:
			print "\nSubnet is out of range [0-32]\n"
			exit()
		else:
			pass
	except:
		usage()
		ptr_usage()
		exit()

#Steps to convert and brute force
def ptr_driver(ipblock):
	#Split the IP/Subnet into 4 octets, 1 slash format subnet
	_ip_block_validate(ipblock)
	block_one = ipblock.split(".")[0]
	block_two = ipblock.split(".")[1]
	block_three = ipblock.split(".")[2]
	block_four = ipblock.split(".")[3].split("/")[0]
	subnet = ipblock.split("/")[1]

	#Put the blocks in order and calculate the hosts and legitimate subnet mask
	one = int(subnet)
	two = one-8
	three = two - 8
	four = three - 8
	block = str(verify_enum_block(one,two,three,four))
	
	#Begin enumeration
	enumerate_block(block_one,block_two,block_three,block_four,block)

#Keep all subnets at 8 bits or less - they are evaluated per octet
def filter_num(num):

        if num > 8:
                num = 8
        return num

#Convert slash format to decimal
def check(num):
        num=filter_num(num)
        if num == 8:
                return 255
        elif num == 7:
                return 254
        elif num == 6:
                return 252
        elif num == 5:
                return 248
        elif num == 4:
                return 240
        elif num == 3:
                return 224
        elif num == 2:
                return 192
        elif num == 1:
                return 128
        elif num == 0:
                return 0
        else:
		return 0

#Get accurate number of hosts in given subnet
def get_hosts(num):
        a = 256/(2**abs(num))
        return a

#Enumerate octets one,two,three,four
def enum_block_one(block_one,block_two,block_three,block_four,host_val):
                ref_point = 0
                while int(block_two) < int(host_val):
                        result= str(str(block_one)+"."+str(block_two)+"."+str(block_three)+"."+str(block_four))
                        ptr_dump(result)
                        enum_block_two(block_one,block_two,block_three,block_four,256)
                        ref_point=ref_point+1
                        block_one=int(block_one)+1
def enum_block_two(block_one,block_two,block_three,block_four,host_val):
                ref_point = 0
                while int(block_two) < int(host_val):
                        result= str(str(block_one)+"."+str(block_two)+"."+str(block_three)+"."+str(block_four))
                        ptr_dump(result)
                        enum_block_three(block_one,block_two,block_three,block_four,256)
                        ref_point=ref_point+1
                        block_two=int(block_two)+1
def enum_block_three(block_one,block_two,block_three,block_four,host_val):
                ref_point = 0
                while int(block_three) < int(host_val):
                        result= str(str(block_one)+"."+str(block_two)+"."+str(block_three)+"."+str(block_four))
                        ptr_dump(result)
                        enum_block_four(block_one,block_two,block_three,block_four,256)
                        ref_point=ref_point+1
                        block_three=int(block_three)+1

def enum_block_four(block_one,block_two,block_three,block_four,host_val):
                ref_point = 0
                while (ref_point+int(block_four)) < int(host_val):
                        result= str(str(block_one)+"."+str(block_two)+"."+str(block_three)+"."+str(int(block_four)+ref_point))
                        ptr_dump(result)
                        ref_point=ref_point+1

#Perform enumeration based on subnet
def enumerate_block(block_one,block_two,block_three,block_four,block):
        block_num=block.split(":")[0]
        host_val=block.split(":")[1]
        if block_num == "1":
                enum_block_one(block_one,block_two,block_three,block_four,host_val)
        elif block_num =="2":
                enum_block_two(block_one,block_two,block_three,block_four,host_val)
        elif block_num =="3":
                enum_block_three(block_one,block_two,block_three,block_four,host_val)
        elif block_num =="4":
                enum_block_four(block_one,block_two,block_three,block_four,host_val)
        else:
                pass

#Test to see what the largest subnet is which will be enumerated
def verify_enum_block(one,two,three,four):
        one=get_hosts((filter_num(one)))
        two=get_hosts((filter_num(two)))
        three=get_hosts((filter_num(three)))
        four=get_hosts((filter_num(four)))
        if one > 1:
                return ("1:"+str(one))
        elif two > 1:
                return ("2:"+str(two))
        elif three > 1:
                return ("3:"+str(three))
        elif four > 1:
                return ("4:"+str(four))
        else:
                return ("0:"+str(none))


#Main
if __name__ == '__main__':
	_main(sys.argv[1:])

