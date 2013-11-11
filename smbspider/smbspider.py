#!/usr/bin/python
#
import os
import argparse
from netaddr import *
from nmb.NetBIOS import NetBIOS
from smb.SMBConnection import SMBConnection
__author__ = 'T$A'

def get_ips(iparg):
   ips = []
   try:
      if os.path.isfile(iparg):
         f = open(iparg,'r')
         for line in f:
            line = line.rstrip()
            if '/' in line:
               for ip in IPNetwork(line).iter_hosts():
                  ips.append(str(ip))
            else:
               ips.append(line)
         f.close()
         return ips
      if '/' in iparg:
         for ip in IPNetwork(iparg).iter_hosts():
            ips.append(str(ip))
      else:
         ips.append(str(IPAddress(iparg)))
   except:
      print ("Error reading file or IP Address notation: %s" % iparg)
      exit()
   return ips

def recurse(smb_conn,ip,share,subfolder,patt,depth):
   try:
      filelist = smb_conn.listPath(share, subfolder)
      dir_list(filelist,ip,subfolder,patt)
      if depth == 0:
         return 0
   except:
      print ("//%s/%s [Unable to read]" % (ip, subfolder))
      return 1

   for result in filelist:
      if result.isDirectory and result.filename != '.' and result.filename != '..':
         recurse(smb_conn,ip,share,subfolder+'/'+result.filename,patt,depth-1)
   return 0

def dir_list(files,ip,path,pattern):
   for result in files:
      for instance in pattern:
         if instance in result.filename:
            if result.isDirectory:
               print ("//%s/%s/%s [dir]" % (ip,path,result.filename))
            else:
	       print ("//%s/%s/%s" % (ip,path,result.filename))
   return 0

def spider_host(ip,share,subfolder,user,pwd,domain,recursive,pattern):
   net = NetBIOS()
   net_name = str(net.queryIPForName(ip)).strip("['").strip("']")
   net.close()

   conn = SMBConnection(user, pwd, 'cobwebs', net_name, domain=domain, use_ntlm_v2 = False)
   if conn.connect(ip, port=139, timeout=5):
      print ("Connecting to %s was a success! How about a nice game of spidering %s%s?" % (ip, share, subfolder))
   else:
      print ("Connection error: %s" % (ip))
      return 1
   if recursive > 0:
      recurse(conn,ip,share,subfolder,pattern,int(recursive))    
   else:
      filelist = conn.listPath(share, subfolder)
      dir_list(filelist,ip, subfolder, pattern)
   conn.close()

def spider_ips(queue,ip,share,subfolder,user,pwd,domain,recursive,pattern):
   while True:
      if ipQueue.empty():
         return 0
      ip = queue.get()
      spider_host(ip,share,subfolder,user,pwd,domain,recursive,pattern)
   return 0

# parse the arguments
parser = argparse.ArgumentParser(description='SMB Spider will search shares. It is best used to search SMB shares for sensitive files, i.e., passwords.xls')
parser.add_argument('-ip','--ipaddress', help='IP Address, IP/CIDR, IP Address File',required=True)
parser.add_argument('-s','--share',help='SMB share to spider', required=True)
parser.add_argument('-f','--subfolder',help='SMB subfolder to spider', default='/', required=False)
parser.add_argument('-pa','--pattern',help='Keyword to search for, i.e., password', default='', required=False)
parser.add_argument('-pf','--patternfile',help='File of keywords to search for, i.e., password', default='', required=False)
parser.add_argument('-u','--user',help='SMB user to connect with', default='', required=False)
parser.add_argument('-p','--pwd',help='SMB password to connect with', default='', required=False)
parser.add_argument('-d','--domain',help='SMB domain to connect with', default='', required=False)
parser.add_argument('-r','--recursive',help='Spider subfolders. Set value for depth.', default=0, required=False)
args = parser.parse_args()

# get the list of ips
ips = get_ips(args.ipaddress)

# create pattern list from supplied args
pattern = []
if args.patternfile != '':
   try:
      f = open(args.patternfile,'r')
      for line in f:
         line = line.rstrip()
         pattern.append(line)
      f.close()
      if args.pattern != '':
         pattern.append(args.pattern)
   except:
      print ("Error reading pattern file: %s" % args.patternfile)
else:
   pattern.append(args.pattern)

for ip in ips:
   spider_host(ip,args.share,args.subfolder,args.user,args.pwd,args.domain,args.recursive,pattern)

print ("Done spidering...")
