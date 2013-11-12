#!/usr/bin/python
# SMB Spider
# Created by T$A
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import time
import Queue
import threading
import argparse
from netaddr import *
from nmb.NetBIOS import NetBIOS
from smb.SMBConnection import SMBConnection

class scan_thread (threading.Thread):
   def __init__(self,ip,share,subfolder,user,pwd,domain,recursive,pattern):
       threading.Thread.__init__(self)
       self.ip = ip
       self.share = share
       self.subfolder = subfolder
       self.user = user
       self.pwd = pwd
       self.domain = domain
       self.recursive = recursive
       self.pattern = pattern
   
   def run(self):
      print "Starting thread for " + self.ip
      net = NetBIOS()
      net_name = str(net.queryIPForName(self.ip)).strip("['").strip("']")
      net.close()
      conn = SMBConnection(self.user, self.pwd, 'cobwebs', net_name, domain=self.domain, use_ntlm_v2 = False)
      if conn.connect(self.ip, port=139, timeout=10):
         print ("Connecting to %s was successful! How about a nice game of spidering %s%s?" % (self.ip, self.share, self.subfolder))
      else:
         print ("Connection error: %s" % (self.ip))
      if self.recursive > 0:
         recurse(conn,self.ip,self.share,self.subfolder,self.pattern,int(self.recursive))    
      else:
         filelist = conn.listPath(self.share, self.subfolder)
         dir_list(filelist,self.ip,self.subfolder,self.pattern)
      conn.close()
      print "Exiting thread for " + self.ip

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
      print ("//%s/%s [Unable to read]" % (ip, subfolder.replace("//","")))
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
               print ("//%s/%s/%s [dir]" % (ip,path.replace("//",""),result.filename))
            else:
               print ("//%s/%s/%s" % (ip,path.replace("//",""),result.filename))
   return 0

banner = " ____________________________________________"
banner += "\n |\'-._(   /                                 |"
banner += "\n | \  .'-._\                           ,   ,|"
banner += "\n |-.\'    .-;                         .'\`-' |"
banner += "\n |   \  .' (                      _.'   \   |"
banner += "\n |.--.\'   _)                   ;-;       \._|"
banner += "\n |    ` _\(_)/_                 \ `'-,_,-'\ |"
banner += "\n |______ /(O)\  ________________/____)_`-._\|"
banner += "\n\n SMB Spider v0.2beta, Authors: T$A"
banner += "\n"
print (banner)

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
parser.add_argument('-t','--threads',help='Number of threads', default=1, required=False)
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
   #create a thread
   thread = scan_thread(ip,args.share,args.subfolder,args.user,args.pwd,args.domain,args.recursive,pattern)
   thread.start()
   
   #make sure threads do not exceed the threshold set by the -t arg
   while threading.activeCount() > int(args.threads):
      time.sleep(0.01)

#make sure all spidering threads are dead before closing primary thread   
while threading.activeCount() > 1:
    time.sleep(0.01)

print ("Done spidering...")