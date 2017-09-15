#!/usr/bin/python
# Author: Hans Lakhan
#######################
# Requirements:
#	boto:		pip install -U boto
#
#######################
# To Do
#	1) Add support for config?
#	2) Change os.system() to subproccess.Popen to manage STDOUT, STDERR better
#	3) add support for re-establishing tunnels
#	4) Add support for connecting to other clusters
#	5) Trim Log Output Time
#	6) Cleanup Try/Catch statments
#
#######################
import boto.ec2
import os
import argparse
import time
import sys
import subprocess
import fcntl
import struct
import socket
import hashlib
import signal
import datetime
import re
from subprocess import Popen, PIPE, STDOUT

#############################################################################################
# Handle Colored Output
#############################################################################################

class bcolors:
  HEADER = '\033[95m'
  OKBLUE = '\033[94m'
  OKGREEN = '\033[92m'
  WARNING = '\033[93m'
  FAIL = '\033[91m'
  ENDC = '\033[0m'
  BOLD = '\033[1m'
  UNDERLINE = '\033[4m'

def error(msg):
  print "[" + bcolors.FAIL + "!" + bcolors.ENDC + "] " + msg
def success(msg):
  print "[" + bcolors.OKGREEN + "*" + bcolors.ENDC + "] " + msg 
def warning(msg):
  print "[" + bcolors.WARNING + "~" + bcolors.ENDC + "] " + msg
def debug(msg):
  if args.v:
    timestamp = datetime.datetime.now()
    print "[i] " + str(timestamp) + " : " + msg

#############################################################################################
# Handle Logging
#############################################################################################

def log(msg):
  timestamp = datetime.datetime.now()
  logfile = open("/tmp/" + logName, 'a')
  logfile.write(str(timestamp))
  logfile.write(" : " + str(msg))
  logfile.write("\n")
  logfile.close()

#############################################################################################
# Handle SigTerm & Clean up
#############################################################################################
def cleanup(signal, frame):
  # Time to clean up
  print "\n"
  success("Roger that! Shutting down...")

  if args.v:
    print 'In debug mode. Press enter to continue.'
    null = raw_input()

  # Connect to EC2 and return list of reservations
  try:
    success("Connecting to Amazon's EC2...")
    cleanup_conn = boto.ec2.connect_to_region(region_name=args.region, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
  except Exception as e:
    error("Failed to connect to Amazon EC2 because: %s" % e)

  # Cleaning routes
  success("Correcting Routes.....")
  debug("SHELL CMD: ip route del " + str(args.target) + " tun0")
  os.system("ip route del %s dev tun0" % str(args.target))

  cleanup_reservations_mgmt = cleanup_conn.get_all_instances(filters={"tag:Name" : nameTag + '_mgmt', "instance-state-name" : "running"})

  # Terminate instance
  success("Terminating Instances.....")
  for reservation in cleanup_reservations_mgmt:
    for instance in reservation.instances:
      instance.terminate()

  cleanup_reservations_node = cleanup_conn.get_all_instances(filters={"tag:Name" : nameTag + '_node', "instance-state-name" : "running"})

  for reservation in cleanup_reservations_node:
    for instance in reservation.instances:
      instance.terminate()

  warning("Pausing so instances can properly terminate.....")
  time.sleep(120)

  # Remove Security Groups
  success("Deleting Amazon Security Groups.....")
  try:
    cleanup_conn.delete_security_group(name=securityGroup)
  except Exception as e:
    error("Deletion of security group failed because %s" % e)

  # Remove Key Pairs
  success("Removing SSH keys.....")
  try:
    cleanup_conn.delete_key_pair(key_name=keyName)
  except Exception as e:
    error("Deletion of key pair failed because %s" % e)

  # Remove local ssh key
  debug("SHELL CMD: rm -f " + homeDir + "/.ssh/" + keyName + ".pem")
  subprocess.Popen("rm -f %s/.ssh/%s.pem" % (homeDir, keyName), shell=True)

  # Remove local routing
  success("Restoring local routing....")
  debug("SHELL CMD: echo 0 > /proc/sys/net/ipv4/ip_forward")
  os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

  # Kill screen session
  success('Terminating OpenVPN')
  os.system('screen -S PC -X quit')
  os.system('killall openvpn')

  # Remove /tmp/nameTag
  success('Removing tmp files')
  os.system('rm -rf /tmp/' + nameTag)

  # Log then close
  log("ProxyCannon Finished.")

  success("Done!")
	
  sys.exit(0)

#############################################################################################
# Rotate Hosts 
#############################################################################################

def rotate_hosts():

  while True:	# could be changed to calling rotate_hosts() at the end
    
    # Establish Connection
    retry_cnt = 0
    while retry_cnt < 6:
      if retry_cnt == 5:
        error("giving up...")
        cleanup("foo", "bar")
      try:
        debug("Connecting to Amazon's EC2.")
        rotate_conn = boto.ec2.connect_to_region(region_name=args.region, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
        retry_cnt = 6
      except Exception as e:
        warning("Failed to connect to Amazon EC2 because: %s. Retrying..." % e)
        retry_cnt = retry_cnt + 1
        time.sleep(+int(retry_cnt))

    # Managment Instances
    retry_cnt = 0
    while retry_cnt < 6:
      if retry_cnt == 5:
        error("giving up...")
        cleanup("foo", "bar")
      try:
        reservation_mgmt = rotate_conn.get_all_instances(filters={"tag:Name" : nameTag + '_mgmt', "instance-state-name" : "running"})
        retry_cnt = 6
      except Exception as e:
        warning("Failed to connect to Amazon EC2 because: %s (rotate_reservations). Retrying..." % e)
        retry_cnt = retry_cnt + 1
        time.sleep(+int(retry_cnt))

    for reservation in reservation_mgmt:
      for instance in reservation.instances:
        mgmt_ip = str(instance.ip_address)
    debug('Public IP for management: ' + mgmt_ip)
 
    # Nodes Instances
    retry_cnt = 0
    while retry_cnt < 6:
      if retry_cnt == 5:
        error("giving up...")
        cleanup("foo", "bar")
      try:
        reservation_nodes = rotate_conn.get_all_instances(filters={"tag:Name" : nameTag + '_node', "instance-state-name" : "running"})
        retry_cnt = 6
      except Exception as e:
        warning("Failed to connect to Amazon EC2 because: %s (rotate_reservations). Retrying..." % e)
        retry_cnt = retry_cnt + 1
        time.sleep(+int(retry_cnt))

    # For each node
    allInstances_public = []
    allInstances_private = []
    for nodes in reservation_nodes:

      # For creating internal route table
      for instance in nodes.instances:
        if instance.ip_address not in allInstances_public:
          if (instance.ip_address):
            allInstances_public.append(str(instance.ip_address))
        if instance.private_ip_address not in allInstances_private:
          if (instance.private_ip_address):
            allInstances_private.append(str(instance.private_ip_address))

      debug('Public IP\'s for all nodes: ' + str(allInstances_public))
      debug('Private IP\'s for all nodes: ' + str(allInstances_private))

      for instance in nodes.instances:
        debug('Rotating: ' + str(instance.ip_address) + ' (' +  str(instance.private_ip_address) + ')')

        # Build new route table ommiting our chosen node for rotation
        debug('Building Route table for mgmt')
        nexthopcmd = 'ip route replace ' + str(args.target) + ' scope global '
        weight = 1

        for private_ip_address in allInstances_private:
          if str(private_ip_address) != str(instance.private_ip_address):
            nexthopcmd = nexthopcmd + 'nexthop via ' + str(private_ip_address) + ' dev eth0 weight ' + str(weight) + ' '
        debug('nexthopcmd: ' + nexthopcmd)
        remote_ssh('root', mgmt_ip, nexthopcmd)    

        # With new route command in place we can monitor for sessions
        while True:

          # Check to see if we have any incoming/outgoing packets on this node for our target it should be 0
          # We wait 10 seconds, but this will not catch half open connections or stale connections. Not sure
          # of a better way to check for state, before we used to use netstat, however, nodes wont be proxying
          # the connection, there wont be a netstat entry
          cmd = 'timeout 10 tcpdump -i eth0 -w /tmp/foo net ' + str(args.target) + '&'
          remote_ssh('root', instance.ip_address, cmd)

          time.sleep(11)

          # Pull down the file so we can check the file size
          remote_scp('root', instance.ip_address, '/tmp/foo', '/tmp/' + keyName + '/foo')

          # Remove the remote old file
          cmd = 'rm -rf /tmp/foo'
          remote_ssh('root', instance.ip_address, cmd)
          
          # Check the size of the file
          statinfo = os.stat('/tmp/' + keyName + '/foo')
          if (int(statinfo.st_size) > 24):
            debug("Connection is in use, sleeping and trying again in .5 seconds")
            time.sleep(.5)
          else:
            debug("Connection is free")
            debug('file size: ' + str(statinfo.st_size))
            break

        # Looks like we're clear to reset the IP's
        # Requesting new IP allocation
        old_address = str(instance.ip_address)
        try:
          new_address = rotate_conn.allocate_address()
        except Exception as e:
          error("Failed to obtain a new address because: " + str(e))
          cleanup("foo", "bar")
        debug("Temporary Elastic IP address: " + new_address.public_ip)

        time.sleep(5)
        # Associating new address
        rotate_conn.associate_address(instance.id, new_address.public_ip)

        ## At this point, your VM should respond on its public ip address. NOTE: It may take up to 30 seconds for the Elastic IP address to begin working
        debug("Sleeping for 15s to allow for new IP to take effect")
        time.sleep(15)

        # Remove assocation forcing a new public ip
        try:
          rotate_conn.disassociate_address(new_address.public_ip)
        except Exception as e:
          error("Failed to dissassociate the address " + str(new_address.public_ip) + " because: " + str(e))
          cleanup("foo", "bar")
        debug("Sleeping for 30s to allow for new IP to take effect")
        time.sleep(30)

        # Return the Second Elastic IP address back to address pool
        try:
          rotate_conn.release_address(allocation_id=new_address.allocation_id)
        except Exception as e:
          error("Failed to release the address " + str(new_address.public_ip) + " because: " + str(e))
          cleanup("foo", "bar")

	# Rebuild our route table for mgmt adding back in our previous private ip
        debug('Building Route table for mgmt')
        nexthopcmd = 'ip route replace ' + str(args.target) + ' scope global '
        weight = 1

        for private_ip_address in allInstances_private:
          nexthopcmd = nexthopcmd + 'nexthop via ' + str(private_ip_address) + ' dev eth0 weight ' + str(weight) + ' '
        debug('nexthopcmd: ' + nexthopcmd)
        remote_ssh('root', mgmt_ip, nexthopcmd)
   
	# Update instance information
	instance.update()
 
	# Note new_address.public_ip does not reflect the new address of the node, we need to requery for all nodes and find the diff 
        success("Replaced " + old_address + " with " + str(instance.ip_address) )
        log(str(new_address.public_ip))


#############################################################################################
# System and Program Arguments
#############################################################################################

parser = argparse.ArgumentParser()
parser.add_argument('-id', '--image-id', nargs='?', default='ami-d05e75b8', help="Amazon ami image ID.  Example: ami-d05e75b8. If not set, ami-d05e75b8.")
parser.add_argument('-t', '--image-type', nargs='?', default='t2.nano', help="Amazon ami image type Example: t2.nano. If not set, defaults to t2.nano.")
parser.add_argument('--region', nargs='?', default='us-east-1', help="Select the region: Example: us-east-1. If not set, defaults to us-east-1.")
parser.add_argument('-r', action='store_true', help="Enable Rotating AMI hosts.")
parser.add_argument('-v', action='store_true', help="Enable verbose logging. All cmd's should be printed to stdout")
parser.add_argument('num_of_instances', type=int, help="The number of amazon instances you'd like to launch.")
parser.add_argument('--name', nargs="?", help="Set the name of the instance in the cluster")
parser.add_argument('-i', '--interface', nargs='?', default='eth0', help="Interface to use, default is eth0")
parser.add_argument('-l', '--log', action='store_true', help="Enable logging of WAN IP's traffic is routed through. Output is to /tmp/")
parser.add_argument('--target', nargs='?', help="IP of target. Can be single IP or network (CIDR). Default is 0.0.0.0")
args = parser.parse_args()

# system variables;
homeDir = os.getenv("HOME")
FNULL = open(os.devnull, 'w')
debug("Homedir: " + homeDir)
address_to_tunnel = {}

# Check for boto config
boto_config = homeDir + "/.boto"
if os.path.isfile(boto_config):
  for line in open(boto_config):
    pattern = re.findall("^aws_access_key_id = (.*)\n", line, re.DOTALL)		
    if pattern:
      aws_access_key_id = pattern[0]	
    pattern = re.findall("^aws_secret_access_key = (.*)\n", line, re.DOTALL)
    if pattern:
      aws_secret_access_key = pattern[0]
else:
  debug("boto config file does not exist")
  aws_access_key_id = raw_input("What is the AWS Access Key Id: ")
  aws_secret_access_key = raw_input("What is the AWS Secret Access Key: ")

  boto_fh = open(boto_config, 'w+')
  boto_fh.write('[default]')
  boto_fh.write("\n")
  boto_fh.write('aws_access_key_id = ')
  boto_fh.write(aws_access_key_id)
  boto_fh.write("\n")
  boto_fh.write('aws_secret_access_key = ')
  boto_fh.write(aws_secret_access_key)
  boto_fh.write("\n")
  boto_fh.close

debug("AWS_ACCESS_KEY_ID: " + aws_access_key_id)
debug("AWS_SECRET_ACCESS_KEY: " + aws_secret_access_key)

# Generate sshkeyname
if args.name:

  # SSH Key Name
  keyName = "PC_" + args.name

  # AMI Security Group Name
  securityGroup = "PC_" + args.name

  # AMI Tag Name
  nameTag = "PC_" + args.name

  # iptables Name 
  iptablesName = "PC_" + args.name

  # log name
  logName = "PC_"  + args.name + ".log"

else:
  pid = os.getpid()
  stamp = time.time()
  m = hashlib.md5()
  tempstring = str(pid + stamp)
  m.update(tempstring)
	
  # SSH key Name
  keyName = "PC_" + m.hexdigest()

  # AMI Security Group Name
  securityGroup = "PC_" + m.hexdigest()

  # AMI Tag Name
  nameTag = "PC_" + m.hexdigest()

  # iptables Name
  iptablesName = "PC_" + m.hexdigest()

  # Log Name
  logName = "PC_" + m.hexdigest() + ".log"

# Get Interface IP
def get_ip_address(ifname):
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  return socket.inet_ntoa(fcntl.ioctl(
    s.fileno(),
    0x8915,  # SIOCGIFADDR
    struct.pack('256s', ifname[:15])
  )[20:24])

# Get Default Route
def get_default_gateway_linux():
  # Read the default gateway directly from /proc.
  with open("/proc/net/route") as fh:
    for line in fh:
      fields = line.strip().split()
      if fields[1] != '00000000' or not int(fields[3], 16) & 2:
        continue

      return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))

localIP = get_ip_address(args.interface)
debug("Local Interface IP for " + args.interface + ": " + localIP)

defaultgateway = get_default_gateway_linux()
debug("IP address of default gateway: " + str(defaultgateway))

debug("Opening logfile: /tmp/" + logName)
log("Proxy Cannon Started.")

# Define SigTerm Handler
signal.signal(signal.SIGINT, cleanup)

#############################################################################################
# Sanity Checks
#############################################################################################

# Check if running as root
if os.geteuid() != 0:
  error("You need to have root privileges to run this script.")
  exit()

# Check for OpenVPN
openvpn_path = subprocess.Popen(['which', 'openvpn'], stdout=subprocess.PIPE).communicate()[0]
if 'openvpn' not in openvpn_path:
  error('openvpn is not installed.')
  error('apt-get install openvpn')
  exit()

# Check args
if args.num_of_instances < 1:
  error("You need at least 1 instance")
  exit()
elif args.num_of_instances > 20:
  warning("Woah there stallion, that's alot of instances, hope you got that sweet license from Amazon.")

if not args.target:
  error('You must specify a target. -T 1.2.3.4/32')
  exit()
elif args.target == '0.0.0.0' or args.target == '0.0.0.0/0':
  error('You can not, and should not set your default traffic to go through this connection.')
  exit()

#############################################################################################
# Remote SSH CMD
#############################################################################################
def remote_ssh(user, ip, cmd):
  debug("Running Remote SSH Command")
  retry_cnt = 0
  retcode = 0
  sshcmd = "ssh -i %s/.ssh/%s.pem -o StrictHostKeyChecking=no %s@%s '%s'" % (homeDir, keyName, user, ip, cmd)

  debug("SSH CMD: " + sshcmd)
  while ((retcode == 1) or (retry_cnt < 6)):
    retcode = subprocess.call(sshcmd, shell=True, stdout=FNULL, stderr=subprocess.STDOUT)
    if retcode:
      warning("Failed to execute SSH command on %s. Retrying..." % ip)
      retry_cnt = retry_cnt + 1
      time.sleep(1)
    else:
      retry_cnt = 6 # probably a better way to do this
    if retry_cnt == 5:
      error("Giving up")
      cleanup("foo", "bar")

#############################################################################################
# Remote SCP CMD
#############################################################################################
def remote_scp(user, ip, src, dst):
  debug("Running Remote SCP Command")
  retry_cnt = 0
  retcode = 0
  sshcmd = "scp -i %s/.ssh/%s.pem -o StrictHostKeyChecking=no %s@%s:'%s' %s" % (homeDir, keyName, user, ip, src, dst)

  debug("SCP CMD: " + sshcmd)
  while ((retcode == 1) or (retry_cnt < 6)):
    retcode = subprocess.call(sshcmd, shell=True, stdout=FNULL, stderr=subprocess.STDOUT)
    if retcode:
      warning("Failed to execute SCP command on %s. Retrying..." % ip)
      retry_cnt = retry_cnt + 1
      time.sleep(1)
    else:
      retry_cnt = 6 # probably a better way to do this
    if retry_cnt == 5:
      error("Giving up")
      cleanup("foo", "bar")

#############################################################################################
# System and Program Arguments
#############################################################################################

# Initialize connection to EC2
success("Connecting to Amazon's EC2...")
try:
  conn = boto.ec2.connect_to_region(region_name=args.region, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
except Exception as e:
  error("Failed to connect to Amazon EC2 because: %s" % e)
  exit()

# Generate KeyPair
success("Generating ssh keypairs...")
keypair = conn.create_key_pair(keyName)
keypair.save("%s/.ssh" % homeDir)
debug("SSH Key Pair Name " + keyName)
time.sleep(5)
success("Generating Amazon Security Group...")
try:
  sg = conn.create_security_group(name=securityGroup, description="Used for proxyCannon")
except Exception as e:
  error("Generating Amazon Security Group failed because: %s" % e)
  exit()

time.sleep(5)

try:
  sg.authorize(ip_protocol='tcp', from_port=22, to_port=22, cidr_ip='0.0.0.0/0')
  sg.authorize(ip_protocol='tcp', from_port=443, to_port=443, cidr_ip='0.0.0.0/0')
  sg.authorize(ip_protocol='-1', from_port=None, to_port=None, src_group=sg)
except Exception as e:
  error("Generating Amazon Security Group failed because: %s" % e)
  exit()

debug('Security Group Name: ' + securityGroup)

# Launch Amazon Instances

#if args.num_of_instances < 3:
#  controller_instance = 't2.nano'
#if args.num_of_instances > 2 and args.num_of_instances < 15:
#  controller_instance = 't2.xlarge'
#if args.num_of_instances > 14 and args.num_of_instances < 30:
#  controller_instance = 'm4.4xlarge'
#if args.num_of_instances > 29:
#  error('To many nodes, try to keep it under 30')
#  cleanup('foo', 'bar')

# Start controller
try:
  res_mgmt = conn.run_instances(args.image_id, key_name=keyName, min_count='1', max_count='1', instance_type=args.image_type, security_groups=[securityGroup])
except Exception as e:
  error("Failed to start new instance: %s" % e)
  cleanup('null', 'null')

# Get subnet_id
for instance_mgmt in res_mgmt.instances:
  debug('SUBNET_ID: ' + instance_mgmt.subnet_id)

# Start Nodes
try:
  res_nodes = conn.run_instances(args.image_id, key_name=keyName, min_count=args.num_of_instances, subnet_id=instance_mgmt.subnet_id, max_count=args.num_of_instances, instance_type=args.image_type)
except Exception as e:
  error("Failed to start new instance: %s" % e)
  cleanup("null", "null")
warning("Starting %s instances, please give about 4 minutes for them to fully boot" % args.num_of_instances)

#sleep for 4 minutes while booting images
for i in range(21):
  sys.stdout.write('\r')
  sys.stdout.write("[%-20s] %d%%" % ('='*i, 5*i))
  sys.stdout.flush()
  time.sleep(11.5)
print "\n"

# Add tag name to instance for better management
# Controller
for instance in res_mgmt.instances:
  instance.add_tag('Name', nameTag + '_mgmt')

# Get groupid
rs = conn.get_all_security_groups(groupnames=[securityGroup])
sg = rs[0]

# Nodes
for instance in res_nodes.instances:
  instance.add_tag("Name", nameTag + '_node')
  conn.modify_instance_attribute(instance.id, attribute='sourceDestCheck', value=False)
  # Assign Security Group
  conn.modify_instance_attribute(instance.id, attribute='groupSet', value=[sg.id])


# Controller
res_mgmt = conn.get_all_instances(filters={'tag:Name' : nameTag + '_mgmt', 'instance-state-name' : 'running'})
for reservation in res_mgmt:
  for instance in reservation.instances:
   interfaces = conn.get_all_network_interfaces(filters={'attachment.instance-id' : instance.id})
   mgmt_ip = str(instance.ip_address)
debug('Public IP for management: ' + mgmt_ip)

#try:
#  res_mgmt = conn.assign_private_ip_addresses(network_interface_id=interfaces[0].id, secondary_private_ip_address_count='3', allow_reassignment=True)
#except Exception as e:
#  error("Failed to request multiple internal addresses on mgmt server: %s" %e)
#  cleanup('null', 'null')

# Nodes
allInstances_public = []
allInstances_private = []
res_nodes = conn.get_all_instances(filters={"tag:Name" : nameTag + '_node', 'instance-state-name' : 'running'})
for reservation in res_nodes:
  for instance in reservation.instances:
    if instance.ip_address not in allInstances_public:
      if (instance.ip_address):
        allInstances_public.append(str(instance.ip_address))
    if instance.private_ip_address not in allInstances_private:
      if (instance.private_ip_address):
        allInstances_private.append(str(instance.private_ip_address))
debug('Public IP\'s for all nodes: ' + str(allInstances_public))
debug('Private IP\'s for all nodes: ' + str(allInstances_private))


#############################################################################################
# Provision Managment Server
#############################################################################################
success('Provisioning managment server.')

# Permit Root Logon
debug('Enabling Root Logon on mgmt server: ' + mgmt_ip)
cmd = "sudo sed -i \"s/PermitRootLogin without-password/PermitRootLogin yes/\" /etc/ssh/sshd_config"
remote_ssh('ubuntu', mgmt_ip, cmd)

# Copy Keys 
debug('Updating SSH Keys on mgmt server: ' + mgmt_ip)
cmd = "sudo cp /home/ubuntu/.ssh/authorized_keys /root/.ssh/"
remote_ssh('ubuntu', mgmt_ip, cmd)

# Restarting Service to take new config (you'd think a simple reload would be enough)
debug('Restarting SSH service on mgmt server: ' + mgmt_ip)
cmd = 'sudo service ssh restart'
remote_ssh('ubuntu', mgmt_ip, cmd)

# Install dependencies
debug('Installing dependencies on mgmt server: ' + mgmt_ip)
cmd = 'apt-get update; apt-get install openvpn easy-rsa -y'
remote_ssh('root', mgmt_ip, cmd)

# Configure OpenVPN
# We could modify VARS but is it needed?
debug('Configuring OpenVPN on mgmt server: ' + mgmt_ip)
cmd = 'make-cadir ~/openvpn-ca; cd ~/openvpn-ca; source vars; ./clean-all; ./build-ca --batch; ./build-key-server --batch server; ./build-dh; openvpn --genkey --secret keys/ta.key; cd keys; cp ca.crt ca.key server.crt server.key ta.key dh2048.pem /etc/openvpn; openssl dhparam -out /etc/openvpn/dh1024.pem 1024; gunzip -c /usr/share/doc/openvpn/examples/sample-config-files/server.conf.gz | sudo tee /etc/openvpn/server.conf'
remote_ssh('root', mgmt_ip, cmd)

# Setting up remote iptables
debug('Configuring iptables on mgmt Server: ' + mgmt_ip)
cmd = 'iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE'
remote_ssh('root', mgmt_ip, cmd)

# Modifying openvpn config
debug('Modifying OpenVPN config: ' + mgmt_ip)
cmd = "sed -i \"s/;tls-auth ta.key 0/tls-auth ta.key 0\\nkey-direction 0/\" /etc/openvpn/server.conf"
remote_ssh('root', mgmt_ip, cmd)

cmd = "sed -i \"s/;cipher AES-128-CBC/cipher AES-128-CBC\\nauth SHA256/\" /etc/openvpn/server.conf"
remote_ssh('root', mgmt_ip, cmd)

cmd = "sed -i \"s/;user nobody/user nobody/\" /etc/openvpn/server.conf"
remote_ssh('root', mgmt_ip, cmd)

cmd = "sed -i \"s/;group nogroup/group nogroup/\" /etc/openvpn/server.conf"
remote_ssh('root', mgmt_ip, cmd)

cmd = "sed -i \"s/port 1194/port 443/\" /etc/openvpn/server.conf"
remote_ssh('root', mgmt_ip, cmd)

cmd = "sed -i \"s/proto udp/proto tcp/\" /etc/openvpn/server.conf"
remote_ssh('root', mgmt_ip, cmd)

# Build Client Key
debug('Building Client Key')
cmd = 'cd ~/openvpn-ca; source vars; ./build-key --batch client'
remote_ssh('root', mgmt_ip, cmd)

# Do we want to force DNS to go through the tunnel?
# Maybe turn into a user defined switch

# Restart OpenVPN
debug('Restarting OpenVPN: ' + mgmt_ip)
cmd = 'service openvpn restart'
remote_ssh('root', mgmt_ip, cmd)

# Setup remote forwarding
debug('Setting up remote forwarding on mgmt: ' + mgmt_ip)
cmd = 'echo 1 > /proc/sys/net/ipv4/ip_forward'
remote_ssh('root', mgmt_ip, cmd)

# Setup Client side config
debug('Setting up temp openvpn folder: /tmp/' + nameTag)
subprocess.Popen("mkdir /tmp/%s" % nameTag, shell=True) 

# using subproccess for future extention to check error state
os.system("touch /tmp/%s/config.txt" % nameTag)
os.system("echo 'client' >> /tmp/%s/config.txt" % nameTag)
os.system("echo 'dev tun' >> /tmp/%s/config.txt" % nameTag)
os.system("echo 'proto tcp' >> /tmp/%s/config.txt" % nameTag)
os.system("echo 'remote %s 443' >> /tmp/%s/config.txt" % (mgmt_ip,nameTag))
os.system("echo 'ca ca.crt' >> /tmp/%s/config.txt" % nameTag)
os.system("echo 'persist-key' >> /tmp/%s/config.txt" % nameTag)
os.system("echo 'persist-tun' >> /tmp/%s/config.txt" % nameTag)
os.system("echo 'cert client.crt' >> /tmp/%s/config.txt" % nameTag)
os.system("echo 'key client.key' >> /tmp/%s/config.txt" % nameTag)
os.system("echo 'remote-cert-tls server' >> /tmp/%s/config.txt" % nameTag)
os.system("echo 'cipher AES-128-CBC' >> /tmp/%s/config.txt" % nameTag)
os.system("echo 'comp-lzo' >> /tmp/%s/config.txt" % nameTag)
os.system("echo 'auth SHA256' >> /tmp/%s/config.txt" % nameTag)
os.system("echo 'key-direction 1' >> /tmp/%s/config.txt" % nameTag)
os.system("echo 'tls-auth ta.key 1' >> /tmp/%s/config.txt" % nameTag)

# Pulling down our keys
debug('Pulling down vpn keys from mgmt server: ' + mgmt_ip)
remote_scp('root', mgmt_ip, '~/openvpn-ca/keys/client.crt', '/tmp/' + nameTag + '/client.crt')
remote_scp('root', mgmt_ip, '~/openvpn-ca/keys/client.key', '/tmp/' + nameTag + '/client.key')
remote_scp('root', mgmt_ip, '/etc/openvpn/ca.crt', '/tmp/' + nameTag + '/ca.crt')
remote_scp('root', mgmt_ip, '/etc/openvpn/ta.key', '/tmp/' + nameTag + '/ta.key')

#############################################################################################
# Provision Nodes
#############################################################################################

success("Provisioning nodes.")
for host in allInstances_public:

  # Log host ip
  log(host)

  # Permit Root Logon
  debug('Enabling Root Logon on node: ' + host)
  cmd = "sudo sed -i \"s/PermitRootLogin without-password/PermitRootLogin yes/\" /etc/ssh/sshd_config"
  remote_ssh('ubuntu', host, cmd)

  # Copy Keys 
  debug('Updating SSH Keys on node: ' + host)
  cmd = "sudo cp /home/ubuntu/.ssh/authorized_keys /root/.ssh/"
  remote_ssh('ubuntu', host, cmd)

  # Restarting Service to take new config (you'd think a simple reload would be enough)
  debug('Restarting SSH service on node: ' + host)
  cmd = 'sudo service ssh restart'
  remote_ssh('ubuntu', host, cmd)

  # Install dependencies
  debug('Installing dependencies on mgmt server: ' + mgmt_ip)
  cmd = 'apt-get update; apt-get install grepcidr -y'
  remote_ssh('root', host, cmd)

  # Setup remote forwarding
  debug('Setting up remote forwarding node: ' + host)
  cmd = 'echo 1 > /proc/sys/net/ipv4/ip_forward'
  remote_ssh('root', host, cmd)

  # Provision ip tables on remote host
  debug('Provisioning iptables on remote host: ' + host)
  cmd = 'iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE'
  remote_ssh('root', host, cmd)	

# Firing openvpn in the background
screen_cmd = 'screen -S PC -d -m bash -c "cd /tmp/' + nameTag + '/; openvpn --config config.txt; exec bash"'
debug('screen_cmd: ' + screen_cmd)
os.system(screen_cmd)

time.sleep(5)
success('Firing openvpn in the background, type screen -x to connect')

# Building managments route table
debug('Building Route table for mgmt')
nexthopcmd = 'ip route add ' + str(args.target) + ' scope global '
weight = 1
for host in allInstances_private:
  nexthopcmd = nexthopcmd + 'nexthop via ' + str(host) + ' dev eth0 weight ' + str(weight) + ' '

debug('SHELL CMD: ' + nexthopcmd)
remote_ssh('root', mgmt_ip, nexthopcmd)

# Add local route change
debug('ip route add ' + str(args.target) + ' dev tun0')
os.system('ip route add ' + str(args.target) + ' dev tun0')

# fire VPN


success("Done!")
print "\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
print "+ Leave this terminal open and start another to run your commands.   +"
print "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n"
if args.r:
  print "[" + bcolors.WARNING + "~" + bcolors.ENDC +"] Press " + bcolors.BOLD + "ctrl + c" + bcolors.ENDC + " to terminate the script gracefully."
  success("Rotating IPs.")
  rotate_hosts()
else:
  print "[" + bcolors.WARNING + "~" + bcolors.ENDC +"] Press " + bcolors.BOLD + "ctrl + c" + bcolors.ENDC + " to terminate the script gracefully."
while 1:
  null = raw_input()
