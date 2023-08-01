#!/usr/bin/env python3
import argparse 
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
import requests
import logging
import logging.config
import sys

VERSION="1.0"    

DEFAULT_TAGS = {
    'Purpose': 'AccessControl',
    'AllowsFrom': 'HomeRouterIP'    
}

DISCOVERY_URL = "https://api.ipify.org"

DEFAULT_ALLOW_PORTS =  [ ('tcp',22), ('tcp', 80), ('tcp',443), ('tcp',3389), ('tcp',8443) ]

ec2 = None
logger = None

def get_ec2_client(region):    
    """Get Boto3 EC2 client
    Args:
        region: A region to make API calls
    Retruns:
        object: EC2 client object created
    """
    my_config = Config(
        region_name = region,
        signature_version = 'v4',
        retries = {
            'max_attempts': 10,
            'mode': 'standard'
        }
    )
    return boto3.client('ec2', config=my_config)

def get_logger(log_level='INFO',
               log_file=None,
               verbose_level=0):
    """Get logger object after initializing it.
    
    Args:
        log_level: Set logging level
        log_file: Set filename to store logs
        verbose_mode: Decide whether logger leave more informative message or not
    Returns:
        logger: configured logger object. 
    """
    
    logger = logging.getLogger('application')
    
    logging_level = eval(f"logging.{log_level}")
    logger.setLevel(logging_level)
    
   
    # create console handler with a higher log level
    ch = logging.StreamHandler()
    ch.setLevel(logging_level)
    
    # create formatter and add it to the handlers
    
    fh_formatter = None
    ch_formatter = None
    if verbose_level == 0:
        fh_formatter = logging.Formatter('%(asctime)s %(levelname)s %(funcName)s: %(message)s')
        ch_formatter = logging.Formatter('%(message)s')
    elif verbose_level == 1:
        fh_formatter = logging.Formatter('%(asctime)s %(levelname)s %(funcName)s: %(message)s')
        ch_formatter = logging.Formatter('%(asctime)s %(levelname)s %(funcName)s: %(message)s')
    else:
        fh_formatter = logging.Formatter('%(asctime)s %(levelname)s %(processName)s[%(process)d] %(module)s:%(funcName)s(%(lineno)d) %(message)s')
        ch_formatter = logging.Formatter('%(asctime)s %(levelname)s %(processName)s[%(process)d] %(module)s:%(funcName)s(%(lineno)d) %(message)s')

    ch.setFormatter(ch_formatter)

    # add the handlers to the logger
    logger.addHandler(ch)    

    # create file handler which logs even debug messages
    if log_file:
        fh = logging.FileHandler(log_file)
        fh.setLevel(logging_level)
        fh.setFormatter(fh_formatter)
        logger.addHandler(fh)
     
    return logger
 
def get_vpcs():
    """Retreive the VPC IDs

    Returns:
        List: Retrieved VPCs
    """
    response = ec2.describe_vpcs()
    vpcs = response.get('Vpcs', [{}])
    
    logger.debug(f"Retrieved VPC(s) - {vpcs}")
    
    return vpcs

def get_relevant_vpc_security_groups(vpc_id):
    """Get security group(s) that match(s) with our tags interested in

    Args:
        vpc_id: A VPC ID to create a security group
    
    Returns:
        string: newly created security group ID
    """

                
    filters=[ { 'Name': 'vpc-id', 'Values': [vpc_id] } ]
    for key in DEFAULT_TAGS.keys():
        filters.append({ "Name": f"tag:{key}", "Values": [ DEFAULT_TAGS[key] ] })

    logger.info("Getting relevant VPC security groups by tags")
    logger.debug(f"Search tags - {filters}")

    response = ec2.describe_security_groups(Filters=filters)
    sgs = response.get('SecurityGroups', [{}])

    return sgs

def create_security_group(vpc):
    """Create a security group within a VPC

    Args:
        vpc: A VPC object for creating a security group
    
    Returns:
        string: newly created security group ID
    """
    
    vpc_  = extract_interested_data_from_vpc(vpc)
    
    tags = []
    for key in DEFAULT_TAGS.keys():
        tags.append({ "Key": key, "Value": DEFAULT_TAGS[key] })
        
    response = ec2.create_security_group(
        Description="SG FOR CONTROL PUBLIC ACCESS",
        GroupName=f"{vpc_['VpcName']}-HomeRouterIP",
        VpcId=vpc_['VpcId'],
        TagSpecifications=[
            {
                'ResourceType': 'security-group',
                'Tags': tags
            }
        ]
    )
    logger.info(f"Security group is in place - {response['GroupId']}")
    return response['GroupId']
    
def update_sg_ingress_rules(sg, ip_cidr, allow_port_list=DEFAULT_ALLOW_PORTS):
    """Update/Replace the ingress rules of the specified security group
    
    Args:
        sg: Security Group to update
        ip_cidr: To check or update the IP address CIDR block 
        allow_port_list: the list object consists of tuple(s) and tuple consists of protocol string (e.g. TCP, UDP) and port number or range (e.g. 1024-65535).
    """
    prev_cidrs = set()
    
    # Get unique CIDR list only
    for ip_permission in sg['IpPermissions']:
        for ip_ranges in ip_permission['IpRanges']:
            prev_cidrs.add(ip_ranges['CidrIp'])
    
    # Check new IP existence in the CIDR list
    if ip_cidr in prev_cidrs:
        logger.warning(f"{ip_cidr} is already configured!")
        return
    
    sg_id = sg['GroupId']
    response = ec2.describe_security_group_rules(
        Filters=[
            {
                "Name": "group-id",
                "Values": [ sg_id ]
            }
        ]
    )
    sg_rules = response.get('SecurityGroupRules', [])
    not_relevant_ingress_rule_ids = [ sg_rule['SecurityGroupRuleId'] for sg_rule in sg_rules if sg_rule.get('CidrIpv4','') != ip_cidr and sg_rule['IsEgress'] == False ]

    # Clean up rules if there's any new IP unrelevant rules.
    if len(not_relevant_ingress_rule_ids) > 0:
        logger.debug(f"Cleaning up ingress rule IDs - {not_relevant_ingress_rule_ids}")
        ec2.revoke_security_group_ingress(GroupId=sg_id, SecurityGroupRuleIds=not_relevant_ingress_rule_ids)

    # Generate IpPermissions contents based on the allow ports information
    ip_permissions = []
    for protocol, port in allow_port_list:
        item = {}
        if type(port) is range:
            item = {
                'IpProtocol': protocol.lower(),
                'FromPort': port.start,
                'ToPort': port.stop,
                'IpRanges': [{'CidrIp': ip_cidr}]
            }                    
        elif type(port) is int:
            item = {
                'IpProtocol': protocol.lower(),
                'FromPort': port,
                'ToPort': port,
                'IpRanges': [{'CidrIp': ip_cidr}]
            }
        else:
            logger.error(f"FIXME: Skip parsing due to invalid syntax or code - {protocol} {port}")
            continue
        
        ip_permissions.append(item)

    logger.info(f"Updating the security group - {sg_id}")        
    logger.debug(f"Generated IpPermissions - {ip_permissions}")
    
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=ip_permissions
    )
    
    for ip_perm in ip_permissions:
        if ip_perm['FromPort'] == ip_perm['ToPort']:
            logger.info(f"Authorized {ip_perm['IpProtocol'].upper()}/{ip_perm['FromPort']} incoming from {ip_perm['IpRanges'][0]['CidrIp']}")
        else:
            logger.info(f"Authorized {ip_perm['IpProtocol'].upper()}/{ip_perm['FromPort']}-{ip_perm['ToPort']} incoming from {ip_perm['IpRanges'][0]['CidrIp']}")
    
def get_my_public_ip():
    """Retrieve current my public IP
    Returns:
        string: an discovered public IP address
    """
    
    public_ip = None        
    
    try:
        response = requests.get(DISCOVERY_URL)
        if response.status_code == 200:
            public_ip = f"{response.text}/32"        
            logger.info(f"Discovered my public IP address - {public_ip}")
        else:
            logger.error('Unable to get an IP address of this machine')
    except:
        pass
    
    return public_ip

def extract_interested_data_from_vpc(vpc):
    """Extract only interested data from a VPC object
    Args:
        vpc: origin VPC object
    """
    new_vpc = {}
    
    new_vpc['VpcId'] = vpc['VpcId']
    new_vpc['CidrBlock'] = vpc['CidrBlock']
    if vpc['IsDefault'] == True:
        new_vpc['VpcName'] = 'Default'
    else:
        tag_name_value = [ tag for tag in vpc.get('Tags', []) if tag['Key'] == 'Name' ]
        if tag_name_value:
            new_vpc['VpcName'] = tag_name_value[0]['Value']
        else:
            # Use VPC ID instead of the Tag Name value if this VPC has no tag Name/Value
            new_vpc['VpcName'] = vpc['VpcId']
    
    return new_vpc

def print_vpcs(vpcs = []):
    """Printing VPC list on the display
    
    Args:
        vpcs: VPC list for printing on the display
    """
    
    i = 0
    logger.info("{: >3} {: ^24} {: ^24} {: ^24}".format('Num', 'VPC ID', 'VPC Name', 'CIDR Block'))
    logger.info("{: >3} {: >24} {: >24} {: >24}".format('='*3, '='*24, '='*24, '='*24))
    for vpc in vpcs:
        vpc_dict  = extract_interested_data_from_vpc(vpc)
        logger.info("{: >3} {: ^24} {: ^24} {: ^24}".format(i, vpc_dict['VpcId'], vpc_dict['VpcName'], vpc_dict['CidrBlock'] ))
        i = i + 1
    
    logger.info("{: >3} {: >24} {: >24} {: >24}".format('='*3, '='*24, '='*24, '='*24))
        
def update_security_groups(vpc, allow_ports, cidr):
    """Update all the security groups of a VPC
    
    Args: 
        vpc: A VPC object to find security groups relevant for updating
        allow_ports: protocol and port list to be allowed
    """


    vpc_id = vpc['VpcId']
    
    sgs = get_relevant_vpc_security_groups(vpc_id)
    
    if len(sgs) == 0:
        logger.warning('Not found relevant security group, Create one!')
        create_security_group(vpc)
        sgs = get_relevant_vpc_security_groups(vpc_id)
    
    for sg in sgs:
        update_sg_ingress_rules(sg, cidr, allow_ports)    
    
    
def parse_args():
    """Initialze argparse
    
    Returns:
        args:  List of strings to parse. The default is taken from sys.argv.
    """
    parser = argparse.ArgumentParser(
        description='Control My IP Security Group',
        epilog='You can freely modify or distribute this script to anyone',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    
    parser.add_argument('--cidr', action='store', 
                        help='CIDR block to be set explicitly')
    
    parser.add_argument('--region', action='store',
                        help='Set region to make API calls')
    
    parser.add_argument('--vpc-id', action='append', 
                        help='Set VPC ID to update.')
    
    parser.add_argument('--port', action='append', 
                        help='Add port to allow. Allowing Syntax: TCP/1234, TCP/20000-30000, UDP/123')
    
    parser.add_argument('--log-file', action='store', 
                        help='Log file to store logs')
    
    parser.add_argument('--log-level', action='store', 
                        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        default="INFO", 
                        help='specifying the log file')    

    parser.add_argument('--show-vpcs-only', action='store_true', 
                        help='Display the VPC list')
        
    parser.add_argument('--verbose', '-v', action='count', default=0, 
                        help='Show verbosive output message')
    
    parser.add_argument('--version', action='version', version=f"%(prog)s v{VERSION}")
    
    return parser.parse_args()
    
            
def main():

    global logger, ec2
    
    args = parse_args()
    logger = get_logger(log_file=args.log_file,
                        log_level=args.log_level, 
                        verbose_level=args.verbose)

    logger.debug(f"Run Options - {args}")
    
    ec2 = get_ec2_client(args.region)
    
    allow_ports = DEFAULT_ALLOW_PORTS    
    # Add port if user wants to allow more port
    if args.port is not None:
        for port in args.port:
            protocol, port_ = port.split('/')
            if '-' in port_:
                from_, to = port_.split('-')
                allow_ports.append(
                    ( 
                        protocol.lower(),
                        range( int(from_), int(to) )
                    )
                )
            else:    
                allow_ports.append( ( protocol.lower(), int(port_)) )        

    vpcs = get_vpcs()

    if args.show_vpcs_only:
        print_vpcs(vpcs)
        sys.exit(0)

    # Select VPCs only if user specify any VPC ID with '--vpc-id' argument
    selected_vpcs = []
    if args.vpc_id is not None:
        # NOTE: args.vpc_id is a list not string!!!
        logger.info(f"VPC ID is configured explicitly - {args.vpc_id}")
        for vpc_id in args.vpc_id:
            for vpc in vpcs:
                if vpc_id == vpc['VpcId']:
                    selected_vpcs.append(vpc)                
    else:
        logger.debug("All VPCs are the target for updating relevant security groups")
        selected_vpcs = vpcs

    # Wants to specify the IP address without making an API call.
    cidr = None
    if args.cidr is not None:
        if '/' not in args.cidr:
            logger.error(f"{args.cidr} is invalid use CIDR form!!")
            sys.exit(1)
        
        logger.info(f"CIDR is configured explicitly - {args.cidr}")
        cidr = args.cidr
    else:
        cidr = get_my_public_ip()
        if cidr is None:
            sys.exit(1)
        
    # Updated security groups that in the selected VPC(s)         
    for vpc in selected_vpcs:
        update_security_groups(vpc, allow_ports, cidr) 
    
if __name__ == "__main__":
    main()
