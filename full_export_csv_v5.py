#!/usr/bin/python
# Written by Viet Le
# Feel free to use for all purposes
# trying to improve the performance/speed up resolve IP/member list.

# The input file name should be a good backup config from the FortiGate and must contain 'config firewall policy'
# In this version the script export firewall from all vdom, each policy has its vdom name in the first column.

import re, os.path
import sys, getopt, time

# change the in/out file location here if runs from IDE
#

backup_file = 'in\\sydney-full.conf'
output_file = 'out\\sydney-full.csv'
object_name = ''

def usage():
    """ Used to print Syntax
    """
    print("Syntax:\n\t{} -i <inputfile> -o <outputfile>".format(os.path.basename(__file__)))
    print("Examples:\n\t{} -i backup-config.conf -o results.csv".format(os.path.basename(__file__)))


def main(argv):
    global backup_file
    global output_file
    global object_name
    try:
        opts, args = getopt.getopt(argv, "hi:o:", ["ifile=", "ofile="])
    except getopt.GetoptError:
        print("Error:\n\tInvalid commands")
        usage()
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            usage()
            sys.exit()
        elif opt in ("-i", "--ifile"):
            backup_file = arg
        elif opt in ("-o", "--ofile"):
            output_file = arg


def get_columns(infile: str):
    """ Used to extract FW policy objects list
        The backup config file must contain 'config firewall policy' command.
    Parameters:
        infile (str): Input file contains FW policy only as input.
    Returns:
        columns (list): List of object name.
    """
    try:
        with open(infile, 'r') as config_file:
            policy_start = False
            policy_stop = False
            column_name = ['vdom', 'id', 'srcaddr', 'srcsubnet', 'dstaddr', 'dstsubnet']
            for line in config_file:
                if re.findall(r'config firewall policy', line):
                    policy_start = True
                    policy_stop = False
                elif re.findall(r'^end', line):
                    if policy_start:
                        policy_stop = True
                elif policy_start and not policy_stop:
                    if re.findall(r'set uuid .*', line):
                        continue
                    elif re.findall(r'set name .*', line):
                        continue
                    elif re.findall(r'set\s', line):
                        set_value = line.strip('\n').strip(' ').split(' ')
                        policy_object = set_value[1]
                        if policy_object not in column_name:
                            column_name.append(policy_object)
            return column_name
    except IOError as e:
        print("Input file error: {} or file {} is in used".format(e.strerror, infile))
        usage()
        sys.exit()


def get_object_subnet() -> dict:
    """
    Get IP subnet from address object
    :param addr_object: address name
    :param vdom: current vdom name
    :param infile: config file in the list
    :return: list of IP subnet
    """
    # global config_file
    # with open(backup_file) as infile:
    line_num = 0
    subnet_list = []
    fw_address = False
    fw_group = False
    vip_address = False
    vip_grp = False
    vd_name = 'root'
    extip = ''
    mappedip = ''
    object_table = dict()
    infile = open(backup_file)
    for cmd_line in infile:
        line_num += 1  # monitor config line number for troubleshooting
        if re.findall(r'^edit .*', cmd_line):  # extract vdom name
            vd_name = cmd_line.strip('\n')[5:]
        elif re.fullmatch(r'config firewall address\n', cmd_line):
            fw_address = True  # start matching address object for wanted vdom
            fw_group = False
        elif re.fullmatch(r'config firewall addrgrp\n', cmd_line):
            fw_group = True  # start matching address group object
            fw_address = False
        elif re.fullmatch(r'config firewall vip\n', cmd_line):
            vip_address = True
        elif re.fullmatch(r'config firewall vipgrp\n', cmd_line):
            vip_grp = True
        elif re.findall(r'^end', cmd_line):
            if fw_address:
                fw_address = False  # end of firewall address block
            if fw_group:
                fw_group = False  # end of address group object
            if vip_address:
                vip_address = False
            if vip_grp:
                vip_grp = False
        elif (fw_address or fw_group or vip_address or vip_grp):
            if re.findall('\s{4}edit ".*"', cmd_line):   # extract object name, it could be any object,
                object_name = vd_name + '-'+ cmd_line.strip(' ').strip('\n')[5:].strip('"')
            elif re.findall('set member .*', cmd_line):
                member_list = cmd_line.strip('\n').strip(' ')[11:].strip('"').split('" "')  # get list of members
                subnet_list.clear()

                for member in member_list:
                    vd_member = vd_name + '-' + member
                    if vd_member in object_table.keys():
                        subnet_list.append(object_table[vd_member])
                    else:
                        subnet_list.append(member)
                object_table[object_name] = '|'.join(x for x in subnet_list) # store object subnet to object table
            elif re.findall(r'set extip .*', cmd_line):
                extip = cmd_line.strip(' ').strip('\n')[10:]
                # subnet_list.append(extip)
            elif re.findall(r'set mappedip .*',cmd_line):
                mappedip = cmd_line.strip(' ').strip('\n')[13:].strip('"')
                if extip == '':
                    extip = '0.0.0.0'
                object_table[object_name] = extip+'->'+mappedip
            elif re.findall(r'set ip .*', cmd_line):
                mappedip = cmd_line.strip(' ').strip('\n')[7:].strip('"')
                if extip == '':
                    extip = '0.0.0.0'
                object_table[object_name] = extip+'->'+mappedip
            elif re.findall(r'set subnet .*', cmd_line):  # indicates object is address object and extract the ipmask
                ip_mask = cmd_line.strip(' ').strip('\n')[11:].split(' ')
                bits = subnet_bits(ip_mask[1])
                if bits == 32:
                    object_table[object_name] = ip_mask[0]
                else:
                    object_table[object_name] = ip_mask[0] + '/' + str(bits)
            elif re.findall(r'set start-ip .*', cmd_line):  # indicate IP range start IP
                start_ip = cmd_line.strip(' ').strip('\n')[13:]
            elif re.findall(r'set end-ip .*', cmd_line):
                end_ip = cmd_line.strip(' ').strip('\n')[11:]  # indicate IP range end IP
                object_table[object_name] = (start_ip + '-' + end_ip)  # combine the range
            elif re.findall(r'set wildcard .*', cmd_line):  # indicate wildcard mask object
                subnet = cmd_line.strip(' ').strip('\n')[13:]
                object_table[object_name] = subnet
            elif re.findall(r'set country .*', cmd_line):  # indicate geography object
                subnet = cmd_line.strip(' ').strip('\n')[12:].strip('"')
                object_table[object_name] = subnet
            elif re.findall(r'set fqdn .*', cmd_line):  # indicates FQDN object
                subnet = cmd_line.strip(' ').strip('\n')[9:].strip('"')
                object_table[object_name] = subnet
    return object_table


def subnet_bits(subnet: str) -> int:
    octets = subnet.split('.')
    bits = ''
    for octet in octets:
        bits += bin(int(octet)).replace('0b', '')
    return bits.count('1')


def get_objects(infile: str) -> list:

    with open(infile) as source_file:
        file_data = source_file.read().split('\n')
        object_list = []
        fw_address = []
        fw_addrgrp = []
        fw_vip = []
        fw_vipgrp = []
        for command_line in file_data:
            if re.fullmatch(r'config vdom', command_line):
                object_list.append(command_line)
            elif re.fullmatch(r'edit .*', command_line):
                object_list.append(command_line)
            elif re.fullmatch(r'next', command_line):
                object_list.append(command_line)
            elif re.fullmatch(r'config firewall address', command_line):
                object_list.append(command_line)
                fw_address = True
            elif re.fullmatch(r'config firewall addrgrp', command_line):
                object_list.append(command_line)
                fw_addrgrp = True
            elif re.fullmatch(r'config firewall vip', command_line):
                object_list.append(command_line)
                fw_vip = True
            elif re.fullmatch(r'config firewall vipgrp', command_line):
                object_list.append(command_line)
                fw_vipgrp = True
            elif re.fullmatch(r'end',command_line):
                if fw_address:
                    object_list.append(command_line)
                    fw_address = False
                if fw_addrgrp:
                    object_list.append(command_line)
                    fw_addrgrp = False
                if fw_vip:
                    object_list.append(command_line)
                    fw_vip = False
                if fw_vipgrp:
                    object_list.append(command_line)
                    fw_vipgrp = False
            else:
                if fw_address or fw_addrgrp or fw_vip or fw_vipgrp:
                    object_list.append(command_line)
        source_file.close()
    return object_list


if __name__ == "__main__":
    main(sys.argv[1:])

    print("Please wait! I am working on {}".format(backup_file))
    print('*' * 60)
    hit = 0  # count number of policies matched
    policy_block = "false"
    rows = [' ']  # policy place holder

    columns = get_columns(backup_file)
    rows *= len(columns)  # copy column structure, number max of column

    new_dict = get_object_subnet()

    # Begin writing output header, the outFile will remain opened until the end.
    try:
        outFile = open(output_file, 'w')
        for field in columns:
            outFile.write(field + ',')
        outFile.write('\n')
    except IOError as e:
        print("Error: Cannot open Output file {} - {}".format(output_file, e.strerror))
        usage()
        sys.exit()
    # End writing output header

    try:
        with open(backup_file, 'r') as config_file:
            policy_block = False
            end_policy = False
            vdom_name = 'root'
            line = 0
            for command_line in config_file:
                line += 1
                if re.findall(r'^edit .*', command_line):
                    vdom_name = command_line[5:].strip('\n')
                    print('working on vdom {} line {}'.format(vdom_name, line))
                elif re.findall(r'config firewall policy', command_line):
                    policy_block = True
                    end_policy = False
                elif re.findall(r'^end', command_line):
                    if policy_block:
                        end_policy = True
                elif policy_block and not end_policy:
                    if re.findall(r'edit \d{1,}', command_line):
                        policy_id = command_line.strip(' ').strip('\n').split(' ')
                        rows[0] = vdom_name
                        rows[1] = policy_id[1]
                        hit += 1
                    elif re.findall(r'set uuid .*', command_line):
                        continue
                    elif re.findall(r'set name .*', command_line):
                        continue
                    elif re.findall(r'set srcaddr .*', command_line):
                        src_addrs = command_line.strip(' ').strip('\n')[12:]
                        idx = columns.index("srcaddr")
                        rows[idx] = src_addrs
                        src_addr = []
                        src_addr = command_line.strip('\n').strip(' ')[12:].strip('"').split('" "')
                        new_src_addr = []
                        for member in src_addr:
                            vdom_member = vdom_name + '-' + member
                            if vdom_member in new_dict.keys():
                                new_src_addr.append(new_dict[vdom_member])
                            else:
                                new_src_addr.append(member)
                        subnets = '|'.join(str(x) for x in new_src_addr)
                        idx = columns.index("srcsubnet")
                        rows[idx] = subnets
                    elif re.findall(r'set dstaddr .*', command_line):
                        dst_addrs = command_line.strip('\n').strip(' ')[12:]
                        idx = columns.index("dstaddr")
                        rows[idx] = dst_addrs
                        dst_addr = []
                        dst_addr = command_line.strip('\n').strip(' ')[12:].strip('"').split('" "')
                        new_dst_addr = []
                        for member in dst_addr:
                            vdom_member = vdom_name + '-' + member
                            if vdom_member in new_dict.keys():
                                new_dst_addr.append(new_dict[vdom_member])
                            else:
                                new_dst_addr.append(member)
                                # object_table[member] = subnets
                        subnets = '|'.join(str(x) for x in new_dst_addr)
                        idx = columns.index("dstsubnet")
                        rows[idx] = subnets

                    elif re.findall(r'set\s', command_line):
                        value = command_line.strip('\n').strip(' ').split(' ')
                        object = value[1]
                        if object not in columns:  # hardly hit this conditions , just in case a field is missing
                            columns.append(object)
                            rows.append('')
                        idx = columns.index(object)  # find the index of field name in the column
                        options = ''  # contains all the values
                        for option in value[2:]:  # skip 'set object' and take the value only
                            options += option + ' '
                        rows[idx] = options  # save value to the corresponding field
                    elif re.findall(r'next', command_line):  # end of policy - flush to output file
                        for eachSetup in rows:
                            # if eachSetup != '':
                            outFile.write(eachSetup + ',')
                        outFile.write('\n')
                        rows = [' ']  # reset the policy place holder
                        rows *= len(columns)
    except IOError as e:
        print("Input file error: {} or file {} is in used".format(e.strerror, backup_file))
        usage()
        sys.exit()
    if hit > 0:
        print("Results: {} policies exported to {}".format(hit, output_file))
    else:
        print("There is no firewall policy in the input file {}".format(backup_file))

    file = open("out\\objectsubnet.txt", 'w')
    for x in new_dict.keys():
        file.write(x + ':'+ str(new_dict[x])+'\n')
    file.close()

    outFile.close()  # close output file
