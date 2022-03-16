#!/usr/bin/python
# Written by Viet Le
# Feel free to use for all purposes

# The input file name should be a good backup config from the FortiGate and must contain 'config firewall policy'

import re, os.path
import sys, getopt

# change the in/out file location here if runs from IDE

backup_file = 'D:\\Extracts\\FW-ITDC-TBS-1_20200114_1735.conf'
output_folder = 'D:\\Extracts\\FW-ITDC-TBS-1_20200114_1735.csv'


def usage():
    """ Used to print Syntax
    """
    print("Syntax:\n\t{} -i <inputfile> -o <outputfile>".format(os.path.basename(__file__)))
    print("Examples:\n\t{} -i backup-config.conf -o results.csv".format(os.path.basename(__file__)))


def main(argv):
    global backup_file
    global output_folder

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
            column_name = ['id']
            for line in config_file:
                if re.findall(r'config firewall policy', line):
                    policy_start = True
                elif re.findall(r'^end', line):
                    if policy_start:
                        policy_stop = True
                elif policy_start and not policy_stop:
                    if re.findall(r'set\s', line):
                        set_value = line.strip('\n').strip(' ').split(' ')
                        policy_object = set_value[1]
                        if policy_object not in column_name:
                            column_name.append(policy_object)
            return column_name
    except IOError as e:
        print("Input file error: {} or file {} is in used".format(e.strerror, infile))
        usage()
        sys.exit()


if __name__ == "__main__":
    main(sys.argv[1:])

    print("Please wait! I am working on {}".format(backup_file))
    print('*' * 60)
    hit = 0  # count number of policies matched
    policy_block = "false"
    rows = [' ']    # policy place holder

    columns = get_columns(backup_file)

    # for i in range(0, len(columns)):
    #     rows.append('')
    rows *= len(columns)    # copy column structure, number max of column
    # rows[0]= 'id'   # the first column is always policy ID


    # Begin writing output header, the outFile will remain opened until the end.
    try:
        outFile = open(output_folder, 'w')
        for field in columns:
            outFile.write(field + ',')
        outFile.write('\n')
    except IOError as e:
        print("Error: Cannot open Output file {} - {}".format(output_folder, e.strerror))
        usage()
        sys.exit()
    # End writing output header

    try:
        with open(backup_file, 'r') as config_file:
            policy_block = False
            end_policy = False
            for command_line in config_file:
                if re.findall(r'config firewall policy', command_line):
                    policy_block = True
                elif re.findall(r'^end', command_line):
                    if policy_block:
                        end_policy = True
                elif policy_block and not end_policy:
                    if re.findall(r'edit \d{1,}', command_line):
                        policy_id = command_line.strip(' ').strip('\n').split(' ')
                        rows[0] = policy_id[1]
                        hit += 1
                    elif re.findall(r'set\s', command_line):
                        value = command_line.strip('\n').strip(' ').split(' ')
                        object = value[1]
                        if object not in columns:   # hardly hit this conditions , just in case a field is missing
                            columns.append(object)
                            rows.append('')
                        idx = columns.index(object)  # find the index of field name in the column
                        options = ''    # contains all the values
                        for option in value[2:]:    # skip 'set object' and take the value only
                            options += option + ' '
                        rows[idx] = options  # save value to the corresponding field
                    elif re.findall(r'next', command_line):  # end of policy - flush to output file
                        for eachSetup in rows:
                            # if eachSetup != '':
                            outFile.write(eachSetup + ',')
                        outFile.write('\n')
                        rows = [' ']    # reset the policy place holder
                        rows *= len(columns)
    except IOError as e:
        print("Input file error: {} or file {} is in used".format(e.strerror, backup_file))
        usage()
        sys.exit()
    if hit > 0:
        print("Results: {} policies exported to {}".format(hit, output_folder))
    else:
        print("There is no firewall policy in the input file {}".format(backup_file))
    outFile.close()
