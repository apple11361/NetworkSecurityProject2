import sys
import json
from os import listdir
from os.path import join, isfile

def main(argv):

    # Get the path of log files
    if(len(sys.argv) != 2):
        sys.exit("Argument error!")
    else:
        rootdir_path = argv[1]

    # Get each testcase dir
    testcase_dir = listdir(rootdir_path)
    testcase_dir.sort()

    # Process each testcase
    j = 0
    for i in testcase_dir:
        j = j + 1
        full_path = join(rootdir_path, i)
        winlog_file_path = join(full_path, "winlogbeat.json")
        packet_file_path = join(full_path, "packetbeat.json")

        winlog_list = []
        packetlog_list = []

        # read json
        packetlog_file = open(packet_file_path)
        for json_obj in packetlog_file:
            log = json.loads(json_obj)
            packetlog_list.append(log)


        if(is_attack2(winlog_list, packetlog_list)):
            print("testcase ", j, ": attack 2", sep="")
        elif(is_attack1(winlog_list, packetlog_list)):
            print("testcase ", j, ": attack 1", sep="")
        elif(is_attack3(winlog_list, packetlog_list)):
            print("testcase ", j, ": attack 3", sep="")
        elif(is_attack4(winlog_list, packetlog_list)):
            print("testcase ", j, ": attack 4", sep="")
        else:
            print("testcase ", j, ": attack 5", sep="")
        
def is_attack1(winlog_list, packetlog_list):
    # Rule: a lot of port 80 request
    total_record_count = 0
    port80_request_count = 0
    for log in packetlog_list:
        total_record_count += 1
        if(log.get("destination", {}).get("port", 0) == 80):
            port80_request_count += 1
    if(port80_request_count/total_record_count > 0.85):
        return True
    else:
        return False



# I think this attack is sql injection
def is_attack2(winlog_list, packetlog_list):
    # Rule: a lot of port 80 request and http status 414
    total_record_count = 0
    port80_request_count = 0
    status414_count = 0
    for log in packetlog_list:
        total_record_count += 1
        if(log.get("destination", {}).get("port", 0) == 80):
            port80_request_count += 1
        if(log.get("http", {}).get("response", {}).get("status_code", 0) == 414):
            status414_count += 1
    if(port80_request_count/total_record_count > 0.5 and status414_count > 5):
        return True
    else:
        return False

def is_attack3(winlog_list, packetlog_list):
    # Rule: access a lot of port
    access_port_list = []
    for log in packetlog_list:
        access_port = log.get("destination", {}).get("port", 0)
        if(not (access_port in access_port_list)):
            access_port_list.append(access_port)
    if(len(access_port_list) > 1000):
        return True
    else:
        return False

def is_attack4(winlog_list, packetlog_list):
    # Rule: destination port 7680 and destination ip 10.0.2.2
    for log in packetlog_list:
        des_port = log.get("destination", {}).get("port", 0)
        des_ip = log.get("destination", {}).get("ip", {})
        if(des_port == 7680 and des_ip == "10.0.2.2"):
            return True
    return False

if __name__ == "__main__":
    main(sys.argv)
