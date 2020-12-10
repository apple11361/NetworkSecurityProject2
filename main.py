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

        if(is_attack2(winlog_file_path, packet_file_path)):
            print("testcase ", j, ": attack 2")
        else:
            print("testcase ", j, ": i don't fucking care")

        
def is_attack1(winlog_file, packet_file):
    return False

def is_attack2(winlog_file, packet_file):
    return False

def is_attack3(winlog_file, packet_file):
    return False

def is_attack4(winlog_file, packet_file):
    return False

def is_attack5(winlog_file, packet_file):
    return False

if __name__ == "__main__":
    main(sys.argv)
