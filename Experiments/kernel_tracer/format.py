#!/usr/bin/python
import re

def main():
    cols = ["TASK-PID", "CPU", "INFOS", "TIMESTAMP", "FUNCTION", "CALLER"]

    kfuncs = {}

    output = open("output")
    while output.readline()[0] == "#":
        continue


    i = 0
    while True:
        try:
            l = re.split("[\ ]+", output.readline())[1:]
            f = l[-2]
            if not f in kfuncs:
                kfuncs[f] = 0
            kfuncs[f] += 1
            i+=1
        except:
            break
    output.close()

    print("Statistics:")
    print("Number of calls: %d" % sum(list(kfuncs.values())))
    print("Different kfunctions called: %d" % len(list(kfuncs.values())))


if __name__ == "__main__":
    main()