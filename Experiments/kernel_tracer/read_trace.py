#!/usr/bin/python
import os
from inotify_simple import INotify, flags

trace_file_path = "trace_test"

def process_line(line):
    print(line)

def monitor_trace_file():
    inotify = INotify()
    watch_flags = flags.CREATE | flags.MODIFY
    watch = inotify.add_watch(trace_file_path, watch_flags)

    while True:
        for event in inotify.read():
            if event.mask & flags.MODIFY:
                with open(trace_file_path, 'r') as trace_file:
                    lines = trace_file.readlines()
                    if lines:
                        new_line = lines[-1].strip()
                        process_line(new_line)

                        with open(trace_file_path, 'w') as trace_file:
                            trace_file.writelines(lines[:-1])

if __name__ == "__main__":
    monitor_trace_file()