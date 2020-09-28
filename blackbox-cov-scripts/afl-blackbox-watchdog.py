#!/usr/bin/env python3

"""
Watchdog for blackbox fuzzing "shadow" queue. So that the blackbox AFL is not
disturbed by more-complex logic, this script watches a "shadow queue" that
stores all testcases, replays these testcases through an instrumented version of
the target program, and deletes testcases that do not lead to new coverage.

Author: Adrian Herrera
"""


from argparse import ArgumentParser, Namespace
from concurrent.futures import ThreadPoolExecutor
from csv import DictWriter as CsvDictWriter
import multiprocessing
import os
from pathlib import Path
from queue import Queue
from shutil import which
import subprocess
from tempfile import NamedTemporaryFile
from threading import Thread
from time import sleep

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from afl.fuzzer_stats import FuzzerStats


# Taken from AFL's config.h
MAP_SIZE_POW2 = 16
MAP_SIZE = 1 << MAP_SIZE_POW2

CSV_FIELDNAMES = ('unix_time', 'map_size', 'execs')


def parse_args() -> Namespace:
    """Parse command-line arguments."""
    parser = ArgumentParser(description='Blackbox coverage watchdog')
    parser.add_argument('-j', type=int, default=0,
                        help='Number of worker threads to spawn')
    parser.add_argument('-t', '--target', required=True,
                        help='Instrumented target')
    parser.add_argument('-c', '--csv', default=None,
                        help='Write coverage information to a CSV')
    parser.add_argument('out_dir', metavar='OUT_DIR',
                        help='AFL output directory')

    return parser.parse_args()


def count_non_255_bytes(mem: list) -> int:
    """
    Adapted from afl-fuzz.

    Count the number of non-255 bytes set in the bitmap.
    """
    count = 0
    for byte in mem:
        if byte != 255:
            count += 1

    return count


def has_new_bits(trace_bits: list, virgin_map: list) -> (int, list):
    """
    Adapted from afl-fuzz.

    Check if the current execution path brings anything new to the table. Update
    virgin bits to reflect the finds.
    """
    ret = 0
    ret_virgin_map = virgin_map.copy()

    for i, (cur, vir) in enumerate(zip(trace_bits, virgin_map)):
        if cur and (cur & vir):
            if ret < 2:
                if cur != 0 and vir == 0xff:
                    ret = 2
                else:
                    ret = 1

            ret_virgin_map[i] = vir & ~cur

    return ret, ret_virgin_map


def remove_duplicate_testcases(virgin_bits: list, queue: Queue,
                               csv_path: Path=None) -> None:
    """
    Retrieve coverage information from the queue, and delete the testcase if it
    does *not* lead to new coverage.
    """
    while True:
        testcase, cov = queue.get()
        new_bits, virgin_bits = has_new_bits(cov, virgin_bits)

        if new_bits == 0:
            os.unlink(testcase)
        elif csv_path:
            # If a CSV file has been provided, write coverage information to the
            # CSV file
            t_bytes = count_non_255_bytes(virgin_bits)
            t_byte_ratio = (t_bytes * 100.0) / MAP_SIZE
            execs = int(testcase.name.split('id:')[1])
            csv_dict= dict(unix_time='%d' % testcase.stat().st_ctime,
                           map_size='%.02f' % t_byte_ratio,
                           execs=execs)

            with open(csv_path, 'a') as outf:
                CsvDictWriter(outf, fieldnames=CSV_FIELDNAMES).writerow(csv_dict)

        queue.task_done()


def run_afl_showmap(target: str, afl_stats: FuzzerStats, testcase: str) -> bytes:
    """
    Run afl-showmap on the target and get the coverage bitmap for a particular
    testcase.
    """
    # Base afl-showmap options and arguements on afl-fuzz options and arguments
    afl_showmap_opts = ['-b', '-q']
    for opt, arg in afl_stats.afl_cmdline:
        if opt in ('-m', '-Q', '-t'):
            afl_showmap_opts.extend([opt, arg])

    # Generate the target command-line for a testcase popped off the task
    # queue. Replace the original (uninstrumented) target binary with the
    # instrumented version
    target_cmdline, target_input = afl_stats.gen_command_line(testcase)
    target_cmdline[0] = target

    with NamedTemporaryFile() as temp:
        # Run afl-showmap
        args = ['afl-showmap', *afl_showmap_opts, '-o', temp.name, '--',
                *target_cmdline]
        subprocess.run(args, input=target_input, check=False,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Read the coverage bitmap
        with open(temp.name, 'rb') as showmap_out:
            return showmap_out.read()


class TestCaseHandler(FileSystemEventHandler):
    """
    Watches the "shadow" queue directory (`queue/.blackbox`) and deduplicates
    testcases that get written to this queue by executing afl-showmap.
    """

    def __init__(self, max_task: int, target: str, afl_stats: FuzzerStats,
                 csv_path: Path=None):
        # Responsible for the pool of worker threads for generating testcase
        # coverage
        self._executor = ThreadPoolExecutor(max_workers=max_task)

        # Thread responsible for deduplicating entries in the output directory
        # and logging coverage to a CSV
        self._cov_bitmap = [255] * MAP_SIZE
        self._cov_queue = Queue(max_task)

        self._cov_thread = Thread(target=remove_duplicate_testcases,
                                  args=(self._cov_bitmap, self._cov_queue,
                                        csv_path))
        self._cov_thread.daemon = True
        self._cov_thread.start()

        # Required for afl-showmap
        self._target = target
        self._afl_stats = afl_stats

    def on_created(self, event) -> None:
        """
        Triggered whenever a new testcase is added to the directory.

        Spawn a worker thread to execute this testcase and determine coverage.
        Add this coverage to the queue for the coverage thread to deduplicate as
        necessary.
        """
        if event.is_directory:
            return

        testcase = event.src_path
        cov_future = self._executor.submit(run_afl_showmap, self._target,
                                           self._afl_stats, testcase)
        self._cov_queue.put((Path(testcase), cov_future.result()))


def main() -> None:
    """The main function."""
    args = parse_args()

    # Check the target
    target = args.target
    if not os.path.isfile(target):
        raise Exception('Target `%s` does not exist' % target)

    # Maxmimum number of tasks. Two 2 tasks are required as a minimum: one for
    # running afl-showmap, and another for updating the coverage bitmap
    max_task = args.j
    if max_task == 0:
        max_task = multiprocessing.cpu_count()
    elif max_task <= 2:
        max_task = 2

    # Check afl-showmap
    if not which('afl-showmap'):
        raise Exception('Could not find afl-showmap. Check PATH')

    # Wait for fuzzer_stats to exist
    out_dir = Path(args.out_dir)
    fuzzer_stats_path = out_dir / 'fuzzer_stats'
    while not fuzzer_stats_path.exists():
        sleep(1)
    with open(fuzzer_stats_path, 'r') as inf:
        afl_stats = FuzzerStats(inf)

    # Open CSV plot_data
    csv_path = args.csv
    if csv_path:
        csv_path = Path(csv_path)
        with open(csv_path, 'w') as outf:
            CsvDictWriter(outf, fieldnames=CSV_FIELDNAMES).writeheader()

    # Start the watchdog
    handler = TestCaseHandler(max_task - 1, target, afl_stats, csv_path)
    observer = Observer()
    observer.schedule(handler, out_dir / 'queue' / '.blackbox')
    observer.start()

    # Continue until interrupted
    try:
        while observer.is_alive():
            observer.join(1)
    except KeyboardInterrupt:
        print('\nCtrl-C detected, goodbye')
        observer.stop()
        observer.join()
        os.kill(0, 9)


if __name__ == '__main__':
    main()
