#!/usr/bin/env python3

"""
Watchdog for blackbox fuzzing "shadow" queue. So that the blackbox AFL is not
disturbed by more-complex logic, this script watches a "shadow queue" that
stores all testcases, replays these testcases through an instrumented version of
the target program, and deletes testcases that do not lead to new coverage.

Author: Adrian Herrera
"""


from argparse import ArgumentParser, Namespace
from concurrent.futures import Future, ProcessPoolExecutor as Executor
from csv import DictWriter as CsvDictWriter
from functools import partial
import multiprocessing
from io import BufferedWriter
import os
from pathlib import Path
from queue import Queue
from shutil import which
import signal
import subprocess
from tarfile import TarFile, TarInfo
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
    parser.add_argument('-j', '--jobs', type=int, default=0,
                        help='Number of worker threads to spawn')
    parser.add_argument('-c', '--csv', default=None,
                        help='Write coverage information to a CSV')
    parser.add_argument('--target', required=True,
                        help='Instrumented target')
    parser.add_argument('--timeout', type=int, default=0,
                        help='Timeout in seconds')
    parser.add_argument('out_dir', metavar='OUT_DIR', type=Path,
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
                               tar_file: BufferedWriter,
                               csv_path: Path=None) -> None:
    """
    Retrieve coverage information from the queue, and delete the testcase if it
    does *not* lead to new coverage.
    """
    while True:
        testcase, cov = queue.get()
        new_bits, virgin_bits = has_new_bits(cov, virgin_bits)

        if new_bits:
            # Write testcase to GZIP
            with open(testcase, 'rb') as inf, \
                    TarFile.open(fileobj=tar_file, mode='w:gz') as tar:
                tar.addfile(TarInfo(testcase.name), inf)
            tar_file.flush()

            if csv_path:
                # If a CSV file has been provided, write coverage information to
                # the CSV file
                t_bytes = count_non_255_bytes(virgin_bits)
                t_byte_ratio = (t_bytes * 100.0) / MAP_SIZE
                execs = int(testcase.name.split('id:')[1])
                csv_dict= dict(unix_time='%d' % testcase.stat().st_ctime,
                               map_size='%.02f' % t_byte_ratio,
                               execs=execs)

                with open(csv_path, 'a') as outf:
                    writer = CsvDictWriter(outf, fieldnames=CSV_FIELDNAMES)
                    writer.writerow(csv_dict)

        # Delete testcase
        Thread(target=lambda: os.unlink(testcase)).start()
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


def no_new_files(signum, frame):
    """
    SIGALRM handler.

    Kills the watchdog.
    """
    print('No new files, goodbye')
    os.kill(0, 9)


class TestCaseHandler(FileSystemEventHandler):
    """
    Watches the "shadow" queue directory (`queue/.blackbox`) and deduplicates
    testcases that get written to this queue by executing afl-showmap.
    """

    def __init__(self, executor: Executor, cov_queue: Queue,
                 target: str, afl_stats: FuzzerStats, timeout: int=0):
        # Responsible for the pool of worker threads that generate testcase
        # coverage
        self._executor = executor
        self._cov_queue = cov_queue

        # Required for afl-showmap
        self._target = target
        self._afl_stats = afl_stats

        # Register signal handler
        self._timeout = timeout
        signal.signal(signal.SIGALRM, no_new_files)

    def add_to_queue(self, testcase: Path, future: Future) -> None:
        """
        Executor callback.

        Adds the testcase and its coverage to the queue.
        """
        self._cov_queue.put((testcase, future.result()))

    def on_created(self, event) -> None:
        """
        Triggered whenever a new testcase is added to the directory.

        Spawn a worker thread to execute this testcase and determine coverage.
        Add this coverage to the queue for the coverage thread to deduplicate as
        necessary.
        """
        if event.is_directory:
            return

        # A new file has been created. Reset the timeout alarm
        signal.alarm(self._timeout)

        testcase = Path(event.src_path)
        cov_future = self._executor.submit(run_afl_showmap, self._target,
                                           self._afl_stats, testcase)
        cov_future.add_done_callback(partial(self.add_to_queue, testcase))


def main() -> None:
    """The main function."""
    args = parse_args()

    # Check the target
    target = args.target
    if not os.path.isfile(target):
        raise Exception('Target `%s` does not exist' % target)

    # Maxmimum number of tasks. Two 2 tasks are required as a minimum: one for
    # running afl-showmap, and another for updating the coverage bitmap
    max_task = args.jobs
    if max_task == 0:
        max_task = multiprocessing.cpu_count()

    # Check afl-showmap
    if not which('afl-showmap'):
        raise Exception('Could not find afl-showmap. Check PATH')

    # Wait for fuzzer_stats to exist
    out_dir = args.out_dir
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

    with Executor(max_workers=max_task) as executor, \
            open(out_dir / 'blackbox.tar.gz', 'wb') as tar_file:
        # The coverage bitmap
        cov_bitmap = [255] * MAP_SIZE
        cov_queue = Queue(max_task)

        # Thread responsible for deduplicating entries in the output directory
        # and logging coverage to a CSV
        cov_thread = Thread(target=remove_duplicate_testcases,
                            args=(cov_bitmap, cov_queue, tar_file, csv_path))
        cov_thread.daemon = True
        cov_thread.start()

        # Start the watchdog
        handler = TestCaseHandler(executor, cov_queue, target, afl_stats,
                                  args.timeout)
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


if __name__ == '__main__':
    main()
