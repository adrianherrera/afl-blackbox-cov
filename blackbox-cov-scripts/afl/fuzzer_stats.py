"""
Container for AFL fuzzer_stats file.

Author: Adrian Herrera
"""


from getopt import getopt, GetoptError
import re


START_TIME_RE = re.compile(r'^start_time\s*: (?P<start_time>\d+)')
LAST_UPDATE_RE = re.compile(r'^last_update\s*: (?P<last_update>\d+)')
FUZZER_PID_RE = re.compile(r'^fuzzer_pid\s*: (?P<fuzzer_pid>\d+)')
CYCLES_DONE_RE = re.compile(r'^cycles_done\s*: (?P<cycles_done>\d+)')
EXECS_DONE_RE = re.compile(r'^execs_done\s*: (?P<execs_done>\d+)')
EXECS_PER_SEC_RE = re.compile(r'^execs_per_sec\s*: (?P<execs_per_sec>[\d.]+)')
PATHS_TOTAL_RE = re.compile(r'^paths_total\s*: (?P<paths_total>\d+)')
PATHS_FAVORED_RE = re.compile(r'^paths_favored\s*: (?P<paths_favored>\d+)')
PATHS_FOUND_RE = re.compile(r'^paths_found\s*: (?P<paths_found>\d+)')
PATHS_IMPORTED_RE = re.compile(r'^paths_imported\s*: (?P<paths_imported>\d+)')
MAX_DEPTH_RE = re.compile(r'^max_depth\s*: (?P<max_depth>\d+)')
CUR_PATH_RE = re.compile(r'^cur_path\s*: (?P<cur_path>\d+)')
PENDING_FAVS_RE = re.compile(r'^pending_favs\s*: (?P<pending_favs>\d+)')
PENDING_TOTAL_RE = re.compile(r'^pending_total\s*: (?P<pending_total>\d+)')
VARIABLE_PATHS_RE = re.compile(r'^variable_paths\s*: (?P<variable_paths>\d+)')
STABILITY_RE = re.compile(r'^stability\s*: (?P<stability>[\d.]+)%')
BITMAP_CVG_RE = re.compile(r'^bitmap_cvg\s*: (?P<bitmap_cvg>[\d.]+)%')
UNIQUE_CRASHES_RE = re.compile(r'^unique_crashes\s*: (?P<unique_crashes>\d+)')
UNIQUE_HANGS_RE = re.compile(r'^unique_hangs\s*: (?P<unique_hangs>\d+)')
LAST_PATH_RE = re.compile(r'^last_path\s*: (?P<last_path>\d+)')
LAST_CRASH_RE = re.compile(r'^last_crash\s*: (?P<last_crash>\d+)')
LAST_HANG_RE = re.compile(r'^last_hang\s*: (?P<last_hang>\d+)')
EXECS_SINCE_CRASH_RE = re.compile(r'^execs_since_crash\s*: (?P<execs_since_crash>\d+)')
EXECS_TIMEOUT_RE = re.compile(r'^execs_timeout\s*: (?P<execs_timeout>\d+)')
AFL_BANNER_RE = re.compile(r'^afl_banner\s*: (?P<afl_banner>,+)')
AFL_VERSION_RE = re.compile(r'^afl_version\s*: (?P<afl_version>.+)')
TARGET_MODE_RE = re.compile(r'^target_mode\s*: (?P<target_mode>.+)')
COMMAND_LINE_RE = re.compile(r'^command_line\s*: (?P<afl_fuzz>.*?afl-.+?)\s+(?P<command_line>.+)')
SLOWEST_EXEC_MS_RE = re.compile(r'^slowest_exec_ms\s*: (?P<slowest_exec_ms>\d+)')
PEAK_RSS_MB_RE = re.compile(r'^peak_rss_mb\s*: (?P<peak_rss_mb>\d+)')

FUZZER_STATS_RES = (
    START_TIME_RE,
    LAST_UPDATE_RE,
    FUZZER_PID_RE,
    CYCLES_DONE_RE,
    EXECS_DONE_RE,
    EXECS_PER_SEC_RE,
    PATHS_TOTAL_RE,
    PATHS_FAVORED_RE,
    PATHS_FOUND_RE,
    PATHS_IMPORTED_RE,
    MAX_DEPTH_RE,
    CUR_PATH_RE,
    PENDING_FAVS_RE,
    PENDING_TOTAL_RE,
    VARIABLE_PATHS_RE,
    STABILITY_RE,
    BITMAP_CVG_RE,
    UNIQUE_CRASHES_RE,
    UNIQUE_HANGS_RE,
    LAST_PATH_RE,
    LAST_CRASH_RE,
    LAST_HANG_RE,
    EXECS_SINCE_CRASH_RE,
    EXECS_TIMEOUT_RE,
    AFL_BANNER_RE,
    AFL_VERSION_RE,
    TARGET_MODE_RE,
    COMMAND_LINE_RE,
    SLOWEST_EXEC_MS_RE,
    PEAK_RSS_MB_RE,
)

AFL_GETOPT = '+i:o:f:m:t:T:dnCB:S:M:x:Q'
AFLGO_GETOPT = '+i:o:f:m:t:T:dnCB:S:M:x:Qz:c:'
MOPT_GETOPT = '+i:o:f:m:t:V:T:L:dnCB:S:M:x:Q'

AFL_GETOPTS = (AFL_GETOPT, AFLGO_GETOPT, MOPT_GETOPT)


class FuzzerStats:
    """Container for AFL fuzzer_stats file."""

    def __init__(self, stats_file):
        """
        Create a fuzzer stats object from a file object (i.e., one created by
        `open`ing a fuzzer_stats file).
        """
        stats = dict()
        self._stats = dict()

        for line in stats_file:
            stat = next((regex.match(line).groupdict()
                         for regex in FUZZER_STATS_RES if regex.match(line)),
                        dict())
            stats.update(stat)

        if not stats:
            raise Exception('Empty fuzzer_stats file `%s`' % stats_file.name)

        # Automatically create class attributes based on the fuzzer_stats fields
        for k, v in stats.items():
            if k == 'command_line':
                afl_opts = None
                target_args = None
                getopt_error = None

                for afl_getopt in AFL_GETOPTS:
                    try:
                        afl_opts, target_args = getopt(v.split(), afl_getopt)
                        break
                    except GetoptError as e:
                        getopt_error = e

                if not afl_opts or not target_args:
                    raise getopt_error

                setattr(self, 'afl_cmdline', afl_opts)
                setattr(self, 'target_cmdline', target_args)
            else:
                # If convertable to a number, treat as a number
                try:
                    v = float(v)
                except ValueError:
                    pass

                setattr(self, k, v)
                self._stats[k] = v

    def gen_command_line(self, testcase):
        """
        Generate the AFL target command-line for the given testcase.

        Replaces '@@' with the given testcase. This can be either a
        command-line argument or stdin (depending on whether '@@' was found on
        the AFL command-line). A tuple of both command-line and stdin input is
        returned.
        """
        found_double_at = False
        new_args = []

        for arg in self.target_cmdline:
            if arg == '@@':
                found_double_at = True
                new_args.append(testcase)
            else:
                new_args.append(arg)

        if found_double_at:
            stdin = None
        else:
            with open(testcase, 'rb') as inf:
                stdin = inf.read()

        return new_args, stdin

    def __iter__(self):
        for k, v in self._stats.items():
            yield k, v

    def __str__(self):
        return '%s' % self._stats
