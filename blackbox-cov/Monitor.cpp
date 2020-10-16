/**
 * Monitor for blackbox fuzzing "shadow" queue. So that the blackbox AFL is not
 * disturbed by more-complex logic, this script watches a "shadow queue" that
 * stores all testcases, replays these testcases through an instrumented version
 * of the target program, and deletes testcases that do not lead to new
 * coverage.
 *
 * Author: Adrian Herrera
 */

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/resource.h>
#include <sys/shm.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ThreadPool.h"

extern "C" {
#include "../config.h"
#include "../debug.h"
#include "../types.h"
}

namespace fs = std::filesystem;

static constexpr size_t EVENT_SIZE = sizeof(struct inotify_event);
static constexpr size_t EVENT_BUFFER_SIZE = 1024 * (EVENT_SIZE + NAME_MAX + 1);
static constexpr char const *AFL_OPTSTRING = "+i:o:f:m:b:t:T:dnCB:S:M:x:QV";

static inline void ToCStringVector(const std::vector<std::string> &V1,
                                   std::vector<const char *> &V2) {
  std::transform(V1.begin(), V1.end(), std::back_inserter(V2),
                 [](const std::string &S) { return S.c_str(); });
}

////////////////////////////////////////////////////////////////////////////////
//
// Adapted from afl-showmap and afl-fuzz
//
////////////////////////////////////////////////////////////////////////////////

static bool Stop;          /**< Stop the monitor */
static u32 Timeout;        /**< Stop the monitor after `Timeout` seconds */
static fs::path OutDir;    /**< AFL output directory */
static FILE *Csv;          /**< CSV log file */
static std::mutex CsvLock; /**< CSV log file lock */

static u64 MemLimit = MEM_LIMIT; /**< Memory limit (MB) */
static u32 ExecTimeout;          /**< Exec timeout (ms) */

static u8 VirginBits[MAP_SIZE];   /**< Regions yet untouched by fuzzing */
static std::mutex VirginBitsLock; /**< Coverage bitmap lock */

// Destructively classify execution counts in a trace. This is used as a
// preprocessing step for any newly acquired traces. Called on every exec, must
// be fast.

static const u8 CountClassLookup8[256] = {
    [0] = 0,          [1] = 1,           [2] = 2,
    [3] = 4,          [4 ... 7] = 8,     [8 ... 15] = 16,
    [16 ... 31] = 32, [32 ... 127] = 64, [128 ... 255] = 128};

static u16 CountClassLookup16[65536];

static void InitCountClass16() {
  u32 B1, B2;

  for (B1 = 0; B1 < 256; B1++)
    for (B2 = 0; B2 < 256; B2++)
      CountClassLookup16[(B1 << 8) + B2] =
          (CountClassLookup8[B1] << 8) | CountClassLookup8[B2];
}

#ifdef WORD_SIZE_64
static inline void ClassifyCounts(const u64 *Mem) {
  u32 I = MAP_SIZE >> 3;

  while (I--) {
    // Optimize for sparse bitmaps
    if (unlikely(*Mem)) {
      u16 *Mem16 = (u16 *)Mem;

      Mem16[0] = CountClassLookup16[Mem16[0]];
      Mem16[1] = CountClassLookup16[Mem16[1]];
      Mem16[2] = CountClassLookup16[Mem16[2]];
      Mem16[3] = CountClassLookup16[Mem16[3]];
    }

    Mem++;
  }
}
#else
static inline void ClassifyCounts(const u32 *Mem) {
  u32 I = MAP_SIZE >> 2;

  while (I--) {
    // Optimize for sparse bitmaps
    if (unlikely(*Mem)) {
      u16 *Mem16 = (u16 *)Mem;

      Mem16[0] = CountClassLookup16[Mem16[0]];
      Mem16[1] = CountClassLookup16[Mem16[1]];
    }

    Mem++;
  }
}
#endif

// Count the number of non-255 bytes set in the bitmap. Used strictly for the
// status screen, several calls per second or so.

#define FF(_b) (0xff << ((_b) << 3))

static u32 CountNon255Bytes(const u8 *Mem) {
  const u32 *Ptr = (const u32 *)Mem;
  u32 I = (MAP_SIZE >> 2);
  u32 Ret = 0;

  while (I--) {
    u32 V = *(Ptr++);

    // This is called on the virgin bitmap, so optimize for the most likely case
    if (V == 0xffffffff)
      continue;
    if ((V & FF(0)) != FF(0))
      Ret++;
    if ((V & FF(1)) != FF(1))
      Ret++;
    if ((V & FF(2)) != FF(2))
      Ret++;
    if ((V & FF(3)) != FF(3))
      Ret++;
  }

  return Ret;
}

// Check if the current execution path brings anything new to the table.
// Update virgin bits to reflect the finds. Returns 1 if the only change is
// the hit-count for a particular tuple; 2 if there are new tuples seen.
// Updates the map, so subsequent calls will always return 0.
//
// This function is called after every exec() on a fairly large buffer, so
// it needs to be fast. We do this in 32-bit and 64-bit flavors.
static inline u8 HasNewBits(const u8 *TraceBits, const u8 *VirginMap) {
#ifdef WORD_SIZE_64
  u64 *Current = (u64 *)TraceBits;
  u64 *Virgin = (u64 *)VirginMap;

  u32 I = (MAP_SIZE >> 3);
#else
  u32 *Current = (u32 *)TraceBits;
  u32 *Virgin = (u32 *)VirginMap;

  u32 I = (MAP_SIZE >> 2);
#endif
  u8 Ret = 0;

  while (I--) {
    if (unlikely(*Current) && unlikely(*Current & *Virgin)) {
      if (likely(Ret < 2)) {
        u8 *Cur = (u8 *)Current;
        u8 *Vir = (u8 *)Virgin;

        // Looks like we have not found any new bytes yet; see if any non-zero
        // bytes in current[] are pristine in virgin[].
#ifdef WORD_SIZE_64
        if ((Cur[0] && Vir[0] == 0xff) || (Cur[1] && Vir[1] == 0xff) ||
            (Cur[2] && Vir[2] == 0xff) || (Cur[3] && Vir[3] == 0xff) ||
            (Cur[4] && Vir[4] == 0xff) || (Cur[5] && Vir[5] == 0xff) ||
            (Cur[6] && Vir[6] == 0xff) || (Cur[7] && Vir[7] == 0xff))
          Ret = 2;
        else
          Ret = 1;
#else
        if ((Cur[0] && Vir[0] == 0xff) || (Cur[1] && Vir[1] == 0xff) ||
            (Cur[2] && Vir[2] == 0xff) || (Cur[3] && Vir[3] == 0xff))
          Ret = 2;
        else
          Ret = 1;
#endif
      }

      *Virgin &= ~*Current;
    }

    Current++;
    Virgin++;
  }

  return Ret;
}

static u64 GetCurTime() {
  struct timeval TV;
  struct timezone TZ;

  gettimeofday(&TV, &TZ);

  return (TV.tv_sec * 1000ULL) + (TV.tv_usec / 1000);
}

static void RemoveShm(s32 ShmId) { shmctl(ShmId, IPC_RMID, NULL); }

static s32 SetupShm(u8 **TraceBits) {
  const s32 ShmId = shmget(IPC_PRIVATE, MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600);
  if (ShmId < 0)
    PFATAL("shmget failed");

  std::string ShmStr = std::to_string(ShmId);
  setenv(SHM_ENV_VAR, ShmStr.c_str(), 1);

  *TraceBits = (u8 *)shmat(ShmId, nullptr, 0);
  if (*TraceBits == (void *)-1)
    PFATAL("shmat failed");

  return ShmId;
}

// Detect @@ in args
static void DetectFileArgs(const fs::path &Target, const fs::path &TC,
                           std::vector<const char *> &Argv) {
  // Replace the target (assume that it is the first argument)
  Argv[0] = Target.c_str();

  // Find and replace @@
  for (unsigned I = 1; I < Argv.size(); ++I)
    if (strstr(Argv[I], "@@"))
      Argv[I] = TC.c_str();
}

static void RunTarget(u8 *TraceBits, const std::vector<const char *> &Argv) {
  struct itimerval IT;
  int Status = 0;

  memset(TraceBits, 0, MAP_SIZE);
  MEM_BARRIER();

  const pid_t ChildPID = fork();
  if (ChildPID < 0)
    PFATAL("fork failed");

  if (!ChildPID) {
    struct rlimit R;

    s32 DevNullFD = open("/dev/null", O_RDWR);
    if (DevNullFD < 0 || dup2(DevNullFD, 1) < 0 || dup2(DevNullFD, 2) < 0) {
      *(u32 *)TraceBits = EXEC_FAIL_SIG;
      PFATAL("Desecriptor initialization failed");
    }
    close(DevNullFD);

    if (MemLimit) {
      R.rlim_max = R.rlim_cur = ((rlim_t)MemLimit) << 20;
#ifdef RLIMIT_AS
      setrlimit(RLIMIT_AS, &R); // Ignore errors
#else
      setrlimit(RLIMIT_DATA, &R); // Ignore errors
#endif
    }

    R.rlim_max = R.rlim_cur = 0;

    setrlimit(RLIMIT_CORE, &R); // Ignore errors

    setsid();
    execv(Argv[0], const_cast<char *const *>(&Argv[0]));

    *(u32 *)TraceBits = EXEC_FAIL_SIG;
    exit(0);
  }

  // Configure timeout, wait for child, cancel timeout

  if (ExecTimeout) {
    IT.it_value.tv_sec = (ExecTimeout / 1000);
    IT.it_value.tv_usec = (ExecTimeout % 1000) * 1000;
  }

  setitimer(ITIMER_REAL, &IT, nullptr);

  if (waitpid(ChildPID, &Status, 0) <= 0)
    FATAL("waitpid failed");

  IT.it_value.tv_sec = 0;
  IT.it_value.tv_usec = 0;
  setitimer(ITIMER_REAL, &IT, nullptr);

  MEM_BARRIER();

  // Cleanup bitmap, analyze exit condition, etc.

  if (*(u32 *)TraceBits == EXEC_FAIL_SIG)
    FATAL("Unable to execute '%s'", Argv[0]);

#ifdef WORD_SIZE_64
  ClassifyCounts((u64 *)TraceBits);
#else
  ClassifyCounts((u32 *)TraceBits);
#endif
}

////////////////////////////////////////////////////////////////////////////////

static void NewTestcase(const struct inotify_event *Event,
                        const fs::path &Target,
                        const std::vector<std::string> &TargetArgs) {
  // Testcases are still being created. Reset the timeout
  alarm(Timeout);

  // Check for a valid testcase
  if (strncmp(Event->name, "id:", 3) != 0)
    return;

  ACTF("New testcase '%s'.", Event->name);

  const fs::path Testcase = OutDir / "queue" / ".blackbox" / Event->name;
  u8 *TraceBits = nullptr;
  u8 HNB = 0;

  std::vector<const char *> Argv;
  ToCStringVector(TargetArgs, Argv);

  const s32 ShmId = SetupShm(&TraceBits);
  DetectFileArgs(Target, Testcase, Argv);
  RunTarget(TraceBits, Argv);

  // Ensure only one thread updates the coverage bitmap at any one time
  {
    std::unique_lock<std::mutex> Lock(VirginBitsLock);
    HNB = HasNewBits(TraceBits, VirginBits);
  }

  if (HNB) {
    const u32 TBytes = CountNon255Bytes(VirginBits);
    double TByteRatio = ((double)TBytes * 100) / MAP_SIZE;

    ACTF("'%s' led to new coverage. Bitmap coverage now %.02f%%.", Event->name,
         TByteRatio);

    if (Csv) {
      // Ensure only one thread writes to the CSV file at any one time
      std::unique_lock<std::mutex> Lock(CsvLock);
      fprintf(Csv, "%llu,%.02f,%s\n", GetCurTime() / 1000, TByteRatio,
              Event->name + 3);
      fflush(Csv);
    }
  } else {
    fs::remove(Testcase);
  }

  RemoveShm(ShmId);
}

static void ParseFuzzerStats(std::istream &IS,
                             std::vector<std::string> &TargetArgs) {
  // Reset argv index
  optind = 1;

  // Get the command line from fuzzer_stats
  bool CmdLineFound = false;
  std::string Line;
  while (std::getline(IS, Line)) {
    if (Line.rfind("command_line      : ", 0) == 0) {
      CmdLineFound = true;
      break;
    }
  }

  if (!CmdLineFound)
    FATAL("Unable to find AFL command-line in fuzzer_stats");

  // Parse the command line
  std::istringstream ISS(Line.substr(20));
  std::vector<std::string> Argv{std::istream_iterator<std::string>(ISS),
                                std::istream_iterator<std::string>()};
  std::vector<const char *> ArgvOpt;
  ToCStringVector(Argv, ArgvOpt);
  int Argc = Argv.size();
  int Opt;

  // Get AFL arguments
  while ((Opt = getopt(Argc, const_cast<char *const *>(&ArgvOpt[0]),
                       AFL_OPTSTRING)) > 0) {
    switch (Opt) {
    case 'm': {
      u8 Suffix = 'M';

      if (!strcmp(optarg, "none")) {
        MemLimit = 0;
        break;
      }

      if (sscanf(optarg, "%llu%c", &MemLimit, &Suffix) < 1 || optarg[0] == '-')
        FATAL("Bad syntax used for -m");

      switch (Suffix) {
      case 'T':
        MemLimit *= 1024 * 1024;
        break;
      case 'G':
        MemLimit *= 1024;
        break;
      case 'k':
        MemLimit /= 1024;
        break;
      case 'M':
        break;
      default:
        FATAL("Unsupported suffix or bad syntax for -m");
      }

      if (MemLimit < 5)
        FATAL("Dangerously low value of -m");
      if (sizeof(rlim_t) == 4 && MemLimit > 2000)
        FATAL("Value of -m out of range on 32-bit systems");
    } break;
    case 't': {
      if (strcmp(optarg, "none")) {
        ExecTimeout = std::stoul(optarg);
        if (ExecTimeout < 20 || optarg[0] == '-')
          FATAL("Dangerously low value of -t");
      }
    } break;
    }
  }

  // The remaining arguments are target arguments
  for (unsigned I = optind; I < Argc; ++I)
    TargetArgs.push_back(Argv[I]);
}

static void HandleSig(int Sig) {
  ACTF("%s detected. Quitting...", strsignal(Sig));
  Stop = true;
}

static void SetupSignalHandlers() {
  struct sigaction SA;

  sigemptyset(&SA.sa_mask);
  memset(&SA, 0, sizeof(struct sigaction));
  SA.sa_handler = HandleSig;

  sigaction(SIGINT, &SA, nullptr);
  sigaction(SIGALRM, &SA, nullptr);
}

static void Usage(const char *Argv0) {
  SAYF("\n%s [ options ] -- /path/to/afl/out/dir\n\n"
       "Required parameters:\n\n"
       "  -a /path/to/target  - Instrumented target\n\n"
       "Optional parameters:\n\n"
       "  -j jobs             - Number of worker threads\n"
       "  -c /path/to/csv     - Write coverage information to a CSV\n"
       "  -t sec              - Timeout\n\n",
       Argv0);

  exit(1);
}

int main(int Argc, char *Argv[]) {
  char EventBuf[EVENT_BUFFER_SIZE];

  int Opt;
  unsigned Jobs = 1;
  fs::path InstTarget;

  while ((Opt = getopt(Argc, Argv, "+j:c:t:a:h")) > 0) {
    switch (Opt) {
    case 'j': { // Num. jobs
      Jobs = std::stoul(optarg);
    } break;
    case 'c': { // CSV path
      if ((Csv = fopen(optarg, "w")) == nullptr)
        PFATAL("fopen failed");
      fprintf(Csv, "unix_time,map_size,execs\n");
    } break;
    case 't': { // Timeout
      Timeout = std::stoul(optarg);
    } break;
    case 'a': { // Instrumented target
      InstTarget = optarg;
    } break;
    case 'h': // Help
    default:
      Usage(Argv[0]);
    }
  }

  if (InstTarget.empty()) {
    SAYF("No target specified\n");
    Usage(Argv[0]);
  }

  if (optind >= Argc) {
    SAYF("No AFL output directory specified\n");
    Usage(Argv[0]);
  }

  OutDir = Argv[optind];

  // Setup signal handlers
  SetupSignalHandlers();

  // Parse fuzzer_stats
  std::ifstream IFS(OutDir / "fuzzer_stats");
  std::vector<std::string> TargetArgs;
  ParseFuzzerStats(IFS, TargetArgs);
  IFS.close();

  // Initialize AFL coverage data structures
  InitCountClass16();
  memset(VirginBits, 255, MAP_SIZE);

  // Initialize thread pool for handling testcase creation
  ThreadPool Pool(Jobs);

  // Configure inotify to emit an event whenever a new testcase is written to
  // the .blackbox directory
  int FD = inotify_init1(IN_NONBLOCK);
  if (FD < 0)
    PFATAL("inotify_init1 failed");

  fd_set WS;
  FD_ZERO(&WS);
  FD_SET(FD, &WS);

  int WD = inotify_add_watch(FD, (OutDir / "queue" / ".blackbox").c_str(),
                             IN_CLOSE_WRITE);
  if (WD < 0)
    PFATAL("inotify_add_watch failed");

  OKF("Configured inotify watch.");

  while (true) {
    if (Stop)
      break;

    if (select(FD + 1, &WS, nullptr, nullptr, nullptr) < 0 && !Stop)
      PFATAL("select failed");

    ssize_t ReadLen = read(FD, EventBuf, EVENT_BUFFER_SIZE);
    if (ReadLen < 0 && !Stop)
      PFATAL("read failed");

    for (char *Ptr = EventBuf; Ptr < EventBuf + ReadLen;) {
      const struct inotify_event *Event = (const struct inotify_event *)Ptr;
      Pool.Enqueue(NewTestcase, Event, InstTarget, TargetArgs);

      Ptr += Event->len + EVENT_SIZE;
    }
  }

  // Cleanup
  close(FD);
  if (Csv)
    fclose(Csv);

  return 0;
}
