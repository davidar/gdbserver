#define _GNU_SOURCE
#include <arpa/inet.h>
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

struct reg_struct {
  int idx, size;
};

#define ARCH_REG_NUM (sizeof(regs_map) / sizeof(struct reg_struct))

#ifdef __i386__

#include <sys/reg.h>

#define SZ 4
#define FEATURE_STR "l<target version=\"1.0\"><architecture>i386</architecture></target>"
static uint8_t break_instr[] = {0xcc};

#define PC EIP
#define EXTRA_NUM 41
#define EXTRA_REG ORIG_EAX
#define EXTRA_SIZE 4

typedef struct user_regs_struct regs_struct;

// gdb/features/i386/32bit-core.c
struct reg_struct regs_map[] = {
    {EAX, 4}, {ECX, 4}, {EDX, 4}, {EBX, 4}, {UESP, 4}, {EBP, 4}, {ESI, 4}, {EDI, 4},
    {EIP, 4}, {EFL, 4}, {CS, 4},  {SS, 4},  {DS, 4},   {ES, 4},  {FS, 4},  {GS, 4},
};

#endif /* __i386__ */

#ifdef __x86_64__

#include <sys/reg.h>

#define SZ 8
#define FEATURE_STR "l<target version=\"1.0\"><architecture>i386:x86-64</architecture></target>"
static uint8_t break_instr[] = {0xcc};

#define PC RIP
#define EXTRA_NUM 57
#define EXTRA_REG ORIG_RAX
#define EXTRA_SIZE 8

typedef struct user_regs_struct regs_struct;

// gdb/features/i386/64bit-core.c
struct reg_struct regs_map[] = {
    {RAX, 8}, {RBX, 8},    {RCX, 8}, {RDX, 8}, {RSI, 8}, {RDI, 8}, {RBP, 8}, {RSP, 8},
    {R8, 8},  {R9, 8},     {R10, 8}, {R11, 8}, {R12, 8}, {R13, 8}, {R14, 8}, {R15, 8},
    {RIP, 8}, {EFLAGS, 4}, {CS, 4},  {SS, 4},  {DS, 4},  {ES, 4},  {FS, 4},  {GS, 4},
};

#endif /* __x86_64__ */

#ifdef __arm__

#define SZ 4
#define FEATURE_STR "l<target version=\"1.0\"><architecture>arm</architecture></target>"

static uint8_t break_instr[] = {0xf0, 0x01, 0xf0, 0xe7};

#define PC 15
#define EXTRA_NUM 25
#define EXTRA_REG 16
#define EXTRA_SIZE 4

typedef struct user_regs regs_struct;

struct reg_struct regs_map[] = {
    {0, 4}, {1, 4}, {2, 4},  {3, 4},  {4, 4},  {5, 4},  {6, 4},  {7, 4},
    {8, 4}, {9, 4}, {10, 4}, {11, 4}, {12, 4}, {13, 4}, {14, 4}, {15, 4},
};

#endif /* __arm__ */

size_t *entry_stack_ptr;

#define THREAD_NUMBER 64

struct thread_id_t {
  pid_t pid, tid;
  int stat;
};

struct thread_list_t {
  struct thread_id_t t[THREAD_NUMBER];
  struct thread_id_t *curr;
  int len;
} threads;

#define BREAKPOINT_NUMBER 64

struct debug_breakpoint_t {
  size_t addr, orig_data;
} breakpoints[BREAKPOINT_NUMBER];

uint8_t tmpbuf[0x20000];
bool attach = false;

static const char hexchars[] = "0123456789abcdef";

int hex(char ch) {
  if ((ch >= 'a') && (ch <= 'f')) return (ch - 'a' + 10);
  if ((ch >= '0') && (ch <= '9')) return (ch - '0');
  if ((ch >= 'A') && (ch <= 'F')) return (ch - 'A' + 10);
  return (-1);
}

char *mem2hex(char *mem, char *buf, int count) {
  unsigned char ch;
  for (int i = 0; i < count; i++) {
    ch = *(mem++);
    *buf++ = hexchars[ch >> 4];
    *buf++ = hexchars[ch % 16];
  }
  *buf = 0;
  return (buf);
}

char *hex2mem(char *buf, char *mem, int count) {
  unsigned char ch;
  for (int i = 0; i < count; i++) {
    ch = hex(*buf++) << 4;
    ch = ch + hex(*buf++);
    *(mem++) = ch;
  }
  return (mem);
}

int unescape(char *msg, int len) {
  char *w = msg, *r = msg;
  while (r - msg < len) {
    char v = *r++;
    *w++ = (v != '}') ? v : *r++ ^ 0x20;
  }
  return w - msg;
}

// packet processing based on GdbConnection.cc in rr

#define PACKET_BUF_SIZE 0x8000

static const char INTERRUPT_CHAR = '\x03';

struct packet_buf {
  uint8_t buf[PACKET_BUF_SIZE];
  int end;
} in, out;

int sock_fd;

void pktbuf_insert(struct packet_buf *pkt, const uint8_t *buf, ssize_t len) {
  if (pkt->end + len >= sizeof(pkt->buf)) {
    puts("Packet buffer overflow");
    exit(-2);
  }
  memcpy(pkt->buf + pkt->end, buf, len);
  pkt->end += len;
}

void pktbuf_erase_head(struct packet_buf *pkt, ssize_t end) {
  memmove(pkt->buf, pkt->buf + end, pkt->end - end);
  pkt->end -= end;
}

static bool poll_socket(int sock_fd, short events) {
  struct pollfd pfd;
  memset(&pfd, 0, sizeof(pfd));
  pfd.fd = sock_fd;
  pfd.events = events;

  int ret = poll(&pfd, 1, -1);
  if (ret < 0) {
    perror("poll() failed");
    exit(-1);
  }
  return ret > 0;
}

void write_packet_bytes(const uint8_t *data, size_t num_bytes) {
  uint8_t checksum = 0;
  pktbuf_insert(&out, "$", 1);
  for (size_t i = 0; i < num_bytes; ++i)
    checksum += data[i];
  pktbuf_insert(&out, data, num_bytes);
  pktbuf_insert(&out, "#", 1);
  char buf[32];
  size_t len = snprintf(buf, sizeof(buf) - 1, "%02x", checksum);
  pktbuf_insert(&out, buf, len);
}

void write_packet(const char *data) { write_packet_bytes((const uint8_t *)data, strlen(data)); }

void write_binary_packet(const char *pfx, const uint8_t *data, ssize_t num_bytes) {
  uint8_t *buf;
  ssize_t pfx_num_chars = strlen(pfx);
  ssize_t buf_num_bytes = 0;
  int i;

  buf = malloc(2 * num_bytes + pfx_num_chars);
  memcpy(buf, pfx, pfx_num_chars);
  buf_num_bytes += pfx_num_chars;

  for (i = 0; i < num_bytes; ++i) {
    uint8_t b = data[i];
    switch (b) {
    case '#':
    case '$':
    case '}':
    case '*':
      buf[buf_num_bytes++] = '}';
      buf[buf_num_bytes++] = b ^ 0x20;
      break;
    default: buf[buf_num_bytes++] = b; break;
    }
  }
  write_packet_bytes(buf, buf_num_bytes);
  free(buf);
}

bool skip_to_packet_start() {
  ssize_t end = -1;
  for (size_t i = 0; i < in.end; ++i)
    if (in.buf[i] == '$' || in.buf[i] == INTERRUPT_CHAR) {
      end = i;
      break;
    }

  if (end < 0) {
    in.end = 0;
    return false;
  }

  pktbuf_erase_head(&in, end);
  assert(1 <= in.end);
  assert('$' == in.buf[0] || INTERRUPT_CHAR == in.buf[0]);
  return true;
}

static bool async_io_enabled;

static void input_interrupt(int unused) {
  if (async_io_enabled) {
    int nread;
    char buf;
    nread = read(sock_fd, &buf, 1);
    assert(nread == 1 && buf == INTERRUPT_CHAR);
    kill(-threads.t[0].pid, SIGINT);
  }
}

int gdb_signal_from_host(int hostsig) {
  switch (hostsig) {
  case SIGHUP:    return 1;
  case SIGINT:    return 2;
  case SIGQUIT:   return 3;
  case SIGILL:    return 4;
  case SIGTRAP:   return 5;
  case SIGABRT:   return 6;
  // case SIGEMT:    return 7;
  case SIGFPE:    return 8;
  case SIGKILL:   return 9;
  case SIGBUS:    return 10;
  case SIGSEGV:   return 11;
  case SIGSYS:    return 12;
  case SIGPIPE:   return 13;
  case SIGALRM:   return 14;
  case SIGTERM:   return 15;
  case SIGURG:    return 16;
  case SIGSTOP:   return 17;
  case SIGTSTP:   return 18;
  case SIGCONT:   return 19;
  case SIGCHLD:   return 20;
  case SIGTTIN:   return 21;
  case SIGTTOU:   return 22;
  case SIGIO:     return 23;
  case SIGXCPU:   return 24;
  case SIGXFSZ:   return 25;
  case SIGVTALRM: return 26;
  case SIGPROF:   return 27;
  case SIGWINCH:  return 28;
  // case SIGLOST:   return 29;
  case SIGUSR1:   return 30;
  case SIGUSR2:   return 31;
  case SIGPWR:    return 32;
  default:        return 143; // GDB_SIGNAL_UNKNOWN
  }
}

bool check_exit() {
  if (WIFEXITED(threads.curr->stat) && threads.len > 1) {
    threads.curr->pid = 0;
    threads.curr->tid = 0;
    threads.curr = NULL;
    threads.len--;
    return true;
  }
  return false;
}

void check_sigtrap() {
  siginfo_t info;
  ptrace(PTRACE_GETSIGINFO, threads.curr->tid, NULL, &info);
  if (info.si_code == SI_KERNEL && info.si_signo == SIGTRAP) {
    size_t pc = ptrace(PTRACE_PEEKUSER, threads.curr->tid, SZ * PC, NULL);
    pc -= sizeof(break_instr);
    for (int i = 0; i < BREAKPOINT_NUMBER; i++)
      if (breakpoints[i].addr == pc) {
        ptrace(PTRACE_POKEUSER, threads.curr->tid, SZ * PC, pc);
        break;
      }
  }
}

bool check_sigstop() {
  siginfo_t info;
  ptrace(PTRACE_GETSIGINFO, threads.curr->tid, NULL, &info);
  if (info.si_code == SI_TKILL && info.si_signo == SIGSTOP) {
    ptrace(PTRACE_CONT, threads.curr->tid, NULL, NULL);
    return true;
  }
  return false;
}

bool check_clone() {
  if (threads.curr->stat >> 8 == (SIGTRAP | (PTRACE_EVENT_CLONE << 8))) {
    size_t newtid;
    int stat;
    ptrace(PTRACE_GETEVENTMSG, threads.curr->tid, NULL, (long)&newtid);
    if (waitpid(newtid, &stat, __WALL) > 0) {
      for (int i = 0; i < THREAD_NUMBER; i++)
        if (!threads.t[i].tid) {
          threads.t[i].pid = threads.curr->pid;
          threads.t[i].tid = newtid;
          threads.len++;
          break;
        }
      ptrace(PTRACE_CONT, newtid, NULL, NULL);
    }
    ptrace(PTRACE_CONT, threads.curr->tid, NULL, NULL);
    return true;
  }
  return false;
}

void set_curr_thread(pid_t tid) {
  for (int i = 0; i < THREAD_NUMBER; i++)
    if (threads.t[i].tid == tid) {
      threads.curr = &threads.t[i];
      break;
    }
}

void prepare_resume_reply(uint8_t *buf, bool cont) {
  if (WIFEXITED(threads.curr->stat)) sprintf(buf, "W%02x", WEXITSTATUS(threads.curr->stat));
  if (WIFSTOPPED(threads.curr->stat)) {
    if (cont) {
      struct thread_id_t *cthread = threads.curr;
      for (int i = 0, n = 0; i < THREAD_NUMBER && n < threads.len - 1; i++)
        if (threads.t[i].pid && threads.t[i].tid != cthread->tid) do {
            threads.curr = &threads.t[i];
            if (syscall(SYS_tgkill, threads.curr->pid, threads.curr->tid, SIGSTOP) == -1)
              printf("Failed to stop thread %d\n", threads.curr->tid);
            waitpid(threads.curr->tid, &threads.curr->stat, __WALL);
            check_exit();
            check_sigtrap();
          } while (check_clone());
      threads.curr = cthread;
    }
    sprintf(buf, "T%02xthread:p%02x.%02x;", gdb_signal_from_host(WSTOPSIG(threads.curr->stat)),
            threads.curr->pid, threads.curr->tid);
  }
}

static int gdb_open_flags_to_system_flags(size_t flags) {
  int ret;
  switch (flags & 3) {
  case 0:  ret = O_RDONLY; break;
  case 1:  ret = O_WRONLY; break;
  case 2:  ret = O_RDWR; break;
  default: assert(0); return 0;
  }

  assert(!(flags & ~(size_t)(3 | 0x8 | 0x200 | 0x400 | 0x800)));

  if (flags & 0x8) ret |= O_APPEND;
  if (flags & 0x200) ret |= O_CREAT;
  if (flags & 0x400) ret |= O_TRUNC;
  if (flags & 0x800) ret |= O_EXCL;
  return ret;
}

int main(int argc, char *argv[]) {
  pid_t pid;
  char **next_arg = &argv[1];
  char *arg_end, *target = NULL;
  int stat;

  if (*next_arg != NULL && strcmp(*next_arg, "--attach") == 0) {
    attach = true;
    next_arg++;
  }

  target = *next_arg;
  next_arg++;

  if (target == NULL || *next_arg == NULL) {
    printf("Usage : gdbserver 127.0.0.1:1234 a.out or gdbserver --attach 127.0.0.1:1234 2468\n");
    exit(-1);
  }

  if (attach) {
    pid = atoi(*next_arg);
    char dirname[64];
    DIR *dir;
    struct dirent *ent;
    int i = 0;

    snprintf(dirname, sizeof dirname, "/proc/%d/task/", (int)pid);
    dir = opendir(dirname);
    if (!dir) perror("opendir()");
    while ((ent = readdir(dir)) != NULL) {
      if (ent->d_name[0] == '.') continue;
      threads.t[i].pid = pid;
      threads.t[i].tid = atoi(ent->d_name);
      threads.len++;
      i++;
    }
    closedir(dir);
    for (int i = 0, n = 0; i < THREAD_NUMBER && n < threads.len; i++)
      if (threads.t[i].tid) {
        if (ptrace(PTRACE_ATTACH, threads.t[i].tid, NULL, NULL) < 0) {
          perror("ptrace()");
          return -1;
        }
        if (waitpid(threads.t[i].tid, &threads.t[i].stat, __WALL) < 0) {
          perror("waitpid");
          return -1;
        }
        ptrace(PTRACE_SETOPTIONS, threads.t[i].tid, NULL, PTRACE_O_TRACECLONE);
        n++;
      }
  } else {
    pid = fork();
    if (pid == 0) {
      char **args = next_arg;
      setpgrp();
      ptrace(PTRACE_TRACEME, 0, NULL, NULL);
      execvp(args[0], args);
      perror(args[0]);
      _exit(1);
    }
    if (waitpid(pid, &stat, __WALL) < 0) {
      perror("waitpid");
      return -1;
    }
    threads.t[0].pid = threads.t[0].tid = pid;
    threads.t[0].stat = stat;
    threads.len = 1;
    ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACECLONE | PTRACE_O_EXITKILL);
  }
  threads.curr = &threads.t[0];

  sigset_t sigio_set;
  sigemptyset(&sigio_set);
  sigaddset(&sigio_set, SIGIO);
  sigprocmask(SIG_BLOCK, &sigio_set, NULL);
  signal(SIGIO, input_interrupt);

  int ret;
  char *port_str;
  int port;
  struct sockaddr_in addr;
  char *port_end;
  const int one = 1;
  int listen_fd;

  port_str = strchr(target, ':');
  if (port_str == NULL) {
    printf("Bad port argument: %s", target);
    exit(-1);
  }
  *port_str = '\0';

  port = strtoul(port_str + 1, &port_end, 10);
  if (port_str[1] == '\0' || *port_end != '\0') {
    printf("Bad port argument: %s", target);
    exit(-1);
  }

  listen_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
  if (listen_fd < 0) {
    perror("socket() failed");
    exit(-1);
  }

  ret = setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  if (ret < 0) {
    perror("setsockopt() failed");
    exit(-1);
  }

  printf("Listening on port %d\n", port);
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = *target ? inet_addr(target) : INADDR_ANY;
  addr.sin_port = htons(port);

  if (addr.sin_addr.s_addr == INADDR_NONE) {
    printf("Bad host argument: %s", target);
    exit(-1);
  }

  ret = bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr));
  if (ret < 0) {
    perror("bind() failed");
    exit(-1);
  }

  ret = listen(listen_fd, 1);
  if (ret < 0) {
    perror("listen() failed");
    exit(-1);
  }

  sock_fd = accept(listen_fd, NULL, NULL);
  if (sock_fd < 0) {
    perror("accept() failed");
    exit(-1);
  }

  ret = setsockopt(sock_fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
  ret = setsockopt(sock_fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

#if defined(F_SETFL) && defined(FASYNC)
  int save_fcntl_flags;

  save_fcntl_flags = fcntl(sock_fd, F_GETFL, 0);
  fcntl(sock_fd, F_SETFL, save_fcntl_flags | FASYNC);
#if defined(F_SETOWN)
  fcntl(sock_fd, F_SETOWN, getpid());
#endif
#endif

  close(listen_fd);
  in.end = 0;
  out.end = 0;

  while (true) {
    while (!skip_to_packet_start()) {
      uint8_t buf[4096];
      poll_socket(sock_fd, POLLIN);
      ssize_t nread = read(sock_fd, buf, sizeof(buf));
      if (nread <= 0) {
        puts("Connection closed");
        exit(0);
      }
      pktbuf_insert(&in, buf, nread);
    }
    pktbuf_insert(&out, "+", 1);

    uint8_t *packetend_ptr = (uint8_t *)memchr(in.buf, '#', in.end);
    int packetend = packetend_ptr - in.buf;
    assert('$' == in.buf[0]);
    char request = in.buf[1];
    char *payload = (char *)&in.buf[2];
    in.buf[packetend] = '\0';

    uint8_t checksum = 0;
    uint8_t checksum_str[3];
    for (int i = 1; i < packetend; i++)
      checksum += in.buf[i];
    assert(checksum == (hex(in.buf[packetend + 1]) << 4 | hex(in.buf[packetend + 2])));

    switch (request) {
    case 'D':
      for (int i = 0, n = 0; i < THREAD_NUMBER && n < threads.len; i++)
        if (threads.t[i].tid)
          if (ptrace(PTRACE_DETACH, threads.t[i].tid, NULL, NULL) < 0) perror("ptrace()");
      exit(0);
    case 'g': {
      regs_struct regs;
      uint8_t regbuf[20];
      tmpbuf[0] = '\0';
      ptrace(PTRACE_GETREGS, threads.curr->tid, NULL, &regs);
      for (int i = 0; i < ARCH_REG_NUM; i++) {
        mem2hex((void *)(((size_t *)&regs) + regs_map[i].idx), regbuf, regs_map[i].size);
        regbuf[regs_map[i].size * 2] = '\0';
        strcat(tmpbuf, regbuf);
      }
      write_packet(tmpbuf);
      break;
    }
    case 'H':
      if ('g' == *payload++) {
        pid_t tid;
        char *dot = strchr(payload, '.');
        assert(dot);
        tid = strtol(dot, NULL, 16);
        if (tid > 0) set_curr_thread(tid);
      }
      write_packet("OK");
      break;
    case 'm': {
      size_t maddr, mlen, mdata;
      assert(sscanf(payload, "%zx,%zx", &maddr, &mlen) == 2);
      if (mlen * SZ * 2 > 0x20000) {
        puts("Buffer overflow!");
        exit(-1);
      }
      for (int i = 0; i < mlen; i += SZ) {
        errno = 0;
        mdata = ptrace(PTRACE_PEEKDATA, threads.curr->tid, maddr + i, NULL);
        if (errno) {
          sprintf(tmpbuf, "E%02x", errno);
          break;
        }
        for (int i = 0; i < BREAKPOINT_NUMBER; i++) {
          size_t bp_addr = breakpoints[i].addr;
          size_t bp_size = sizeof(break_instr);
          if (bp_addr && bp_addr + bp_size > maddr && bp_addr < maddr + sizeof(size_t)) {
            for (size_t j = 0; j < bp_size; j++) {
              if (bp_addr + j >= maddr && bp_addr + j < maddr + sizeof(size_t))
                ((uint8_t *)&mdata)[bp_addr + j - maddr] =
                    ((uint8_t *)&breakpoints[i].orig_data)[j];
            }
          }
        }
        mem2hex((void *)&mdata, tmpbuf + i * 2, (mlen - i >= SZ ? SZ : mlen - i));
      }
      tmpbuf[mlen * 2] = '\0';
      write_packet(tmpbuf);
      break;
    }
    case 'M': {
      size_t maddr, mlen, mdata;
      assert(sscanf(payload, "%zx,%zx", &maddr, &mlen) == 2);
      for (int i = 0; i < mlen; i += SZ) {
        if (mlen - i >= SZ)
          hex2mem(payload + i * 2, (void *)&mdata, SZ);
        else {
          mdata = ptrace(PTRACE_PEEKDATA, threads.curr->tid, maddr + i, NULL);
          hex2mem(payload + i * 2, (void *)&mdata, mlen - i);
        }
        ptrace(PTRACE_POKEDATA, threads.curr->tid, maddr + i, mdata);
      }
      write_packet("OK");
      break;
    }
    case 'p': {
      int i = strtol(payload, NULL, 16);
      if (i >= ARCH_REG_NUM && i != EXTRA_NUM) {
        write_packet("E01");
        break;
      }
      size_t regdata;
      if (i == EXTRA_NUM) {
        regdata = ptrace(PTRACE_PEEKUSER, threads.curr->tid, SZ * EXTRA_REG, NULL);
        mem2hex((void *)&regdata, tmpbuf, EXTRA_SIZE);
        tmpbuf[EXTRA_SIZE * 2] = '\0';
      } else {
        regdata = ptrace(PTRACE_PEEKUSER, threads.curr->tid, SZ * regs_map[i].idx, NULL);
        mem2hex((void *)&regdata, tmpbuf, regs_map[i].size);
        tmpbuf[regs_map[i].size * 2] = '\0';
      }
      write_packet(tmpbuf);
      break;
    }
    case 'P': {
      int i = strtol(payload, &payload, 16);
      assert('=' == *payload++);
      if (i >= ARCH_REG_NUM && i != EXTRA_NUM) {
        write_packet("E01");
        break;
      }
      size_t regdata = 0;
      hex2mem(payload, (void *)&regdata, SZ * 2);
      if (i == EXTRA_NUM)
        ptrace(PTRACE_POKEUSER, threads.curr->tid, SZ * EXTRA_REG, regdata);
      else
        ptrace(PTRACE_POKEUSER, threads.curr->tid, SZ * regs_map[i].idx, regdata);
      write_packet("OK");
      break;
    }
    case 'q': {
      const char *name;
      char *args;

      args = strchr(payload, ':');
      if (args) *args++ = '\0';
      name = payload;
      if (!strcmp(name, "C")) {
        snprintf(tmpbuf, sizeof(tmpbuf), "QCp%02x.%02x", threads.curr->pid, threads.curr->tid);
        write_packet(tmpbuf);
      }
      if (!strcmp(name, "Attached")) write_packet(attach ? "1" : "0");
      if (!strcmp(name, "Offsets")) write_packet("");
      if (!strcmp(name, "Supported"))
        write_packet("PacketSize=8000;qXfer:features:read+;qXfer:auxv:read+;qXfer:exec-file:read+;"
                     "multiprocess+");
      if (!strcmp(name, "Symbol")) write_packet("OK");
      if (name == strstr(name, "ThreadExtraInfo")) {
        args = payload;
        args = 1 + strchr(args, ',');
        write_packet("41414141");
      }
      if (!strcmp(name, "TStatus")) write_packet("");
      if (!strcmp(name, "Xfer")) {
        name = args;
        args = strchr(args, ':');
        *args++ = '\0';
        const char *mode = args;
        args = strchr(args, ':');
        *args++ = '\0';
        if (!strcmp(name, "features") && !strcmp(mode, "read")) write_packet(FEATURE_STR);
        if (!strcmp(name, "auxv") && !strcmp(mode, "read")) {
          uint8_t proc_auxv_path[20];
          FILE *fp;
          int ret;
          sprintf(proc_auxv_path, "/proc/%d/auxv", threads.t[0].pid);
          fp = fopen(proc_auxv_path, "r");
          ret = fread(tmpbuf, 1, sizeof(tmpbuf), fp);
          fclose(fp);
          write_binary_packet("l", tmpbuf, ret);
        }
        if (!strcmp(name, "exec-file") && !strcmp(mode, "read")) {
          uint8_t proc_exe_path[20], file_path[256] = {'l'};
          sprintf(proc_exe_path, "/proc/%d/exe", threads.t[0].pid);
          realpath(proc_exe_path, file_path + 1);
          write_packet(file_path);
        }
      }
      if (!strcmp(name, "fThreadInfo")) {
        struct thread_id_t *ptr = threads.t;
        uint8_t pid_buf[20];
        assert(threads.len > 0);
        strcpy(tmpbuf, "m");
        for (int i = 0; i < threads.len; i++, ptr++) {
          while (!ptr->tid)
            ptr++;
          snprintf(pid_buf, sizeof(pid_buf), "p%02x.%02x,", ptr->pid, ptr->tid);
          strcat(tmpbuf, pid_buf);
        }
        tmpbuf[strlen(tmpbuf) - 1] = '\0';
        write_packet(tmpbuf);
      }
      if (!strcmp(name, "sThreadInfo")) write_packet("l");
      break;
    }
    case 'v': {
      const char *name;
      char *args;
      args = strchr(payload, ';');
      if (args) *args++ = '\0';
      name = payload;

      if (!strcmp("Cont", name)) {
        if (args[0] == 'c') {
          for (int i = 0, n = 0; i < THREAD_NUMBER && n < threads.len; i++)
            if (threads.t[i].tid) {
              ptrace(PTRACE_CONT, threads.t[i].tid, NULL, NULL);
              n++;
            }
          do {
            pid_t tid;
            int stat;
            sigset_t sigio_set;
            sigemptyset(&sigio_set);
            sigaddset(&sigio_set, SIGIO);
            sigprocmask(SIG_UNBLOCK, &sigio_set, NULL);
            async_io_enabled = true;
            tid = waitpid(-1, &stat, __WALL);
            set_curr_thread(tid);
            threads.curr->stat = stat;
            sigprocmask(SIG_BLOCK, &sigio_set, NULL);
            async_io_enabled = false;
          } while (check_exit() || check_sigstop() || check_clone());
          prepare_resume_reply(tmpbuf, true);
          write_packet(tmpbuf);
        }
        if (args[0] == 's') {
          assert(args[1] == ':');
          char *dot = strchr(args, '.');
          assert(dot);
          pid_t tid = strtol(dot + 1, NULL, 16);
          set_curr_thread(tid);
          ptrace(PTRACE_SINGLESTEP, threads.curr->tid, NULL, NULL);
          waitpid(threads.curr->tid, &threads.curr->stat, __WALL);
          prepare_resume_reply(tmpbuf, false);
          write_packet(tmpbuf);
        }
      }
      if (!strcmp("Cont?", name)) write_packet("vCont;c;C;s;S;");
      if (!strcmp("Kill", name)) {
        kill(-threads.t[0].pid, SIGKILL);
        write_packet("OK");
      }
      if (!strcmp("MustReplyEmpty", name)) write_packet("");
      if (name == strstr(name, "File:")) {
        char *operation = strchr(name, ':') + 1;
        if (operation == strstr(operation, "open:")) {
          char result[10];
          char *parameter = strchr(operation, ':') + 1;
          char *end = strchr(parameter, ',');
          int len, fd;
          size_t flags, mode;
          assert(end != NULL);
          *end = 0;
          len = strlen(parameter);
          hex2mem(parameter, tmpbuf, len);
          tmpbuf[len / 2] = '\0';
          parameter += len + 1;
          assert(sscanf(parameter, "%zx,%zx", &flags, &mode) == 2);
          flags = gdb_open_flags_to_system_flags(flags);
          assert((mode & ~(int64_t)0777) == 0);
          fd = open(tmpbuf, flags, mode);
          sprintf(result, "F%x", fd);
          write_packet(result);
        } else if (operation == strstr(operation, "close:")) {
          char *parameter = strchr(operation, ':') + 1;
          size_t fd;
          assert(sscanf(parameter, "%zx", &fd) == 1);
          close(fd);
          write_packet("F0");
        } else if (operation == strstr(operation, "pread:")) {
          char *parameter = strchr(operation, ':') + 1;
          size_t fd, size, offset;
          assert(sscanf(parameter, "%zx,%zx,%zx", &fd, &size, &offset) == 3);
          assert(size >= 0);
          if (size * 2 > PACKET_BUF_SIZE) size = PACKET_BUF_SIZE / 2;
          assert(offset >= 0);
          char *buf = malloc(size);
          FILE *fp = fdopen(fd, "rb");
          fseek(fp, offset, SEEK_SET);
          int ret = fread(buf, 1, size, fp);
          sprintf(tmpbuf, "F%x;", ret);
          write_binary_packet(tmpbuf, buf, ret);
          free(buf);
        } else if (operation == strstr(operation, "setfs:")) {
          char *endptr;
          int64_t pid = strtol(operation + 6, &endptr, 16);
          assert(*endptr == 0);
          write_packet("F0");
        } else
          write_packet("");
      }
      break;
    }
    case 'X': {
      size_t maddr, mlen, mdata;
      int offset, new_len;
      assert(sscanf(payload, "%zx,%zx:%n", &maddr, &mlen, &offset) == 2);
      payload += offset;
      new_len = unescape(payload, (char *)packetend_ptr - payload);
      assert(new_len == mlen);
      for (int i = 0; i < mlen; i += SZ) {
        if (mlen - i >= SZ)
          memcpy((void *)&mdata, payload + i, SZ);
        else {
          mdata = ptrace(PTRACE_PEEKDATA, threads.curr->tid, maddr + i, NULL);
          memcpy((void *)&mdata, payload + i, mlen - i);
        }
        ptrace(PTRACE_POKEDATA, threads.curr->tid, maddr + i, mdata);
      }
      write_packet("OK");
      break;
    }
    case 'Z': {
      size_t type, addr, length;
      assert(sscanf(payload, "%zx,%zx,%zx", &type, &addr, &length) == 3);
      if (type == 0 && sizeof(break_instr)) {
        bool ret = false;
        for (int i = 0; i < BREAKPOINT_NUMBER; i++)
          if (breakpoints[i].addr == 0) {
            size_t data = ptrace(PTRACE_PEEKDATA, threads.curr->tid, (void *)addr, NULL);
            breakpoints[i].orig_data = data;
            breakpoints[i].addr = addr;
            assert(sizeof(break_instr) <= length);
            memcpy((void *)&data, break_instr, sizeof(break_instr));
            ptrace(PTRACE_POKEDATA, threads.curr->tid, (void *)addr, data);
            ret = true;
            break;
          }
        write_packet(ret ? "OK" : "E01");
      } else
        write_packet("");
      break;
    }
    case 'z': {
      size_t type, addr, length;
      assert(sscanf(payload, "%zx,%zx,%zx", &type, &addr, &length) == 3);
      if (type == 0) {
        bool ret = false;
        for (int i = 0; i < BREAKPOINT_NUMBER; i++)
          if (breakpoints[i].addr == addr) {
            ptrace(PTRACE_POKEDATA, threads.curr->tid, (void *)addr, breakpoints[i].orig_data);
            breakpoints[i].addr = 0;
            ret = true;
            break;
          }
        write_packet(ret ? "OK" : "E01");
      } else
        write_packet("");
      break;
    }
    case '?': write_packet("S05"); break;
    default:  write_packet("");
    }

    pktbuf_erase_head(&in, packetend + 3);

    size_t write_index = 0;
    while (write_index < out.end) {
      ssize_t nwritten;
      poll_socket(sock_fd, POLLOUT);
      nwritten = write(sock_fd, out.buf + write_index, out.end - write_index);
      if (nwritten < 0) {
        printf("Write error\n");
        exit(-2);
      }
      write_index += nwritten;
    }
    out.end = 0;
  }

  return 0;
}
