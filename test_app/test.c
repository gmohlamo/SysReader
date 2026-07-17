#define _GNU_SOURCE
#include <sched.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#define SYS_open 2    /* open()          */
#define SYS_read 0    /* read()          */
#define SYS_write 1   /* write()         */
#define SYS_close 3   /* close()         */
#define SYS_fork 57   /* fork()          */
#define SYS_clone 54  /* clone()          */
#define SYS_mmap 9    /*  mman()          */
#define SYS_munmap 11 /*  mman()          */

/* Flags for open() – we only need read‑only */
#define O_RDONLY 0

#define STACK_SIZE (1024 * 1024) /* Stack size for cloned child */

static int read_passwd(const char *path) {
  /* ---- open("/etc/passwd", O_RDONLY) ---- */
  int fd = (int)syscall(SYS_open, path, O_RDONLY);
  if (fd < 0) { /* could not open the file */
    _exit(1);
  }

  char buffer[1024];
  ssize_t nread = (ssize_t)syscall(SYS_read, fd, buffer, sizeof(buffer));
  if (nread > 0) {
    /* ---- write(buf, nread) to stdout ---- */
    syscall(SYS_write, STDOUT_FILENO, buffer, (unsigned long)nread);
    syscall(SYS_write, STDOUT_FILENO, "\n", 1);
  }

  /* ---- close(fd) ---- */
  syscall(SYS_close, fd);
  return 0;
}

int main(void) {
  char *stack;    /* Start of stack buffer */
  char *stackTop; /* End of stack buffer */
  const char *path = "/etc/passwd";
  long pid;
  unsigned long flags = CLONE_NEWUTS | SIGCHLD;

  // allocate stack memory
  stack = (void *)syscall(SYS_mmap, NULL, STACK_SIZE, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
  if (stack == MAP_FAILED) {
    _exit(1);
  }

  // FIX: Calculate stackTop BEFORE passing it to the assembly block
  stackTop = stack + STACK_SIZE; /* Assume stack grows downward */

  // Direct x86_64 Syscall Assembly
  // RAX = 56 (SYS_clone)
  // RDI = flags
  // RSI = stackTop
  __asm__ volatile("movq %1, %%rdi\n\t"  // Put flags into RDI
                   "movq %2, %%rsi\n\t"  // Put stackTop into RSI
                   "movq $56, %%rax\n\t" // Syscall number 56 for clone
                   "syscall\n\t"         // Invoke the kernel directly
                   "movq %%rax, %0\n\t"  // Store the return value into 'pid'
                   : "=r"(pid)
                   : "r"(flags), "r"(stackTop)
                   : "rax", "rdi", "rsi", "rcx", "r11", "memory");

  // Note: Raw Linux system calls return error codes as negative values
  // (-errno). If pid == -1, it means -EPERM (1), which stands for "Operation
  // Not Permitted".
  if (pid == -1) {
    syscall(SYS_write, 2, "Failed to get pid (EPERM: Run with sudo)\n", 40);
  } else if (pid < -1) {
    // If it's another negative number like -22 (-EINVAL), print that out
  } else if (pid == 0) {
    read_passwd(path);
    _exit(0);
  } else {
    // Parent context continues here
    waitpid(pid, NULL, 0);
    syscall(SYS_munmap, stack, STACK_SIZE);
  }

  return 0;
}
