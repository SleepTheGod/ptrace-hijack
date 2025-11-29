# ✨ ptrace-hijack

### **Runtime Process Injection Using ptrace (linux.c)**

By **Taylor Christian Newsome**

## Overview

`ptrace-hijack` is a minimal C program that demonstrates how to attach to a running Linux process, read its CPU registers, and write custom bytes into its instruction stream at runtime.

It uses the `ptrace` API to
* locate a process by name
* attach and pause execution
* read current register state including RIP
* patch memory at the instruction pointer
* detach and allow the process to continue

This project is intended for **reverse-engineering, debugging, and low-level Linux internals research**.

---

## Features

* Scans `/proc` to find a process by its `comm` name
* Attaches using `PTRACE_ATTACH`
* Reads full register context with `PTRACE_GETREGS`
* Writes arbitrary bytes to the process using `PTRACE_POKETEXT`
* Demonstrates modifying execution flow at `RIP`
* Fully self-contained C source file `linux.c`

---

## Usage
Compile

```bash
gcc linux.c -o linux.out
````

Run

```bash
./linux.out <process_name>
```

### Example

```
root@clumsy~/linux# ./linux.out
Usage ./linux.out <process_name>
Examples ./linux.out nautilus   GNOME file manager  explorer.exe
          ./linux.out dolphin    KDE
          ./linux.out firefox
```

---

## Example Run

Finding a process and injecting

```
root@clumsy:~/linux# ./linux.out bitcoind
[+] Found bitcoind at PID 940
[+] Current RIP: 0x7f4f7fe292dc - injecting shellcode...
[+] Shellcode injected! Catch the reverse shell with:
    nc -lvnp 4444
The target process is now your shell
root@clumsy:~/linux#  
```

---

## How It Works High Level

### 1. Process Discovery

`linux.c` walks `/proc` opening each PID’s `comm` file to match the target name.

### 2. Attaching

`PTRACE_ATTACH` pauses the process so its state can be safely modified.

### 3. Register Snapshot

`PTRACE_GETREGS` reads the process’s registers including `RIP`.

### 4. Memory Injection

The program writes the provided byte sequence into the target’s memory using `PTRACE_POKETEXT`.

### 5. Detaching

`PTRACE_DETACH` resumes execution allowing the patched bytes to run.

---

## File Structure

```
linux.c   main source file
```

---

## Disclaimer

This project is provided **for research debugging and educational study of ptrace behavior** on Linux systems
Use responsibly and only on processes you own and control

---
