# Memory Dumper

Dump a process memory and extract data based on regular expressions. Tool uses multithreading.

Dump and inspect a process memory:

* during inactivity in an application,
* after locking an application,
* after logging out from an application.

Garbage cleaners might not free the unused memory immediately, but should do so after 5-10 minutes after the last action.

CPU and RAM consumption, as well as duration heavily depends on:

* number of memory dump files,
* size of each memory dump file,
* number of regular expressions and their complexity.
* occurrence of each regular expression.

Built with Visual Studio Community 2019 v16.10.2 (64-bit) and tested on Windows 10 Enterprise OS (64-bit).

Made for educational purposes. I hope it will help!

## Table of Contents

* [How to Run](#how-to-run)
* [Manual Memory Dumping](#manual-memory-dumping)
* [Manual Memory Inspection](#manual-memory-inspection)
	* [rabin2](#rabin2)
	* [strings](#strings)
* [Images](#images)

## How to Run

Run MemoryDumper_x86.exe (32-bit) or MemoryDumper_x64.exe (64-bit).

Check the example file with regular expressions [here](https://github.com/ivan-sincek/memory-dumper/blob/main/files/expressions.txt).

## Manual Memory Dumping

To manually dump a process memory, open Task Manager -> right click on the desired process -> click on `Create dump file`.

## Manual Memory Inspection

The following was tested on Kali Linux v2023.1 (64-bit).

Install the required tools on your Kali Linux:

```bash
apt-get -y install strings radare2 grep
```

I prefer using `rabin2` over `strings`.

### rabin2

Inspect memory dump, binary, executable, or any other files:

```bash
rabin2 -zzzqq somefile | grep -Pi '(keyword-1|keyword-2|keyword-3)'

rabin2 -zzzqq somefile | sort -uf > strings.txt
```

Automate file inspection from the current directory:

```bash
IFS=$'\n'; for file in $(find . -type f); do echo -n "\nFILE: \"${file}\"\n"; rabin2 -zzzqq "${file}" 2>/dev/null | grep -Pi '(keyword-1|keyword-2|keyword-3)'; done

IFS=$'\n'; for file in $(find . -type f); do rabin2 -zzzqq "${file}" 2>/dev/null; done | sort -uf > strings.txt
```

### strings

Inspect memory dump, binary, executable, or any other files:

```bash
strings somefile | grep -Pi '(keyword-1|keyword-2|keyword-3)'

strings somefile | sort -uf > strings.txt
```

Automate file inspection from the current directory:

```bash
IFS=$'\n'; for file in $(find . -type f); do echo -n "\nFILE: \"${file}\"\n"; strings "${file}" 2>/dev/null | grep -Pi '(keyword-1|keyword-2|keyword-3)'; done

IFS=$'\n'; for file in $(find . -type f); do strings "${file}" 2>/dev/null; done | sort -uf > strings.txt
```

## Images

<p align="center"><img src="https://github.com/ivan-sincek/memory-dumper/blob/main/img/run.jpg" alt="Run"></p>

<p align="center">Figure 1 - Run</p>
