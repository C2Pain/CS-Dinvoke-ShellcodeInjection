# CS-Dinvoke-ShellcodeInjection
DInvoke version Shellcode Injection POC in C#

	Usage: shellcodeinjection.exe <method> <Process Name> -f <rawfile path>

	Method: -c: classic -d: dynamicinvoke -m: manualmap -o: overload -s: syscalls


	Example 1: shellcodeinjection.exe -s notepad -f beacon.bin
	Example 2: shellcodeinjection.exe -d notepad -f 'C:\temp\beacon.bin'

	Example 3: shellcodeinjection.exe
	Default inject process: explorer
	Default inject payload: beacon.bin


Reference: https://github.com/crypt0ace/CS-ShellcodeInjection
