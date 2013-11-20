# sigsleeper #

_sigsleeper_ is a tool for setting up [sleeper](http://en.wikipedia.org/wiki/Sleeper_cell) code in [Linux](http://en.wikipedia.org/wiki/Linux).

**What do you mean by "sleeper code"?**

Sleeper code would be code that sits unseen on a target system. In this case, _sigsleeper_ hides its payload inside of a legitimate process on Linux. It does this by [injecting](http://en.wikipedia.org/wiki/Ptrace) the payload into a target process and setting it up as a [signal handler](http://en.wikipedia.org/wiki/Unix_signal). The payload can be either [shellcode](http://en.wikipedia.org/wiki/Shellcode) or [commands to execute](http://en.wikipedia.org/wiki/Exec_%28computing%29). The payload is then run anytime a "trigger" signal is received. _sigsleeper_ can also be used to hijack an existing signal handler, running the original signal handler after the completion of the payload.

**That's awesome! [1337 h4X0rZ rUL3!!](http://hackertyper.com/)**

While I do think it's pretty neat, this really isn't ["hacking"](http://en.wikipedia.org/wiki/Hacker_%28computer_security%29). There are no exploits here. _shelljack_ takes advantage of some Linux [deep magic](http://en.wikipedia.org/wiki/Deep_magic) that is completely legitimate, although often not well understood. In order to shelljack a target, you will need the appropriate permissions to do so.

While this may not be a ["sploit"](http://en.wikipedia.org/wiki/Sploit), it is a very handy tool designed to empower [pentesters](http://en.wikipedia.org/wiki/Pentester) and educators.

**What are signals and signal handlers?**

A signal handler is a piece of code that is run anytime a process receives a signal. Signals are a mechanism used to notify processes of any number of events. Normally, this is an asynchronous notification from the kernel. (The signal can originate from another process, such as kill, but are delivered through the kernel.)

As an example, let's look at SIGINT. This is a normal signal that is used to tell a process it has been "interrupted", such as by a "[ctrl-c](http://en.wikipedia.org/wiki/Ctrl-C)". The signal handler in this case is a default handler called SIG_DFL (which in this case will terminate the process). Using a custom signal handler to intercept SIGINT is not unheard of. A programmer may want to do that to ensure that the process has time to properly clean up after itself before exiting. The function that performs that cleanup would be the custom signal handler.

**What's the use-case for _sigsleeper_?**

_sigsleeper_ would be used during the post-exploitation phase of a pentest for setting up a persistence mechanism. 

**Is this a [rootkit](http://en.wikipedia.org/wiki/Rootkit)?**

Not exactly. It demonstrates the sort of [userland](http://en.wikipedia.org/wiki/User_space) rootkit that is possible. This tool, taken with some others from my repositories, and a bit of creativity, could be used as the basis of a Linux userland rootkit.

**Where can I learn more about signals in Linux?**

There are a couple of places that can give guidance on this topic:

* The [signal (7)](http://linux.die.net/man/7/signal) man page is a good start. This will give you a reasonable high-level overview.
* Chapter 10 from Stevens & Rago's ["Advanced Programming in the UNIX Environment (3rd Edition)"](http://www.amazon.com/Programming-Environment-Addison-Wesley-Professional-Computing/dp/0321637739/ref=sr_1_1?ie=UTF8&qid=1380089492&sr=8-1&keywords=Advanced+Programming+in+the+UNIX+Environment+%283rd+Edition%29) covers signals in depth. I cannot recommend this book highly enough.

Finally, both the above links describe signals as they work in theory. To understand the dirty details of implementation, you really have to go source diving. From the Linux kernel source, read:

* kernel/signal.c
* arch/x86/kernel/signal.c

And from the glibc source, read:

* sysdeps/posix/signal.c
* sysdeps/unix/sysv/linux/x86_64/sigaction.c

**What Architectures / OSs will this run on?**

Currently, _sigsleeper_ will only run on x86_64 Linux. Because it uses the Linux ptrace interface to inject assembly language [syscalls](http://en.wikipedia.org/wiki/Syscall) into a target process, nothing here is portable. That said, check out my other project, [<i>ptrace_do</i>](https://github.com/emptymonkey/ptrace_do). If I get around to supporting <i>ptrace_do</i> for other architectures, then porting _shelljack_ shouldn't be too hard.

# Usage #

	Usage: sigsleeper [-s SIGNAL] [-o] [-f] [-e COMMAND] [-d] PID
	
		-s SIGNAL  : Use SIGNAL as the trigger. Signal name, short name, or number are all accepted. (SIGUSR1 is the default).
		-o         : Invoke the original signal handler after running our payload.
		-f         : Add fork() shellcode so that the payload runs in a child process, ensuring the original process does not block.
		-e COMMAND : Use exec() shellcode to launch COMMAND for the payload instead of reading from stdin.
		           : This option requires that COMMAND have an absolute path.
		-d         : Display debug output.

# Example #

As an example, we will embed a call to _'/bin/echo Hello world!'_ into the shell we are logged into. We can then trigger it by using the kill command to send SIGUSR1 to our current shell. 

	empty@monkey:~$ sigsleeper -f -e '/bin/echo Hello world!' $$
	empty@monkey:~$ kill -USR1 $$
	empty@monkey:~$ Hello world!

# Prerequisites #

To help with the heavy lifting, I've written a supporting library that is needed by _sigsleeper_:

* [<i>ptrace_do</i>](https://github.com/emptymonkey/ptrace_do): A ptrace library for easy syscall injection in Linux.

# Installation #

	git clone https://github.com/emptymonkey/ptrace_do.git
	cd ptrace_do
	make
	cd ..

	git clone https://github.com/emptymonkey/sigsleeper.git
	cd sigsleeper
	make

## A Quick Note on Ethics ##

I write and release these tools with the intention of educating the larger [IT](http://en.wikipedia.org/wiki/Information_technology) community and empowering legitimate pentesters. If I can write these tools in my spare time, then rest assured that the dedicated malicious actors have already developed versions of their own.

