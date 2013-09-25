


#define _GNU_SOURCE


#include <ctype.h>
#include <errno.h>
#include <error.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>



extern int global_debug;



/*
 * Lessons in macro expansion: When using nested macros for integer division, parenthesis are *very* important.
 * Exactly why is left as an exercise for the reader.
 */
#define BYTES_PER_WORD (__WORDSIZE/CHAR_BIT)


#define DEFAULT_SIGNAL SIGUSR1


#ifndef SA_RESTORER
#define SA_RESTORER 0x04000000
#endif


/*
 * Lessons in understanding low-level userspace code: Occasionally the man pages will lie to you.
 *
 * There is actually a *fourth* arg to sigaction. Check out: sys_rt_sigaction in linux/kernel/signal.c
 * Since glibc uses _NSIG/8 for this value, we will too, though it feels like a dirty hack. Both glibc and the kernel
 * source that reference this arg are preceded by triple-X comments. (In defense of glibc and the kernel, if feels 
 * like a legacy segment where Linus' "DON'T BREAK USERSPACE!" rule has run headlong into glibc's quest to offer a 
 * standardized posix interface to the kernel. Both of these are good things. Legacy just happens sometimes.)
 *
 * As a general rule though, if the results from your code are contradicting the documentation, go and read the source.
 * (And I don't mean the comments from the source. Those can help to find your way around, but they can also lie. The
 * code, however, cannot.)
 */
#define KERNEL_SIGSETSIZE (_NSIG/8)



/* The args for the kernel's version of the sigaction struct are in a different order? Sure, why not. */
struct kernel_sigaction {
	__sighandler_t k_sa_handler;
	unsigned long sa_flags;
	void (*sa_restorer) (void);
	sigset_t sa_mask;
};


/*
 * This is the structure we will use to hold the translated binary shellcode. It's a pretty simple linked list of words
 * that are ready for a PTRACE_POKEDATA call. The node_count is used for a quick calculation of the space needed to hold
 * the shellcode. (node_count * BYTES_PER_WORD gives us total memory needed.)
 */
struct ptrace_pokedata {

	struct data_node *head;
	struct data_node *tail;
	int tail_index;

	void *remote_address;
	unsigned long node_count;
};

struct data_node {
	unsigned long ptrace_word;
	struct data_node *next;
};


/*
 * If we are running a COMMAND through our own execve() shellcode, then we'll need to setup an argv in the remote
 * processes memory. This struct helps us organize that.
 */
struct argv_payload {

	/* The locations of the command strings, and the location of those locations. */
	unsigned long *remote_string_addresses;
	unsigned long remote_argv_address;

	int argc;
	char **command_string_vector;
	int *word_counts;
};


/* This is how we map signal names to their numbers and default actions. */
struct sigmap_element {
	char *name;
	int number;
	int default_action;
};

#define ACTION_IGNORE    1
#define ACTION_TERMINATE 2
#define ACTION_COREDUMP  3
#define ACTION_STOP      4

extern const struct sigmap_element sigmap[];

/* strlen("SIGRTMIN+XX") */
#define MAX_SIGNAL_NAME_LEN 11

