
#include "sigsleeper.h"


/**********************************************************************************************************************
 *
 * int add_shellcode(struct ptrace_pokedata *shellcode, char *buffer)
 *
 *	Input:
 *		A pointer to the ptrace_pokedata structure where you want the translated shellcode stored.
 *		A string of hex characters representing the shellcode.
 *
 *	Output:
 *		A return code.
 *		The translated shellcode (in the ptrace_pokedata structure).
 *
 *	Purpose:
 *		Translate shellcode into a form that is ready for being injected into a remote process with a PTRACE_POKEDATA
 *		call. We do this in a manor that takes a little bit extra work up front, but ensures a minimum amount of time
 *		between the PTRACE_ATTACH and PTRACE_DETACH calls.
 *
 *	Limitations:
 *		The buffer passed as input needs to have an even number of hex characters and be null terminated. Also, we 
 *		assume that the filtering out of non-hex characters already happened when the buffer was being filled.
 *
 **********************************************************************************************************************/
int add_shellcode(struct ptrace_pokedata *shellcode, char *buffer){

	int buffer_index;

	struct data_node *this, *tmp;

	char translation_buffer[BYTES_PER_WORD];
	int translation_buffer_index;

	// Each shellcode entry is a string made from two chars plus one null.
	char hex_str[3];
	int hex_str_index;


	translation_buffer_index = 0;
	memset(&translation_buffer, 0, sizeof(translation_buffer));

	// First time through? Lets setup the initial state.
	if(!shellcode->head){	

		if((shellcode->head = (struct data_node *) calloc(1, sizeof(struct data_node))) == NULL){
			if(global_debug){
				fprintf(stderr, "%s: add_shellcode(): calloc(1, %d): %s\n", program_invocation_short_name, (int) sizeof(struct data_node), strerror(errno));
			}
			return(-1);
		}

		shellcode->tail = shellcode->head;
		this = shellcode->tail;
		shellcode->node_count = 1;

		// We've been called for this list before. Let's restore the state and head on in.
	}else{

		memcpy(translation_buffer, &(shellcode->tail->ptrace_word), sizeof(shellcode->tail->ptrace_word));
		translation_buffer_index = shellcode->tail_index;
		this = shellcode->tail;
	}

	hex_str_index = 0;
	memset(&hex_str, 0, 3);

	buffer_index = 0;
	while(buffer[buffer_index]){

		if(translation_buffer_index == sizeof(translation_buffer)){

			memset(&translation_buffer, 0, sizeof(translation_buffer));
			translation_buffer_index = 0;

			if((tmp = (struct data_node *) calloc(1, sizeof(struct data_node))) == NULL){
				if(global_debug){
					fprintf(stderr, "%s: add_shellcode(): calloc(1, %d): %s\n", program_invocation_short_name, (int) sizeof(struct data_node), strerror(errno));
				}
				return(-1);
			}
			this->next = tmp;
			this = tmp;
			shellcode->node_count++;
		}

		hex_str[hex_str_index] = buffer[buffer_index++];
		if(hex_str_index){
			*(translation_buffer + translation_buffer_index++) = strtol(hex_str, NULL, 16);

			if(translation_buffer_index == sizeof(translation_buffer)){
				memcpy(&(this->ptrace_word), translation_buffer, sizeof(this->ptrace_word));
			}
		}
		hex_str_index = (hex_str_index + 1) % 2;
	}

	if(translation_buffer_index != sizeof(translation_buffer)){
		memcpy(&(this->ptrace_word), translation_buffer, sizeof(this->ptrace_word));
	}

	shellcode->tail = this;
	shellcode->tail_index = translation_buffer_index;

	return(0);
}

