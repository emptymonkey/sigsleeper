
#include "sigsleeper.h"


/**********************************************************************************************************************
 *
 * int sig_string_to_int(char *sig_string)
 *
 *	Input: The name of a signal, as defined in: /usr/include/bits/signum.h
 *
 *	Output: The number of the signal associated with the name.
 *
 *	Assumptions: We will be leveraging the sigmaps (and supporting) data structues globally defined in this repo. If
 *	you copy this function for later use, make sure you grab those too. Also note, we do not hande real-time signals
 *	here.
 *
 **********************************************************************************************************************/
int sig_string_to_int(char *sig_string){
	int retval_int;
	int i;
	int tmp_string_len;

	char *string_to_match;
	
	// We want to handle strings that follow the naming convention in use by the procps version of kill. That means
	// "USR1" is a reasonable variant of "SIGUSR1". Lets check if the string starts with "SIG". If not, we prepend
	// it and then do our compare.
	if(strncmp(sig_string, "SIG", 3)){
		tmp_string_len = strlen(sig_string);

		if((string_to_match = (char *) calloc(tmp_string_len + 3 + 1, sizeof(char))) == NULL){
			if(global_debug){
				fprintf(stderr, "%s: sig_string_to_int(): calloc(%d, %d): %s\n", program_invocation_short_name, tmp_string_len + 3 + 1, (int) sizeof(char), strerror(errno));
			}
			return(-1);
		}
		sprintf(string_to_match, "SIG%s", sig_string);
	}else{
		string_to_match = sig_string;
	}

	// Step through our handy-dandy sigmap struct and look for a match! 
	for(i = 0; sigmap[i].number; i++){
		tmp_string_len = strlen(sigmap[i].name);
		if(!(retval_int = strncmp(string_to_match, sigmap[i].name, tmp_string_len))){
			return(sigmap[i].number);
		}
	}

	return(0);
}
