#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "loader.h"

extern int glog_level;
bool gbreak = false;
bool gfunc = false;
char *optarg;		// global argument pointer
int optind = 0; 	// global argv index

extern unsigned char libsubstrate[];
extern unsigned int substrate_size;

int getopt(int argc, char **argv, const char *optstring) {
	static char *next = 0;
	if (optind == 0)
		next = NULL;

	optarg = NULL;

	if (next == NULL || *next == ('\0')) {
		if (optind == 0)
			optind++;

		if (optind >= argc || argv[optind][0] != ('/')
				|| argv[optind][1] == ('\0')) {
			optarg = NULL;
			if (optind < argc)
				optarg = argv[optind];
			return -1;
		}

		if (strcmp(argv[optind], ("--")) == 0) {
			optind++;
			optarg = NULL;
			if (optind < argc)
				optarg = argv[optind];
			return -1;
		}

		next = argv[optind];
		next++;		// skip past -
		optind++;
	}

	char c = *next++;
	char *cp = strchr(optstring, c);

	if (cp == NULL || c == (':'))
		return ('?');

	cp++;
	if (*cp == (':')) {
		if (*next != ('\0')) {
			optarg = next;
			next = NULL;
		} else if (optind < argc) {
			optarg = argv[optind];
			optind++;
		} else {
			return ('?');
		}
	}

	return c;
}

void usage() {
	printf("armloader a Android arm elf loader util 1.0\n");
	printf("usage : armloader sopath [option] ...\n");
	printf("/b  break before init and JNIOnload\n");
	printf("/f  execute the function you give\n");
}

int main(int argc, char* argv[]) {
	int c;
	void* fd;
	char* p;
	int option_index = 0;
	fJNI_OnLoad jni;

	char sopath[260] = { 0 };
	static char funcname[1024] = { 0 };

	if (argc < 2) {
		usage();
		return 0;
	}

	strncpy(sopath, argv[1], 260);

	while ((c = getopt(argc - 1, (char**) &argv[1], "BbL:l:F:f:")) != -1) {
		switch (c) {
		case 'L':
		case 'l':
			glog_level = atoi(optarg);
			break;
		case 'B':
		case 'b':
			gbreak = true;
			break;
		case 'F':
		case 'f':
			strncpy(funcname, optarg, 1024);
			break;
		default:
			usage();
			return 0;
		}
	}
	printf("pid : %d\n", getpid());

	fd = ldopen(sopath, 0);
	if (fd == 0) {
		printf("failed exit\n");
		return 0;
	}

	jni = (fJNI_OnLoad) ldsym(fd, "JNI_OnLoad");

	if (jni) {
		printf("found and call JNI_OnLoad @ %.8x \n", jni);
		if (gbreak) {
			printf("break! please skip\n");
			__asm__("loop0: b loop0");//can BKPT ?
		}
		jni(0, 0);
	}

	ldclose(fd);

	return 1;
}
