#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <pcap/pcap.h>
#include <string.h>
#include <signal.h>

#define MAX_PACKET 1024000
#define TRUNCATE_MIN 12
#define SNAP_LEN 16128
#define TIMEOUT 1000

#define ARG_ARRAY \
	CHOOSE(input-interface, required_argument, "i:", "--input-interface IF -i IF\tSpecify the name of interface to get packets.") \
	CHOOSE(file, required_argument, "f:", "--file PCAP -f PCAP\tSpecify path to get packets.") \
	CHOOSE(output-interface, required_argument, "o:", "--output-interface IF -o IF\tSpecify Name of interface to send packets.") \
	CHOOSE(write, required_argument, "w:", "--write PCAP -w PCAP\tSpecify file to dump packets.") \
	CHOOSE(length, required_argument, "l:", "--length NUM -l NUM\tSpecify length to truncate.") \
	CHOOSE(verbose, no_argument, "v", "--verbose -v\tPrint more infomation.") \
	CHOOSE(help, no_argument, "h", "--help -h\tPrint this help.")

#define CHOOSE(full, has_arg, short_form, desc) \
	{#full, has_arg, NULL, short_form[0]},

struct option longopts[] = {
	ARG_ARRAY
};

#undef CHOOSE
#define CHOOSE(full, has_arg, short_form, desc) short_form

const char *short_arg_string = ARG_ARRAY;

#undef CHOOSE
#define CHOOSE(full, has_arg, short_form, desc) desc "\n"
const char *help_page = ARG_ARRAY "\nExample: tp -i ge0 -o ge1 -l 64\n";

typedef enum {
	IO_TYPE_IF,
	IO_TYPE_PCAP,

	IO_TYPE_MAX,
} io_type_e;

const char *io_type_string[IO_TYPE_MAX + 1] = {
	"interface",
	"pcap",
	"invalid"
};

struct io {
	io_type_e type;
	char *name;

	pcap_t *pcap;
	pcap_dumper_t *dumper;
};

struct context {
	struct io input;
	struct io output;
	int length;
	int verbose;
};

#define DECLARE_CONTEX(_name) \
struct context _name = { \
	.input = { \
		.type = IO_TYPE_MAX, \
		.name = "none", \
	}, \
	.output = { \
		.type = IO_TYPE_MAX, \
		.name = "none", \
	}, \
	.length = 64, \
	.verbose = 0, \
}

volatile int g_run = 1;

int init_ctx_from_args(struct context *ctx, int argc, char **argv)
{
	int opt;

	while(1) {
		opt = getopt_long(argc, argv, short_arg_string, longopts, 0);

		if (opt == EOF)
			break;

		switch (opt) {
		case 0:
			break;
		case 'i':
		case 'f':
			if (ctx->input.type != IO_TYPE_MAX) {
				printf("Only one input supported.\n");

				exit(-1);
			}
			ctx->input.type = opt == 'i' ?
				IO_TYPE_IF : IO_TYPE_PCAP;
			ctx->input.name = strdup(optarg);
			break;
		case 'o':
		case 'w':
			if (ctx->output.type != IO_TYPE_MAX) {
				printf("Only one input supported.\n");

				exit(-1);
			}
			ctx->output.type = opt == 'o' ?
				IO_TYPE_IF : IO_TYPE_PCAP;
			ctx->output.name = strdup(optarg);
			break;
		case 'l':
			ctx->length = atoi(optarg);
			if (ctx->length < TRUNCATE_MIN || SNAP_LEN < ctx->length) {
				printf("Invalid length.\n");

				exit(-1);
			}
			break;
		case 'v':
			ctx->verbose = 1;
			break;
		case 'h':
			printf("%s", help_page);
			exit(0);
		}
	}

	if (ctx->input.type < IO_TYPE_IF
	    || ctx->input.type >= IO_TYPE_MAX
	    || ctx->output.type < IO_TYPE_IF
	    || ctx->output.type >= IO_TYPE_MAX) {
		printf("Arguments is not enough.\n");
	}

	if (ctx->output.type == IO_TYPE_IF && ctx->length < 60) {
		fprintf(stderr, "Length is length than 60, %d - 60 part will filled by 0",
			ctx->length);
	}

	return 0;
}

void print_ctx(struct context *ctx)
{
	printf("read packet from %s %s\n"
	       "truncate packet length to %d\n"
	       "write packet to %s %s\n",
	       io_type_string[ctx->input.type], ctx->input.name,
	       ctx->length,
	       io_type_string[ctx->output.type], ctx->output.name);
}

int open_input(struct io *io)
{
	char errbuf[PCAP_ERRBUF_SIZE];

	if (IO_TYPE_IF == io->type) {
		io->pcap = pcap_open_live(io->name, SNAP_LEN, 1, TIMEOUT, errbuf);
		if (NULL == io->pcap) {
			printf("Open interface %s fail, err: %s\n",
			       io->name, errbuf);

			return -1;
		}
	} else if (IO_TYPE_PCAP == io->type) {
		io->pcap = pcap_open_offline(io->name, errbuf);
		if (NULL == io->pcap) {
			printf("Open pcap file %s fail, err: %s\n",
			       io->name, errbuf);

			return -1;
		}
	} else {
		printf("Invalid io type %d\n", io->type);

		return -1;
	}

	return 0;
}

int open_output(struct io *io)
{
	char errbuf[PCAP_ERRBUF_SIZE];

	if (IO_TYPE_IF == io->type) {
		io->pcap = pcap_open_live(io->name, SNAP_LEN, 1, TIMEOUT, errbuf);
		if (NULL == io->pcap) {
			printf("Open interface %s fail, err: %s\n",
			       io->name, errbuf);

			return -1;
		}
	} else if (IO_TYPE_PCAP == io->type) {
		io->pcap = pcap_open_dead(1, SNAP_LEN);
		if (NULL == io->pcap) {
			printf("Open dead pcap\n");

			return -1;
		}
		io->dumper = pcap_dump_open(io->pcap, io->name);
		if (NULL == io->dumper) {
			printf("Fail to open dumper\n");

			return -1;
		}
	} else {
		printf("Invalid io type %d\n", io->type);

		return -1;
	}

	return 0;
}

int prepare(struct context *ctx)
{
	if (0 != open_input(&ctx->input)) {
		return -1;
	}

	if (0 != open_output(&ctx->output)) {
		return -1;
	}

	return 0;
}

void input_to_output(struct context *ctx)
{
	int nr;
	int nr_truncated;
	int ret;
	const unsigned char *pkt;
	struct pcap_pkthdr header;

	nr = 0;
	nr_truncated = 0;
	while (g_run) {
		do {
			pkt = pcap_next(ctx->input.pcap, &header);
		} while (NULL == pkt && IO_TYPE_IF == ctx->input.type);
		if (NULL == pkt)
			break;

		if (ctx->verbose)
			printf("%02x:%02x:%02x:%02x:%02x:%02x -> "
			       "%02x:%02x:%02x:%02x:%02x:%02x, "
			       "caplen: %u, len: %u\n",
			       pkt[0], pkt[1], pkt[2], pkt[3], pkt[4], pkt[5],
			       pkt[6], pkt[7], pkt[8], pkt[9], pkt[10], pkt[11],
			       header.caplen, header.len);

		if (ctx->length < header.caplen) {
			header.caplen = ctx->length;
			nr_truncated++;
		}

                if (IO_TYPE_PCAP == ctx->output.type) {
			pcap_dump((unsigned char *)ctx->output.dumper,
				  &header, pkt);
		} else if (IO_TYPE_IF == ctx->output.type) {
			ret = pcap_sendpacket(ctx->output.pcap,
					      pkt, header.caplen);
			if (ret != 0 && ctx->verbose) {
				printf("Fail to send packet\n");
			}
		}

		if (++nr >= MAX_PACKET)
			break;
	}

	printf("captured: %d, truncated: %d\n", nr, nr_truncated);
}

void finish(struct context *ctx)
{
	pcap_close(ctx->input.pcap);
	free(ctx->input.name);

	if (IO_TYPE_PCAP == ctx->output.type) {
		pcap_dump_close(ctx->output.dumper);
		pcap_close(ctx->output.pcap);
	}
	free(ctx->output.name);
}

void sigfn(int sig)
{
	g_run = 0;
}

void signal_set(int signo, void (*fn)(int))
{
	struct sigaction sig;
	struct sigaction old_sig;

	sig.sa_handler = fn;
	sigemptyset(&sig.sa_mask);
	sig.sa_flags = 0;
#ifdef SA_RESTART
	sig.sa_flags |= SA_RESTART;
#endif

	sigaction(signo, &sig, &old_sig);
}

int main(int argc, char **argv)
{
	DECLARE_CONTEX(ctx);

	signal_set(SIGINT, sigfn);
	signal_set(SIGQUIT, sigfn);

	init_ctx_from_args(&ctx, argc, argv);

	print_ctx(&ctx);

	if (-1 == prepare(&ctx)) {
		printf("Fail to prepare.\n");

		exit(-1);
	}

	input_to_output(&ctx);

	finish(&ctx);

	exit(0);
}
