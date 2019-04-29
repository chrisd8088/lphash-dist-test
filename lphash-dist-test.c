#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "spooky/spooky.h"

enum key_type {
	KEY_TYPE_SEQ,
	KEY_TYPE_RAND
};

enum hash_type {
	HASH_TYPE_MULT,
	HASH_TYPE_MULTADD,
	HASH_TYPE_MASK,
	HASH_TYPE_SPOOKY
};

enum reduce_type {
	REDUCE_TYPE_MOD,
	REDUCE_TYPE_SHIFT,
	REDUCE_TYPE_XORMOD,
	REDUCE_TYPE_XORSHIFT
};

enum arg_type {
	ARG_TYPE_KEY,
	ARG_TYPE_HASH,
	ARG_TYPE_REDUCE,
	ARG_TYPE_OPS,
	ARG_TYPE_SIZE,
	ARG_TYPE_MAXKEY,
	ARG_TYPE_MAXALLOC,
	ARG_TYPE_MINALLOC,
	ARG_TYPE_ERROR
};
					// 2^32 * inverse golden ratio (Phi)
#define MULT_KNUTH 2654435769U		// floor(2^32 * 0.5 * (sqrt(5) - 1))
#define MULT_PRIME 2654435761U		// prime number near above

static uint32_t mult_hash32(uint32_t key, uint32_t add)
{
	//return key * MULT_KNUTH + add;
	return key * MULT_PRIME + add;
}

static void exit_nomem()
{
	fprintf(stderr, "ERROR: out of memory\n");
	exit(1);
}

struct key_table {
	uint8_t *keys;
	unsigned int size;
	unsigned int used;
	unsigned int next;
};

static struct key_table *create_keys(unsigned int size)
{
	struct key_table *keys;

	keys = calloc(1, sizeof(*keys));
	if (keys == NULL)
		exit_nomem();

	keys->keys = calloc(size, sizeof(*keys->keys));
	if (keys->keys == NULL)
		exit_nomem();

	keys->size = size;
	return keys;
}

static void destroy_keys(struct key_table *keys)
{
	free(keys->keys);
	free(keys);
}

static unsigned int random_key(struct key_table *keys, int alloc)
{
	unsigned int ret;
	uint8_t state = alloc ? 0 : 1;

	while (1) {
		ret = random() % keys->size;
		if (keys->keys[ret] == state) {
			keys->keys[ret] = alloc;
			return ret;
		}
	}
}

static unsigned int alloc_key(struct key_table *keys, int random)
{
	unsigned int next, ret;

	if (keys->used == keys->size) {
		fprintf(stderr, "ERROR: all keys allocated\n");
		exit(1);
	}

	if (random) {
		ret = random_key(keys, 1);
	} else {
		ret = next = keys->next;
		keys->keys[next++] = 1;

		while (next < keys->size && keys->keys[next])
			++next;
		if (next == keys->size) {
			next = 0;
			while (keys->keys[next])
				++next;
		}

		keys->next = next;
	}

	++keys->used;
	return ret;
}

static unsigned int dealloc_key(struct key_table *keys)
{
	unsigned int ret = random_key(keys, 0);

	--keys->used;
	return ret;
}

#define EMPTY_FLAG -1
#define REMOVED_FLAG -2

static int test_table_entry(int32_t entry, uint32_t hash, int remove_flag)
{
	if (!remove_flag)
		return (entry == EMPTY_FLAG || entry == REMOVED_FLAG);
	else if (entry != EMPTY_FLAG)
		return entry == hash;

	fprintf(stderr, "ERROR: could not find entry to remove: %u\n", hash);
	exit(1);
}

static unsigned int table_update(int32_t *table, unsigned int table_size,
				 unsigned int index, uint32_t hash,
				 int remove_flag)
{
	unsigned int num_probes = 1;
	unsigned int i;

	for (i = index; i < table_size; ++i, ++num_probes) {
		if (test_table_entry(table[i], hash, remove_flag)) {
			table[i] = remove_flag ? REMOVED_FLAG : hash;
			return num_probes;
		}
	}
	for (i = 0; i < index; ++i, ++num_probes) {
		if (test_table_entry(table[i], hash, remove_flag)) {
			table[i] = remove_flag ? REMOVED_FLAG : hash;
			return num_probes;
		}
	}

	fprintf(stderr, "ERROR: no space left in table\n");
	exit(1);
}

static void run_hash_test(enum key_type key_type, enum hash_type hash_type,
			  enum reduce_type reduce_type,
			  unsigned int num_ops, unsigned int table_size,
			  unsigned int alloc_size,
			  unsigned int min_alloc, unsigned int max_alloc)
{
	int32_t *table;
	struct key_table *keys;
	unsigned int alloc_range = max_alloc - min_alloc + 1;
	unsigned int target_alloc = 0;
	unsigned int *probes;
	unsigned int max_probes = 0;
	unsigned int shift = 0;
	unsigned int index, i;
	uint32_t mask = table_size - 1;
	uint32_t add = 0;
	uint32_t key, hash;
	int remove = 0;

	table = calloc(table_size, sizeof(*table));
	if (table == NULL)
		exit_nomem();
	memset(table, 0xFF, table_size * sizeof(*table));	// fill with -1

	probes = calloc(table_size, sizeof(*probes));
	if (probes == NULL)
		exit_nomem();

	keys = create_keys(alloc_size);

	if (hash_type == HASH_TYPE_MULTADD) {
		while (add == 0)		// ensure non-zero
			add = random();
	}

	if (reduce_type == REDUCE_TYPE_SHIFT ||
	    reduce_type == REDUCE_TYPE_XORSHIFT) {
		unsigned int size = table_size;

		while (size >>= 1)
			++shift;
		shift = sizeof(hash) * 8 - shift;
	}

	for (i = 0; i < num_ops; ++i) {
		unsigned int num_probes;

		while (target_alloc == keys->used)
			target_alloc = random() % alloc_range + min_alloc;

		if (target_alloc > keys->used) {
			key = alloc_key(keys, key_type == KEY_TYPE_RAND);
			remove = 0;
		} else {
			key = dealloc_key(keys);
			remove = 1;
		}

		if (hash_type == HASH_TYPE_MASK)
			hash = key & mask;
		else if (hash_type == HASH_TYPE_SPOOKY)
			hash = spooky_hash32(&key, sizeof(key), 0);
		else
			hash = mult_hash32(key, add);

		if (reduce_type == REDUCE_TYPE_XORMOD ||
		    reduce_type == REDUCE_TYPE_XORSHIFT) {
			hash ^= hash >> 16;
		}
		if (reduce_type == REDUCE_TYPE_MOD ||
		    reduce_type == REDUCE_TYPE_XORMOD) {
			index = hash & mask;	// 2^x table size so mask==mod
		} else {
			index = hash >> shift;
		}

		num_probes = table_update(table, table_size, index, hash,
					  remove);
		++probes[num_probes];
		if (max_probes < num_probes)
			max_probes = num_probes;
	}

	printf("MAX PROBES: %d\nPROBES DISTRIBUTION:\n", max_probes);
	for (i = 1; i <= max_probes; ++i)
		printf("%d: %u\n", i, probes[i]);

	destroy_keys(keys);
	free(probes);
	free(table);
}

static int parse_key_type(const char *arg, enum key_type *type)
{
	if (strcmp("seq", arg) == 0)
		*type = KEY_TYPE_SEQ;
	else if (strcmp("rand", arg) == 0)
		*type = KEY_TYPE_RAND;
	else
		return -1;
	return 0;
}

static int parse_hash_type(const char *arg, enum hash_type *type)
{
	if (strcmp("mult", arg) == 0)
		*type = HASH_TYPE_MULT;
	else if (strcmp("multadd", arg) == 0)
		*type = HASH_TYPE_MULTADD;
	else if (strcmp("mask", arg) == 0)
		*type = HASH_TYPE_MASK;
	else if (strcmp("spooky", arg) == 0)
		*type = HASH_TYPE_SPOOKY;
	else
		return -1;
	return 0;
}

static int parse_reduce_type(const char *arg, enum reduce_type *type)
{
	if (strcmp("mod", arg) == 0)
		*type = REDUCE_TYPE_MOD;
	else if (strcmp("shift", arg) == 0)
		*type = REDUCE_TYPE_SHIFT;
	else if (strcmp("xormod", arg) == 0)
		*type = REDUCE_TYPE_XORMOD;
	else if (strcmp("xorshift", arg) == 0)
		*type = REDUCE_TYPE_XORSHIFT;
	else
		return -1;
	return 0;
}

static void exit_usage(const char *prog, const char *msg)
{
	fprintf(stderr,
		"Usage: %s [seq|rand] "
			  "[mult|multadd|mask|spooky]\n  "
			  "[mod|shift|xormod|xorshift]\n  "
			  "[<num-ops> [<table-size> "
			    "[<max-key> [<max-alloc> [<min-alloc>]]]]]\n\n"
		"Error: %s\n",
		prog, msg);
	exit(1);
}

#define DEFAULT_TABLE_SIZE 8192		// require a power of two table size
#define MIN_TABLE_SIZE 8
#define MAX_TABLE_SIZE (1 << (sizeof(unsigned int) * 8 - 1))

#define DEFAULT_NUM_OPS 1000		// unused for incr key type

int main(int argc, char **argv)
{
	const char *prog = argv[0];
	enum key_type key_type = KEY_TYPE_SEQ;
	enum hash_type hash_type = HASH_TYPE_MULT;
	enum reduce_type reduce_type = REDUCE_TYPE_MOD;
	enum arg_type arg_type = ARG_TYPE_KEY;
	long int num_ops = 0;
	long int table_size = DEFAULT_TABLE_SIZE;
	long int max_key = 0;
	long int max_alloc = 0;
	long int min_alloc = 0;
	unsigned int alloc_size = table_size * 2;
	unsigned int max_load = alloc_size / 3;
	int optarg = 1;
	struct timeval tv;

	while (optarg < argc) {
		switch (arg_type) {
		case ARG_TYPE_KEY:
			if (!parse_key_type(argv[optarg], &key_type))
				++optarg;
			break;
		case ARG_TYPE_HASH:
			if (!parse_hash_type(argv[optarg], &hash_type))
				++optarg;
			break;
		case ARG_TYPE_REDUCE:
			if (!parse_reduce_type(argv[optarg], &reduce_type))
				++optarg;
			break;
		case ARG_TYPE_OPS:
			errno = 0;
			num_ops = strtol(argv[optarg++], NULL, 10);
			if (errno > 0 || num_ops < 1) {
				exit_usage(prog, (optarg < 4) ?
						 "invalid arguments" :
						 "invalid operation count");
			}
			break;
		case ARG_TYPE_SIZE:
			errno = 0;
			table_size = strtol(argv[optarg++], NULL, 10);
			if (errno > 0 || table_size < MIN_TABLE_SIZE ||
			    (unsigned int)table_size > MAX_TABLE_SIZE ||
			    __builtin_popcountl(table_size) != 1) {
				exit_usage(prog, "invalid table size");
			}
			alloc_size = table_size * 2;	// default
			max_load = alloc_size / 3;
			break;
		case ARG_TYPE_MAXKEY:
			errno = 0;
			max_key = strtol(argv[optarg++], NULL, 10);
			if (errno > 0 || max_key < 1)
				exit_usage(prog, "invalid maximum key");
			alloc_size = max_key + 1;
			break;
		case ARG_TYPE_MAXALLOC:
			errno = 0;
			max_alloc = strtol(argv[optarg++], NULL, 10);
			if (errno > 0 || max_alloc < 1 ||
			    max_alloc > alloc_size ||
			    max_alloc > table_size) {
				exit_usage(prog,
					   "invalid maxmium allocated keys");
			}
			break;
		case ARG_TYPE_MINALLOC:
			errno = 0;
			min_alloc = strtol(argv[optarg++], NULL, 10);
			if (errno > 0 || min_alloc < 0 ||
			    min_alloc > max_alloc) {
				exit_usage(prog,
					   "invalid minimum allocated keys");
			}
			break;
		case ARG_TYPE_ERROR:
			exit_usage(prog, "too many arguments");
			break;
		}
		++arg_type;
	}

	if (max_alloc == 0)
		max_alloc = max_load;

	if (min_alloc == max_alloc) {
		if (num_ops == 0)
			num_ops = max_load;
		else if (num_ops > table_size)
			exit_usage(prog, "operations exceed table size");
	} else if (num_ops == 0) {
		num_ops = DEFAULT_NUM_OPS;
	}

	gettimeofday(&tv, NULL);
	srandom(tv.tv_sec + tv.tv_usec);

	printf("OPERATIONS: %u\n", num_ops);
	printf("TABLE SIZE: %u\n", table_size);
	printf("MAX KEY: %u\n", alloc_size - 1);
	printf("LOAD RANGE: %.2f-%.2f (%u-%u)\n\n",
	       100 * (float)min_alloc / table_size, min_alloc,
	       100 * (float)max_alloc / table_size, max_alloc);

	run_hash_test(key_type, hash_type, reduce_type,
		      num_ops, table_size, alloc_size, min_alloc, max_alloc);

	exit(0);
}
