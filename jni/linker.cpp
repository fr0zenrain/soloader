#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <unistd.h>

#include "elf.h"
#include "linker_phdr.h"
#include "linker.h"
#include "loader.h"


extern bool gbreak;

/* Assume average path length of 64 and max 8 paths */
#define LDPATH_BUFSIZE 512
#define LDPATH_MAX 8

#define LDPRELOAD_BUFSIZE 512
#define LDPRELOAD_MAX 8

#ifdef ANDROID_ARM_LINKER
typedef long unsigned int* _Unwind_Ptr;
extern "C" _Unwind_Ptr dl_unwind_find_exidx(_Unwind_Ptr pc, int* pcount);
#else

#endif
/* >>> IMPORTANT NOTE - READ ME BEFORE MODIFYING <<<
 *
 * Do NOT use malloc() and friends or pthread_*() code here.
 * Don't use printf() either; it's caused mysterious memory
 * corruption in the past.
 * The linker runs before we bring up libc and it's easiest
 * to make sure it does not depend on any complex libc features
 *
 * open issues / todo:
 *
 * - are we doing everything we should for ARM_COPY relocations?
 * - cleaner error reporting
 * - after linking, set as much stuff as possible to READONLY
 *   and NOEXEC
 */

// We can't use malloc(3) in the dynamic linker. We use a linked list of anonymous
// maps, each a single page in size. The pages are broken up into as many struct soinfo
// objects as will fit, and they're all threaded together on a free list.
#define SOINFO_PER_POOL ((PAGE_SIZE - sizeof(soinfo_pool_t*)) / sizeof(soinfo))
struct soinfo_pool_t {
	soinfo_pool_t* next;
	soinfo info[SOINFO_PER_POOL];
};
static struct soinfo_pool_t* gSoInfoPools = NULL;
static soinfo* gSoInfoFreeList = NULL;

soinfo* solist = &libdl_info;
static soinfo* sonext = &libdl_info;
static soinfo* somain; /* main process, always the one after libdl_info */

static char gLdPathsBuffer[LDPATH_BUFSIZE];
static const char* gLdPaths[LDPATH_MAX + 1] = { "", "/system/lib",
		"/vendor/lib", "/data/local/tmp", };

static const char* system_lib[] = { "libc.so", "libm.so", "libstdc++.so",
		"libz.so", "liblog.so", "libcutils.so", "libnativehelper.so",
		"libcorkscrew.so", "libgccdemangle.so", "libselinux.so",
		"libstlport.so", "libdvm.so", };

static char gLdPreloadsBuffer[LDPRELOAD_BUFSIZE];
static const char* gLdPreloadNames[LDPRELOAD_MAX + 1];

static soinfo* gLdPreloads[LDPRELOAD_MAX + 1];

int gLdDebugVerbosity;

enum RelocationKind {
	kRelocAbsolute = 0, kRelocRelative, kRelocCopy, kRelocSymbol, kRelocMax
};

#if STATS
struct linker_stats_t {
	int count[kRelocMax];
};

static linker_stats_t linker_stats;

static void count_relocation(RelocationKind kind) {
	++linker_stats.count[kind];
}
#else
static void count_relocation(RelocationKind) {
}
#endif

#if COUNT_PAGES
static unsigned bitmask[4096];
#define MARK(offset) \
    do { \
        bitmask[((offset) >> 12) >> 3] |= (1 << (((offset) >> 12) & 7)); \
    } while(0)
#else
#define MARK(x) do {} while (0)
#endif

// You shouldn't try to call memory-allocating functions in the dynamic linker.
// Guard against the most obvious ones.
#define DISALLOW_ALLOCATION(return_type, name, ...) \
    return_type name __VA_ARGS__ \
    { \
        const char* msg = "ERROR: " #name " called from the dynamic linker!\n"; \
        __libc_format_log(ANDROID_LOG_FATAL, "linker", "%s", msg); \
        write(2, msg, strlen(msg)); \
        abort(); \
    }
#define UNUSED __attribute__((unused))
/*DISALLOW_ALLOCATION(void*, malloc, (size_t u UNUSED));
 DISALLOW_ALLOCATION(void, free, (void* u UNUSED));
 DISALLOW_ALLOCATION(void*, realloc, (void* u1 UNUSED, size_t u2 UNUSED));
 DISALLOW_ALLOCATION(void*, calloc, (size_t u1 UNUSED, size_t u2 UNUSED));*/

static char tmp_err_buf[768];
static char __linker_dl_err_buf[768];

char* linker_get_error_buffer() {
	return &__linker_dl_err_buf[0];
}

size_t linker_get_error_buffer_size() {
	return sizeof(__linker_dl_err_buf);
}

static bool ensure_free_list_non_empty() {
	if (gSoInfoFreeList != NULL) {
		return true;
	}

	// Allocate a new pool.
	soinfo_pool_t* pool = reinterpret_cast<soinfo_pool_t*>(mmap(NULL,
			sizeof(*pool), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
			0, 0));
	if (pool == MAP_FAILED) {
		return false;
	}

	// Add the pool to our list of pools.
	pool->next = gSoInfoPools;
	gSoInfoPools = pool;

	// Chain the entries in the new pool onto the free list.
	gSoInfoFreeList = &pool->info[0];
	soinfo* next = NULL;
	for (int i = SOINFO_PER_POOL - 1; i >= 0; --i) {
		pool->info[i].next = next;
		next = &pool->info[i];
	}

	return true;
}

static void set_soinfo_pool_protection(int protection) {
	for (soinfo_pool_t* p = gSoInfoPools; p != NULL; p = p->next) {
		if (mprotect(p, sizeof(*p), protection) == -1) {
			abort(); // Can't happen.
		}
	}
}

soinfo* soinfo_alloc(const char* name) {
	if (strlen(name) >= SOINFO_NAME_LEN) {
		loader_printf(LOG_ERR, "library name \"%s\" too long\n", name);
		return NULL;
	}

	if (!ensure_free_list_non_empty()) {
		loader_printf(LOG_ERR, "out of memory when loading \"%s\"\n", name);
		return NULL;
	}

	// Take the head element off the free list.
	soinfo* si = gSoInfoFreeList;
	gSoInfoFreeList = gSoInfoFreeList->next;

	// Initialize the new element.
	memset(si, 0, sizeof(soinfo));
	strlcpy(si->name, name, sizeof(si->name));
	sonext->next = si;
	sonext = si;

	loader_printf(LOG_DBG, "name %s: allocated soinfo @ %p\n", name, si);
	return si;
}

static void soinfo_free(soinfo* si) {
	if (si == NULL) {
		return;
	}

	soinfo *prev = NULL, *trav;

	loader_printf(LOG_DBG, "name %s: freeing soinfo @ %p\n", si->name, si);

	for (trav = solist; trav != NULL; trav = trav->next) {
		if (trav == si)
			break;
		prev = trav;
	}
	if (trav == NULL) {
		/* si was not in solist */
		loader_printf(LOG_DBG, "name \"%s\" is not in solist!\n", si->name);
		return;
	}

	/* prev will never be NULL, because the first entry in solist is
	 always the static libdl_info.
	 */
	prev->next = si->next;
	if (si == sonext) {
		sonext = prev;
	}
	si->next = gSoInfoFreeList;
	gSoInfoFreeList = si;
}

static void parse_path(const char* path, const char* delimiters,
		const char** array, char* buf, size_t buf_size, size_t max_count) {
	if (path == NULL) {
		return;
	}

	size_t len = strlcpy(buf, path, buf_size);

	size_t i = 0;
	char* buf_p = buf;
	while (i < max_count && (array[i] = strsep(&buf_p, delimiters))) {
		if (*array[i] != '\0') {
			++i;
		}
	}

	// Forget the last path if we had to truncate; this occurs if the 2nd to
	// last char isn't '\0' (i.e. wasn't originally a delimiter).
	if (i > 0 && len >= buf_size && buf[buf_size - 2] != '\0') {
		array[i - 1] = NULL;
	} else {
		array[i] = NULL;
	}
}

#ifdef ANDROID_ARM_LINKER

/* For a given PC, find the .so that it belongs to.
 * Returns the base address of the .ARM.exidx section
 * for that .so, and the number of 8-byte entries
 * in that section (via *pcount).
 *
 * Intended to be called by libc's __gnu_Unwind_Find_exidx().
 *
 * This function is exposed via dlfcn.cpp and libdl.so.
 */
extern "C" _Unwind_Ptr dl_unwind_find_exidx(_Unwind_Ptr pc, int *pcount)
{
	soinfo *si;
	unsigned addr = (unsigned)pc;

	for (si = solist; si != 0; si = si->next) {
		if ((addr >= si->base) && (addr < (si->base + si->size))) {
			*pcount = si->ARM_exidx_count;
			return (_Unwind_Ptr)si->ARM_exidx;
		}
	}
	*pcount = 0;
	return NULL;
}

#elif defined(ANDROID_X86_LINKER) || defined(ANDROID_MIPS_LINKER)

/* Here, we only have to provide a callback to iterate across all the
 * loaded libraries. gcc_eh does the rest. */
int
dl_iterate_phdr(int (*cb)(dl_phdr_info *info, size_t size, void *data),
		void *data)
{
	int rv = 0;
	for (soinfo* si = solist; si != NULL; si = si->next) {
		dl_phdr_info dl_info;
		dl_info.dlpi_addr = si->link_map.l_addr;
		dl_info.dlpi_name = si->link_map.l_name;
		dl_info.dlpi_phdr = si->phdr;
		dl_info.dlpi_phnum = si->phnum;
		rv = cb(&dl_info, sizeof(dl_phdr_info), data);
		if (rv != 0) {
			break;
		}
	}
	return rv;
}

#endif

static Elf32_Sym* soinfo_elf_lookup(soinfo* si, unsigned hash,
		const char* name) {
	Elf32_Sym* symtab = si->symtab;
	const char* strtab = si->strtab;

	for (unsigned n = si->bucket[hash % si->nbucket]; n != 0; n =
			si->chain[n]) {
		Elf32_Sym* s = symtab + n;
		if (strcmp(strtab + s->st_name, name))
			continue;

		/* only concern ourselves with global and weak symbol definitions */
		switch (ELF32_ST_BIND(s->st_info)) {
		case STB_GLOBAL:
		case STB_WEAK:
			if (s->st_shndx == SHN_UNDEF) {
				continue;
			}

			loader_printf(LOG_DBG, "FOUND %s in %s (%08x) %d\n", name, si->name,
					s->st_value, s->st_size);
			return s;
		}
	}

	return NULL;
}

static unsigned elfhash(const char* _name) {
	const unsigned char* name = (const unsigned char*) _name;
	unsigned h = 0, g;

	while (*name) {
		h = (h << 4) + *name++;
		g = h & 0xf0000000;
		h ^= g;
		h ^= g >> 24;
	}
	return h;
}

static Elf32_Sym* soinfo_do_lookup(soinfo* si, const char* name, soinfo** lsi,
		soinfo* needed[]) {
	unsigned elf_hash = elfhash(name);
	Elf32_Sym* s = NULL;
	loader_printf(LOG_DBG,"si %x somain = %x\n",si,somain);
	if (si != NULL && somain != NULL) {

		/*
		 * Local scope is executable scope. Just start looking into it right away
		 * for the shortcut.
		 */

		if (si == somain) {
			s = soinfo_elf_lookup(si, elf_hash, name);
			if (s != NULL) {
				*lsi = si;
				goto done;
			}
		} else {
			/* Order of symbol lookup is controlled by DT_SYMBOLIC flag */

			/*
			 * If this object was built with symbolic relocations disabled, the
			 * first place to look to resolve external references is the main
			 * executable.
			 */

			if (!si->has_DT_SYMBOLIC) {
				loader_printf(LOG_DBG, "%s: looking up %s in executable %s\n",
						si->name, name, somain->name);
				s = soinfo_elf_lookup(somain, elf_hash, name);
				if (s != NULL) {
					*lsi = somain;
					goto done;
				}
			}

			/* Look for symbols in the local scope (the object who is
			 * searching). This happens with C++ templates on i386 for some
			 * reason.
			 *
			 * Notes on weak symbols:
			 * The ELF specs are ambiguous about treatment of weak definitions in
			 * dynamic linking.  Some systems return the first definition found
			 * and some the first non-weak definition.   This is system dependent.
			 * Here we return the first definition found for simplicity.  */

			s = soinfo_elf_lookup(si, elf_hash, name);
			if (s != NULL) {
				*lsi = si;
				goto done;
			}

			/*
			 * If this object was built with -Bsymbolic and symbol is not found
			 * in the local scope, try to find the symbol in the main executable.
			 */

			if (si->has_DT_SYMBOLIC) {
				loader_printf(LOG_DBG,
						"%s: looking up %s in executable %s after local scope\n",
						si->name, name, somain->name);
				s = soinfo_elf_lookup(somain, elf_hash, name);
				if (s != NULL) {
					*lsi = somain;
					goto done;
				}
			}
		}
	}

	/* Next, look for it in the preloads list */
	for (int i = 0; gLdPreloads[i] != NULL; i++) {
		s = soinfo_elf_lookup(gLdPreloads[i], elf_hash, name);
		if (s != NULL) {
			*lsi = gLdPreloads[i];
			goto done;
		}
	}
	loader_printf(LOG_DBG,
			"si->base = 0x%08x, si->strtab = %p, si->symtab = %p,si->bucket = %p,si->chain = %p\n",
			si->base, si->strtab, si->symtab, si->bucket, si->chain);
	for (int i = 0; needed[i] != NULL; i++) {
		loader_printf(LOG_DBG, "%s: looking up %s in %s\n", si->name, name,
				needed[i]->name);
		s = soinfo_elf_lookup(needed[i], elf_hash, name);
		if (s != NULL) {
			*lsi = needed[i];
			goto done;
		}
	}

	done: if (s != NULL) {
		loader_printf( LOG_DBG,
				"si %s sym %s s->st_value = 0x%08x, " "found in %s, base = 0x%08x, load bias = 0x%08x\n",
				si->name, name, s->st_value, (*lsi)->name, (*lsi)->base,
				(*lsi)->load_bias);
		return s;
	}

	return NULL;
}

/* This is used by dlsym(3).  It performs symbol lookup only within the
 specified soinfo object and not in any of its dependencies.

 TODO: Only looking in the specified soinfo seems wrong. dlsym(3) says
 that it should do a breadth first search through the dependency
 tree. This agrees with the ELF spec (aka System V Application
 Binary Interface) where in Chapter 5 it discuss resolving "Shared
 Object Dependencies" in breadth first search order.
 */
Elf32_Sym* dlsym_handle_lookup(soinfo* si, const char* name) {
	return soinfo_elf_lookup(si, elfhash(name), name);
}

/* This is used by dlsym(3) to performs a global symbol lookup. If the
 start value is null (for RTLD_DEFAULT), the search starts at the
 beginning of the global solist. Otherwise the search starts at the
 specified soinfo (for RTLD_NEXT).
 */
Elf32_Sym* dlsym_linear_lookup(const char* name, soinfo** found,
		soinfo* start) {
	unsigned elf_hash = elfhash(name);

	if (start == NULL) {
		start = solist;
	}

	Elf32_Sym* s = NULL;
	for (soinfo* si = start; (s == NULL) && (si != NULL); si = si->next) {
		s = soinfo_elf_lookup(si, elf_hash, name);
		if (s != NULL) {
			*found = si;
			break;
		}
	}

	if (s != NULL) {
		loader_printf(LOG_DBG, "%s s->st_value = 0x%08x, found->base = 0x%08x",
				name, s->st_value, (*found)->base);
	}

	return s;
}

soinfo* find_containing_library(const void* p) {
	Elf32_Addr address = reinterpret_cast<Elf32_Addr>(p);
	for (soinfo* si = solist; si != NULL; si = si->next) {
		if (address >= si->base && address - si->base < si->size) {
			return si;
		}
	}
	return NULL;
}

Elf32_Sym* dladdr_find_symbol(soinfo* si, const void* addr) {
	Elf32_Addr soaddr = reinterpret_cast<Elf32_Addr>(addr) - si->base;

	// Search the library's symbol table for any defined symbol which
	// contains this address.
	for (size_t i = 0; i < si->nchain; ++i) {
		Elf32_Sym* sym = &si->symtab[i];
		if (sym->st_shndx != SHN_UNDEF && soaddr >= sym->st_value
				&& soaddr < sym->st_value + sym->st_size) {
			return sym;
		}
	}

	return NULL;
}

void dump(soinfo* si) {
	Elf32_Sym* s = si->symtab;
	for (unsigned n = 0; n < si->nchain; n++) {
		loader_printf(LOG_DBG, "%04d> %08x: %02x %04x %08x %08x %s", n, s,
				s->st_info, s->st_shndx, s->st_value, s->st_size,
				si->strtab + s->st_name);
		s++;
	}
}

static int open_library_on_path(const char* name, const char* const paths[]) {
	char buf[512];
	for (size_t i = 0; paths[i] != NULL; ++i) {
		if (strcmp(paths[i], "") == 0) {
			int fd = open(name, O_RDONLY | O_CLOEXEC);
			if (fd != -1) {
				return fd;
			}

		}

		int n = snprintf(buf, sizeof(buf), "%s/%s", paths[i], name);
		if (n < 0 || n >= static_cast<int>(sizeof(buf))) {
			loader_printf(LOG_DBG,
					"Warning: ignoring very long library path: %s/%s\n",
					paths[i], name);
			continue;
		}
		int fd = open(buf, O_RDONLY | O_CLOEXEC);
		if (fd != -1) {
			return fd;
		}
	}
	return -1;
}

int open_library(const char* name) {

	// If the name contains a slash, we should attempt to open it directly and not search the paths.
	if (strchr(name, '/') != NULL) {
		int fd = open(name, O_RDONLY | O_CLOEXEC);
		if (fd != -1) {
			return fd;
		}
		// ...but nvidia binary blobs (at least) rely on this behavior, so fall through for now.
	}

	// Otherwise we try LD_LIBRARY_PATH first, and fall back to the built-in well known paths.
	int fd = open_library_on_path(name, gLdPaths);

	return fd;
}

static soinfo* load_library(const char* name) {
	// Open the file.
	loader_printf(LOG_INFO, "open %s\n", name);

	int fd = open_library(name);
	if (fd == -1) {
		loader_printf(LOG_ERR, "library \"%s\" not found\n", name);
		return NULL;
	}

	// Read the ELF header and load the segments.
	ElfReader elf_reader(name, fd, 0);
	if (!elf_reader.Load()) {
		return NULL;
	}

	const char* bname = strrchr(name, '/');
	soinfo* si = soinfo_alloc(bname ? bname + 1 : name);
	if (si == NULL) {
		return NULL;
	}
	si->base = elf_reader.load_start();
	si->size = elf_reader.load_size();
	si->load_bias = elf_reader.load_bias();
	si->flags = 0;
	si->entry = 0;
	si->dynamic = NULL;
	si->phnum = elf_reader.phdr_count();
	si->phdr = elf_reader.loaded_phdr();
	
	return si;
}

soinfo *find_loaded_library(const char *name) {
	soinfo *si;
	const char *bname;

	// TODO: don't use basename only for determining libraries
	// http://code.google.com/p/android/issues/detail?id=6670

	bname = strrchr(name, '/');
	bname = bname ? bname + 1 : name;

	for (si = solist; si != NULL; si = si->next) {
		if (!strcmp(bname, si->name)) {
			return si;
		}
	}
	return NULL;
}

static soinfo* find_library_internal(const char* name) {
	if (name == NULL) {
		return somain;
	}

	soinfo* si = find_loaded_library(name);
	if (si != NULL) {
		if (si->flags & FLAG_LINKED) {
			return si;
		}
		loader_printf(LOG_DBG, "OOPS: recursive link to \"%s\"\n", si->name);
		return NULL;
	}

	loader_printf(LOG_INFO, "[ '%s' has not been loaded yet.  Locating...]\n",
			name);
	si = load_library(name);
	if (si == NULL) {
		return NULL;
	}

	// At this point we know that whatever is loaded @ base is a valid ELF
	// shared library whose segments are properly mapped in.
	loader_printf(LOG_DBG, "[ init_library base=0x%08x sz=0x%08x name='%s' ]\n",
			si->base, si->size, si->name);

	if (!soinfo_link_image(si, true, 0)) {
		munmap(reinterpret_cast<void*>(si->base), si->size);
		soinfo_free(si);
		return NULL;
	}

	return si;
}

static soinfo* find_library(const char* name) {
	soinfo* si = find_library_internal(name);
	if (si != NULL) {
		si->ref_count++;
	}
	return si;
}

static int soinfo_unload(soinfo* si) {
	if (si->ref_count == 1) {
		loader_printf(LOG_DBG, "unloading '%s'\n", si->name);
		if (!strcmp(si->name, "libc.so") || !strcmp(si->name, "libstdc++.so")
				|| !strcmp(si->name, "libm.so") || !strcmp(si->name, "libz.so")
				|| !strcmp(si->name, "libdl.so")
				|| !strcmp(si->name, "liblog.so"))
			;
		else
			si->CallDestructors();

		for (Elf32_Dyn* d = si->dynamic; d->d_tag != DT_NULL; ++d) {
			if (d->d_tag == DT_NEEDED) {
				const char* library_name = si->strtab + d->d_un.d_val;
				loader_printf(LOG_DBG, "%s needs to unload %s\n", si->name,
						library_name);
				soinfo_unload(find_loaded_library(library_name));
			}
		}

		munmap(reinterpret_cast<void*>(si->base), si->size);
		//notify_gdb_of_unload(si);
		soinfo_free(si);
		si->ref_count = 0;
	} else {
		si->ref_count--;
		loader_printf(LOG_DBG,
				"not unloading '%s', decrementing ref_count to %d\n", si->name,
				si->ref_count);
	}
	return 0;
}

soinfo* do_dlopen(const char* name, int flags) {
	if ((flags & ~(RTLD_NOW | RTLD_LAZY | RTLD_LOCAL | RTLD_GLOBAL)) != 0) {
		loader_printf(LOG_DBG, "invalid flags to dlopen: %x", flags);
		return NULL;
	}
	set_soinfo_pool_protection(PROT_READ | PROT_WRITE);
	soinfo* si = find_library(name);

	if (si != NULL) {
		if (!strcmp(si->name, "libc.so") || !strcmp(si->name, "libstdc++.so")
				|| !strcmp(si->name, "libz.so") || !strcmp(si->name, "libm.so")
				|| !strcmp(si->name, "liblog.so"))
			;
		else {
			si->CallConstructors();
		}
	}
	set_soinfo_pool_protection (PROT_READ);
	return si;
}

int do_dlclose(soinfo* si) {
	set_soinfo_pool_protection(PROT_READ | PROT_WRITE);
	int result = soinfo_unload(si);
	set_soinfo_pool_protection (PROT_READ);
	return result;
}

/* TODO: don't use unsigned for addrs below. It works, but is not
 * ideal. They should probably be either uint32_t, Elf32_Addr, or unsigned
 * long.
 */
static int soinfo_relocate(soinfo* si, Elf32_Rel* rel, unsigned count,
		soinfo* needed[]) {
	Elf32_Sym* symtab = si->symtab;
	const char* strtab = si->strtab;
	Elf32_Sym* s;
	Elf32_Rel* start = rel;
	soinfo* lsi;

	for (size_t idx = 0; idx < count; ++idx, ++rel) {
		unsigned type = ELF32_R_TYPE(rel->r_info);
		unsigned sym = ELF32_R_SYM(rel->r_info);
		Elf32_Addr reloc =
				static_cast<Elf32_Addr>(rel->r_offset + si->load_bias);
		Elf32_Addr sym_addr = 0;
		char* sym_name = NULL;

		loader_printf(LOG_DBG, "Processing '%s' relocation at index %d\n",
				si->name, idx);
		if (type == 0) { // R_*_NONE
			continue;
		}
		if (sym != 0) {
			sym_name = (char *) (strtab + symtab[sym].st_name);
			s = soinfo_do_lookup(si, sym_name, &lsi, needed);
			if (s == NULL) {
				/* We only allow an undefined symbol if this is a weak
				 reference..   */
				s = &symtab[sym];
				if (ELF32_ST_BIND(s->st_info) != STB_WEAK) {
					loader_printf(LOG_DBG,
							"cannot locate symbol \"%s\" referenced by \"%s\"...\n",
							sym_name, si->name);
				}

				/* IHI0044C AAELF 4.5.1.1:

				 Libraries are not searched to resolve weak references.
				 It is not an error for a weak reference to remain
				 unsatisfied.

				 During linking, the value of an undefined weak reference is:
				 - Zero if the relocation type is absolute
				 - The address of the place if the relocation is pc-relative
				 - The address of nominal base address if the relocation
				 type is base-relative.
				 */

				switch (type) {
#if defined(ANDROID_ARM_LINKER)
				case R_ARM_JUMP_SLOT:
				case R_ARM_GLOB_DAT:
				case R_ARM_ABS32:
				case R_ARM_RELATIVE: /* Don't care. */
#elif defined(ANDROID_X86_LINKER)
				case R_386_JMP_SLOT:
				case R_386_GLOB_DAT:
				case R_386_32:
				case R_386_RELATIVE: /* Dont' care. */
#endif /* ANDROID_*_LINKER */
				/* sym_addr was initialized to be zero above or relocation
				 code below does not care about value of sym_addr.
				 No need to do anything.  */
				break;

#if defined(ANDROID_X86_LINKER)
				case R_386_PC32:
				sym_addr = reloc;
				break;
#endif /* ANDROID_X86_LINKER */

#if defined(ANDROID_ARM_LINKER)
				case R_ARM_COPY:
				/* Fall through.  Can't really copy if weak symbol is
				 not found in run-time.  */
#endif /* ANDROID_ARM_LINKER */
			default:
				loader_printf(LOG_DBG, "unknown weak reloc type %d @ %p (%d)\n",
						type, rel, (int) (rel - start));
				return -1;
				}
			} else {
				/* We got a definition.  */
#if 0
				if ((base == 0) && (si->base != 0)) {
					/* linking from libraries to main image is bad */
					DL_ERR("cannot locate \"%s\"...",
							strtab + symtab[sym].st_name);
					return -1;
				}
#endif
				sym_addr =
						static_cast<Elf32_Addr>(s->st_value + lsi->load_bias);
			}
			count_relocation(kRelocSymbol);
		} else {
			s = NULL;
		}

		/* TODO: This is ugly. Split up the relocations by arch into
		 * different files.
		 */
		switch (type) {
#if defined(ANDROID_ARM_LINKER)
		case R_ARM_JUMP_SLOT:
		count_relocation(kRelocAbsolute);
		MARK(rel->r_offset);
		loader_printf(LOG_DBG,"RELO JMP_SLOT %08x <- %08x %s\n", reloc, sym_addr, sym_name);
		*reinterpret_cast<Elf32_Addr*>(reloc) = sym_addr;
		break;
		case R_ARM_GLOB_DAT:
		count_relocation(kRelocAbsolute);
		MARK(rel->r_offset);
		loader_printf(LOG_DBG,"RELO GLOB_DAT %08x <- %08x %s\n", reloc, sym_addr, sym_name);
		*reinterpret_cast<Elf32_Addr*>(reloc) = sym_addr;
		break;
		case R_ARM_ABS32:
		count_relocation(kRelocAbsolute);
		MARK(rel->r_offset);
		loader_printf(LOG_DBG,"RELO ABS %08x <- %08x %s\n", reloc, sym_addr, sym_name);
		*reinterpret_cast<Elf32_Addr*>(reloc) += sym_addr;
		break;
		case R_ARM_REL32:
		count_relocation(kRelocRelative);
		MARK(rel->r_offset);
		loader_printf(LOG_DBG,"RELO REL32 %08x <- %08x - %08x %s\n",
				reloc, sym_addr, rel->r_offset, sym_name);
		*reinterpret_cast<Elf32_Addr*>(reloc) += sym_addr - rel->r_offset;
		break;
#elif defined(ANDROID_X86_LINKER)
		case R_386_JMP_SLOT:
		count_relocation(kRelocAbsolute);
		MARK(rel->r_offset);
		loader_printf(LOG_DBG,"RELO JMP_SLOT %08x <- %08x %s", reloc, sym_addr, sym_name);
		*reinterpret_cast<Elf32_Addr*>(reloc) = sym_addr;
		break;
		case R_386_GLOB_DAT:
		count_relocation(kRelocAbsolute);
		MARK(rel->r_offset);
		loader_printf(LOG_DBG,"RELO GLOB_DAT %08x <- %08x %s", reloc, sym_addr, sym_name);
		*reinterpret_cast<Elf32_Addr*>(reloc) = sym_addr;
		break;
#elif defined(ANDROID_MIPS_LINKER)
		case R_MIPS_REL32:
		count_relocation(kRelocAbsolute);
		MARK(rel->r_offset);
		TRACE_TYPE(RELO, "RELO REL32 %08x <- %08x %s",
				reloc, sym_addr, (sym_name) ? sym_name : "*SECTIONHDR*");
		if (s) {
			*reinterpret_cast<Elf32_Addr*>(reloc) += sym_addr;
		} else {
			*reinterpret_cast<Elf32_Addr*>(reloc) += si->base;
		}
		break;
#endif /* ANDROID_*_LINKER */

#if defined(ANDROID_ARM_LINKER)
		case R_ARM_RELATIVE:
#elif defined(ANDROID_X86_LINKER)
		case R_386_RELATIVE:
#endif /* ANDROID_*_LINKER */
		count_relocation(kRelocRelative);
		MARK(rel->r_offset);
		if (sym) {
			printf("odd RELATIVE form...");
			return -1;
		}
		loader_printf(LOG_DBG, "RELO RELATIVE %08x <- +%08x %08x\n", reloc,
				si->base,si->load_bias);
		*reinterpret_cast<Elf32_Addr*>(reloc) += si->base;
		break;

#if defined(ANDROID_X86_LINKER)
		case R_386_32:
		count_relocation(kRelocRelative);
		MARK(rel->r_offset);

		loader_printf(LOG_DBG,"RELO R_386_32 %08x <- +%08x %s\n", reloc, sym_addr, sym_name);
		*reinterpret_cast<Elf32_Addr*>(reloc) += sym_addr;
		break;

		case R_386_PC32:
		count_relocation(kRelocRelative);
		MARK(rel->r_offset);
		loader_printf(LOG_DBG,"RELO R_386_PC32 %08x <- +%08x (%08x - %08x) %s\n",
				reloc, (sym_addr - reloc), sym_addr, reloc, sym_name);
		*reinterpret_cast<Elf32_Addr*>(reloc) += (sym_addr - reloc);
		break;
#endif /* ANDROID_X86_LINKER */

#ifdef ANDROID_ARM_LINKER
		case R_ARM_COPY:
		if ((si->flags & FLAG_EXE) == 0) {
			/*
			 * http://infocenter.arm.com/help/topic/com.arm.doc.ihi0044d/IHI0044D_aaelf.pdf
			 *
			 * Section 4.7.1.10 "Dynamic relocations"
			 * R_ARM_COPY may only appear in executable objects where e_type is
			 * set to ET_EXEC.
			 *
			 * TODO: FLAG_EXE is set for both ET_DYN and ET_EXEC executables.
			 * We should explicitly disallow ET_DYN executables from having
			 * R_ARM_COPY relocations.
			 */
			loader_printf(LOG_DBG,"%s R_ARM_COPY relocations only supported for ET_EXEC", si->name);
			return -1;
		}
		count_relocation(kRelocCopy);
		MARK(rel->r_offset);
		loader_printf(LOG_DBG,"RELO %08x <- %d @ %08x %s", reloc, s->st_size, sym_addr, sym_name);
		if (reloc == sym_addr) {
			Elf32_Sym *src = soinfo_do_lookup(NULL, sym_name, &lsi, needed);

			if (src == NULL) {
				loader_printf(LOG_DBG,"%s R_ARM_COPY relocation source cannot be resolved", si->name);
				return -1;
			}
			if (lsi->has_DT_SYMBOLIC) {
				loader_printf(LOG_DBG,"%s invalid R_ARM_COPY relocation against DT_SYMBOLIC shared "
						"library %s (built with -Bsymbolic?)", si->name, lsi->name);
				return -1;
			}
			if (s->st_size < src->st_size) {
				loader_printf(LOG_DBG,"%s R_ARM_COPY relocation size mismatch (%d < %d)",
						si->name, s->st_size, src->st_size);
				return -1;
			}
			memcpy((void*)reloc, (void*)(src->st_value + lsi->load_bias), src->st_size);
		} else {
			loader_printf(LOG_DBG,"%s R_ARM_COPY relocation target cannot be resolved", si->name);
			return -1;
		}
		break;
#endif /* ANDROID_ARM_LINKER */

	default:
		loader_printf(LOG_DBG, "unknown reloc type %d @ %p (%d)\n", type, rel,
				(int) (rel - start));
		return -1;
		}
	}
	return 0;
}

void soinfo::CallArray(const char* array_name UNUSED,
		linker_function_t* functions, size_t count, bool reverse) {
	if (functions == NULL) {
		return;
	}

	loader_printf(LOG_DBG, "[ Calling %s (size %d) @ %p for '%s' ]\n",
			array_name, count, functions, name);

	int begin = reverse ? (count - 1) : 0;
	int end = reverse ? -1 : count;
	int step = reverse ? -1 : 1;

	for (int i = begin; i != end; i += step) {
		loader_printf(LOG_DBG, "[ %s[%d] == %p ]\n", array_name, i,
				functions[i]);
		CallFunction("function", functions[i]);
	}

	loader_printf(LOG_DBG, "[ Done calling %s for '%s' ]\n", array_name, name);
}

void soinfo::CallFunction(const char* function_name UNUSED,
		linker_function_t function) {
	if (function == NULL
			|| reinterpret_cast<uintptr_t>(function)
					== static_cast<uintptr_t>(-1)) {
		return;
	}

	loader_printf(LOG_ERR, "[ Calling %s @ %p for '%s' ]\n", function_name,
			function, name);

	if (gbreak) {
		loader_printf(LOG_ERR, "break! please use debugger attach\n");
		__asm__("loop: b loop");
		//some phone can not break,so use dead loop
	}

	function();

	loader_printf(LOG_ERR, "[ Done calling %s @ %p for '%s' ]\n", function_name,
			function, name);

	// The function may have called dlopen(3) or dlclose(3), so we need to ensure our data structures
	// are still writable. This happens with our debug malloc (see http://b/7941716).
	set_soinfo_pool_protection(PROT_READ | PROT_WRITE);
}

void soinfo::CallPreInitConstructors() {
	// DT_PREINIT_ARRAY functions are called before any other constructors for executables,
	// but ignored in a shared library.
	CallArray("DT_PREINIT_ARRAY", preinit_array, preinit_array_count, false);
}

void soinfo::CallConstructors() {
	if (constructors_called) {
		return;
	}

	// We set constructors_called before actually calling the constructors, otherwise it doesn't
	// protect against recursive constructor calls. One simple example of constructor recursion
	// is the libc debug malloc, which is implemented in libc_malloc_debug_leak.so:
	// 1. The program depends on libc, so libc's constructor is called here.
	// 2. The libc constructor calls dlopen() to load libc_malloc_debug_leak.so.
	// 3. dlopen() calls the constructors on the newly created
	//    soinfo for libc_malloc_debug_leak.so.
	// 4. The debug .so depends on libc, so CallConstructors is
	//    called again with the libc soinfo. If it doesn't trigger the early-
	//    out above, the libc constructor will be called again (recursively!).
	constructors_called = true;

	if ((flags & FLAG_EXE) == 0 && preinit_array != NULL) {
		// The GNU dynamic linker silently ignores these, but we warn the developer.
		loader_printf(LOG_INFO,
				"\"%s\": ignoring %d-entry DT_PREINIT_ARRAY in shared library!\n",
				name, preinit_array_count);
	}

	if (dynamic != NULL) {
		for (Elf32_Dyn* d = dynamic; d->d_tag != DT_NULL; ++d) {
			if (d->d_tag == DT_NEEDED) {
				const char* library_name = strtab + d->d_un.d_val;
				//loader_printf(LOG_DBG,"\"%s\": calling constructors in DT_NEEDED \"%s\"\n", name, library_name);
				//find_loaded_library(library_name)->CallConstructors();
				soinfo* si = find_loaded_library(library_name);
				if (!strcmp(si->name, "libc.so") || !strcmp(si->name, "libstdc++.so")
				|| !strcmp(si->name, "libm.so") || !strcmp(si->name, "libz.so")
				|| !strcmp(si->name, "libdl.so")
				|| !strcmp(si->name, "liblog.so"))
			    ;
		    else
				    si->CallConstructors();
			}
		}
	}

	loader_printf(LOG_INFO, "\"%s\": calling constructors\n", name);

	// DT_INIT should be called before DT_INIT_ARRAY if both are present.

	CallFunction("DT_INIT", init_func);
  CallArray("DT_INIT_ARRAY", init_array, init_array_count, false);

}

void soinfo::CallDestructors() {
	loader_printf(LOG_INFO, "\"%s\": calling destructors\n", name);

	// DT_FINI_ARRAY must be parsed in reverse order.
	CallArray("DT_FINI_ARRAY", fini_array, fini_array_count, true);

	// DT_FINI should be called after DT_FINI_ARRAY if both are present.
	CallFunction("DT_FINI", fini_func);
}

/* Force any of the closed stdin, stdout and stderr to be associated with
 /dev/null. */
static int nullify_closed_stdio() {
	int dev_null, i, status;
	int return_value = 0;

	dev_null = open("/dev/null", O_RDWR);
	if (dev_null < 0) {
		loader_printf(LOG_DBG, "cannot open /dev/null: %s", strerror(errno));
		return -1;
	}
	loader_printf(LOG_DBG, "[ Opened /dev/null file-descriptor=%d]", dev_null);

	/* If any of the stdio file descriptors is valid and not associated
	 with /dev/null, dup /dev/null to it.  */
	for (i = 0; i < 3; i++) {
		/* If it is /dev/null already, we are done. */
		if (i == dev_null) {
			continue;
		}

		loader_printf(LOG_DBG, "[ Nullifying stdio file descriptor %d]", i);
		/* status = fcntl(i, F_GETFL);
		 if (status != -1) {
		 continue;
		 }*/

		/* The only error we allow is that the file descriptor does not
		 exist, in which case we dup /dev/null to it. */
		if (errno != EBADF) {
			loader_printf(LOG_DBG, "fcntl failed: %s", strerror(errno));
			return_value = -1;
			continue;
		}

		/* Try dupping /dev/null to this stdio file descriptor and
		 repeat if there is a signal.  Note that any errors in closing
		 the stdio descriptor are lost.  */
		status = dup2(dev_null, i);
		if (status < 0) {
			loader_printf(LOG_DBG, "dup2 failed: %s", strerror(errno));
			return_value = -1;
			continue;
		}
	}

	/* If /dev/null is not one of the stdio file descriptors, close it. */
	if (dev_null > 2) {
		loader_printf(LOG_DBG, "[ Closing /dev/null file-descriptor=%d]\n",
				dev_null);
		status = close(dev_null);
		if (status == -1) {
			loader_printf(LOG_DBG, "close failed: %s", strerror(errno));
			return_value = -1;
		}
	}

	return return_value;
}

bool soinfo_link_image(soinfo* si, bool breloc, ElfReader* reader) {
	/* "base" might wrap around UINT32_MAX. */
	Elf32_Addr base = si->load_bias;
	const Elf32_Phdr *phdr = si->phdr;
	int phnum = si->phnum;
	bool relocating_linker = (si->flags & FLAG_LINKER) != 0;

	/* We can't debug anything until the linker is relocated */
	if (!relocating_linker) {
		loader_printf(LOG_INFO, "[ linking %s ]\n", si->name);
		loader_printf(LOG_DBG, "si->base = 0x%08x si->flags = 0x%08x\n",
				si->base, si->flags);
	}

	/* Extract dynamic section */
	size_t dynamic_count;
	Elf32_Word dynamic_flags;
	phdr_table_get_dynamic_section(phdr, phnum, base, &si->dynamic,
			&dynamic_count, &dynamic_flags, reader);
	if (si->dynamic == NULL) {
		if (!relocating_linker) {
			loader_printf(LOG_DBG, "missing PT_DYNAMIC in \"%s\"\n", si->name);
		}
		return false;
	} else {
		if (!relocating_linker) {
			loader_printf(LOG_DBG, "dynamic = %p\n", si->dynamic);
		}
	}

#ifdef ANDROID_ARM_LINKER
	(void) phdr_table_get_arm_exidx(phdr, phnum, base,
			&si->ARM_exidx, &si->ARM_exidx_count,reader);
#endif

	// Extract useful information from dynamic section.
	uint32_t needed_count = 0;
	for (Elf32_Dyn* d = si->dynamic; d->d_tag != DT_NULL; ++d) {
		loader_printf(LOG_DBG,
				"d = %p, d[0](tag) = 0x%08x d[1](val) = 0x%08x\n", d, d->d_tag,
				d->d_un.d_val);
		switch (d->d_tag) {
		case DT_HASH:
			si->nbucket = ((unsigned *) (base + d->d_un.d_ptr))[0];
			si->nchain = ((unsigned *) (base + d->d_un.d_ptr))[1];
			si->bucket = (unsigned *) (base + d->d_un.d_ptr + 8);
			si->chain =
					(unsigned *) (base + d->d_un.d_ptr + 8 + si->nbucket * 4);
			break;
		case DT_STRTAB:
			si->strtab = (const char *) (base + d->d_un.d_ptr);
			break;
		case DT_SYMTAB:
			si->symtab = (Elf32_Sym *) (base + d->d_un.d_ptr);
			break;
		case DT_PLTREL:
			if (d->d_un.d_val != DT_REL) {
				loader_printf(LOG_DBG, "unsupported DT_RELA in \"%s\"",
						si->name);
				return false;
			}
			break;
		case DT_JMPREL:
			si->plt_rel = (Elf32_Rel*) (base + d->d_un.d_ptr);
			break;
		case DT_PLTRELSZ:
			si->plt_rel_count = d->d_un.d_val / sizeof(Elf32_Rel);
			break;
		case DT_REL:
			si->rel = (Elf32_Rel*) (base + d->d_un.d_ptr);
			break;
		case DT_RELSZ:
			si->rel_count = d->d_un.d_val / sizeof(Elf32_Rel);
			break;
		case DT_PLTGOT:
			/* Save this in case we decide to do lazy binding. We don't yet. */
			si->plt_got = (unsigned *) (base + d->d_un.d_ptr);
			break;
			/*case DT_DEBUG:
			 // Set the DT_DEBUG entry to the address of _r_debug for GDB
			 // if the dynamic table is writable
			 if ((dynamic_flags & PF_W) != 0) {
			 d->d_un.d_val = (int) &_r_debug;
			 }
			 break;*/
		case DT_RELA:
			loader_printf(LOG_DBG, "unsupported DT_RELA in \"%s\"", si->name);
			return false;
		case DT_INIT:
			si->init_func = reinterpret_cast<linker_function_t>(base
					+ d->d_un.d_ptr);
			loader_printf(LOG_DBG, "%s constructors (DT_INIT) found at %p",
					si->name, si->init_func);
			break;
		case DT_FINI:
			si->fini_func = reinterpret_cast<linker_function_t>(base
					+ d->d_un.d_ptr);
			loader_printf(LOG_DBG, "%s destructors (DT_FINI) found at %p",
					si->name, si->fini_func);
			break;
		case DT_INIT_ARRAY:
			si->init_array = reinterpret_cast<linker_function_t*>(base
					+ d->d_un.d_ptr);
			loader_printf(LOG_DBG,
					"%s constructors (DT_INIT_ARRAY) found at %p", si->name,
					si->init_array);
			break;
		case DT_INIT_ARRAYSZ:
			si->init_array_count = ((unsigned) d->d_un.d_val)
					/ sizeof(Elf32_Addr);
			break;
		case DT_FINI_ARRAY:
			si->fini_array = reinterpret_cast<linker_function_t*>(base
					+ d->d_un.d_ptr);
			loader_printf(LOG_DBG, "%s destructors (DT_FINI_ARRAY) found at %p",
					si->name, si->fini_array);
			break;
		case DT_FINI_ARRAYSZ:
			si->fini_array_count = ((unsigned) d->d_un.d_val)
					/ sizeof(Elf32_Addr);
			break;
		case DT_PREINIT_ARRAY:
			si->preinit_array = reinterpret_cast<linker_function_t*>(base
					+ d->d_un.d_ptr);
			loader_printf(LOG_DBG,
					"%s constructors (DT_PREINIT_ARRAY) found at %p", si->name,
					si->preinit_array);
			break;
		case DT_PREINIT_ARRAYSZ:
			si->preinit_array_count = ((unsigned) d->d_un.d_val)
					/ sizeof(Elf32_Addr);
			break;
		case DT_TEXTREL:
			si->has_text_relocations = true;
			break;
		case DT_SYMBOLIC:
			si->has_DT_SYMBOLIC = true;
			break;
		case DT_NEEDED:
			++needed_count;
			break;
#if defined DT_FLAGS
			// TODO: why is DT_FLAGS not defined?
			case DT_FLAGS:
			if (d->d_un.d_val & DF_TEXTREL) {
				si->has_text_relocations = true;
			}
			if (d->d_un.d_val & DF_SYMBOLIC) {
				si->has_DT_SYMBOLIC = true;
			}
			break;
#endif
		}
	}

	loader_printf(LOG_DBG,
			"si->base = 0x%08x, si->strtab = %p, si->symtab = %p,si->bucket = %p,si->chain = %p\n",
			si->base, si->strtab, si->symtab, si->bucket, si->chain);

	// Sanity checks.
	if (relocating_linker && needed_count != 0) {
		loader_printf(LOG_DBG,
				"linker cannot have DT_NEEDED dependencies on other libraries\n");
		return false;
	}
	if (si->nbucket == 0) {
		loader_printf(LOG_DBG,
				"empty/missing DT_HASH in \"%s\" (built with --hash-style=gnu?)\n",
				si->name);
		return false;
	}
	if (si->strtab == 0) {
		loader_printf(LOG_DBG, "empty/missing DT_STRTAB in \"%s\"\n", si->name);
		return false;
	}
	if (si->symtab == 0) {
		loader_printf(LOG_DBG, "empty/missing DT_SYMTAB in \"%s\"\n", si->name);
		return false;
	}

	// If this is the main executable, then load all of the libraries from LD_PRELOAD now.
	if (si->flags & FLAG_EXE) {
		memset(gLdPreloads, 0, sizeof(gLdPreloads));
		size_t preload_count = 0;
		for (size_t i = 0; gLdPreloadNames[i] != NULL; i++) {
			soinfo* lsi = find_library(gLdPreloadNames[i]);
			if (lsi != NULL) {
				gLdPreloads[preload_count++] = lsi;
			} else {
				// As with glibc, failure to load an LD_PRELOAD library is just a warning.
				loader_printf(LOG_DBG,
						"could not load library \"%s\" from LD_PRELOAD for \"%s\"; caused by %s\n",
						gLdPreloadNames[i], si->name,
						linker_get_error_buffer());
			}
		}
	}

	soinfo** needed = (soinfo**) malloc((1 + needed_count) * sizeof(soinfo*));
	soinfo** pneeded = needed;

	for (Elf32_Dyn* d = si->dynamic; d->d_tag != DT_NULL; ++d) {
		if (d->d_tag == DT_NEEDED) {
			const char* library_name = si->strtab + d->d_un.d_val;
			loader_printf(LOG_DBG, "%s needs %s\n", si->name, library_name);
			soinfo* lsi = find_library(library_name);
			if (lsi == NULL) {
				strlcpy(tmp_err_buf, linker_get_error_buffer(),
						sizeof(tmp_err_buf));
				loader_printf(LOG_DBG,
						"could not load library \"%s\" needed by \"%s\"; caused by %s\n",
						library_name, si->name, tmp_err_buf);
				return false;
			}
			*pneeded++ = lsi;
		}
	}
	*pneeded = NULL;

	if (si->has_text_relocations) {
		/* Unprotect the segments, i.e. make them writable, to allow
		 * text relocations to work properly. We will later call
		 * phdr_table_protect_segments() after all of them are applied
		 * and all constructors are run.
		 */
		loader_printf(LOG_DBG,
				"%s has text relocations. This is wasting memory and is "
						"a security risk. Please fix.", si->name);
		if (phdr_table_unprotect_segments(si->phdr, si->phnum, si->load_bias)
				< 0) {
			loader_printf(LOG_DBG,
					"can't unprotect loadable segments for \"%s\": %s",
					si->name, strerror(errno));
			return false;
		}
	}

	if (si->plt_rel != NULL && breloc) {
		loader_printf(LOG_DBG, "[ relocating %s plt ]\n", si->name);
		if (soinfo_relocate(si, si->plt_rel, si->plt_rel_count, needed)) {
			return false;
		}
	}
	if (si->rel != NULL && breloc) {
		loader_printf(LOG_INFO, "[ relocating %s ]\n", si->name);
		if (soinfo_relocate(si, si->rel, si->rel_count, needed)) {
			return false;
		}
	}

#ifdef ANDROID_MIPS_LINKER
	if (!mips_relocate_got(si, needed)) {
		return false;
	}
#endif

	si->flags |= FLAG_LINKED;
	loader_printf(LOG_INFO, "[ finished linking %s ]\n", si->name);

	if (si->has_text_relocations) {
		/* All relocations are done, we can protect our segments back to
		 * read-only. */
		if (phdr_table_protect_segments(si->phdr, si->phnum, si->load_bias)
				< 0) {
			loader_printf(LOG_DBG, "can't protect segments for \"%s\": %s\n",
					si->name, strerror(errno));
			return false;
		}
	}

	/* We can also turn on GNU RELRO protection */
	if (phdr_table_protect_gnu_relro(si->phdr, si->phnum, si->load_bias) < 0) {
		loader_printf(LOG_DBG,
				"can't enable GNU RELRO protection for \"%s\": %s\n", si->name,
				strerror(errno));
		return false;
	}
	
	si->flags |= FLAG_LINKED;

	return true;
}

/*
 * This code is called after the linker has linked itself and
 * fixed it's own GOT. It is safe to make references to externs
 * and other non-local data at this point.
 */
/* Compute the load-bias of an existing executable. This shall only
 * be used to compute the load bias of an executable or shared library
 * that was loaded by the kernel itself.
 *
 * Input:
 *    elf    -> address of ELF header, assumed to be at the start of the file.
 * Return:
 *    load bias, i.e. add the value of any p_vaddr in the file to get
 *    the corresponding address in memory.
 */
static Elf32_Addr get_elf_exec_load_bias(const Elf32_Ehdr* elf) {
	Elf32_Addr offset = elf->e_phoff;
	const Elf32_Phdr* phdr_table = (const Elf32_Phdr*) ((char*) elf + offset);
	const Elf32_Phdr* phdr_end = phdr_table + elf->e_phnum;

	for (const Elf32_Phdr* phdr = phdr_table; phdr < phdr_end; phdr++) {
		if (phdr->p_type == PT_LOAD) {
			return reinterpret_cast<Elf32_Addr>(elf) + phdr->p_offset
					- phdr->p_vaddr;
		}
	}
	return 0;
}

int glog_level = LOG_ERR;

int loader_printf(int level, const char* format, ...) {
	if (level >= glog_level) {
		va_list args;

		va_start(args, format);

		vfprintf(stdout, format, args);

		va_end(args);
	}
}
