#ifndef _LINKER_H_
#define _LINKER_H_

#include <unistd.h>
#include <sys/types.h>
#include "elf.h"
#include <stdarg.h>

#define LOG_DBG   0
#define LOG_INFO  1
#define LOG_ERR   2

int loader_printf(int level, const char* format, ...);

// Returns the address of the page containing address 'x'.
#define PAGE_START(x)  ((x) & PAGE_MASK)

// Returns the offset of address 'x' in its page.
#define PAGE_OFFSET(x) ((x) & ~PAGE_MASK)

// Returns the address of the next page after address 'x', unless 'x' is
// itself at the start of a page.
#define PAGE_END(x)    PAGE_START((x) + (PAGE_SIZE-1))

#define PAGE_ALIGN(x)  (((x)+PAGE_SIZE-1)& PAGE_MASK)

/* bionic is currently only 32-bit. */
#define ElfW(type) Elf32_##type

struct dl_phdr_info {
	ElfW(Addr) dlpi_addr;
	const char* dlpi_name;
	const ElfW(Phdr)* dlpi_phdr;
	ElfW(Half) dlpi_phnum;
};

// Magic shared structures that GDB knows about.

struct link_map_t {
	uintptr_t l_addr;
	char* l_name;
	uintptr_t l_ld;
	link_map_t* l_next;
	link_map_t* l_prev;
};

// Values for r_debug->state
enum {
	RT_CONSISTENT, RT_ADD, RT_DELETE
};

struct r_debug {
	int32_t r_version;
	link_map_t* r_map;
	void (*r_brk)(void);
	int32_t r_state;
	uintptr_t r_ldbase;
};

#define FLAG_LINKED     0x00000001
#define FLAG_EXE        0x00000004 // The main executable
#define FLAG_LINKER     0x00000010 // The linker itself

#define SOINFO_NAME_LEN 128

typedef void (*linker_function_t)();

struct soinfo {
public:
	char name[SOINFO_NAME_LEN];
	const Elf32_Phdr* phdr;
	size_t phnum;
	Elf32_Addr entry;
	Elf32_Addr base;
	unsigned size;

	uint32_t unused1;  // DO NOT USE, maintained for compatibility.

	Elf32_Dyn* dynamic;

	uint32_t unused2; // DO NOT USE, maintained for compatibility
	uint32_t unused3; // DO NOT USE, maintained for compatibility

	soinfo* next;
	unsigned flags;

	const char* strtab;
	Elf32_Sym* symtab;

	size_t nbucket;
	size_t nchain;
	unsigned* bucket;
	unsigned* chain;

	unsigned* plt_got;

	Elf32_Rel* plt_rel;
	size_t plt_rel_count;

	Elf32_Rel* rel;
	size_t rel_count;

	linker_function_t* preinit_array;
	size_t preinit_array_count;

	linker_function_t* init_array;
	size_t init_array_count;
	linker_function_t* fini_array;
	size_t fini_array_count;

	linker_function_t init_func;
	linker_function_t fini_func;

#if defined(ANDROID_ARM_LINKER)
	// ARM EABI section used for stack unwinding.
	unsigned* ARM_exidx;
	size_t ARM_exidx_count;
#elif defined(ANDROID_MIPS_LINKER)
	unsigned mips_symtabno;
	unsigned mips_local_gotno;
	unsigned mips_gotsym;
#endif

	size_t ref_count;
	link_map_t link_map;

	bool constructors_called;

	// When you read a virtual address from the ELF file, add this
	// value to get the corresponding address in the process' address space.
	Elf32_Addr load_bias;

	bool has_text_relocations;
	bool has_DT_SYMBOLIC;

	void CallConstructors();
	void CallDestructors();
	void CallPreInitConstructors();

private:
	void CallArray(const char* array_name, linker_function_t* functions, size_t count, bool reverse);
	void CallFunction(const char* function_name, linker_function_t function);
};

extern soinfo libdl_info;

// These aren't defined in <sys/exec_elf.h>.
#ifndef DT_PREINIT_ARRAY
#define DT_PREINIT_ARRAY   32
#endif
#ifndef DT_PREINIT_ARRAYSZ
#define DT_PREINIT_ARRAYSZ 33
#endif

void do_android_update_LD_LIBRARY_PATH(const char* ld_library_path);
soinfo* do_dlopen(const char* name, int flags);
int do_dlclose(soinfo* si);

Elf32_Sym* dlsym_linear_lookup(const char* name, soinfo** found, soinfo* start);
soinfo* find_containing_library(const void* addr);

Elf32_Sym* dladdr_find_symbol(soinfo* si, const void* addr);
Elf32_Sym* dlsym_handle_lookup(soinfo* si, const char* name);

char* linker_get_error_buffer();
size_t linker_get_error_buffer_size();
class ElfReader;
int open_library(const char* name);
soinfo* soinfo_alloc(const char* name);
bool soinfo_link_image(soinfo* si, bool breloc, ElfReader* reader);

#endif
