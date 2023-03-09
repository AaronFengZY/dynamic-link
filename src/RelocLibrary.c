#include <dlfcn.h> //turn to dlsym for help at fake load object
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <elf.h>
#include <link.h>
#include <string.h>
#include "Link.h"

// glibc version to hash a symbol
static uint_fast32_t
dl_new_hash(const char *s)
{
    uint_fast32_t h = 5381;
    for (unsigned char c = *s; c != '\0'; c = *++s)
        h = h * 33 + c;
    return h & 0xffffffff;
}

// find symbol `name` inside the symbol table of `dep`
void *symbolLookup(LinkMap *dep, const char *name)
{
    if(dep->fake)
    {
        void *handle = dlopen(dep->name, RTLD_LAZY);
        if(!handle)
        {
            fprintf(stderr, "relocLibrary error: cannot dlopen a fake object named %s", dep->name);
            exit(-1);
        }
        dep->fakeHandle = handle;
        return dlsym(handle, name);
    }

    Elf64_Sym *symtab = (Elf64_Sym *)dep->dynInfo[DT_SYMTAB]->d_un.d_ptr;
    const char *strtab = (const char *)dep->dynInfo[DT_STRTAB]->d_un.d_ptr;

    uint_fast32_t new_hash = dl_new_hash(name);
    Elf64_Sym *sym;
    const Elf64_Addr *bitmask = dep->l_gnu_bitmask;
    uint32_t symidx;
    Elf64_Addr bitmask_word = bitmask[(new_hash / __ELF_NATIVE_CLASS) & dep->l_gnu_bitmask_idxbits];
    unsigned int hashbit1 = new_hash & (__ELF_NATIVE_CLASS - 1);
    unsigned int hashbit2 = ((new_hash >> dep->l_gnu_shift) & (__ELF_NATIVE_CLASS - 1));
    if ((bitmask_word >> hashbit1) & (bitmask_word >> hashbit2) & 1)
    {
        Elf32_Word bucket = dep->l_gnu_buckets[new_hash % dep->l_nbuckets];
        if (bucket != 0)
        {
            const Elf32_Word *hasharr = &dep->l_gnu_chain_zero[bucket];
            do
            {
                if (((*hasharr ^ new_hash) >> 1) == 0)
                {
                    symidx = hasharr - dep->l_gnu_chain_zero;
                    /* now, symtab[symidx] is the current symbol.
                       Hash table has done its job */
                    const char *symname = strtab + symtab[symidx].st_name;
                    if (!strcmp(symname, name))
                    {    
                        Elf64_Sym *s = &symtab[symidx];
                        // return the real address of found symbol
                        return (void *)(s->st_value + dep->addr);
                    }
                }
            } while ((*hasharr++ & 1u) == 0);
        }
    }
    return NULL; 
}

void RelocLibrary(LinkMap *lib, int mode)
{
    void *pt = dlopen("./test_lib/SimpleMul.so", RTLD_LAZY);
	Elf64_Rela *relocation_table_addr = NULL;
	Elf64_Sym *sym_table_addr = NULL;
	void *sadr = NULL;
	int siz = 0;
	Elf64_Dyn *dst = lib->dyn;
	while ((dst++)->d_tag != DT_NULL)
		if (dst->d_tag == DT_PLTRELSZ) siz = dst->d_un.d_ptr;
		else if (dst->d_tag == DT_JMPREL) relocation_table_addr = (void*)dst->d_un.d_ptr;
		else if (dst->d_tag == DT_SYMTAB) sym_table_addr = (Elf64_Sym*)dst->d_un.d_ptr;
		else if (dst->d_tag == DT_STRTAB) sadr = (void*)dst->d_un.d_ptr;
		
	if (relocation_table_addr==NULL) return;
	
	int pos = relocation_table_addr->r_info>>32;
	for (int i=0; i<pos; i++,sym_table_addr++);
	int str_offset = sym_table_addr->st_name;
	Elf64_Addr recod =(Elf64_Addr) (sadr + str_offset + relocation_table_addr->r_addend);
	Elf64_Addr *renew =(Elf64_Addr *) (relocation_table_addr->r_offset + lib->addr);
	*renew = recod;
	void *handle = dlopen("libc.so.6", RTLD_LAZY);
	void *real_address = dlsym(handle, (const char*)recod);
	if (real_address == NULL)
		for (int i=0; i<10; i++)
		{
			real_address = dlsym(pt, (const char*)recod);
			if (real_address != NULL)
				break;
		}
	*renew = (Elf64_Addr)real_address;
	
	
	relocation_table_addr = NULL;
	int st=0, ht=0;
	dst = lib->dyn;
	
	while ((dst++)->d_tag!=DT_NULL)
		if (dst->d_tag == DT_RELASZ) st = dst->d_un.d_ptr;
		else if (dst->d_tag == DT_RELA) relocation_table_addr = (void*)dst->d_un.d_ptr;
		else if (dst->d_tag == DT_RELAENT) ht = dst->d_un.d_ptr;
		else if (dst->d_tag == DT_SYMTAB) sym_table_addr = (Elf64_Sym*)dst->d_un.d_ptr;
	
	int tag=st/ht;
	while (tag--)
	{
		renew = (Elf64_Addr*) (relocation_table_addr[tag].r_offset+lib->addr);
		recod =(Elf64_Addr) (lib->addr+relocation_table_addr[tag].r_addend);
		*renew = recod;
		if (relocation_table_addr[tag].r_info != 8)
		{
			int pos=relocation_table_addr[tag].r_info>>32;
			str_offset=sym_table_addr[pos].st_name;
			char *str=sadr + str_offset;
			real_address=symbolLookup(lib, str);
			*renew = (Elf64_Addr) real_address;	
		}
	}
}
