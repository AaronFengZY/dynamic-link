#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <elf.h>
#include <unistd.h> //for getpagesize
#include <sys/mman.h>
#include <fcntl.h>
#include "Link.h"
#include "LoaderInternal.h"
#include <errno.h>

#define ALIGN_DOWN(base, size) ((base) & -((__typeof__(base))(size)))
#define ALIGN_UP(base, size) ALIGN_DOWN((base) + (size)-1, (size))

static const char *sys_path[] = {
    "/usr/lib/x86_64-linux-gnu/",
    "/lib/x86_64-linux-gnu/",
    ""
};

static const char *fake_so[] = {
    "libc.so.6",
    "ld-linux.so.2",
    ""
};

static void setup_hash(LinkMap *l)
{
    uint32_t *hash;

    /* borrowed from dl-lookup.c:_dl_setup_hash */
    Elf32_Word *hash32 = (Elf32_Word *)l->dynInfo[DT_GNU_HASH_NEW]->d_un.d_ptr;
    l->l_nbuckets = *hash32++;
    Elf32_Word symbias = *hash32++;
    Elf32_Word bitmask_nwords = *hash32++;

    l->l_gnu_bitmask_idxbits = bitmask_nwords - 1;
    l->l_gnu_shift = *hash32++;

    l->l_gnu_bitmask = (Elf64_Addr *)hash32;
    hash32 += 64 / 32 * bitmask_nwords;

    l->l_gnu_buckets = hash32;
    hash32 += l->l_nbuckets;
    l->l_gnu_chain_zero = hash32 - symbias;
}

static void fill_info(LinkMap *lib)
{
    Elf64_Dyn *dyn = lib->dyn;
    Elf64_Dyn **dyn_info = lib->dynInfo;

    while (dyn->d_tag != DT_NULL)
    {
        if ((Elf64_Xword)dyn->d_tag < DT_NUM)
            dyn_info[dyn->d_tag] = dyn;
        else if ((Elf64_Xword)dyn->d_tag == DT_RELACOUNT)
            dyn_info[DT_RELACOUNT_NEW] = dyn;
        else if ((Elf64_Xword)dyn->d_tag == DT_GNU_HASH)
            dyn_info[DT_GNU_HASH_NEW] = dyn;
        ++dyn;
    }
    #define rebase(tag)                             \
        do                                          \
        {                                           \
            if (dyn_info[tag])                          \
                dyn_info[tag]->d_un.d_ptr += lib->addr; \
        } while (0)
    rebase(DT_SYMTAB);
    rebase(DT_STRTAB);
    rebase(DT_RELA);
    rebase(DT_JMPREL);
    rebase(DT_GNU_HASH_NEW); //DT_GNU_HASH
    rebase(DT_PLTGOT);
    rebase(DT_INIT);
    rebase(DT_INIT_ARRAY);
}

void *MapLibrary(const char *libpath)
{
    /*
     * hint:
     * 
     * lib = malloc(sizeof(LinkMap));
     * 
     * foreach segment:
     * mmap(start_addr, segment_length, segment_prot, MAP_FILE | ..., library_fd, 
     *      segment_offset);
     * 
     * lib -> addr = ...;
     * lib -> dyn = ...;
     * 
     * fill_info(lib);
     * setup_hash(pt);
     * 
     * return pt;
    */ 
    /* Your code here */
	//=========test 0==================
	
	
	LinkMap *lib = malloc(sizeof(LinkMap));
	FILE *fp = fopen(libpath, "r"); //read only open
	Elf64_Ehdr *renew_element = malloc(sizeof(Elf64_Ehdr)); 
	fread(renew_element, sizeof(Elf64_Ehdr), 1, fp);
	int pdr_num = (int)renew_element->e_phnum;
	Elf64_Phdr **pdr = malloc(sizeof(Elf64_Phdr*) * pdr_num); 
	
	// print(pdr)
	for (int i=0; i<pdr_num; i++)
		pdr[i] = malloc(sizeof(Elf64_Phdr));
	fseek(fp, renew_element->e_phoff, SEEK_SET);
	for (int i=0; i<pdr_num; i++)
		fread(pdr[i],renew_element->e_phentsize,1,fp);
	uint64_t base_address,record_address,offset_address; 
	int fd=open(libpath, O_RDWR),siz=0;

	char *p = (char *) malloc(sizeof(char)*(5*pdr[0]->p_align));
	base_address =(uint64_t) p;
	free(p);
	
	for (int i=0;i<pdr_num;i++)
	{
		if (pdr[i]->p_type!=PT_LOAD && pdr[i]->p_type!=PT_DYNAMIC) continue;
		Elf64_Phdr *segm = pdr[i];
		if (pdr[i]->p_type == PT_DYNAMIC)
		{
			lib->dyn = (Elf64_Dyn *)(segm->p_vaddr + base_address);
			continue;
		}
		
		int prot = 0;
		prot |= (segm->p_flags & PF_R)? PROT_READ : 0;
		prot |= (segm->p_flags & PF_W)? PROT_WRITE : 0;
		prot |= (segm->p_flags & PF_X)? PROT_EXEC : 0;
		void *mmap_addr =(void*) ALIGN_DOWN(segm->p_vaddr+base_address, getpagesize());
		siz = ALIGN_UP(segm->p_vaddr+base_address+segm->p_memsz, getpagesize()) - ALIGN_DOWN(segm->p_vaddr+base_address, getpagesize());
		record_address =(uint64_t) mmap(mmap_addr, siz, prot, MAP_FILE | MAP_PRIVATE, fd, ALIGN_DOWN(segm->p_offset, getpagesize()));
		
		if (i==0) base_address=record_address; 
		offset_address+=siz;
		
		//print("base_address = %d",base_address);
		// print(" i= %d",i);
	}
	
	lib->addr=(uint64_t)base_address;
	fill_info(lib);
	setup_hash(lib);
	//free pointer
	free(renew_element);
	for (int i=0;i<pdr_num;i++)free(pdr[i]);
		
    return lib;
}
