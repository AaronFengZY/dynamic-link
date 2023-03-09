#include <stdlib.h>
#include <stdio.h>
#include <elf.h>
#include <stdint.h>

#include "Link.h"
#include "LoaderInternal.h"

void InitLibrary(LinkMap *l)
{
    /* Your code here */
	Elf64_Addr *pt = NULL;
	Elf64_Dyn *now_pointer = l->dyn;
	void (*new_start)(void) = NULL;
	int siz=0;
	
	while ((now_pointer++)->d_tag!=DT_NULL)
		if (now_pointer->d_tag==DT_INIT) new_start=now_pointer->d_un.d_ptr;
		else if (now_pointer->d_tag==DT_INIT_ARRAY) pt=now_pointer->d_un.d_ptr;
		else if (now_pointer->d_tag==DT_INIT_ARRAYSZ) siz=now_pointer->d_un.d_ptr;
	
	new_start();
	
	int tag=siz/8;
	while(tag--)
	{
		void (*func)(void) =(void*) (*pt);
		if (func<(l->addr)) func+=(l->addr);
		func(),pt++;
	}
}
