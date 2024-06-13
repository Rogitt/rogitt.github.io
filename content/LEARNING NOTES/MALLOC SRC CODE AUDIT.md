---
title: MALLOC SRC CODE AUDIT
draft: false
tags:
  - blog
  - heap-exploitation
  - learning
date: 02-06-2024
---

PREVIOUS >> [[MALLOC LABS]]

THIS IS A SOURCE CODE AUDIT OF MALLOC.C FROM  [GLIBC 3.8.9000]
- I did the following audit a while back in october last year 
- I am putting out the following as I had went through glibc source code to learn heap exploitation
- Hopefuly it is of use even though the newer glibc just dropped

#### ALLOCATION SIZES AND METHODS --
_______________
```
requests of sizes -->
- >=  512 bytes - best-fit allocation FIFO 
- <=   64 bytes - first fit caching LIFO?
- >= 128K bytes - system memory mapping facilities --mmap

ALIGNMENT - 2 * sizeof(size_t)
	Even a request for zero bytes (i.e., malloc(0)) returns a
	pointer to something of the minimum allocatable size.

wastage is less than or equal to minsize usually but during mmap, allocation made is in the order of two pages.

Values that appear to be negative after overhead and alignment are supported by only mmap. On failure of the following returns NULL.

MALLOC_DEBUG DMALLOC_DEBUG and stuff can be used to run malloc while it checks across the size fields of the following.

TCACHE_MAX_BINS     -     64
TCACHE_FILL_COUNT   - no of chunks held by a bin - usually 7 max - 65535 UINT16
idx 0   bytes 0..24 (64-bit) or 0..12 (32-bit)
idx 1   bytes 25..40 or 13..20
idx 2   bytes 41..56 or 21..28
...

REALLOC_ZERO_BYTES_FREES - controls if realloc(0) calls free [1 - default]
TRIM_FASTBINS            - controls if to trim fastbins for reducing memory footprint and avoiding usage of system level emmory [0 - default] 

M_MXFAST - Fastbin sizes range from 0 to 80 where 0 would disable it resulting in best-fit for all cases. set by the macro [64 - default]
M_TRIM_THRESHOLD - [32*0x1000] can be set to -1 to disable it. Chooses when to trim the heap by checking this value.
M_TOP_PAD        - [0] amount of padding/free space to retain while giving a call to sbrk
M_MMAP_THRESHOLD - [32*0x1000] has MIN AND MAX VALUES MIN HAS FOLLOWING WHILE MAX HAS 128 * 0X1000
M_MMAP_MAX       - 65536

```

##### LIBC FUNCTIONS FOR MEMORY MANAGEMENT :
```c
[__libc_malloc]  (size_t)         - allocating memory
[__libc_free  ]  (void *)         - freeing up memory once used
[__libc_calloc]  (size_t,size_t)  - allocating and 0-ing memory
[__libc_realloc] (void *,size_t)  - reallocating memory
[__libc_memalign](size_t,size_t)  - aligning memory to size_t
[__libc_valloc]  (size_t)         - system mem allocation
[__libc_mallocinfo]               - gets info related to malloc
[__libc_pvalloc] (size_t)         - allocate sys-mem pagealigned
[__malloc_trim]  (size_t)         - gives mem back to system

```

##### MORECORE
- Used to obtain memory from the OS through sbrk
```
MORECORE            - type usually sbrk
MORECORE_FAILURE    - defines if morecore failed
MORECORE_CONTIGUOUS - defines if allocation is contiguous
MORECORE_CLEARS     - defines 0ing out of memory
HAVE_MREMAP         - allows the remapping of blocks
```

#### STRUCTURE OF CHUNK:
```c
malloc chunk{
size_t prev_size
size_t chunk_size

// used when only free -- all blocks
chunk * fd;    
chunk * bk;

// used in only large blocks and if free
chunk * fd_nextsize 
chunk * bk_nextsize
}
```

```
EXCEPTIONS TO THE MALLOC CHUNK RULES --
- Top chunk does not use the trailing size field as it does not have any data beyond it
- If the mmapped bit is set then the other bits are ignored as the mmapped memory do not belong in an arena or are never adjacent to a freed chunk
- Fastbin chunks are consolidated only in bulk in malloc_consolidate else they are considered as allocated
```
##### MEMORY TAGGING
The malloc functions which has a prefix `__int_` to it are used to deal with untagged memory.

#### IMPORTANT STRUCTURES THAT MANAGE MEMORY
##### BINS : 
Bins is the version of a segregated linked list in malloc which is in size-ordered fashion. There are in total 128 bins whose inner sizes are logarithmically spaced. Bins work in a FIFO approach.
The following is the way the bins are split
```
64 bins of size        8
32 bins of size        64
16 bins of size       512
 8 bins of size      4096
 4 bins of size     32768
 2 bins of size    262144
 1 bin  of size  what's left
```
##### UNSORTED BINS : 
Unsorted chunks are stored at the bin 1 which is usually un-indexable. It acts like a queue where chunks are placed on it due to free and malloc_consolidate and taken off during calls to malloc i.e placed in proper bins or to be used. NON_MAIN_ARENA flag is never set in these chunks.

##### TOP CHUNK:
Top chunk is the top most available chunk which is never included in any bin and is only used if no other chunk is available. Memory here can be released back to the system if above M_TRIM_THRESHOLD. Top points to its own bin with initial size as 0. This is to avoid any special case checking for the top chunk every time any function is being called. The following also helps top to treat the bin as legal but unusable during the time between initialisation and first call to sysmalloc. During first call initial_top is defined as one of the unsorted_chunks.
##### BINMAP:
Binmap is a one-level index structure [a bit vector] used for bin-by-bin searching. It records if the bins are not empty so that they can be skipped during traversals. The bits are marked only when they are noticed during malloc traversal. 
##### FASTBINS:
Segregated free list holding recently freed small chunks
- works on LIFO
- Singly linked lists
- Ordering doesnt matter 
- Inuse bit is set and thus only consolidates during malloc_consolidate
```
default MAX_FAST_SIZE 180/0XA0 BYTES
FASTBIN_CONSOLIDATION_THRESHOLD 65535 - size of a chunk in free that triggers auto-consolidation of nearby fastbin chunks. 
NON_CONTIGOUS_BIT used when MORECORE returns memory which are not contigous regions. The initial value is false as MORECORE_CONTIGOUS is set to true.
have_fastchunks indicate the presence of fastbin chunks, set to NULL during calls to malloc_consolidate().
```
max_fast can be changed which can even be set to very small values for disabling fastbins. The max memory handled in fastbins is defined by this global variable.
   Precondition: there is no existing fastbin chunks in the main arena.
   Since do_check_malloc_state () checks this, it calls malloc_consolidate () before changing max_fast.  Note other arenas will leak their fast bin
   entries if max_fast is reduced.
###### IMPORTANT BITS:
	PREV_INUSE  - LOWEST BIT INDICATES IF PREVIOUS IS FREE OR IN USE
	IS_MMAPPED  - SECOND LOWEST > FOR CHECKING IF BLOCK WAS MMAPPED
	NON_MAIN_AR - THIRD LOWEST UNUSED WHEN NO NEW THREADS ARE THERE

#### OTHER STRUCTURES USED:

- ##### malloc_state
Malloced states are placed in mmapped areas which are part of arenas. It has the state of malloc and dynamic memory allocations within the current arena. 
mstates are operated on by the following functions:
```c
static void *sysmalloc (INTERNAL_SIZE_T,mstate);
static int   systrim (size_t,mstate);
static void malloc_consolidate (mstate);
static void tcache_thread_shutdown (void);
```
- ##### malloc_par

 This is used for storing important parameters such as trim_threshold, top_pad, mmap_threshold, arena_test, arena_max etc.  Keeping track of mmapped memory and number of mmaps. sbrk_base. If tcache is enabled then the following parameters are specified within, no of tcache bins, no of chunks in each bucket, number of chunks to remove from bucket.
#### MITIGATIONS :-
______________
1. - SAFE LINKING
To protect the single-linked list of Fast-Bins and T-Cache and double linked list of Small-Bins from getting pointer hijacked, Masking is done to the "next" pointers of the lists in the chunks using the randomness from ASLR/(mmap_base). In short a simple xor with the upper bytes of the memory page the current requested chunk lies in i.e 
[pointer ^ ptr >> 12]
demasking code --
- works when the pointer points to the memory lying within the same page
```python
	hex((encoded ^ (encoded >> 12) ^ (encoded >> 24)) ^ (encoded >> 36))
```

2. -  MEMORY TAGGING
The pointers alongside the blocks are coloured and they are recoloured when they are freed and given back. This is used to detect buffer overflows and use-after-frees. This has a performance impact but the old ptr's are ensured to not be used due to this. usually DISABLED. But can be enabled in systems such as ARM.

3. -  DOUBLE FREE DETECTION
The tcache entry has a key field in the backward pointer to detect double frees. The backward pointer is set to this specific key value which then prevents it from being overwrittten and freed again.

#### DEBUG-MODE MALLOC FUNCTIONS:
##### do_check_chunk (mstate av,mchunkptr p)
>Checks if the chunk is in a valid address if it is contigous
>Checks if top size is at least MINSIZE
>Checks if top predecessor is always marked inuse
>Checks if top size is always greater than MINSIZE
>IF MMAPPED
>checks if chunk is page aligned
>checks if chunk is mem aligned

##### do_check_free_chunk (mstate av, mchunkptr p)
> Calls do_check_chunk()
> Checks if chunk is free and chunk is not mmapped
> Checks if chunk remains coalesced if any
> Checks if it has proper links

##### do_check_inuse_chunk (mstate av, mchunkptr p)
> Calls do_check_chunk()
> Checks if chunk is mmapped if yes it returns
> else it checks if the chunk claims to be inuse
> checks if next chunk claims to be prev inuse if not it checks for a free chunk by calling do_check_free_chunk()
> Checks topchunk by calling do_check_free_chunk on top

##### do_check_remalloced_chunk (mstate av, mchunkptr p,INTERNAL_SIZE_T s)
> Checks if chunk is mmapped if not checks if arena is same as obtained
> Calls do_check_inuse_chunk()
> Checks if the size is valid alongside alignment
> Checks if chunk is less than minsize or more than requested size "s"
> All of these results in a fail

##### do_check_malloced_chunk (mstate av, mchunkptr p, INTERNAL_SIZE_T s)
>Calls do_check_remalloced_chunk()
>Prev inuse is true for every allocated chunk

##### do_check_malloced_state (mstate av)
>Checks if INTERNAL_SIZE_T is only as small as pointer type
>Checks if alignment is a power of two
>Checks if the arena is initialised i.e top!=0 if yes it returns
>ELSE checks the consistency of the main_arena with the sbrk base
>+
>FASTBIN CHECKS
>Check if max_fast is only in the allowed range
>Checks if all bins past max_fast are empty
>Checks if all fastbin chunks claim to be inuse and is aligned
>Checks if the chunk belongs to the respective bin
>+
>NORMBIN CHECKS
>Checks if the binmap is correct
>Checks if the chunks in the bin are free
>Checks if chunk belongs in the bin
>Checks if the lists are sorted
>Checks if the chunk lists are proper.
>Check the top chunk again by calling check_chunk()
>Check if the induvidual chunks are followed by a chain of inuse chunks

#### SPECIFIC FUNCTION SUMMARIES
___
##### Unlink_chunk - 
Unlinks a chunk from the bin list.
list of checks -- 
1. checks if the prev_size of next chunk is same as the chunksize else returns corrupted size vs. prev size
2. checks if the forward pointer of the previous is same as the backward pointer of the next field, else marks corrupted double-linked list.
3. Checks if the pointer is small by checking fd_nextsize and bk_nextsize
##### get_max_fast() -
checks if the global variable max_fast is greater than MAX_FAST_SIZE macro and if yes it calls an error else it returns global_max_fast. This is to prevent out of bound memory access in an array form.

#### SYSTEM ALLOCATION ROUTINES:
___
##### Sysmalloc_mmap (INTERNAL_SIZE_T nb,size_t pagesize,int extra_flags,mstate av) 
Calls mmap on behalf of malloc with the specified size nb and flags
returns if the call to mmap fails and assumes av->top doesnt have enough space to service the request.
list of checks --
1. Checks if the mmap size value wraps around zero, if yes the call fails
Other things it does -- 
2. If flags are lacking for a very large allocation advises kernel using madvice() which calls madvise() with advise as HUGE_PAGE
3. Calls mmap and sets the header and footer with the aligned size field always aligns it despite no chances of page-aligned memory not being aligned.
4. Updates n_mmaps and max_mmapped_memoryCalls check_chunk() 
5. returns pointer to mmapped memory 

##### Sysmalloc_mmap_fallback (long int \*s,INTERNAL_SIZE_T nb, INTERNAL_SIZE_T old_size,size_t minsize, size_t pagesize, int extra_flags,mstate av)
Used as a fallback if MORECORE fails to provide enough memory.
list of checks --
1. Checks if the mmap size value wraps around zero, if yes the call fails
Other things that this does --
2. Sets as noncontigous in the arena so as to mark the region as not part of the original heap so as to not rely on regions being contigous
##### sysmalloc (INTERNAL_SIZE_T nb ,mstate av)
The call has a precondition that it is only called if the top has lesser space than what is required.
list of checks --
- Checks if the current top has the prev_inuse set and if its aligned alongside having at least MINSIZE value.
It does the following functions --
1. Direct call to mmap if the size meets mmap_threshold and mmap is there and av == NULL, i.e no arena 
> if the mmap call fails then it returns 0 else av is set to the new mmaped region.
2. if av != main_arena this means that memory cant be obtained using sbrk so 
	---> Tries to grow current heap by trying to mprotect memory 
	---> if failed tries to allocate new heap 
	---> if failed calls mmap using sysmalloc_mmap() if tried is not set
	---> if failed returns idk cause if MAP_FAILED it considers av as main arena and goes to the else block. .. wierd maybe it just returns...
3. If av== main_arena Page aligns the size and calls MORECORE which gets memory from OS through sbrk.
	---> if MORECORE fails then sysmalloc_mmap_fallback() is used 
	---> if failed sets brk as MAP_FAILED and snd_brk as brk+size
	If previous routine doesnt fail then extends top and sets head
4. It checks if there was an intervening sbrk call and if there was it calls sbrk with a correction amount which ends at a page boundary. This is what happens when the memory is contigous. If not contigous the sbrk call is made with argument 0 which will help to set up footers and move to another chunk.
5. When sbrk is checked if a gap is present between the previous sbrk call and top chunk then it sets it as correction and artificial chunks are created around it which are set to always inuse. These are described as fenceposts in the source. When setting up such fenceposts the old top can completely be overwritten due to it, if in case it was of size -> MINSIZE. If there is remaining size after setting up the fenceposts it is freed and added to the unsorted bins.
After all of the following is done the function checks if at least one of the following paths succeed setting the size. This returns the pointer p which would be our allocated memory address.
If failed it sets the error and returns zero.

##### Systrim(size_t pad,mstate av)
It does the following
1. It checks for foreign sbrk calls and returns 0 if a external call was made
2. It page aligns pad and subtracts that amount from the top chunk and also unmaps by calling sbrk with -ve value of the amount.
3. It checks if the released amount is not 0, it returns 1 after adjusting top by subtracting released amount and sets head and calls check_malloc_state()
##### munmap_chunk(mchunkptr p)
The following is what the function does
1. It makes sure the given ptr is a mmapped ptr : bit 2 is set and that the ptr is a multiple of pagesize and 2
2. If yes it unmaps the pointer if it fails the program simply returns claiming nothing much can be done.

##### mremap_chunk(mchunkptr p, size_t new_size)
calls mremap if the newsize versus total size has an increase  or decrease in number of pages. if failed returns 0,
-> checks alignment
-> checks prev field on if it is set to true always
-> sets header with the required offset subtracted from it
-> returns the pointer p when it succeeds
___
#### TCACHE FUNCTIONS :
TCACHE ENTRY STRUCTURE
___
```
struct tcache_entry {

struct tcache_entry *next;

// key to prevent double frees
uintptr_t key;

}
```
Tcache backward pointer will have a specific key value of 64 bits which is placed to denote that the chunk has been freed once. This is used against bugs such as double-frees().

- There is a `tcache_perthread_struct` which has the number of bins and pointer to the entries and the structure is a global variable within libc
- Tcache key that exists are initialised by the `tcache_key_initialise`function
> The caller should verify if everything's good when calling `tcache_put`
- `tcache_put` - sets the key to be the tcache_key - which is a global variable and protects the pointer and puts it in updating the tcache index.
- `tcache_get_n` -  checks if a chunk is aligned and returns the following chunk after unlinking it from the tcache list, same is with `tcache_get` but it instead removes from front.
- `tcache_next` iterates through the list
- `tcache_shutdown` Shuts down tcache and frees all the lists held by tcaching for coalescing after an alignment check.
- `tcache_init` - It does not work when tcache_shutting_down variable is set. 

#### LIBC FUNCTIONS MALLOC/FREE
##### \_\_libc_malloc(size_t bytes)
CHECKS MADE -
- Checks if the memory returned by \_\_int_malloc() calls are proper
Functionality of code -
1. If `__malloc_initialised` is set to zero it calls `ptmalloc_init()` to initialise malloc. Else it proceeds and converts size to accomodate headers and to check if it is zero even after that. If yes it returns error. 
2. Else it continues with converting the size to a tcache index if tcache is uninitialised or bins are less than index it doesnt use tcache else it gets the chunk from the specified index if the value is greater than 0 by using `tcache_get(index)`
3. If single threaded it calls `__int_malloc()` which returns a ptr which is then memory tagged if tagging is enabled else it returns the pointer to the memory returned by `__int_malloc()`
4. Else it tries to get the arena which it belongs to and then calls \_int_malloc. if it fails then it retries with another usable arena by calling `arena_get_retry()` which either creates a new arena or looks for another one.
5.  It returns after tagging the memory and asserting that either the returned memory belongs in the same arena as it claims or doesnt exist or is mmaped.
##### \_\_libc_free(void \*mem)

CHECKS PRESENT --
Functionality of the code --
1. free (0) just returns
2. If mtags are enabled then it checks the pointer given with the tag applied to it, useful against double-free(). 
3. It checks if the pointer given to is of an mmapped region separate from the normal malloc routine, checks upper and lower malloc threshold with the size and also checks if dynamic threshold (user defined) is enabled. If yes it updates the threshold to the chunksize and the trim threshold to twice the mmap threshold. After which the chunk is unmapped.
4. Else It initialises tcache if not yet initialised, and tags memory if mtags enabled and gets the arena and calls  `_int_free()`
5. If none of the following occurs it sets error and returns

##### \_\_libc_realloc(void \*oldmem, size_t bytes)
CHECKS DONE -- 
- realloc() has a wraparound check for the size field which checks if the value of size could be malicously crafted or misplaced.
Functionality of code --
1. If malloc is not initialised then it calls ptmalloc_init()
> if size is 0 it frees if the REALLOC_ZERO_BYTE_FREES macro is active else realloc of null gives same results as malloc of null
2. mtag checks are done if mtag is enabled.
> If the size requested is fullfilled by the alignment padding then the same pointer is returned as such.
3. If the chunk is mmapped then it sets arenaptr to `NULL` else if tcache is not initialised it initializes tcache. and sets ar_ptr to arena_for_chunk. If chunk is mmapped or after headers the size field is 0 it exits. 
4. If chunk was mmaped it uses mremap to remap the current chunk and tags the memory again with a different tag. Else if remap is not enabled then it uses a malloc call to allocate space. If memory is returned then it returns memory after unmapping previous chunk and copying content.
5. If the process is single threaded then it calls `_int_realloc()` and asserts the returned pointer either is `NULL` or is mmapped or is ar_ptr is arena_for_chunk() If memory is failed to be obtained in one arena it checks or allocates memory through other arenas and returns a pointer to memory.


##### \_mid_memalign(size_t alignment, size_t bytes, void \*addr)
Functionality of the code --
1. \_\_libc_malloc() is called if alignment is less or equal to malloc_alignment. Else it ensures it is a minimum chunk size. If the alignment is greater than SIZE_MAX /2 + 1 it can cause an overflow thus it sets error and exits. 
2. It checks if alignment is a power of two.  
3. If tcache is enabled gets tcache alongside checking all instances of pointers within the tcache is aligned. If tagging of memory is present then tagging is done and the pointer is returned. If no tcache mem or no tcache then does next.
4. If it is single threaded process it just calls \_int\_memalign() If the arena does not have enough space then it tries to get a new arena and then returns the tagged memory after finding the arena for chunk.

##### \_\_libc\_valloc (size_t bytes)
Functionality of the code --
Same functionality as malloc() but the memory returned by calls to valloc are page-aligned memory. It just calls mid_memalign but with pagesize argument. Same with libc_pvalloc() but it has an overflow check in the rounded_bytes given by pagesize

##### \_\_libc_calloc (size_t n, size_t elem_size)
Functionality of the code --
1. Checks if the malloc_initialised flag is set, if not initialise malloc.  If tcache remains unitiated initiate tcache. If it is a single threaded process then it sets av as mainarena and then if av exists, 
2. Morecore clears flag is set then it gives by cutting from topsize. This means the normal morecore routine zeros memory if its greater than Minsize then the memory newly allocated is sure to be clear. 
3. While using mtags the whole memory is zeroed out irrespective of the morecore_clears flag. If the memory is not freshly sbrked then only the clearing happens.

#### CORE FUNCTIONS
##### _\_int_malloc (mstate av, size_t bytes)_

The functionality of the code --
1. Converts the requested size by padding it with the overhead size and checking with checked_request2size which checks for requests that wraps around 0.
2. Checks for if any usable arenas exist >>
	- If yes it continues
	- Else it calls sysmalloc instead with null which then sets up a region of memory, The arena checks were done previously in outer libc functions thus the following call is made directly without checking
3. CHECK IF SIZE QUALIFIES AS FASTBIN --
	- Checks if the memory within fastbin is greater than the chunk
	- Checks if there is an available fastbin pointer in the index
		- Checks if it is aligned if yes proceeds else calls error align fastbin
		- Checks if chunksize belongs in fastbin if failed calls mem corruption:fastbin
		- else calls check_remalloced_chunk
	- If encountered other chunks of same size puts them into tcache if tcache_enabled. During this another fastbin check is present which checks for alignment of fastbins.
	- After putting them in the tcache we return the pointer to the memory and return from the function. if perturb byte present does memset <!to be understood>.
4. CHECK IF THE SIZE QUALIFIES IN THE RANGE OF A SMALL BIN
	- Does the backward to forward check but not forward to back
	- If the av not main arena then sets non main arena bit
	- tcache stashing occurs same as in fastbins and is unlinked from smallbins
	- The function returns the pointer finally which is of the requested size
5. CHECK IF THE SIZE QUALIFIES IN THE RANGE OF A LARGE BIN
	- When a large request is called it calls malloc_consolidate to free up fast bins and make memory available.
	- Sets the index to a large bin index, sets the tc_idx to a tcache index
6.  Does an infinite loop 
	1. CASE 1
	-  Starts looking at unsorted bins to satisfy request.
	- Multiple checks are made to check for memory corruption
	- Checks if it is the only unsorted chunk and if yes checks for the last remainder if the chunk was the last remainder then if the current size is satisfied the chunk is alloted and pointer is returned
	2. CASE 2
	- If the first fails it tries to fill tcache if it is best fit.
	- If tcache is full then it tries to return if it is exact fit
	- Goes for smallbin first
		- places the chunk in the bin
	- Goes for largebin next
		- places the chunk in sorted order
		- Has the forward and backward ptr check alongside the \_nextsize field check 
	- If the tcache processing is complete it returns the tcached chunk at the index 
	- If iteration exceeds 10000 it breaks
	- If all the small chunks found ended up cached return one
	- If it is a large request scan through the chunks of the current bin in sorted order to find the smallest that fits , uses a skiplist
	- Finally it puts the remaining size after allocation into the unsorted bins
7. LOOKS THROUGH THE BINMAP 
	- If a proper chunk is obtained same procedure occurs
8. SEES IF TOP CHUNK IS ENOUGH
	- If top chunk can satisfy the request the chunk is cut out and allocation is given
9. CALLS SYSMALLOC IF NOTHING WORKS TO ALLOCATE THROUGH SYSTEM
___

##### _\_int_free (mstate av, mchunkptr p,int have_lock)_
The functionality of the code --
1. Checks if the given pointer is misaligned or if the size is less than minsize, if failed exits else checks the inuse chunk.
2. TCACHE DUMPING --
	- If tcache is enabled then it checks to see if its already in the tcache if yes it detects a double free.
	- If tcache count is greater than tcache_count var it states too many chunks and exits.
	- It also checks alignment and exits if unaligned.
	- If tcache putting worked then it returns
3. FASTBIN FORWARDING --
	- Again checks are made but it checks the top of fastbin alone to check if a double free occured in single thread, thus making bypass easy.
	- In multi thread it checks all of the fastbins for a double free
	- Then it gets a lock for it to add it to fastbin if it has a lock
4. UNSORTED BIN THROWAWAY --
	- Checks for double free corruption top , chunk boundary check , inuse check, invalid next size etc
	- It tries to consolidate backward if previze is not same as chunksize it states corrupted prev size and exits
	- It tries forward coalescing afterwards and unlinks the chunk and clears inuse bit.
	- The following chunk is thrown into the unsorted bins and then check_free_chunk is called.
	- If chunk borders top the chunk merges with the top
5. OTHERS
	- It calls malloc_consolidate() if the fastbin_consolidation_threshold is met. and if av is main arena it tries systrim() if trim threshold is met.
	- Also tries heap_trim even if the top chunk is not large 
	- If chunk was allocated due to mmap it does a munmap_chunk() call which unmaps the chunk.

##### _malloc_consolidate(mstate av)_
Checks --
- fastbin alignment check
- chunk size check
- during consolidation : prev_size check
The functionality of the code --
1. REMOVAL INTO UNSORTED BINS --
	- It removes each chunk from the fastbin into an unsorted bin so that only during requirements will the sorting into actual bins happen.
	- After putting a fastbin chunk into an unsorted bin it does a consolidation of the fastbins
	- If a fastbin chunk borders top chunk it merges down with the top chunk

##### _\_int_realloc(mstate av,mchunkptr oldp,SIZE_T oldsize,SIZE_T nb)_
CHECKS MADE --
- Size check for next size, caller is filtered for mmapped chunks thus an assertion is made that the chunk is not mmapped.
- A check for size on old size on if it is valid.

Functionality of the code --
- If it is already big enough it checks with the top chunk and coalesces down if next chunk is top chunk.
- If next chunk is not top chunk then it tries to expand forward into next chunk if it is free and the next is a remainder
- If nothing above works it allocates using \_int\_malloc 
	- It does a copy if the newp obtained through malloc is not the very next chunk
	- And it if it is the next chunk it extends the size and returns the given pointer itself.
- If possible it tries to free extra space from the previous chunk and marks remainder as inuse so that free doesnt complain and then calls free on the remainder memory which can then put it into unsorted bins.
- If memory tagging is there it returns tagged memory else untagged
- Finally the function returns

