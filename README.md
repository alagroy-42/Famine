# Famine

Famine is the first project of a 4 project suite aiming to design viruses.

It aims to infect a 64-bit ELF file with self-replicating code so that launching infected binaries will spread the code to others. For the sake of my machine during the devlopment of this virus, it will only aim and spread in `/tmp/test/` and `/tmp/test2/` directories.

### Disclaimer

This project is purely pedagogicaland is not made to any illegal or irresponsible use.

## Infection

Once infectable binaries (ELF 64-bit not infected yet) are found in the corresponding directories, the virus will check the segment padding to choose the best infection strategy.

### Constraints
While starting this project, I wanted an actually deployable working strategy even though this is not specified in the subject. Hijacking a PT_NOTE to add a PT_LOAD was not enough for me. I don't want my virus to be spot by a simple `readelf` which means that:
- the number of segments and their size should remain the same after the infection (An additionnal segment or any RWX segment would be very easily spotable)
- sections addresses and offset should remain consistent
- entrypoint shouldn't change (Even with a very stealthy infection, an entrypoint placed at the end of the .text segment would be too easy to spot)

### Strategy 1

The optimal strategy that I prefer is the .text padding infection. Since segments must be page align and ELF specification notify that file offsets and addresses must be consistent, memory padding also happens in the file so we have a zero-filled area between the end of the code and the next page aligned offset (from 0 to 0x1000 bytes).
This padding area is the perfect place to place our parasite, it is mapped on an executable segment of memory.
Infection will consist in the following steps :
- copy the payload in the padding area.
- increase the .text segment size so that our payload gets mapped into memory at runtime
- increase the last section of the segment (usually .fini) so that our payload fit in a section to avoid any suspicion.
- hijack execution to execute the payload (this method will be identical to both strategies and described later)

There is a slight downside to this method, it doesn't work if the segment padding area is not large enough for the payload to fit in. That's why we have our second strategy.

### Strategy 2

This strategy will be chosen if we din't have enough room in the text segment padding to insert the payload. It consists in inserting the payload at the end of the data segment which adds a layer of complexity to the task. The last section of the data segment is usually the BSS, a SH_NOBITS section which is not present in the file but zero-filled in memory. Infecting the data segment right after its last bit would result in the loss of our first instructions that would be overridden by the bss zero-filled memory area. We have to first make sure that this doesn't happen but without altering the execution of the host program.
To do so, we will :
- create a zero-filled area in the file that has the same length than the BSS.
- change the program header of the corresponding segment to increase the `p_filesz` value to be the same as `p_memsz`.
- change the section type from SHT_NOBITS to SHT_PROGBITS.

Now that we have done all that, the bss issue is solved and we can put our payload after the data segment, but to get it executed without modifying the permissions of the data segment, we also have to insert a chunk of code in the text segment so that our payload will get execution permission at runtime.
To do so, we will now :
- copy the payload at the end of the .data section.
- increase the corresponding segment and section (for the same purpose/reasons as above).
- shift everything that follows (symbol/string table etc..) to keep the data in the file.
- change the offsets and addresses of those to keep it coherent. (those last two steps will actually happen before the bss extension in the file to avoid any loss of data but it makes more sense to put it there)
- insert a little payload in the text padding area that will call mprotect so the main payload can have the execute permissions (this implies all the steps of strategy 1 since it actually kind of the same).

The advantage of this strategy is that we can fit any payload no matter its size (with the slightly and very unlikely exception where we don't have enough room for the mprotect call in the text segment) but downsides are that execution of code placed in the data segment would be very suspicious for an anti-virus and the added layers of complexity make this strategy way harder to code than strategy one.

Even though I think that with the little amount of functions famine has, strategy 1 would be more than enough for most of the binaries, the functionnalities that will be added in the next projects will make the payload bigger and bigger which will justiofy the implementation of strategy 2. Strategy one might even be useless at some point if payload gets larger than a page.

## Execution hijacking

To get the payload executed without changing the entrypoint, we will go for the constructor hijacking method. In every C/C++ program, a lot happens before the `main` function execution. The part which interests us is the `_init` function which is called at the beginning of `__libc_start_main`. This function will call every function contained in the function pointer array present in the `.init_array` section. Even for really simplist program (cf `sample.c`), there is at least one function in this array, the `frame_dummy` function. By overriding this pointer with the address of our code, we will be able to launch our function even before `main`. We will then jump on the original function that was in the array to preserve the execution sanity. This method is not spottable by a simple readelf but it is not that stealthy because any AV would spot that constructors should be in the `.text` section, which will not be our case (the payload will probably be inside the `.fini` section).

## Conclusion

With the implementation of everything explained and detailled above, we now have a functionnal virus that will be able top infect any ELF executable that fulfills those requirements (most of them do):
- there are sections
- there are segments
- the `.init_array` section is present

All of our constraints are also respected, after the infection, it is impossible to spot any peculiar thing with a simple `readelf`. It is still very easy to spot the fact that there is a parasite inside the binary by:
- checking the location of the `.init_array` functions.
- analizing the code. Even without understanding it, the use of the syscall instruction is something that will never occur in a normal C program since the compiler will usually call the libc wrapper for those.
- following the execution. If strategy 2 is chosen for an infection, the execution of code located in the data segment would be something that would catch the attention af any aware user.
- fully reversing the code. Our code is written on disk and absolutely not obfuscated which will make the analysis quite easy for any reverse engineer that will be able to break every secrets of it.
