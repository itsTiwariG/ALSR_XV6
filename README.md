These are the parts of the files in XV where modifications were made.

 Our attack works by overwriting the value of the return address - which stores where the 
function has to return after the call.

 Figuring out how to overflow the buffer: We see that the payload is being read till 100 bytes while the buffer in 
vulnerable_function is smaller (4 size in the example), hence we can overflow it by passing a large payload.
 Identifying the calling address of the target function foo: First of all we disabled optimizations by putting CFLAG -O0 
instead of -O2 in the make file, CFLAG ensures compiler optimizations during compilation, this may interfere with 
the structure of the code. Then, we did “ printf(1, "%x", foo); ” to know the address of the foo function. This came out 
to be 0, as foo is the starting of the user program it would be stored at the starting of the page table of the program

 Attacking the target: We got error as “ pid 3 buffer_overflow: trap 14 err 4 on cpu 0 eip 0x1c1b1a19 addr 
0x1c1b1a19--kill proc ”This meant that the 0x19 byte is of interest to us, which is the 24th byte. Now to 
generalise, we know we kept 12 byte buffer, hence the offset should be 12+buffer_size

Prevention of Buffer Overflow 
Attack:
 Technique: Address Space Layout Randomization
 Description: Address space layout  randomization is a computer 
security technique that randomizes the memory addresses of a 
process to make it harder for attackers to exploit vulnerabilities.
 Goal: Make buffer overflow and similar memory-based attacks 
more difficult by introducing randomness into the memory layout


Implementation:
 First we created a file called aslr_flag that contains the current status of ASLR in xv6. The first step to 
implement ASLR is to create a file called aslr_flag that contains the current status of ASLR in xv6. 
Turn on or off ASLR based on the value in aslr_flag file We modify the system call for the open function to 
check if the requested file is "aslr_flag."
 Create a random number generator:- We create a random number generator using the Linear Congruential 
Generator (LCG) algorithm, which is a simple and fast algorithm that generates a sequence of pseudorandom 
numbers. 
We  modify the memory allocation routines to use the random number generator to randomize the location 
of regions in the process’s virtual address space


Design Details
 // If ASLR is enabled, change the load offset
 if(aslr_enabled){
 loff = random();  // Generate a random offset for ASLR
 // For addresses from 0 to loff, map them to 0 to reserve the space
 sz = allocuvm(pgdir, 0, loff);  // Allocate memory up to the offset
 // Apply the offset to the program segment's virtual address
 ph.vaddr += loff;
 // Allocate memory for the program segment with the offset 
applied
 if((sz = allocuvm(pgdir, sz, ph.vaddr + ph.memsz)) == 0)
 sz = PGROUNDUP(sz);
 uint soff = 2;
 // If ASLR is enabled, change the stack offset
 if(aslr_enabled){
 soff += (random()/2) % 500 + 1;
 }
 if((sz = allocuvm(pgdir, sz, sz + soff*PGSIZE)) == 
0)
 goto bad;
 clearpteu(pgdir, (char*)(sz - 2*PGSIZE));
 sp = sz;
 goto bad;
