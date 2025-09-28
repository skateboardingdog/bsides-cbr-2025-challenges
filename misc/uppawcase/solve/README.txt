solution: %28$*s%28$224s%28$hhn%28$s

%28$*s                    %28$224s                    %28$hhn         %28$s
 ^ ^ ^                       ^   ^                       ^               ^
 | | |                       |   |                       |               |
 | | |                       |   |                       |               v
 | | |                       |   |                       |          Print the 28th argument
 | | |                       |   |                       |          as a string!
 | | |                       |   |                       |
 | | |                       |   |                       |
 | | |                       |   |                       |
 | | |                       |   |                       +--> Write the low byte of the total
 | | |                       |   |                        printed char count to the address
 | | |                       |   |                        pointed to by the 28th argument.
 | | |                       |   |
 | | |                       |   +----------------------------------------.
 | | |                       |                                            |
 | | |                       |                                            |
 | | |                       | Again, print the 28th argument which is    |
 | | |                       | a null string so nothing is printed.       v
 | | |                       +------------------------------------------> Field width of 224 which is -32 mod 256.
 | | |
 | | +---- Print as a string, since the 28th argument points to null,
 | |       the string is empty and nothing is printed apart from the width space characters.
 | |
 | +------ Use the value of the 1st argument as the printing width to write that many characters.
 |
 +-------- Use the 28th argument (`28$`) as a pointer to the string to print.
           It is a stack address that points to null so we use it as a scratch
           buffer and also to print empty strings.
