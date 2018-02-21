
## LicenseCheck ##
#### Writeup by r3ndom ####
Created 2018-2-20

### Problem ###

I want a valid license for a piece of software, [here](https://github.com/Jumboperson/EasyCTF2018_writeups/blob/master/LicenseCheck/license_check.exe?raw=true) is the license validation software. Can you give me a valid license for the email `mzisthebest@notarealemail.com`?

Note: flag is _not_ in easyctf{} format.

### Hint ###
None

## Answer ##

### Overview ###

Go through the code and determine the algorithm for key verification to find a valid license key.

### Details ###

First we open up and try to find the main C++ function (assuming it was compiled with C++ just based on how the entry point looks).

Sure enough we scroll down and here it is, calling something with the arguments `(argc, argv, envp)`.

![](https://github.com/Jumboperson/EasyCTF2018_writeups/blob/master/LicenseCheck/finding_the_entry_point.png?raw=true)
[alt link](https://i.imgur.com/9loEeFP.png)

I renamed `loc_4012F0` to `main` and started looking at it. 

It's all pretty normal until about right here: 

![](https://github.com/Jumboperson/EasyCTF2018_writeups/blob/master/LicenseCheck/first_obfu_encounter.png?raw=true)
[alt link](https://i.imgur.com/VsH7yVr.png)

This code doesn't look right at all, the `jz` and `jnz` both go to an address in the middle of another instruction. So we should undefine that one byte its skipping to see what happens.

![](https://github.com/Jumboperson/EasyCTF2018_writeups/blob/master/LicenseCheck/fixed_first_obfu.png?raw=true)
[alt link](https://i.imgur.com/8N41u8L.png)

Now that looks _so_ much better doesn't it? This is a fairly basic bit of code that can fool IDA's linear disassembler because of an unconditional jump masquerading as a conditional jump.

Now looking closer at that assembly code we see the `argv[2]` passed to an unknown function here:

![](https://github.com/Jumboperson/EasyCTF2018_writeups/blob/master/LicenseCheck/function_call1.png?raw=true)
[alt link](https://i.imgur.com/m6n9cwj.png)

Unfortunately I cut off one little bit of the code there where it does `mov     [ebp-14h], eax` but I'm too lazy to redo the screenshot. Basically that just saves the return value of this function to the stack. Let's go through what that function does later because I just looked at it and its got some nasty exception stuff.

![](https://github.com/Jumboperson/EasyCTF2018_writeups/blob/master/LicenseCheck/second_obfu_encounter.png?raw=true)
[alt link](https://i.imgur.com/0EO1YBi.png)

Looking at the code it's, again, very ugly. But this time its a different way to mess up disassembly. Again an unconditional jump masquerading as a conditional jump with the `cmp eax, [esp]` which will always be false. Then it adds just enough to a pointer gotten by doing `call $+5` so that it can continue the code. Which if you do the math is again 1 byte after the label `jz`'d to by the code above. Then again it puts the stuff on the stack for a few bytes after that with a `sub` instruction where it subtracts a negative value. 

The code ends up looking like this:

![](https://github.com/Jumboperson/EasyCTF2018_writeups/blob/master/LicenseCheck/fixed_second_obfu.png?raw=true)
[alt link](https://i.imgur.com/yHQEkoL.png)

Immediately after the obfuscation the value saved on the stack beforehand is compared to 0x10 or 16. If it is equal to that then it jumps to some other code, seemingly also obfuscated. And if it's not it does more obfuscated code too. However these obfuscation bits have very similar MOs to the first bit of obfuscation we ran into but with more junk bytes.

Because of the aforementioned fact I've taken the liberty of deobfuscating the assembly.

![](https://github.com/Jumboperson/EasyCTF2018_writeups/blob/master/LicenseCheck/fixed_third_obfu.png?raw=true)
[alt link](https://i.imgur.com/5bFPtKd.png)

If its not equal to 16 then it'll set eax to -1 (0xffffffff) and jump to another loc that is the end of the function. So `if (sub_401000(argv[2]) != 16) return -1;` And then here below we see `sub_401000` being called again this time with what looks to be `argv[1]`.

Now that we've hit two calls of this function lets take a longer look at it, with the knowledge we have of these obfuscation methods implemented in the code we've already looked over.

![](https://github.com/Jumboperson/EasyCTF2018_writeups/blob/master/LicenseCheck/sub_401000_begin.png?raw=true)
[alt link](https://i.imgur.com/I0GOm0m.png)

Most of this looks like compiler mumbo-jumbo for exceptions until we get down to `40106F`, where the TryLevel is set to 0, presumably because we're entering a `try` block, then some code is executed then the TryLevel is set to -1.

The code inside of the TryLevel stuff is also really odd.

```asm
pushf
or [esp], 100h
popf
nop
```

So we look at the CPU flags and check what 0x100 is. According to the [wikipedia article](https://en.wikipedia.org/wiki/FLAGS_register) on the CPU flags register 0x100 is the trap flag, for single stepping in a debugger. So the code intentionally triggers a single step debug event, which is an exception.

Also we see the first argument is moved into `var_20` which as we know is either `argv[2]` or `argv[1]` so its a C-string. this is then checked to be sure the value at the pointer is 0 before continuing into the code. Presumbly this means this code parses a string somehow.

![](https://github.com/Jumboperson/EasyCTF2018_writeups/blob/master/LicenseCheck/sub_401000_debugchk.png?raw=true)
[alt link](https://i.imgur.com/KvPrwFm.png)

Here because IDA so kindly labels the code as `Exception handler 0 for function 401000` we see that in the case of an exception it sets a single variable, `var_19`, to 1, which looking above it was initialized to 0 before the exception code. Then immediately following the exception it checks if that value is non-zero with

```asm
movzx ecx, [ebp+var_19]
test ecx, ecx
```

And then jumps if the value is zero.

The question remains why trigger an exception only to handle it and then set something to 1 if it was handled? The answer lies in how most basic debuggers work. Single stepping in a debugger is accomplished by setting the trap flag after every instruction and then swallowing the exception so that you can continue execution as normal. By triggering an exception with the trap flag a regular debugger would swallow this exception and then the exception handler would never be executed. Which in turn means `var_19` remains 0. If `var_19` is 0 then a debugger is attached. 

If I took the time to navigate what happens if the value is zero I'm sure the program kills itself in a creative and fun way. But I'm an incredibly lazy reverse engineer and I'm just going to soldier on as if that didn't matter. Also I kind of want to solve this using exclusively static RE.

![](https://github.com/Jumboperson/EasyCTF2018_writeups/blob/master/LicenseCheck/sub_401000_debugpt2.png?raw=true)
[alt link](https://i.imgur.com/S6bYWfS.png)

This is self explanatory enough, it calls `IsDebuggerPresent` and if that is false it goes somewhere else so let's look at where that is.

![](https://github.com/Jumboperson/EasyCTF2018_writeups/blob/master/LicenseCheck/sub_401000_final.png?raw=true)
[alt link](https://i.imgur.com/oxEPWYZ.png)

This is the last bit of code in the function, and all it does is add 1 to a variable initialized to 0 before jumping back to the start of the loop at `401054`.

This `var_24` is also the value `mov`'d into `eax` before the function returns so its the return value. Basically telling me this code just keeps going until it hits a zero character, counting the number of real characters in the string.

For all intents its `strlen` with anti-debug and obfuscation. Quite a pain.

Moving back to the main function's code having renamed `sub_401000` to `obfu_strlen` we can now see that `argv[2]` has to be of length 16 and then `argv[1]` has to be of at least length 10, as evidenced below.

![](https://github.com/Jumboperson/EasyCTF2018_writeups/blob/master/LicenseCheck/post_obfu_strlen.png?raw=true)
[alt link](https://i.imgur.com/TZCXp5W.png)

Looking back at the initial string we saw printed in main, `"Usage: %s <email> <license key>\n"` we now know `argv[1]` or the email, needs to be at least 10 characters long and the `argv[2]` or the license key needs to be exactly 16 characters long. 

If I'm going to be honest that was a lot of work for some basic stuff especially when we were given the email to use for the license key input, which is well over 10 characters. But thats reverse engineering for you.

I'm going to take the liberty of deobfuscating the code myself before showing you all because once you've seen the bits we've already seen you can get most variations of that kind through pattern recognition.

![](https://github.com/Jumboperson/EasyCTF2018_writeups/blob/master/LicenseCheck/email_parse_for_loop.png?raw=true)
[alt link](https://i.imgur.com/EqBrg1r.png)

Here we have some variable initializations. `[ebp-8]` to `0xaed0dea` and `[ebp-10h]` to 0. Then some more obfuscation. Then `[ebp-4]` is 0. And if you don't remember from above `[ebp-0Ch]` is the length of the email or `argv[1]` string. And we see `[ebp-4]` being compared to `[ebp-0Ch]` which suggests that `[ebp-4]` is an iterator through this string.

Once we know that its basically `for(int i = 0; i < lengthOfEmail; ++i)` we can continue on a bit easier. We grab the email or argv[1] string again then grab the character at `argv[1][[ebp-4]]` and compare it to 40h, which is `'@'`. If it is `'@'` then we set `[ebp-10h]` to 1 and keep going.

Because I had to cut off some code here is what is done after the `'@'` check.

![](https://github.com/Jumboperson/EasyCTF2018_writeups/blob/master/LicenseCheck/post_at_check.png?raw=true)
[alt link](https://i.imgur.com/5BKKf8Q.png)

We compare `[ebp-10h]` to 0, if it was 0 then we grab the character from `argv[1][[ebp-4]]` and we add it to value at `[ebp-8]` which was `0xaed0dea`. If `[ebp-10h]` is not zero then we do the same thing but with xor instead of add.

If you write a basic C program to mimic this behavior on the email provided in the problem description then we get that the resulting value of `[ebp-8]` should be `0xaed12f1`. 

![](https://github.com/Jumboperson/EasyCTF2018_writeups/blob/master/LicenseCheck/after_email_loop.png?raw=true)
[alt link](https://i.imgur.com/cRHfre9.png)

Now looking at this code that follows the for loop we see `[ebp-8]` being compared to `0xAED12F1` and if its not equal then we do `return somevalue;`. Which confirms our findings. However again, this is verifying information already provided by the problem description, still nothing really new to help us figure out the flag.

Lets move on and start fixing some more obfuscation...

![](https://github.com/Jumboperson/EasyCTF2018_writeups/blob/master/LicenseCheck/main_end.png?raw=true)
[alt link](https://i.imgur.com/iizwbrc.png)

Well now this looks promising, we finally see a call to `puts` with a parameter `"correct!"`. We see the assembly code grab `argv[2]` and pass it to a mystery function `loc_401140`. We then check the return value of this function, xor'd by `[ebp-8]` which should be `0xaed12f1`, and then again xor'd by `0xAECBCC2` against 0. 

If this xor result is not zero then we skip printing `"correct!"` and just end the function. If it is zero then we print `"correct!"`.

Which should approximately translate to something like so:

```c
if ((loc_401140(argv[2]) ^ var_ebp_8 ^ 0xaecbcc2) == 0)
	puts("correct!");
```

This tells us exactly what we need to know. `loc_401140(argv[2])` needs to be equal to `0xaed12f1 ^ 0xaecbcc2` which using the windows calculator we know is `0x1ae33`.

The next step is clearly to figure out what `loc_401140` is doing so we can determine what the key needs to be. But before even that we have to name it something better. I changed it to `key_verify` but you can do whatever you see fit.

![](https://github.com/Jumboperson/EasyCTF2018_writeups/blob/master/LicenseCheck/key_verify_start.png?raw=true)
[alt link](https://i.imgur.com/3KNfT4Z.png)

We see some normal stack setup stuff and some more tiring obfuscation I've already mostly fixed. We see a few stack variables being setup. `[ebp-34h]` is initialized to 0. `[ebp-28h]` is done likewise. `[ebp-3Ch]` is set to the first parameter (our license key input). And then seemingly 5 bytes from `[ebp-24h]` to `[ebp-20h]` inclusive are 0'd. And finally `[ebp-30h]` is 0'd as well.

![](https://github.com/Jumboperson/EasyCTF2018_writeups/blob/master/LicenseCheck/key_verify_loop_start.png?raw=true)
[alt link](https://i.imgur.com/UKu8PM0.png)

Here we see some awfully familiar code. It looks exactly like that anti-debug code from earlier with a different variable being added to at the start. `[ebp-30h]` in this case. Seems IDA missed the SEH setup stuff in its analysis but that's alright. We have some knowledge of this already so we can ignore all the normal anti-debug things in here with the exception stuff.

What we need to look at is that `strtol` call. [strtol](http://www.cplusplus.com/reference/cstdlib/strtol/) is a C function that takes 3 arguments, the second really doesn't matter for our purposes. Looking at the stack we see base is `0x1E` and the string provided is the start of that 5 byte array at `[ebp-24h]`.

And looking just a few lines up we see that 4 bytes at a time are copied from the license key string in `[ebp-3Ch]` and put into the byte array to act as a temporary string. 

The result of this `strtol` call is stored in `[ebp-38h]` to be used later. Then the exception stuff does it's thing.

![](https://github.com/Jumboperson/EasyCTF2018_writeups/blob/master/LicenseCheck/key_verify_final.png?raw=true)
[alt link](https://i.imgur.com/DEX7b6c.png)

Skipping the rest of the exception stuff and a bit of obfuscation we find ourselves comparing the result of the `strtol` to 0, if it isnt 0 then we don't call do some code that will clearly crash the program (calling the function pointer at [0]). Basically we can't have any of our four character groupings be 0. 

After the program ensures that the value isn't 0 it xors `[ebp-34h]` with the result of `strtol` and stores it. Then it loops again, seemingly until all the characters of the license key are parsed. With each 4 character grouping being in base `0x1E` or in normal decimal, 30.

We need 4, 4 character long base 30 numbers that xor together to equal `0x1ae33`, none of which can be 0. 

The easiest way out of this is simply to convert `0x1ae33` to base 30 and then xor it by 1, having all the remaining 3 numbers be 1. Because `1 ^ 1 ^ 1` is 1, so `(0x1ae33 ^ 1) ^ 1 ^ 1 ^ 1` will be equal to `0x1ae33`.

`0x1ae33` in base 30 is `42b1` so we just do `42b0000100010001` for our key.

This results in the program outputting `"correct!"` when run or when submitted on the problems page getting the points.

### Flag ###

The flag is any combination of 4, 4 character base 30 numbers that xor to equal `42b1` in base 30 or `0x1ae33` in hex.

More to the point `42b0000100010001` works.
