# Project N2
## Definition
It was propsoed to us to try to analyse using reverse engineering a suspicius code that was found on campus using Reverse engineering techniques that were thought trought the semester. \
We need to find a response to the following questions:\
- **Do we really have a malware?**\
- **How the malware works and why a deb is used?**\
- **Are other hosts involved?**\
- **What is the potential impact to our organization?**\

## Strategy

First of all we started with a simple search of what is a deb and what are their components. This is the relevant information that we found:
- Deb is the file format that debian uses in its destributioiins
- This archive has 3 files: debian-binary (Containing package format number), control archive (Containig package name, version, dependencies and maintainer) and data archive(Containg the installable files)

### Integrity check 
As we checked there was too many files a shell script was made (with the help of stack overflow) to check the md5 of interely folders so we can compare them witha  genuine version

#### Control
Control is a file that contains the dependencies needed, seeing that the md5 didn't match the original one  we checked this file which contained two added depedencies:
- libcurl4-openssl-dev
- curl