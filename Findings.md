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

