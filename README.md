<img src="/images/logo.png" alt="wZD Logo"/>

Документация на русском: https://github.com/eltaline/wzd/blob/master/README-RUS.md

wZD is a server written in Go language that uses a <a href=https://github.com/eltaline/bolt>modified</a> version of the BoltDB database as a backend for saving and distributing any number of small and large files, NoSQL keys or values, in a compact form inside micro Bolt databases (archives), with distribution of files or values in BoltDB databases depending on the number of directories or subdirectories and the general structure of the directories. Using wZD can permanently solve the problem of a large number of files on any POSIX compatible file system, including a clustered one. Outwardly it works like a regular WebDAV server. 

...and billions of files will no longer be a problem.

<img src="/images/wzd-scheme.png" alt="wZD Scheme"/>

Architecture:
========

<img src="/images/wzd-arch.png" alt="wZD Arch"/>

Current stable version: 1.0.0
========

Features
========

- Multithreading
- Multi servers for fault tolerance and load balancing
- Maximum transparency for the user or developer
- Supported HTTP methods: GET, HEAD, PUT and DELETE
- Manage read and write behavior through client headers
- Support for customizable virtual hosts
- Linear scaling of read and write using clustered file systems
- Effective methods of reading and writing data
- Supports CRC data integrity when writing or reading
- Support for Range and Accept-Ranges, If-None-Match and If-Modifed-Since headers
- Store and share 10,000 times more files than there are inodes on any Posix compatible file system, depending on the directory structure
- Support for adding, updating, deleting files and values, and delayed compaction of Bolt archives
- Allows the server to be used as a NoSQL database, with easy sharding based on the directory structure
- Bolt archives support for selective reading of a certain number of bytes from a value
- Easy sharding of data for thousands or millions of Bolt archives based on the directory structure
- Mixed mode support, with ability to save large files separately from Bolt archives
- Support for obtaining a list or number of keys in a directory, including non-unique ones
- Semi-dynamic buffers for minimal memory consumption and optimal network performance tuning
- Includes multithreaded <a href=https://github.com/eltaline/wza>wZA</a> archiver for migrating files without stopping the service

Incompatibilities
========

- Multipart is not supported
- The POST method is not yet supported
- The HTTPS protocol is not yet supported
- There is no native protocol and drivers for different programming languages
- There is no way to transparently mount the structure as a file system via WebDAV or FUSE
- For security reasons, the server does not support recursive deletion of directories
- The server does not allow uploading files to the root directory of the virtual host (applies only to Bolt archives)
- Directories and subdirectories of virtual hosts do not allow other people's files with the .bolt extension
- Data disks cannot simply be transferred from the Little Endian system to the Big Endian system, or vice versa

Multipart will not be supported, since a strict record of a specific amount of data is required so that underloaded files do not form and other problems arise.

Use only binary data transfer protocol to write files or values.


