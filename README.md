<img src="/images/logo.png" alt="wZD Logo"/>

Документация на русском: https://github.com/eltaline/wzd/blob/master/README-RUS.md

wZD is a server written in Go language that uses a <a href=https://github.com/eltaline/bolt>modified</a> version of the BoltDB database as a backend for saving and distributing any number of small and large files, NoSQL keys/values, in a compact form inside micro Bolt databases (archives), with distribution of files and values in BoltDB databases depending on the number of directories or subdirectories and the general structure of the directories. Using wZD can permanently solve the problem of a large number of files on any POSIX compatible file system, including a clustered one. Outwardly it works like a regular WebDAV server. 

...and billions of files will no longer be a problem.

<img align="center" src="/images/wzd-scheme.png" alt="wZD Scheme"/>

Architecture
========

<img align="center" src="/images/wzd-arch.png" alt="wZD Arch"/>

Current stable version: 1.1.3
========

- <a href=/CHANGELOG.md>Changelog</a>

**Important: incompatibilities with previous versions**

- For use all ```Keys*``` headers, you need to add a header ```curl "-H Sea" ...```
- Headers ```Keys...Archive``` renamed to ```Keys...Archives```
- In the docker image, getkeys and getinfo options are disabled by default

Added in version 1.1.3:

- Advanced recursive search for files and values
- Global options: gcpercent, srchcache (configure garbage collector and search cache)
- ```Sea``` header (required to work with ```Keys*``` search)
- Headers: ```KeysSearch*, Recursive``` (getsearch, getrecursive parameters)
- Headers: ```Expression, StopFirst``` (regular expression and stop search)
- Headers: ```WithValue, Expire``` (getvalue, getcache parameters)
- Headers: ```MinSize, MaxSize, MinStmp, MaxStmp, WithUrl```
- Headers: ```Expire, SkipCache``` (Query cache search and skip cache)
- Response headers: ```Hitcache, Errcache, Errmsg``` for search
- ```FromFile``` header for GET and DELETE methods
- Updated documentation

Fixed in version 1.1.3:

- Minor bug fixes

Features
========

- Multi threading
- Multi servers for fault tolerance and load balancing
- Complete file and value search
- Supports HTTPS and IP authorization
- Supported HTTP methods: GET, HEAD, OPTIONS, PUT, POST and DELETE
- Manage read and write behavior through client headers
- Support for customizable virtual hosts
- Linear scaling of read and write using clustered file systems
- Effective methods of reading and writing data
- Supports CRC data integrity when writing or reading
- Support for Range and Accept-Ranges, If-None-Match and If-Modified-Since headers
- Store and share 10,000 times more files than there are inodes on any POSIX compatible file system, depending on the directory structure
- Support for adding, updating, deleting files and values, and delayed compaction/defragmentation of Bolt archives
- Allows the server to be used as a NoSQL database, with easy sharding based on the directory structure
- Bolt archives support for selective reading of a certain number of bytes from a value
- Easy sharding of data over thousands or millions of Bolt archives based on the directory structure
- Mixed mode support, with ability to save large files separately from Bolt archives
- Semi-dynamic buffers for minimal memory consumption and optimal network performance tuning
- Includes multi threaded <a href=https://github.com/eltaline/wza>wZA</a> archiver for migrating files without stopping the service

Incompatibilities
========

- Multipart is not supported
- There is no native protocol and drivers for different programming languages
- There is no way to transparently mount the structure as a file system via WebDAV or FUSE
- For security reasons, the server does not support recursive deletion of directories
- The server does not allow uploading files to the root directory of the virtual host (applies only to Bolt archives)
- Directories and subdirectories of virtual hosts do not allow other people's files with the .bolt extension
- Data disks cannot simply be transferred from the Little Endian system to the Big Endian system, or vice versa

Multipart will not be supported, since a strict record of a specific amount of data is required so that underloaded files do not form and other problems arise.

Use only binary data transfer protocol to write files or values.

Requirements
========

- Operating Systems: Linux, BSD, Solaris, OSX
- Architectures: amd64, arm64, ppc64 and mips64, with only amd64 tested
- Supported Byte Order: Little or Big Endian
- Any POSIX compatible file system with full locking support (preferred clustered MooseFS)

Recommendations
========

- It is recommended to upload large files directly to the wZD server, bypassing reverse proxy servers

Real application
========

Our cluster used has about 250,000,000 small pictures and 15,000,000 directories on separate SATA drives. It utilizes the MooseFS cluster file system. This works well with so many files, but at the same time, its Master servers consume 75 gigabytes of RAM, and since frequent dumps of a large amount of metadata occur, this is bad for SSD disks. Accordingly, there is also a limit of about 1 billion files in MooseFS itself with the one replica of each file.

With a fragmented directory structure, an average of 10 to 1000 files are stored in most directories. After installing wZD and archiving the files in Bolt archives, it turned out about 25 times less files, about 10,000,000. With proper planning of the structure, a smaller number of files could have been achieved, but this is not possible if the already existing structure remains unchanged. Proper planning would result in very large inodes savings, low memory consumption of the cluster FS, significant acceleration of the MooseFS operation itself, and a reduction in the actual space occupied on the MooseFS cluster FS. The fact is, MooseFS always allocates a block of 64 KB for each file, that is, even if a file has a size of 3 KB, will still be allocated 64 KB.

The multi threaded <a href=https://github.com/eltaline/wza>wZA</a> archiver has already been tested on real data.

Our cluster used (10 servers) is an Origin server installed behind a CDN network and served by only 2 wZD servers.

<p align="center">
<img align="center" src="/images/reduction-full.png"/>
</p>

Mixed use
========

The wZD server was designed for mixed use. One can write not only ordinary files, but even html or json generated documents, and one can even simply use NoSQL as a sharding database consisting of a large number of small BoltDB databases, and carry out all sharding through the structure of directories and subdirectories.

Performance tests (Updated v1.1.0)
========

**Testing shows the read or write difference between working with regular files and with Bolt archives. The writeintegrity and readintegrity options are enabled; that is, when writing or reading files in Bolt archives, CRC is used.**

**Important: The time in the tests is indicated for full GET or PUT requests, and the full write or read of HTTP files by the client is included in these milliseconds.**

Tests were carried out on SSD disks, since on SATA disks the tests are not very objective, and there is no clear difference between working with Bolt archives and ordinary files.

The test involved 32 KB, 256 KB, 1024 KB, 4096 KB, and 32768 KB files.

- <b>GET 1000 files and GET 1000 files from 1000 Bolt archives</b>

<img align="center" src="/images/get.png"/>

- <b>PUT 1000 files and PUT 1000 files in 1000 Bolt archives</b>

<img align="center" src="/images/put.png"/>

As can be seen from the graphs, the difference is practically insignificant.

Below is a more visual test done with files of 32 megabytes in size. In this case, writing to Bolt archives becomes slower compared to writing to regular files. Although this is a count, writing 32 MB for 250ms is generally quite fast. Reading such files works quite quickly, and if one wants to store large files in Bolt archives, and the write speed is not critical, such use is allowed but not recommended, and not more than 32 MB per uploaded file.

<b>GET 32M 1000 files and files from Bolt archives and PUT 32M 1000 files and files in Bolt archives</b>

<img align="center" src="/images/get-put-32M.png"/>

<p align="center">
<b>A table that describes the best options for using the server. How many files can be uploaded in one Bolt archive.</b>
<img src="/images/optimal.png"/>
</p>

Documentation
========

Installation
--------

Install packages or binaries
--------

- <a href=https://github.com/eltaline/wzd/releases>Download</a>

```
systemctl enable wzd && systemctl start wzd
```

Install docker image
--------

- **Docker image automatically recursively change UID and GID in mounted /var/storage**

```bash
docker run -d --restart=always -e bindaddr=127.0.0.1:9699 -e host=localhost -e root=/var/storage \
-v /var/storage:/var/storage --name wzd -p 9699:9699 eltaline/wzd
```

More advanced option:

```bash
docker run -d --restart=always -e bindaddr=127.0.0.1:9699 -e host=localhost -e root=/var/storage \
-e upload=true -e delete=true -e compaction=true -e fmaxsize=1048576 \
-e writeintegrity=true -e readintegrity=true \
-e args=false -e getbolt=false -e getcount=true -e getkeys=true -e getinfo=true \
-e getsearch=true -e getrecursive=true -e getvalue=true -e getcache=true \
-v /var/storage:/var/storage --name wzd -p 9699:9699 eltaline/wzd
```

All ENV default parameters can be viewed here: <a href=/Dockerfile>Dockerfile</a>

- Enable rotation on the host system for containers:

Put in /etc/logrotate.d/wzd:

```
/var/lib/docker/containers/*/*.log {
        rotate 7
        daily
        compress
        missingok
        delaycompress
        copytruncate
}
```

Configuring and using wZD server
--------

**For security reasons, if wZD is installed from deb or rpm packages, or from binaries, upload and delete options are disabled by default in the configuration file /etc/wzd/wzd.conf in the localhost virtual host.**

In most cases it is enough to use the default configuration file. A full description of all product parameters is available here: <a href="/OPTIONS.md">Options</a>

General methods
--------

Downloading file (the existing normal file is downloaded first and not the one in the Bolt archive)

```bash
curl -o test.jpg http://localhost/test/test.jpg
```

Downloading file from the file (forced)

```bash
curl -o test.jpg -H "FromFile: 1" http://localhost/test/test.jpg
```

Downloading file from the Bolt archive (forced)

```bash
curl -o test.jpg -H "FromArchive: 1" http://localhost/test/test.jpg
```

Downloading the whole Bolt archive from the directory (if the server parameter getbolt = true)

```bash
curl -o test.bolt http://localhost/test/test.bolt
```

Uploading file to the directory

```bash
curl -X PUT --data-binary @test.jpg http://localhost/test/test.jpg
```

Uploading file to the Bolt archive (if the server parameter fmaxsize is not exceeded)

```bash
curl -X PUT -H "Archive: 1" --data-binary @test.jpg http://localhost/test/test.jpg
```

Deleting file (a regular file is deleted first, if it exists, and not the file in the bolt archive)

```bash
curl -X DELETE http://localhost/test/test.jpg
```

Deleting file (forced)

```bash
curl -X DELETE -H "FromFile: 1" http://localhost/test/test.jpg
```

Deleting file from the Bolt archive (forced)

```bash
curl -X DELETE -H "FromArchive: 1" http://localhost/test/test.jpg
```

Deleting the whole Bolt archive from the directory (if the server parameter delbolt = true)

```bash
curl -X DELETE http://localhost/test/test.bolt
```

Search
--------

Getting list of all unique file names from directory and archive (if the server parameter getkeys = true)

```bash
curl -H "Sea: 1" -H "Keys: 1" http://localhost/test
```

Getting list of all file names from the directory and archive (if the server parameter getkeys = true)

```bash
curl -H "Sea: 1" -H "KeysAll: 1" http://localhost/test
```

Getting list of all file names only from the directory (if the server parameter getkeys = true)

```bash
curl -H "Sea: 1" -H "KeysFiles: 1" http://localhost/test

```
Getting list of all file names only from the archive (if the server parameter getkeys = true)

```bash
curl -H "Sea: 1" -H "KeysArchives: 1" http://localhost/test
```

Getting list of all unique file names from the directory and archive with their sizes and dates (if the server parameter getinfo = true)

```bash
curl -H "Sea: 1" -H "KeysInfo: 1" http://localhost/test
```

Getting list of all file names from the directory and archive with their sizes and dates (if the server parameter getinfo = true)

```bash
curl -H "Sea: 1" -H "KeysInfoAll: 1" http://localhost/test
```

Getting list of all file names only from the directory with their sizes and dates (if the server parameter getinfo = true)

```bash
curl -H "Sea: 1" -H "KeysInfoFiles: 1" http://localhost/test

```
Getting list of all file names only from the archive with their sizes and dates (if the server parameter getinfo = true)

```bash
curl -H "Sea: 1" -H "KeysInfoArchives: 1" http://localhost/test
```

Getting list of all unique file names from the directory and archive with their sizes and dates (if the server parameter getsearch = true)

```bash
curl -H "Sea: 1" -H "KeysSearch: 1" -H "Expression: (\.jpg$)" http://localhost/test
```

Getting list of all file names from the directory and archive with their sizes and dates (if the server parameter getsearch = true)

```bash
curl -H "Sea: 1" -H "KeysSearchAll: 1" -H "Expression: (\.jpg$)" http://localhost/test
```

Getting list of all file names only from the directory with their sizes and dates (if the server parameter getsearch = true)

```bash
curl -H "Sea: 1" -H "KeysSearchFiles: 1" -H "Expression: (\.jpg$)" http://localhost/test

```
Getting list of all file names only from the archive with their sizes and dates (if the server parameter getsearch = true)

```bash
curl -H "Sea: 1" -H "KeysSearchArchives: 1" -H "Expression: (\.jpg$)" http://localhost/test
```

Getting count number of all unique files from the directory and archive (if the server parameter getcount = true)

```bash
curl -H "Sea: 1" -H "KeysCount: 1" http://localhost/test
```

Getting count number of all files from directory and archive (if the server parameter getcount = true)

```bash
curl -H "Sea: 1" -H "KeysCountAll: 1" http://localhost/test
```

Getting count number of all files only from the directory (if the server parameter getcount = true)

```bash
curl -H "Sea: 1" -H "KeysCountFiles: 1" http://localhost/test
```

Getting count number of all files only from the archive (if the server parameter getcount = true)

```bash
curl -H "Sea: 1" -H "KeysCountArchives: 1" http://localhost/test
```

Advanced search
--------

- **```Keys, KeysInfo``` headers also support all search headers except the ```WithValue``` header**
- **```KeysCount``` headers also support all search headers except ```Limit, Offset, WithValue``` headers**
- **```WithValue``` header is only available if you use ```KeysSearch*``` and ```JSON``` headers together**
- **The ```Recursive``` header supports a maximum recursion depth of 3**
- **The ```Expire``` header sets the lifetime once for a particular request. Other same particular request returns result from the cache and the lifetime for the result in the cache is not updated**
- **Using ```Expire``` and ```SkipCache``` headers together will force updates the result and lifetime in the cache**
- **When using header ```WithValue``` values are encoded by base64(outer) and HEX(inner)**

Regex search (if server parameter getsearch = true)

```bash
curl -H "Sea: 1" -H "KeysSearchAll: 1" -H "JSON: 1" -H "Expression: (\ .jpg $)" http://localhost/test
````

Recursive search (if server parameter getrecursive = true)

```bash
curl -H "Sea: 1" -H "KeysSearchAll: 1" -H "JSON: 1" -H "Recursive: 3" http://localhost/test
````

Search with saving the result to the server cache for 120 seconds (if the server parameter getcache = true)

```bash
curl -H "Sea: 1" -H "KeysSearchAll: 1" -H "JSON: 1" -H "Expire: 120" http://localhost/test
````

Search with a skip result from the server cache

```bash
curl -H "Sea: 1" -H "KeysSearchAll: 1" -H "JSON: 1" -H "SkipCache: 1" http://localhost/test
````

Search with skipping the result from the server cache and changing the value in the server cache with set new lifetime of 120 seconds (if the server parameter getcache = true)

```bash
curl -H "Sea: 1" -H "KeysSearchAll: 1" -H "JSON: 1" -H "Expire: 120" -H "SkipCache: 1" http://localhost/test
````

Limit with Offset Search

```bash
curl -H "Sea: 1" -H "KeysSearchAll: 1" -H "JSON: 1" -H "Limit: 25" -H "Offset: 100" http://localhost/test
````

Search with adding the virtual host URL to the key names

```bash
curl -H "Sea: 1" -H "KeysSearchAll: 1" -H "JSON: 1" -H "WithUrl: 1" http://localhost/test
````

Search with size limits. ```WithValue: 1``` If any value exceeds the server parameter vmaxsize, then value will not be included in the output, but the key in the output will be present

```bash
curl -H "Sea: 1" -H "KeysSearchAll: 1" -H "JSON: 1" -H "MinSize: 512" -H "MaxSize: 1024" -H "WithUrl: 1" -H "WithValue: 1" http://localhost/test
````

Search with timestamp date interval. ```WithValue: 1``` If any value exceeds the server parameter vmaxsize, then value will not be included in the output, but the key in the output will be present

```bash
curl -H "Sea: 1" -H "KeysSearchAll: 1" -H "JSON: 1" -H "MinStmp: 1570798400" -H "MaxStmp: 1580798400" -H "WithUrl: 1" -H "WithValue: 1" http://localhost/test
```

Search before the first match

```bash
curl -H "Sea: 1" -H "KeysSearchAll: 1" -H "JSON: 1" -H "Expression: (10.jpg)" -H "StopFirst: 1" http://localhost/test
```

No comments

```bash
curl -H "Sea: 1" -H "KeysSearchAll: 1" -H "JSON: 1" -H "Recursive: 3" -H "Expression: (\.jpg$)" -H "MinSize: 512" -H "MaxSize: 1024" -H "MinStmp: 1570798400" -H "MaxStmp: 1580798400" -H "Limit: 25 " -H "Offset: 50" -H "WithUrl: 1" -H "WithValue: 1" -H "Expire: 3600" http://localhost/test
```

Data migration in 3 steps without stopping the service
--------

This server was developed not only for use from scratch but also for use on current real production systems. To do this, the <a href=https://github.com/eltaline/wza>wZA</a> archiver is proposed for use with the wZD server.

The archiver allows for converting current files to Bolt archives without deletion and with deletion, and allows for unpacking them back. It supports overwrite and other functions.

**The archiver, as far as possible, is safe. It does not support a recursive traversal, only works on a pre-prepared list of files or Bolt archives, and provides for repeated reading of the file after packing and CRC verification of the checksum on the fly.**

Data migration guide:

The path to be migrated: /var/storage. Here are jpg files in the 1 million subdirectories of various depths that need to be archived in Bolt archives, but only those files that are no larger than 1 MB.

- wZD server should be configured with a virtual host and with a root in the /var/storage directory

- Perform a recursive search:

   ```bash
   find /var/storage -type f -name '*.jpg' -not -name '*.bolt' > /tmp/migration.list
   ```

- Start archiving without deleting current files:

   ```bash
   wza --pack --fmaxsize=1048576 --list=/tmp/migration.list
   ```

- Start deleting old files with key checking in Bolt archives without deleting files that are larger than fmaxsize:

  ```bash
  wza --pack --delete --fmaxsize=1048576 --list=/tmp/migration.list
  ```
  
This can be combined into one operation with the removal of the old files.
The archiver skips non-regular files and will not allow archiving of the Bolt archive to the Bolt archive.
The archiver will not delete the file until the checksum of the file being read coincides, after archiving, with the newly read file from the Bolt archive, unless of course that is forced to disable.
While the wZD server is running, it returns data from regular files, if it finds them. This is a priority.

This guide provides an example of a single-threaded start, stopping at any error with any file, even if non-regular files were included in the prepared list or files were suddenly deleted by another process but remained in the list. To ignore already existing files from the list, the --ignore-not option must be added. The same is true when unpacking.

Restarting archiving without the --overwrite option will not overwrite files in Bolt archives. The same is true when unpacking.

The archiver also supports the multi threaded version --threads= and other options.
In the multi threaded version, the --ignore option is automatically applied so as not to stop running threads when any errors occur. In case of an error with the --delete option turned on, the source file will not be deleted.

A full description of all product parameters is available here: <a href="/OPTIONS.md">Options</a>

Notes and Q&A
========

- Outwardly, at its core, this server looks like a regular WebDAV server for a user or developer

- The server works with only one system user. UID and GID for any Bolt archives and files are taken at server startup from the current user or from the systemd startup script

- The server automatically creates directories and Bolt archives during the upload files or values. Just upload the file to the desired path

- Bolt archives are automatically named with the name of the directory in which they are created

- Effective reduction of the number of files within the data instance depends on the selected directory structure, and the planned number of file uploads in these directories

- It is not recommended uploading 100,000+ files to one directory (one Bolt archive); this would be a large overhead. If possible, plan your directory structure correctly

- It is not recommended uploading files or values larger than 16 MB to Bolt archives. By default, the parameter fmaxsize = 1048576 bytes

- If the fmaxsize parameter is exceeded, even with the "Archive: 1" client header set, the data will be loaded into a separate regular file without notification. The maximum possible size of the parameter is fmaxsize = 33554432 bytes

- If the nonunique = true parameter is turned on in the virtual host, this means that the wZD server will allow uploading of individual files with the same name, even if the Bolt archive in this directory already contains data with the same key name as the uploaded file

- Despite the fact that the nonunique = false parameter is disabled in the virtual host, the wZD server will upload the file or value to the new Bolt archive, even if the key name matches the already existing file name in this directory. This is required for non-stop operation of the service and working in a mixed mode during data migration to Bolt archives, including when adding new files non-stop through the PUT method or deleting them through the DELETE method

- When using the writeintegrity = true and readintegrity = true parameters, the downloaded file or value is completely written to RAM, but no more than 32 MB per request, with the maximum parameter fmaxsize set. It is highly recommended that these options be enabled as true. These parameters affect only files or values in Bolt archives

- If the writeintegrity = true parameter has not been enabled, and a lot of files or values have been uploaded to the Bolt archives, then the checksum will not have been calculated for them. In this case, for the checksum to be calculated and recorded, <a href=https://github.com/eltaline/wza>wZA</a> archiver can be used to unpack all current Bolt archives and repack them again, but without disabling the CRC amount record in the archiver itself. In the future, the archiver will support the calculation and recording of the checksum for files or values in the current Bolt archives without unpacking and packing operations, if the values in the Bolt archives did not initially have a checksum

- If the checksum of the files or values has not been calculated and recorded as a result of the writeintegrity = false parameter set, then with the readintegrity = true parameter enabled, everything will work, but the checksum will not be checked when downloading

- The server does not allow uploading files to the root directory of the virtual host. This is prohibited only when trying to upload a file or value to the root of the virtual host with the "Archive: 1" header set. Regular files without packing can be uploaded to the root of the virtual host

- The server uses an extended version of BoltDB by the current developer of wZD. Added functions are GetLimit(), GetOffset(), GetRange(). This allows as much data to be read as is needed by a byte from files or values, for example, using the headers "Range: bytes = ...", If-None-Match, If-Modified-Since, or the HEAD and OPTIONS methods, which allows the same significant saving of disk subsystem resources as simply reading the entire file or value using the standard Get() function

- The server does not create any temporary files during its operation, and at the same time it consumes little RAM. Large files are transferred through customizable, semi-dynamic, small-sized buffers on the fly. The wZD server does not use the simple function ctx.SendFile() or ctx.ServeContent()

- At the request of the community, some parameters can be transferred from the [global] section to the [server] section
- At the request of the community, new advanced functionality can also be added. Use the feature request

 ToDo
 ========
 
- Development of own replicator and distributor with a geo for possible use in large systems without cluster FS
- The ability to fully reverse restore metadata when it is completely lost (if using a distributor)
- Native protocol for the possibility of using permanent network connections and drivers for different programming languages
- ~~Support for HTTPS protocol, it may be supported only in the future distributor~~ (Completed in standart version)
- ~~Advanced features for using NoSQL component~~ (Completed)
- Implementing background calculate checksums for single large files
- Periodic checksum checks in the background to protect against bit rot
- FUSE and / or WebDAV Mount, full support may be implemented, including write support
- ~~Abandoning of SQLite in favor of a simpler solution (abandoning CGO)~~ (Completed)
- Different types of compression (gzip, zstd, snappy) for files or values inside Bolt archives and for ordinary files
- Different types of encryption for files or values inside Bolt archives and for regular files
- Server-side delayed video conversion, including on GPU

Parameters
========

A full description of all product parameters is available here: <a href="/OPTIONS.md">Options</a>

HTTP Core
========

Uses <a href=https://github.com/kataras/iris>Iris</a> as server http core

Guarantees
========

No warranty is provided for this software. Please test first

Donations
========

<a href="https://www.paypal.me/xwzd"><img src="/images/paypal.png"><a/>

Contacts
========

- E-mail: dev@wzd.dev
- wZD website: https://wzd.dev
- Company website: <a href="https://elta.ee">Eltaline</a>

```
Copyright © 2020 Andrey Kuvshinov. Contacts: <syslinux@protonmail.com>
Copyright © 2020 Eltaline OU. Contacts: <eltaline.ou@gmail.com>
All rights reserved.
```
