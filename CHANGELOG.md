Version: 1.2.1
========

- Update to Go 1.14
- Update to Iris 12.1.8
- Transition to Go module support

Version: 1.2.0
========

**Important: incompatibilities with previous versions**

- **By default, now curl -X PUT without additional headers works in automatic mode based on the fmaxsize parameter**
- **Search now without replication(in development)**
- Removed excessive carriage return `"\n"` when displaying in all types of search
- Removed redundant headers ```KeysAll, KeysInfoAll, KeysSearchAll, KeysCountAll```
- Removed double encoding when working with the header ```WithValue```, the values are encoded only in HEX
- For headers ```Keys, KeysFiles, KeysArchives``` added a type of file/key
- Renamed `srchcache` option to `searchcache`, dimension changed to bytes
- Project license changed to Apache License 2.0

Added in version 1.2.0:

- **Implemented a fast search, the search has been completely rewritten**
- **Implemented automatic sharding of Bolt archives within the directory (skeyscnt, smaxsize parameters)**
- Header ```File``` for PUT method
- Headers ```Prefix, WithJoin, Sort```
- Header ```Compact``` for PUT and DELETE methods
- Updated documentation

Fixed in version 1.2.0:

- Fixed work with the header ```WithValue```

Version: 1.1.3
========

**Important: incompatibilities with previous versions**

- For use all ```Keys*``` headers, you need to add a header ```curl "-H Sea" ...```
- Headers ```Keys...Archive`` renamed to ```Keys...Archives```
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

Version: 1.1.2
========

**Important: incompatibilities with previous versions**

The procedure for upgrading to version 1.1.2:

- Install wZD server and archiver <a href=https://github.com/eltaline/wza>wZA</a> version 1.1.2
- Restart wZD server
- Update Bolt archives (one time required)

*Restarting the update is excluded by the archiver itself

```bash
find /var/storage -type f -name '*.bolt'> /tmp/upgrade.list
wza --upgrade --list=/tmp/upgrade.list
```

Added in version 1.1.2:

- The archiver <a href=https://github.com/eltaline/wza>wZA</a> now comes immediately in the docker image
- Headers Keys* KeysInfo* KeysCount* (parameters getkeys, getinfo, getcount)
- Headers JSON, Limit, Offset (advanced use of NoSQL component)
- Updating the format of Bolt archives (for future support for WEB interface and FUSE)
- Support for UTF-8

Fixed in version 1.1.2:

- Fixed date storage format from uint32 to uint64
- Correction of various errors
- Fixed memory leaks

Version: 1.1.1
========

Fixed in version 1.1.1:

- Small fixes
- Fixed freelist select algorithm when Read

Version: 1.1.0
========

Added in version 1.1.0:

- HTTPS (parameters bindaddrssl, onlyssl, sslcrt, sslkey)
- IP authorization (parameters getallow, putallow, delallow)
- Choice of free page algorithm in BoltDB (freelist parameter)
- Keepalive (keepalive parameter)
- POST method (binary data protocol only)
- OPTIONS method (parameter options)
- Access-Control-Allow-Origin header (parameter headorigin)
- X-Frame-Options header (parameter xframe)
- Content-Encoding header for pre-compressed gzip files (automatic + parameter gzstatic)
- Logging 4xx (parameter log4xx)

Fixed in version 1.1.0:

- Fixed set of HTTP timeouts
- Exclusion of the ability to upload files with the extension .bolt
- Fixed some regular expressions
- Ability to use server without reverse proxy servers

**Version 1.0.0 is deprecated and removed from public access, because this is first design-release without important features**
