Version: 1.1.3
========

**Important: incompatibilities with previous versions**

- For use all ```Keys*``` headers, you need to add a header ```curl "-H Sea" ...```
- Headers ```Keys...Archive`` renamed to ```Keys...Archives```
- In the docker image, getkeys and getinfo options are disabled by default

Added in version 1.1.3:

- Advanced recursive search for files and values
- Global options: gcpercent, srchcache (configure garbage collector and search cache)
- Sea header (required to work with Keys* search)
- Headers: KeysSearch*, Recursive (getsearch, getrecursive parameters)
- Headers: Expression, StopFirst (regular expression and stop search)
- Headers: WithValue, Expire (getvalue, getcache parameters)
- Headers: MinSize, MaxSize, MinStmp, MaxStmp, WithUrl
- Headers: Expire, SkipCache (Query cache search and skip cache)
- Response headers: Hitcache, Errcache, Errmsg search
- FromFile header for GET and DELETE methods
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
