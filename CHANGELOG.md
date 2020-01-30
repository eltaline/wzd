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

- Fix date storage format from uint32 to uint64
- Correction of various errors
- Fix memory leaks

Version: 1.1.1
========

Fixed in version 1.1.1:

- Small fixes
- Fix freelist select algorithm when Read

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

- Fix set of HTTP timeouts
- Exclusion of the ability to upload files with the extension .bolt
- Fix some regular expressions
- Ability to use server without reverse proxy servers

**Version 1.0.0 is deprecated and removed from public access, because this is first design-release without important features**
