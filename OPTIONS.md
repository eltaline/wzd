<img src="/images/logo.png" alt="wZD Logo"/>

wZD Parameters:
========

Section [command line]
------------

- -config string
        --config=/etc/wzd/wzd.conf (default is "/etc/wzd/wzd.conf")
- -debug 
        --debug - debug mode
- -help 
        --help - displays help
- -version 
        --version - print version

Section [global]
------------

bindaddr
- **Description**: This is the primary address and TCP port. The value is ": 9699" for all addresses.
- **Default:** "127.0.0.1:9699"
- **Type:** string
- **Section:** [global]

readtimeout
- **Description:** This sets the timeout for the maximum data transfer time from the client to the server. It should be increased to transfer large files. If the wZD server is installed behind Nginx or HAProxy, this timeout can be disabled by setting it to 0 (no timeout). It is not configured for a virtual host.
- **Default:** 60
- **Values:** 0-86400
- **Type:** int
- **Section:** [global]

readheadertimeout
- **Description:** This sets the timeout for the maximum time for receiving headers from the client. If the wZD server is installed behind Nginx or HAProxy, this timeout can be disabled by setting it to 0. If the parameter = 0, the readtimeout parameter is taken. If the readtimeout = 0, the readheadertimeout timeout is not used (no timeout). It is not configured for a virtual host.
- **Default:** 5
- **Values:** 0-86400
- **Type:** int
- **Section:** [global]

idletimeout
- **Description:** This sets the timeout for the maximum lifetime of keep alive connections. If the parameter = 0, the readtimeout parameter value is taken. If the readtimeout = 0, the idletimeout timeout is not used (no timeout). It is not configured for a virtual host.
- **Default:** 60
- **Values:** 0-86400
- **Type:** int
- **Section:** [global]

writetimeout
- **Description:** This sets the timeout for the maximum data transfer time to the client. The transfer of large files should be significantly increased. If the wZD server is installed behind Nginx or HAProxy, this timeout can be disabled by setting it to 0 (no timeout). It is not configured for a virtual host.
- **Default:** 60
- **Values:** 0-86400
- **Type:** int
- **Section:** [global]

realheader
- **Description:** This is the real IP address header from the reverse proxy. It is not configured for a virtual host.
- **Default:** "X-Real-IP"
- **Type:** string
- **Section:** [global]
       
charset
- **Description:** This is the encoding used for the entire server. It is not configured for a virtual host.
- **Default:** "UTF-8"
- **Type:** string
- **Section:** [global]

debugmode
- **Description:** This is the debug mode.
- **Default:** false
- **Values:** true or false
- **Type:** boolean
- **Section:** [global]

pidfile
- **Description:** This is the PID file path.
- **Default:** "/run/wzd/wzd.pid"
- **Type:** string
- **Section:** [global]

logdir
- **Description:** This is the path to the log directory.
- **Default:** "/var/log/wzd"
- **Type:** string
- **Section:** [global]

logmode
- **Description:** This sets the permissions for the log files (mask).
- **Default:** 0640
- **Values:** 0600-0666
- **Type:** uint32
- **Section:** [global]

defsleep
- **Description:** This sets the sleep time between attempts to open Bolt archive (seconds).
- **Default:** 1
- **Values:** 1-5
- **Type:** int
- **Section:** [global]

cmpsched = true
- **Description:** This globally enables or disables the automatic compaction manager for Bolt archives.
- **Default:** false
- **Values:** true or false
- **Type:** boolean
- **Section:** [global]

cmpdir
- **Description:** This is the directory of the technical database. There is little technical data for the compaction manager.
- **Default:** /var/lib/wzd
- **Type:** string
- **Section:** [global]

cmptime = 30 
- **Description:** This is the compaction timeout for updated Bolt archives (days).
- **Default:** 30
- **Values:** 1-1000
- **Type:** int
- **Section:** [global]

cmpcheck = 5
- **Description:** This is the start interval of the automatic compaction manager (seconds).
- **Default:** 5
- **Values:** 1-5
- **Type:** int
- **Section:** [global]

Section [server] and subsections [server.name]
------------

[server.name]
- **Description:** This is the primary internal identifier of the virtual host. After "." any name can be used. This is not a domain name, only an internal identifier.
- **Type:** string
- **Section:** [server]

host
- **Description:** This is the virtual host name. The value * or _ is not supported. To convert multiple virtual hosts to one virtual host in a wZD server, use Nginx or HAProxy, or any other reverse proxy server with a hard-set "proxy_set_header Host hostname;" (using Nginx as an example) where hostname = host in the wZD server virtual host.
- **Default:** Required
- **Type:** string
- **Section:** [server.name]

root
- **Description:** This is the virtual host root directory.
- **Default:** Required
- **Type:** string
- **Section:** [server.name]

upload
- **Description:** This enables or disables the PUT method for the virtual host.
- **Default:** Required
- **Values:** true or false
- **Type:** boolean
- **Section:** [server.name]

delete
- **Description:** This enables or disables the DELETE method for the virtual host.
- **Default:** Required
- **Values:** true or false
- **Type:** boolean
- **Section:** [server.name]

compaction
- **Description:** This enables or disables the automatic addition of tasks for the compaction manager of the Bolt archives when updating or deleting files or values in Bolt archives, if parameter cmpsched is not disabled globally.
- **Default:** Required
- **Values:** true or false
- **Type:** boolean
- **Section:** [server.name]

writeintegrity
- **Description:** This enables or disables the calculation and recording of the checksum in the binary header while uploading files or values through the wZD server to Bolt archives. It is recommended that this be enabled.
- **Default:** Required
- **Values:** true or false
- **Type:** boolean
- **Section:** [server.name]

readintegrity
- **Description:** This enables or disables checksum verification from the binary header during the output of files or values to the client. It is recommended that this be enabled.
- **Default:** Required
- **Values:** true or false
- **Type:** boolean
- **Section:** [server.name]

trytimes
- **Description:** This is the number of attempts to obtain a virtual lock of the Bolt archive before returning an HTTP error (number).
- **Default:** Required
- **Values:** 1-1000
- **Type:** int
- **Section:** [server.name]

opentries
- **Description:** This is the number of attempts to open Bolt archive before returning an HTTP error (number).
- **Default:** Required
- **Values:** 1-1000
- **Type:** int
- **Section:** [server.name]

fmaxsize
- **Description:** This is the maximum size of the uploaded file or value in the Bolt archive. If this parameter is exceeded, the file or value will be loaded as a separate file with the same path. The recommended size is not more than 1048576 (1MB). It is not recommended to upload files or values to Bolt archives that are larger than 16MB. Such files or values must be stored separately (bytes).
- **Default:** Required
- **Values:** 1-33554432
- **Type:** int64
- **Section:** [server.name]

args
- **Description:** If this is disabled, query arguments will be denied for GET requests. It is recommended that this be enabled if using Vary header on a reverse proxy server, or if versioning through query arguments.
- **Default:** Required
- **Values:** true or false
- **Type:** boolean
- **Section:** [server.name]

getbolt
- **Description:**  If this is disabled, direct download of Bolt archives will be forbidden.
- **Default:** Required
- **Values:** true or false
- **Type:** boolean
- **Section:** [server.name]

getcount
- **Description:** If this is disabled, getting a count of the total number of files or values (including individual files) in the directory will be forbidden.
- **Default:** Required
- **Values:** true or false
- **Type:** boolean
- **Section:** [server.name]

getkeys
- **Description:** If this is disabled, getting file or key names (including individual files) from the directory will be forbidden.
- **Default:** Required
- **Values:** true or false
- **Type:** boolean
- **Section:** [server.name]

nonunique
- **Description:** If this is enabled, it is then possible to upload a file with a non-unique name to a directory where there is already a Bolt archive, and where the Bolt archive includes a file or value with the same key name as the separate file to be uploaded. If this parameter is turned off, the reverse will be possible. That is, it will be possible to upload a file or value to the Bolt archive, even if there is already a separate file in the same directory with the same name as the name of the key loaded into the Bolt file archive or value.
- **Default:** Required
- **Values:** true or false
- **Type:** boolean
- **Section:** [server.name]  

cctrl
- **Description:** This sets the Cache-Control header.
- **Default:** Required
- **Values:** 0-2147483647
- **Type:** int
- **Section:** [server.name]

buffers options
- **Description:** This controls the read and write buffers. All buffers can be increased several times for networks with 10-100 Gbit bandwidth. Each subsequent buffer cannot be less than or equal to the previous one. Increasing the buffer is required for very large files. Here, the minimum possible values are set for all buffers except minbuffer, which has a minimum possible value of 4096 bytes. The default options are sufficient for most tasks.
- **Default:** Required 
- **Type:** int
- **Section:** [global]

- minbuffer = 262144 # -- minimum memory buffer. If this value is not exceeded, an even smaller buffer is used. 
- lowbuffer = 1048576 # -- small memory buffer. If this value is exceeded, the minbuffer memory buffer is used.
- medbuffer = 67108864 # -- medium memory buffer. If this value is exceeded, the lowbuffer memory buffer is used.
- bigbuffer = 536870912 # -- not quite a memory buffer. When this value is exceeded, the medbuffer memory buffer is used.

filemode
- **Description:** This sets the permissions to create Bolt archives, files and virtual attributes in a binary header inside values in Bolt archives. 
- **Default:** Required
- **Values:** 0600-0666
- **Type:** uint32
- **Section:** [server.name]

dirmode
- **Description:** This sets directory creation permissions.
- **Default:** Required
- **Values:** 0700-0777
- **Type:** uint32
- **Section:** [server.name]

delbolt
- **Description:** If this is enabled, direct deletion of Bolt archives will be allowed.
- **Default:** Required
- **Values:** true or false
- **Type:** boolean
- **Section:** [server.name]

deldir
- **Description:** If this is enabled, the wZD server will delete the last empty directory, provided there really are no files or subdirectories and the number of keys in the Bolt archive = 0. Only the current directory is deleted. Recursive traversal is not implemented for security reasons.
- **Default:** Required
- **Values:** true or false
- **Type:** boolean
- **Section:** [server.name]
