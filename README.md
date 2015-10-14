# syslog module for node and backendjs

Supports UDP and Unix domain socket, the primary goal is to use with local syslogd server,
does not depend on the libc syslog library.

# Usage

 - `open(name, priority, facility)` - initialize syslog client, used by the logger module
 - `send(level, text)`
 - `close()`

```javascript

  var syslog = require("bkjs-syslog");
  syslog.open("test", syslog.LOG_PID | syslog.LOG_CONS, syslog.LOG_DAEMON);
  syslog.send(syslog.LOG_ERR, "Error test");
```

# Author 

Vlad Seryakov

