//
//  Author: Vlad Seryakov vseryakov@gmail.com
//  April 2013
//

#include <node.h>
#include <node_object_wrap.h>
#include <node_buffer.h>
#include <node_version.h>
#include <v8.h>
#include <v8-profiler.h>
#include <uv.h>
#include <nan.h>

using namespace node;
using namespace v8;
using namespace std;

#include <errno.h>
#include <syslog.h>
#include <sys/un.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdarg.h>

#ifdef __APPLE__
#define LOGDEV         "/var/run/syslog"
#else
#define LOGDEV         "/dev/log"
#endif

#define LOG_RFC3339    0x10000

#define NAN_REQUIRE_ARGUMENT_STRING(i, var) if (info.Length() <= (i) || !info[i]->IsString()) {Nan::ThrowError("Argument " #i " must be a string"); return;} Nan::Utf8String var(info[i]->ToString());
#define NAN_REQUIRE_ARGUMENT_INT(i, var) if (info.Length() <= (i)) {Nan::ThrowError("Argument " #i " must be an integer"); return;} int var = info[i]->Int32Value();
#define NAN_DEFINE_CONSTANT_INTEGER(target, constant, name) Nan::ForceSet(target, Nan::New(#name).ToLocalChecked(), Nan::New(constant),static_cast<PropertyAttribute>(ReadOnly | DontDelete) );

namespace Syslog {

struct SyslogConfig {
    SyslogConfig(): sock(-1), port(514), tag("backend"), path(LOGDEV), connected(0), options(0), facility(LOG_USER), severity(LOG_INFO) {}

    int      sock;                /* fd for log */
    int      port;                /* port for remote syslog */
    string   tag;                 /* string to tag the entry with */
    string   path;                /* path to socket or hostname */
    int      connected;           /* have done connect */
    int      options;             /* status bits, set by openlog() */
    int      facility;            /* default facility code */
    int      severity;            /* default severity code */
};

static void _syslogOpen(string path, string tag, int options, int facility);
static void _syslogClose(void);
static void _syslogSend(int severity, const char *fmt, ...);
static void _syslogSendV(int severity, const char *fmt, va_list ap);
static SyslogConfig _config;

NAN_METHOD(open)
{
    NAN_REQUIRE_ARGUMENT_STRING(0, name);
    NAN_REQUIRE_ARGUMENT_INT(1, options);
    NAN_REQUIRE_ARGUMENT_INT(2, facility);

    _syslogClose();
    _syslogOpen("", *name, options, facility);
}

NAN_METHOD(send)
{
    NAN_REQUIRE_ARGUMENT_INT(0, level);
    NAN_REQUIRE_ARGUMENT_STRING(1, msg);

    _syslogSend(level, "%s", *msg);
}

NAN_METHOD(close)
{
    _syslogClose();
}

static long long _clock()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long long)((long long)(tv.tv_sec)*1000 + (tv.tv_usec/1000));
}

static string _fmtTime3339(int64_t msec)
{
    char buf[128];
    time_t sec = msec / 1000;
    msec = msec % 1000;

    struct tm tmbuf;
    struct tm *tm = localtime_r((time_t*)&sec, &tmbuf);
    snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02d.%03d%c%02d:%02d",
             tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
             tm->tm_hour, tm->tm_min, tm->tm_sec,
             (int)msec,
             tm->tm_gmtoff < 0 ? '-' : '+',
             (int)(tm->tm_gmtoff / 3600), (int)((tm->tm_gmtoff % 3600) / 60));
    return buf;
}

static void _syslogOpen(string path, string tag, int options, int facility)
{
    int changed = 0;

    if (!path.empty() && path != _config.path) {
        _config.path = path;
        changed = 1;
    }
    if (!tag.empty() && tag != _config.tag) {
        _config.tag = tag;
        changed = 1;
    }
    if (options && options != _config.options) {
        _config.options = options;
        changed = 1;
    }
    if (facility != -1 && facility != _config.facility) {
        _config.facility = facility;
        changed = 1;
    }
    if (changed) {
        _syslogClose();
    }

    if (_config.sock == -1) {
        if (!_config.path.empty() && _config.path[0] == '/') {
            struct sockaddr_un un;
            memset(&un, 0, sizeof(un));
            un.sun_family = AF_UNIX;
            strncpy(un.sun_path, _config.path.c_str(), sizeof(un.sun_path) - 1);
            if (_config.options & LOG_NDELAY) {
                _config.sock = socket(AF_UNIX, SOCK_DGRAM, 0);
            }
            if (_config.sock != -1 && !_config.connected && connect(_config.sock, (struct sockaddr*)&un, sizeof(un)) != -1) {
                _config.connected = 1;
            }
        } else {
            struct sockaddr_in sa;
            char *ptr = (char*)strchr(_config.path.c_str(), ':');
            if (ptr != NULL) {
                *ptr++ = 0;
                _config.port = atoi(ptr);
            }
            memset(&sa, 0, sizeof(struct sockaddr_in));
            sa.sin_family = AF_INET;
            sa.sin_addr.s_addr = inet_addr(_config.path.c_str());
            sa.sin_port = htons(_config.port);

            if (_config.options & LOG_NDELAY) {
                _config.sock = socket(AF_INET, SOCK_DGRAM, 0);
            }
            if (_config.sock != -1 && !_config.connected && connect(_config.sock, (struct sockaddr*)&sa, sizeof(sa)) != -1) {
                _config.connected = 1;
            }
        }
    }
}

static void _syslogClose(void)
{
    if (_config.sock != -1) ::close(_config.sock);
    _config.sock = -1;
    _config.connected = 0;
}

static void _syslogSend(int severity, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    _syslogSendV(severity, fmt, ap);
    va_end(ap);
}

static void _syslogSendV(int severity, const char *fmt, va_list ap)
{
    string buf, err = strerror(errno);
    int fd, offset;

    if (severity == -1) severity = _config.severity;

    // see if we should just throw out this message
    if (!LOG_MASK(LOG_PRI(severity)) || (severity &~ (LOG_PRIMASK|LOG_FACMASK))) return;

    if (_config.sock < 0 || !_config.connected) {
        _syslogClose();
        _syslogOpen("", "", _config.options | LOG_NDELAY, -1);
        if (!_config.connected) return;
    }

    // set default facility if none specified
    if ((severity & LOG_FACMASK) == 0) severity |= _config.facility;

    // build the message
    char tmp[128];
    if (_config.options & LOG_RFC3339) {
        snprintf(tmp, sizeof(tmp), "<%d>%s ", severity, _fmtTime3339(_clock()).c_str());
        buf = tmp;
    } else {
        time_t now = time(NULL);
        snprintf(tmp, sizeof(tmp), "<%d>%.15s ", severity, ctime(&now) + 4);
        buf = tmp;
    }
    offset = buf.size();

    if (!_config.tag.empty()) {
        buf += _config.tag;
    }
    if (_config.options & LOG_PID) {
        sprintf(tmp, "[%d]", getpid());
        buf += tmp;
    }
    if (!_config.tag.empty()) {
        buf += ": ";
    }

    char *str = NULL;
    int n = vasprintf(&str, fmt, ap);
    if (n > 0) {
        buf += str;
        free(str);
    }

    // output to stderr if requested
    if (_config.options & LOG_PERROR) {
        n = write(2, buf.c_str() + offset, buf.size() - offset);
    }

    // output to the syslog socket
    int rc = write(_config.sock, buf.c_str(), buf.size());
    if (rc == -1) _syslogClose();

    // output to the console if requested
    if (_config.options & LOG_CONS) {
        if ((fd = ::open("/dev/console", O_WRONLY|O_NOCTTY, 0)) < 0) return;
        buf += "\r\n";
        const char *p = index(buf.c_str(), '>') + 1;
        n = write(fd, p, buf.size() - (p - buf.c_str()));
        ::close(fd);
    }
}

static NAN_MODULE_INIT(SyslogInit)
{
    Nan::HandleScope scope;
    NAN_EXPORT(target, open);
    NAN_EXPORT(target, send);
    NAN_EXPORT(target, close);

    // syslog facilities
    NAN_DEFINE_CONSTANT_INTEGER(target, LOG_KERN, LOG_KERN);
    NAN_DEFINE_CONSTANT_INTEGER(target, LOG_USER, LOG_USER);
    NAN_DEFINE_CONSTANT_INTEGER(target, LOG_MAIL, LOG_MAIL);
    NAN_DEFINE_CONSTANT_INTEGER(target, LOG_DAEMON, LOG_DAEMON);
    NAN_DEFINE_CONSTANT_INTEGER(target, LOG_AUTH, LOG_AUTH);
    NAN_DEFINE_CONSTANT_INTEGER(target, LOG_SYSLOG, LOG_SYSLOG);
    NAN_DEFINE_CONSTANT_INTEGER(target, LOG_LPR, LOG_LPR);
    NAN_DEFINE_CONSTANT_INTEGER(target, LOG_NEWS, LOG_NEWS);
    NAN_DEFINE_CONSTANT_INTEGER(target, LOG_UUCP, LOG_UUCP);
    NAN_DEFINE_CONSTANT_INTEGER(target, LOG_CRON,  LOG_CRON);
    NAN_DEFINE_CONSTANT_INTEGER(target, LOG_AUTHPRIV, LOG_AUTHPRIV);
    NAN_DEFINE_CONSTANT_INTEGER(target, LOG_FTP, LOG_FTP);
    NAN_DEFINE_CONSTANT_INTEGER(target, LOG_LOCAL0, LOG_LOCAL0);
    NAN_DEFINE_CONSTANT_INTEGER(target, LOG_LOCAL1, LOG_LOCAL1);
    NAN_DEFINE_CONSTANT_INTEGER(target, LOG_LOCAL2, LOG_LOCAL2);
    NAN_DEFINE_CONSTANT_INTEGER(target, LOG_LOCAL3, LOG_LOCAL3);
    NAN_DEFINE_CONSTANT_INTEGER(target, LOG_LOCAL4, LOG_LOCAL4);
    NAN_DEFINE_CONSTANT_INTEGER(target, LOG_LOCAL5, LOG_LOCAL5);
    NAN_DEFINE_CONSTANT_INTEGER(target, LOG_LOCAL6, LOG_LOCAL6);
    NAN_DEFINE_CONSTANT_INTEGER(target, LOG_LOCAL7, LOG_LOCAL7);

    // syslog options for openlog
    NAN_DEFINE_CONSTANT_INTEGER(target, LOG_PID, LOG_PID);
    NAN_DEFINE_CONSTANT_INTEGER(target, LOG_CONS, LOG_CONS);
    NAN_DEFINE_CONSTANT_INTEGER(target, LOG_ODELAY, LOG_ODELAY);
    NAN_DEFINE_CONSTANT_INTEGER(target, LOG_NDELAY, LOG_NDELAY);
    NAN_DEFINE_CONSTANT_INTEGER(target, LOG_NOWAIT, LOG_NOWAIT);
    NAN_DEFINE_CONSTANT_INTEGER(target, LOG_PERROR, LOG_PERROR);
    NAN_DEFINE_CONSTANT_INTEGER(target, LOG_RFC3339, LOG_RFC3339);

    // syslog priorities
    NAN_DEFINE_CONSTANT_INTEGER(target, LOG_EMERG, LOG_EMERG);
    NAN_DEFINE_CONSTANT_INTEGER(target, LOG_ALERT, LOG_ALERT);
    NAN_DEFINE_CONSTANT_INTEGER(target, LOG_CRIT, LOG_CRIT);
    NAN_DEFINE_CONSTANT_INTEGER(target, LOG_ERR, LOG_ERR);
    NAN_DEFINE_CONSTANT_INTEGER(target, LOG_WARNING, LOG_WARNING);
    NAN_DEFINE_CONSTANT_INTEGER(target, LOG_NOTICE, LOG_NOTICE);
    NAN_DEFINE_CONSTANT_INTEGER(target, LOG_INFO, LOG_INFO);
    NAN_DEFINE_CONSTANT_INTEGER(target, LOG_DEBUG, LOG_DEBUG);

}

NODE_MODULE(binding, SyslogInit);

}
