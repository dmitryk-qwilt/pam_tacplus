
#include "libtac.h"
#include <a/sys/aaa/manager/tacacs/libtac/logger_macro.h>
#include <a/sys/aaa/manager/tacacs/libtac/wrapper.h>
#include <a/infra/log/util/field.h>
#include <a/infra/string/to_string.h>


namespace a {
namespace sys {
namespace aaa {
namespace manager {
namespace tacacs {
namespace libtac {

#define MAX_STR_LEN 1024

#define A_NAME_MODULE_SYS_AAA_MANAGER_TACACS_LIBTAC         "sys-aaa-manager-tacacs-libtac"

#define A_NAME_GROUP_SYS_AAA_MANAGER_TACACS_LIBTAC_WRAPPER  "wrapper"
#define A_NAME_GROUP_SYS_AAA_MANAGER_TACACS_LIBTAC_INTERNAL "internal"

logCB logFunc = NULL;

int libtac_log (int lvl, const char* fmt, ...)
{
    #define MAX_LOG_MSG_SIZE 10000
    char msg[MAX_LOG_MSG_SIZE];

    va_list argptr;
    va_start(argptr, fmt);
    vsnprintf(msg, MAX_LOG_MSG_SIZE-1, fmt, argptr);

    switch (lvl)
    {
    case LOG_DEBUG:
        A_LIBTAC_LOG(kDebug3, SYS_AAA_MANAGER_TACACS_LIBTAC, INTERNAL, "libtac-log-debug", msg);
        break;
    case LOG_ERR:
        A_LIBTAC_LOG(kError, SYS_AAA_MANAGER_TACACS_LIBTAC, INTERNAL, "libtac-log-err", msg);
        break;
    default:
        A_LIBTAC_LOG(kError, SYS_AAA_MANAGER_TACACS_LIBTAC, INTERNAL, "libtac-log-bad-prio", "PROBLEM: Got an invalid lvl value: " << lvl << ". Message follows, as an error");
        A_LIBTAC_LOG(kError, SYS_AAA_MANAGER_TACACS_LIBTAC, INTERNAL, "libtac-log-bad-prio-err", msg);
    }
    
    return 0;
}

void init_logger_cb(logCB cb)
{
    logFunc = cb;
    A_LIBTAC_LOG(kDebug3, SYS_AAA_MANAGER_TACACS_LIBTAC, WRAPPER, "init-logger-cb", "called.");
}

int64_t tacw_connect_single(const std::string& serverAddr, uint16_t port, const std::string& key, incrementCounter incCB, void* pyCB)
{
    A_LIBTAC_LOG(kDebug3, SYS_AAA_MANAGER_TACACS_LIBTAC, WRAPPER, "tacw-connect-single", "called."
                 << A_LOG_UTIL_FIELD(serverAddr, "")
                 << A_LOG_UTIL_FIELD(port, "")
                 << A_LOG_UTIL_FIELD_PTR(incCB, "")
                 << A_LOG_UTIL_FIELD(pyCB, ""));
    struct addrinfo hints, *addr;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    std::string portStr = ::a::string::ToString<uint16_t>()(port);

    if (getaddrinfo(serverAddr.c_str(), portStr.c_str(), &hints, &addr) != 0)
    {
        return -1;
    }

    int64_t fd = tac_connect_single(addr, key.c_str(), NULL);

    if (fd <= 0)
    {
        A_LIBTAC_LOG(kError, SYS_AAA_MANAGER_TACACS_LIBTAC, WRAPPER, "tacw-connect-single-failed-to-connect", "tac_connect_single() failed."
                     << A_LOG_UTIL_FIELD(serverAddr, "")
                     << A_LOG_UTIL_FIELD(port, "")
                     << A_LOG_UTIL_FIELD(fd, ""));
        return -1;
    }

    A_LIBTAC_LOG(kDebug3, SYS_AAA_MANAGER_TACACS_LIBTAC, WRAPPER, "tacw-connect-single-done", "done."
                 << A_LOG_UTIL_FIELD(serverAddr, "")
                 << A_LOG_UTIL_FIELD(port, "")
                 << A_LOG_UTIL_FIELD(fd, ""));
    return fd;
}

void tacw_connection_close(int64_t fd, incrementCounter incCB, void* pyCB)
{
    A_LIBTAC_LOG(kDebug3, SYS_AAA_MANAGER_TACACS_LIBTAC, WRAPPER, "tacw-connection-close", "called."
                 << A_LOG_UTIL_FIELD(fd, "")
                 << A_LOG_UTIL_FIELD_PTR(incCB, "")
                 << A_LOG_UTIL_FIELD(pyCB, ""));
    shutdown(fd, SHUT_RDWR);
    close(fd);
    A_LIBTAC_LOG(kDebug3, SYS_AAA_MANAGER_TACACS_LIBTAC, WRAPPER, "tacw-connection-close-done", "done."
                 << A_LOG_UTIL_FIELD(fd, ""));
}

int getVer(int* val)
{
    *val = 10;
    return 5;
}

int64_t test_callback(int64_t x, void* pyCB, multiplyCB cb)
{
    return cb(x, pyCB);
}

int64_t test_logCallback(int64_t x)
{
    A_LIBTAC_LOG(kDebug, SYS_AAA_MANAGER_TACACS_LIBTAC, WRAPPER, "test-log-callback", "called.");
    return x*2;
}

int64_t tacw_authen_send(int64_t fd, const std::string& user, const std::string& pass, const std::string& tty, const std::string& r_addr, incrementCounter incCB, void* pyCB)
{
    A_LIBTAC_LOG(kDebug3, SYS_AAA_MANAGER_TACACS_LIBTAC, WRAPPER, "tacw-authen-send", "called" 
                 << A_LOG_UTIL_FIELD(user, "")
                 << A_LOG_UTIL_FIELD(r_addr, "")
                 << A_LOG_UTIL_FIELD_PTR(incCB, "")
                 << A_LOG_UTIL_FIELD(pyCB, ""));
    char sUser[MAX_STR_LEN] = "";
    char sPass[MAX_STR_LEN] = "";
    char sTty[MAX_STR_LEN] = "";
    char sRAddr[MAX_STR_LEN] = "";
    strncat(sUser, user.c_str(), MAX_STR_LEN-1);
    strncat(sPass, pass.c_str(), MAX_STR_LEN-1);
    strncat(sTty, tty.c_str(), MAX_STR_LEN-1);
    strncat(sRAddr, r_addr.c_str(), MAX_STR_LEN-1);
    int64_t res = tac_authen_send(fd, sUser, sPass, sTty, sRAddr);
    A_LIBTAC_LOG(kDebug3, SYS_AAA_MANAGER_TACACS_LIBTAC, WRAPPER, "tacw-authen-send-done", "done" 
                 << A_LOG_UTIL_FIELD(user, "")
                 << A_LOG_UTIL_FIELD(r_addr, "")
                 << A_LOG_UTIL_FIELD(res, ""));
    return res;
}

int64_t tacw_authen_read(int64_t fd, incrementCounter incCB, void* pyCB)
{
    A_LIBTAC_LOG(kDebug3, SYS_AAA_MANAGER_TACACS_LIBTAC, WRAPPER, "tacw-authen-read", "called."
                 << A_LOG_UTIL_FIELD(fd, "")
                 << A_LOG_UTIL_FIELD_PTR(incCB, "")
                 << A_LOG_UTIL_FIELD(pyCB, ""));
    int64_t res = tac_authen_read(fd);
    return res;
    A_LIBTAC_LOG(kDebug3, SYS_AAA_MANAGER_TACACS_LIBTAC, WRAPPER, "tacw-authen-read-done", "done."
                 << A_LOG_UTIL_FIELD(fd, "")
                 << A_LOG_UTIL_FIELD(res, ""));
}

int64_t tacw_cont_send(int64_t fd, const std::string& pass, incrementCounter incCB, void* pyCB)
{
    A_LIBTAC_LOG(kDebug3, SYS_AAA_MANAGER_TACACS_LIBTAC, WRAPPER, "tacw-cont-send", "called."
                 << A_LOG_UTIL_FIELD(fd, "")
                 << A_LOG_UTIL_FIELD_PTR(incCB, "")
                 << A_LOG_UTIL_FIELD(pyCB, ""));
    char sPass[MAX_STR_LEN] = "";
    strncat(sPass, pass.c_str(), MAX_STR_LEN-1);
    int64_t res = tac_cont_send(fd, sPass);
    A_LIBTAC_LOG(kDebug3, SYS_AAA_MANAGER_TACACS_LIBTAC, WRAPPER, "tacw-cont-send-done", "done."
                 << A_LOG_UTIL_FIELD(fd, "")
                 << A_LOG_UTIL_FIELD(res, ""));
    return res;
}

int64_t tacw_author_send_authorization_request(int64_t fd, const std::string& user, const std::string& r_addr, incrementCounter incCB, void* pyCB)
{
    A_LIBTAC_LOG(kDebug3, SYS_AAA_MANAGER_TACACS_LIBTAC, WRAPPER, "tacw-author-send-authorization-request", "called."
                 << A_LOG_UTIL_FIELD(fd, "")
                 << A_LOG_UTIL_FIELD(user, "")
                 << A_LOG_UTIL_FIELD(r_addr, "")
                 << A_LOG_UTIL_FIELD_PTR(incCB, "")
                 << A_LOG_UTIL_FIELD(pyCB, ""));

    struct tac_attrib *attr = NULL;
    char attr1[] = "service";
    char attr1Val[] = "shell";
    char attr2[] = "cmd";
    tac_add_attrib(&attr, attr1, attr1Val);
    tac_add_attrib_pair(&attr, attr2, '*', NULL);

    char terminal[] = "";
    char hostname[MAX_STR_LEN] = "";
    strncat(hostname, r_addr.c_str(), MAX_STR_LEN-1);
    int64_t res = tac_author_send(fd, user.c_str(), terminal, hostname, attr);
    if (res != 0)
    {
        A_LIBTAC_LOG(kError, SYS_AAA_MANAGER_TACACS_LIBTAC, WRAPPER, "tacw-author-send-authorization-request-send-failed", "tac_author_send() failed."
                     << A_LOG_UTIL_FIELD(res, "")
                     << A_LOG_UTIL_FIELD(fd, "")
                     << A_LOG_UTIL_FIELD(user, "")
                     << A_LOG_UTIL_FIELD(r_addr, ""));
        return -1;
    }
    

    tac_free_attrib(&attr);

    A_LIBTAC_LOG(kDebug3, SYS_AAA_MANAGER_TACACS_LIBTAC, WRAPPER, "tacw-author-send-authorization-request-done", "done."
                 << A_LOG_UTIL_FIELD(fd, "")
                 << A_LOG_UTIL_FIELD(user, "")
                 << A_LOG_UTIL_FIELD(r_addr, ""));
    return 0;
}

int64_t tacw_author_read_authorization_response(int64_t fd, int* success, int64_t* priv_lvl, std::string* groups, incrementCounter incCB, void* pyCB)
{
    A_LIBTAC_LOG(kDebug3, SYS_AAA_MANAGER_TACACS_LIBTAC, WRAPPER, "tacw-author-read-authorization-response", "called."
                 << A_LOG_UTIL_FIELD(fd, "")
                 << A_LOG_UTIL_FIELD_PTR(incCB, "")
                 << A_LOG_UTIL_FIELD(pyCB, ""));
    *priv_lvl = -1;
    struct areply arep;
    int64_t res = tac_author_read(fd, &arep);

    std::string counterName = "";
    switch (arep.status)
    {
        case TAC_PLUS_AUTHOR_STATUS_PASS_ADD:
            counterName = "authorization-response-pass-add";
            break;
        case TAC_PLUS_AUTHOR_STATUS_PASS_REPL:
            counterName = "authorization-response-pass-repl";
            break;
        case TAC_PLUS_AUTHOR_STATUS_FAIL:
            counterName = "authorization-response-fail";
            break;
        case TAC_PLUS_AUTHOR_STATUS_ERROR:
            counterName = "authorization-response-error";
            break;
        case TAC_PLUS_AUTHOR_STATUS_FOLLOW:
            counterName = "authorization-response-follow";
            break;
    }
    if (pyCB)
    {
        if (counterName.length())
        {
            if (incCB(counterName, 1, pyCB) != 0)
            {
                A_LIBTAC_LOG(kError, SYS_AAA_MANAGER_TACACS_LIBTAC, WRAPPER, "tacw-author-read-authorization-response-failed-to-increase-counter", "incCB(counterName) failed."
                             << A_LOG_UTIL_FIELD(counterName, "")
                             << A_LOG_UTIL_FIELD(fd, ""));
                // do not return an error, we can still work even if the counter was not updated
            }
        }
    }
    if(arep.status != AUTHOR_STATUS_PASS_ADD && arep.status != AUTHOR_STATUS_PASS_REPL)
    {
        A_LIBTAC_LOG(kNotice, SYS_AAA_MANAGER_TACACS_LIBTAC, WRAPPER, "tacw-author-read-authorization-response-auth-failure", "tac_author_read() return error status."
                     << A_LOG_UTIL_FIELD(res, "")
                     << A_LOG_UTIL_FIELD(fd, ""));
        if(arep.msg != NULL)
        {
            free (arep.msg);
        }
        *success = false;
    }
    else
    {
        A_LIBTAC_LOG(kDebug3, SYS_AAA_MANAGER_TACACS_LIBTAC, WRAPPER, "tacw-author-read-authorization-response-auth-success", "tac_author_read() returned success status."
                     << A_LOG_UTIL_FIELD(res, "")
                     << A_LOG_UTIL_FIELD(fd, ""));
        *success = true;
        struct tac_attrib *attr = arep.attr;
        while (attr != NULL)
        {
            A_LIBTAC_LOG(kDebug3, SYS_AAA_MANAGER_TACACS_LIBTAC, WRAPPER, "tacw-author-read-authorization-response-attrib", "attribute"
                         << A_LOG_UTIL_FIELD(attr->attr, "")
                         << A_LOG_UTIL_FIELD(fd, ""));
            char attribute[attr->attr_len];
            char value[attr->attr_len];
            char *sep;

            sep = index(attr->attr, '=');
            if(sep == NULL)
                sep = index(attr->attr, '*');
            if (sep == (char*)NULL)
            {
                // format error
                *success = false;
                return -1;
            }
            bcopy(attr->attr, attribute, attr->attr_len-strlen(sep));
            attribute[attr->attr_len-strlen(sep)] = '\0';
            bcopy(sep+1, value, strlen(sep)-1);
            value[strlen(sep)-1] = '\0';

            size_t i;
            for (i = 0; attribute[i] != '\0'; i++)
            {
                attribute[i] = tolower(attribute[i]);
                if (attribute[i] == '-')
                    attribute[i] = '_';
            }

            if (!strncmp(attribute, "priv_lvl", strlen("priv_lvl")))
            {
                *priv_lvl = atoi(value);
            }
            else if (!strncmp(attribute, "task", strlen("task")))
            {
                *groups = value;
            }
            attr = attr->next;
        }
    }
    A_LIBTAC_LOG(kDebug3, SYS_AAA_MANAGER_TACACS_LIBTAC, WRAPPER, "tacw-author-read-authorization-response-done", "done."
                 << A_LOG_UTIL_FIELD(*success, "")
                 << A_LOG_UTIL_FIELD(*priv_lvl, "")
                 << A_LOG_UTIL_FIELD(fd, ""));
    return 0;
}

// constants
int64_t _TAC_PLUS_AUTHEN_STATUS_PASS = TAC_PLUS_AUTHEN_STATUS_PASS;
int64_t _TAC_PLUS_AUTHEN_STATUS_FAIL = TAC_PLUS_AUTHEN_STATUS_FAIL;
int64_t _TAC_PLUS_AUTHEN_STATUS_GETDATA = TAC_PLUS_AUTHEN_STATUS_GETDATA;
int64_t _TAC_PLUS_AUTHEN_STATUS_GETUSER = TAC_PLUS_AUTHEN_STATUS_GETUSER;
int64_t _TAC_PLUS_AUTHEN_STATUS_GETPASS = TAC_PLUS_AUTHEN_STATUS_GETPASS;
int64_t _TAC_PLUS_AUTHEN_STATUS_RESTART = TAC_PLUS_AUTHEN_STATUS_RESTART;
int64_t _TAC_PLUS_AUTHEN_STATUS_ERROR = TAC_PLUS_AUTHEN_STATUS_ERROR;
int64_t _TAC_PLUS_AUTHEN_STATUS_FOLLOW = TAC_PLUS_AUTHEN_STATUS_FOLLOW;


}}}}}} // namespace

