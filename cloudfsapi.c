#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/stat.h>
#ifdef __linux__
#include <alloca.h>
#endif
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/time.h>
#include <libxml/tree.h>
#include "cloudfsapi.h"
#include "config.h"

#define RHEL5_LIBCURL_VERSION 462597
#define RHEL5_CERTIFICATE_FILE "/etc/pki/tls/certs/ca-bundle.crt"

#define REQUEST_RETRIES 4

static int _debug_mem_ = 0;
static int _dir_entries_cnt_ = 0;

static char storage_url[MAX_URL_SIZE];
static char storage_token[MAX_HEADER_SIZE];

static pthread_mutex_t curl_pool_mut;
static CURL *curl_pool[MAX_CNT_CURL_POOL];
static int curl_pool_count = 0;

#define MAX_CNT_DE_POOL (1024)
static pthread_mutex_t de_pool_mut;
static dir_entry *de_pool[MAX_CNT_DE_POOL] = {NULL,};
static int de_pool_count = 0;

//static int __cloudfs_debug__ = 0;
static int verify_ssl = 1;
static int rhel5_mode = 0;

struct debug_hander_t debughander = {
    .stream = NULL,
};

#ifdef HAVE_OPENSSL
#include <openssl/crypto.h>
static pthread_mutex_t *ssl_lockarray;
static void lock_callback(int mode, int type, char *file, int line)
{
    if (mode & CRYPTO_LOCK)
        pthread_mutex_lock(&(ssl_lockarray[type]));
    else
        pthread_mutex_unlock(&(ssl_lockarray[type]));
}

static unsigned long thread_id()
{
    return (unsigned long)pthread_self();
}
#endif

static void rewrite_url_snet(char *url)
{
    char protocol[MAX_URL_SIZE];
    char rest[MAX_URL_SIZE];
    sscanf(url, "%[a-z]://%s", protocol, rest);
    if (strncasecmp(rest, "snet-", 5))
        sprintf(url, "%s://snet-%s", protocol, rest);
}

static size_t octet_upload(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    int ret;
    size_t remnant;
    size_t cnt;
    const char *buf;
    struct putObjectContext *poc = (struct putObjectContext *)userdata;

    cnt = size * nmemb; 
    if (cnt <= 0 ) {
        debugf("Error, octet_upload, size*nmemb = 0, poc: bufsize=%d, buf=%s ", size*nmemb, poc->buf_size, (poc->buf)?"not-null":"null");
        if((ret = sem_post(&(poc->pot->can_write))) < 0) {
            debugf("Error, octet_upload, sem_post can_write");
        }
        return 0;
    }

again_wait:
    if (is_debug())
        debugf("---> octet_upload, sem_wait(can_cloud)");
    if ((ret = sem_wait(&(poc->pot->can_cloud))) < 0) {
        if(errno == EINTR)
            goto again_wait;

        debugf("Error, sem_wait can_cloud");
        return 0;
    }

    pthread_mutex_lock(&(poc->pot->lock));
    if(poc->buf_size == 0 || poc->buf == NULL) {
        /*Okay, all is OVER!*/

        poc->isOkay = 1;

        pthread_mutex_unlock(&(poc->pot->lock));

        if((ret = sem_post(&(poc->pot->write_can_return))) < 0) {
            debugf("Error, octet_upload, sem_post write_can_return");
        }
        if((ret = sem_post(&(poc->pot->can_cloud))) < 0) {
            debugf("Error, octet_upload, sem_post can_cloud");
        }
        if((ret = sem_post(&(poc->pot->can_write))) < 0) {
            debugf("Error, octet_upload, sem_post can_write");
        }
        if((ret = sem_post(&(poc->pot->can_release))) < 0) {
            debugf("Error, octet_upload, sem_post can_release");
        }

        if (is_debug())
            debugf("---> octet_upload, poc->buf_size is 0, return 0");
        return 0;
    }

    remnant = poc->buf_size - poc->current_off;
    if(remnant <= 0) {
        /*write 系统调用挂上来的那个 buf 全部都上传到了cloud中，继续等待下一个write挂buf */

        poc->isOkay = 1;

        pthread_mutex_unlock(&(poc->pot->lock));

        if((ret = sem_post(&(poc->pot->write_can_return))) < 0) {
            debugf("Error, octet_upload, sem_post write_can_return");
        }

        if((ret = sem_post(&(poc->pot->can_write))) < 0) {
            debugf("Error, sem_post can_write");
        }

        if (is_debug())
            debugf("---> octet_upload, %ld/%ld, wait next write-systemcal...", poc->buf_size, poc->put_cnt);
        goto again_wait;
    }

    /*write 系统调用挂上来的那个 buf 还没有全部上传到 cloud，
     *继续上传这个 buf 中的下一片段, 为此，必须调用 sem_post(&can_cloud) */
    buf = poc->buf + poc->current_off;
    if (cnt > remnant) 
        cnt = remnant; 
    memcpy(ptr, buf, cnt);
    poc->put_cnt += cnt;
    poc->current_off += cnt;

    pthread_mutex_unlock(&(poc->pot->lock));
    if (is_debug())
        debugf("---> octet_upload, move bytes %ld/%ld to cloud", cnt, poc->buf_size);

    if((ret = sem_post(&(poc->pot->can_cloud))) < 0) {
        debugf("Error, octet_upload, sem_post can_cloud");
        cnt = 0;
    }

    return cnt;
}

static size_t octet_download(void *ptr, size_t size, size_t nmemb, void *stream)
{
  size_t bufsize;
  size_t cnt;
  char *buf;
  struct getObjectContext *goc = (struct getObjectContext *)stream;

  bufsize = goc->buf_size;
  buf = goc->buf + goc->current_off;
  cnt = size * nmemb;
  
  if(cnt > bufsize) {
    if (is_debug())
        debugf("octet_download, truncate bytes %d - %d", cnt, bufsize);
    cnt = bufsize; 
  }

  memcpy(buf, ptr, cnt);
  goc->got_cnt += cnt;
  goc->current_off += cnt;

  if (is_debug())
      debugf("<--- octet_download, move bytes %d to user", cnt);
  
  return cnt;
}

static size_t parse_header(void *ptr, size_t size, size_t nmemb, void *data)
{
    char *p = NULL;
    dir_entry *de = (dir_entry *)data;

    static const char *p_http = "HTTP/1.1";
    static const char *p_lm = "Last-Modified:";
    static const char *p_ct = "Content-Type:";
    static const char *p_cl = "Content-Length:";
    static const char *p_xcoc = "X-Container-Object-Count:";
    static const char *p_xcbu = "X-Container-Bytes-Used:";

    if (size * nmemb <= 2 || !ptr) { /*strlen("\r\n") = 2*/
        return size * nmemb;
    }

    if (size * nmemb > 2)
        ((char *)ptr)[size * nmemb - 2] = '\0';

    /*if(is_debug())
        debugf("---parse_header: %s, size: %d, nmemb: %d", (char *)ptr, size, nmemb);*/

    if (!strncasecmp(ptr, p_http, strlen(p_http))) {
        int response;
        char *endptr;
        p = ptr + strlen(p_http);
        while (*p == ' ')
            p++;
        errno = 0;
        response = strtol(p, &endptr, 10);
        if ((errno == ERANGE && (response == LONG_MAX || response == LONG_MIN)) 
            || (errno != 0 && response == 0)) {
               debugf("Error, strtol, %s", strerror(errno));
        }

        if (endptr == p) {
           debugf("Error, strtol, No digits were found");
        }
        /*if(is_debug())
            debugf("------get response: %d", response);*/
        if (!(response >= 200 && response < 400)) {
            return (size * nmemb);
        }
        
    }else if (!strncasecmp(ptr, p_lm, strlen(p_lm))) {
        struct tm last_modified;
        p = ptr + strlen(p_lm);
        while (*p == ' ')
            p++;
        strptime(p, "%a, %d %b %Y %T", &last_modified);
        de->last_modified = mktime(&last_modified);
        if(is_debug())
            debugf("------get last_modified: %ld", de->last_modified);
    }else if (!strncasecmp(ptr, p_ct, strlen(p_ct))) {
        char *semicolon = NULL;
        p = ptr + strlen(p_ct);
        while (*p == ' ')
            p++;
        semicolon = strchr(p, ';');
        if (semicolon)
          *semicolon = '\0';
        if (de->content_type) {
            debugf("Error, de->content_type is NOT NULL");
            free(de->content_type);
        }
        de->content_type = strdup(p); 
        if (de->isdir == 0) {
            de->isdir = de->content_type && 
                        ((strstr(de->content_type, "application/folder") != NULL) || 
                         (strstr(de->content_type, "application/directory") != NULL));
        }
        /*if(is_debug()) 
            debugf("------get content-type: %s, isdir: %d", de->content_type ? de->content_type : "NULL", de->isdir);*/

    }else if (!strncasecmp(ptr, p_xcoc, strlen(p_xcoc))) {
        p = ptr + strlen(p_ct);
        while (*p == ' ')
            p++;
        de->isdir = 1; 
        /*if(is_debug())
            debugf("------get X-Container-Object-Count: %s, isdir: %d", p, de->isdir);*/

    }else if (!strncasecmp(ptr, p_cl, strlen(p_cl))) {
        char *endptr;
        p = ptr + strlen(p_cl);
        while (*p == ' ' )
            p++;
        errno = 0;
        de->size = strtol(p, &endptr, 10);
        if ((errno == ERANGE && (de->size == LONG_MAX || de->size == LONG_MIN)) 
            || (errno != 0 && de->size == 0)) {
               debugf("Error, strtol, %s", strerror(errno));
        }

        if (endptr == p) {
           debugf("Error, strtol, No digits were found\n");
        }
        /*if(is_debug())
            debugf("------yes, get content-length: %d", de->size);*/
    } 
    
    return (size * nmemb);
}

static size_t xml_dispatch(void *ptr, size_t size, size_t nmemb, void *stream)
{
    xmlParseChunk((xmlParserCtxtPtr)stream, (char *)ptr, size * nmemb, 0);
    return size * nmemb;
}

static CURL *get_connection(const char *path)
{
    CURL *curl = NULL;

    pthread_mutex_lock(&curl_pool_mut);
    if (curl_pool_count > 0) 
        curl = curl_pool[--curl_pool_count];
    pthread_mutex_unlock(&curl_pool_mut);

    if (curl == NULL) 
        curl = curl_easy_init();
  
    if (curl == NULL) 
        debugf("Error, curl alloc failed");

    return curl;
}

static void return_connection(CURL *curl)
{
    pthread_mutex_lock(&curl_pool_mut);

    if (curl_pool_count >= MAX_CNT_CURL_POOL)
        curl_easy_cleanup(curl);
    else
        curl_pool[curl_pool_count++] = curl;
  
    pthread_mutex_unlock(&curl_pool_mut);
}

static void add_header(curl_slist **headers, const char *name, const char *value)
{
    char x_header[MAX_HEADER_SIZE];
    snprintf(x_header, sizeof(x_header), "%s: %s", name, value);
    *headers = curl_slist_append(*headers, x_header);
}

static int send_getfile_request(char *method, const char *path, struct getObjectContext *gocptr, curl_slist *extra_headers)
{
    CURLcode res;
    char url[MAX_URL_SIZE];
    char *slash;
    long response = -1;
    int tries = 0;
    curl_slist *extra;

    if (!storage_url[0]) {
        debugf("Error, send_request with no storage_url?");
        abort();
    }

    if(gocptr == NULL || gocptr->buf == NULL) {
        debugf("send_getfile_request, but user buf is NULL");
        return response; 
    }

    while ((slash = strstr(path, "%2F")) || (slash = strstr(path, "%2f"))) {
        *slash = '/';
        memmove(slash+1, slash+3, strlen(slash+3)+1);
    }

    while (*path == '/')
        path++;

    snprintf(url, sizeof(url), "%s/%s", storage_url, path);

    for (tries = 0; tries < REQUEST_RETRIES; tries++) {
        CURL *curl = get_connection(path);
        if (!curl) {
            sleep(1 << (tries+1)); 
            continue;
        }
        if (rhel5_mode)
            curl_easy_setopt(curl, CURLOPT_CAINFO, RHEL5_CERTIFICATE_FILE);
        curl_slist *headers = NULL;
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_HEADER, 0);
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
        curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, USER_AGENT);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, verify_ssl);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10);
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
        add_header(&headers, "X-Auth-Token", storage_token);

        curl_easy_setopt(curl, CURLOPT_WRITEDATA, gocptr);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &octet_download);

        /* add the headers from extra_headers if any */
        if (extra_headers) {
            for (extra = extra_headers; extra; extra = extra->next) {
                if (is_debug())
                    debugf("adding header: %s", extra->data);
                headers = curl_slist_append(headers, extra->data);
            }
        }
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        res = curl_easy_perform(curl);
        if (CURLE_OK != res) {
            debugf("Error, curl_easy_perform, %s", strerror(res));
            response = -1;
            curl_slist_free_all(headers);
            curl_easy_reset(curl);
            return_connection(curl);
            continue;
        }

        res = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response);
        if (CURLE_OK != res) {
            debugf("Error, curl_easy_getinfo, %s", strerror(res));
            response = -1;
            curl_slist_free_all(headers);
            curl_easy_reset(curl);
            return_connection(curl);
            continue;
        }
        curl_slist_free_all(headers);
        curl_easy_reset(curl);
        return_connection(curl);
        if (response >= 200 && response < 400)
            return response;
        sleep(1 << (tries+1)); 
        if (response == 401 && !cloudfs_connect()) {
            /*re-authenticate on 401s */
            return response;
        }
    }
    return response;
}

struct getObjectContext* get_getObjectContext(void)
{
    struct getObjectContext* goc; 

    goc = (struct getObjectContext *)malloc(sizeof(struct getObjectContext));
    if(!goc)
        return NULL;

    goc->buf_size = -1;
    goc->buf = NULL;
    goc->got_cnt = 0;
    goc->current_off = 0;

    if (_debug_mem_)
        debugf("+++memory info allo @%ld, get_getObjectContext", (unsigned long int)goc);

    return goc;
}

struct putObjTask * get_putObjectTask_entry(void)
{
    struct putObjTask *pot = NULL;
    pot = (struct putObjTask *)malloc(sizeof(struct putObjTask));
    if (NULL == pot)
        return NULL;

    if(pthread_mutex_init(&pot->lock, NULL) != 0) {
        free(pot);
        return NULL;
    }

    if(sem_init(&pot->can_cloud, 0, 0) < 0) {
        pthread_mutex_destroy(&pot->lock);
        free(pot);
        return NULL;
    }

    if(sem_init(&pot->can_write, 0, 1) < 0) {
        pthread_mutex_destroy(&pot->lock);
        sem_destroy(&pot->can_cloud);
        free(pot);
        return NULL;
    }

    if(sem_init(&pot->write_can_return, 0, 0) < 0) {
        pthread_mutex_destroy(&pot->lock);
        sem_destroy(&pot->can_cloud);
        sem_destroy(&pot->can_write);
        free(pot);
        return NULL;
    }

    if(sem_init(&pot->can_release, 0, 0) < 0) {
        pthread_mutex_destroy(&pot->lock);
        sem_destroy(&pot->can_cloud);
        sem_destroy(&pot->can_write);
        sem_destroy(&pot->write_can_return);
        free(pot);
        return NULL;
    }

    pot->tid = (pthread_t)-1;

    if (_debug_mem_)
        debugf("+++memory info allo @%ld, get_putObjectTask_entry", (unsigned long int)pot);
    
    return pot;
}

struct putObjectContext* get_putObjectContext(void)
{ 
    struct putObjectContext* poc;
    poc = (struct putObjectContext *)malloc(sizeof(struct putObjectContext));
    if(!poc) 
        return NULL; 

    poc->curl = NULL;
    poc->isOkay = 0;
    poc->flags = 0;
    poc->path = NULL;
    poc->buf_size = 0;
    poc->buf = NULL;
    poc->put_cnt = 0;
    poc->current_off = 0;
    poc->pot = NULL;

    if (_debug_mem_)
        debugf("+++memory info allo @%ld, get_putObjectContext", (unsigned long int)poc);

    return poc;
}

int reset_read_buffer(struct read_buffer* rbuf, int clean_flag)
{
    if (!rbuf || !rbuf->enable)
        return 0;

    if (NULL == rbuf->buffer) {
        if ((rbuf->buffer = (char *)malloc(sizeof(char) * MAX_READBUFFER_SIZE)) == NULL) {
            rbuf->enable = 0;
            return 0;
        }
    }
    memset(rbuf->buffer, 0, (sizeof(char) * MAX_READBUFFER_SIZE));

    rbuf->enable = 1;
    rbuf->buf_len = 0;
    rbuf->offset = 0;
    if (clean_flag && READBUFFER_CLEAN_RCNT)
        rbuf->rcnt = 0;

    return 1;    
}

struct openfile* get_openfile(void)
{
    struct openfile *of;
    of = (struct openfile *)malloc(sizeof(struct openfile));
    if (of == NULL)
        return NULL;

    of->open_for = OPENFILE_FOR_UNKNOWN;
    of->obj_size = 0;

    of->rbuf.enable = 1;
    of->rbuf.buf_len = 0;
    of->rbuf.buffer = NULL;

    of->goc = NULL;
    of->poc = NULL;

    if (_debug_mem_)
        debugf("+++memory info allo @%ld, get_openfile", (unsigned long int)of);

    return of;
}

void destroy_getObjectContext(struct getObjectContext *goc)
{
    if (_debug_mem_)
        debugf("---memory info free @%ld, destroy_getObjectContext", goc ? (unsigned long int)goc  : 0);

    if(!goc)
        return;

    free(goc);
    return;
}

void destroy_putObjTask_entry(struct putObjTask *pot)
{
    if (_debug_mem_)
        debugf("---memory info free @%ld, destroy_putObjectTask_entry", pot ? (unsigned long int)pot  : 0);

    if(pot == NULL)
        return;

    pthread_mutex_destroy(&pot->lock);
    sem_destroy(&pot->can_cloud);
    sem_destroy(&pot->can_write);
    sem_destroy(&pot->write_can_return);
    sem_destroy(&pot->can_release);
    free(pot);
    return;
}

void destroy_putObjectContext(struct putObjectContext *poc)
{
    struct putObjTask *pot;

    if (_debug_mem_)
        debugf("---memory info free @%ld, destroy_putObjectContext", poc ? (unsigned long int)poc : 0);

    if(poc == NULL)
        return;
    if(poc->path != NULL)
        free(poc->path);

    pot = poc->pot;
    destroy_putObjTask_entry(pot);
    poc->pot = NULL;

    free(poc);
    return;
}

void destroy_openfile(struct openfile *of)
{
    struct putObjTask *pot;
    struct putObjectContext *poc;

    if (_debug_mem_)
        debugf("---memory info free @%ld, destroy_openfile", of ? (unsigned long int)of : 0);

    if (of == NULL)
        return;

    if (of->poc)
        destroy_putObjectContext(of->poc);
    if (of->goc)
        destroy_getObjectContext(of->goc);

    if (of->rbuf.buffer)
        free(of->rbuf.buffer);
 
    of->poc = NULL;
    of->goc = NULL;
    free(of);

    return;
}

void* send_putfile_request(void *args)
{
    int debug = 0;
    CURLcode res;
    char url[MAX_URL_SIZE];
    char *slash;
    long response = -1;
    int tries = 0;
    int ret = 0;
    off_t retval = 0;
    char *path;
    struct putObjectContext *poc = (struct putObjectContext *)args;

    path = poc->path;

    if (!storage_url[0]) {
        debugf("Error, send_putfile_request with no storage_url?");
        abort();
    }

    while ((slash = strstr(path, "%2F")) || (slash = strstr(path, "%2f"))) {
        *slash = '/';
        memmove(slash+1, slash+3, strlen(slash+3)+1);
    }
    while (*path == '/')
        path++;

    snprintf(url, sizeof(url), "%s/%s", storage_url, path);

    CURL *curl = get_connection(path);
    if(!curl) {
        debugf("Error, send_putfile_request failed, get_connection NULL");
        return (void *)retval;
    }

    if (rhel5_mode)
      curl_easy_setopt(curl, CURLOPT_CAINFO, RHEL5_CERTIFICATE_FILE);
    curl_slist *headers = NULL;
    poc->curl = curl;
    /*curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);*/
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HEADER, 0);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, USER_AGENT);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, verify_ssl);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, debug);
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1);
    curl_easy_setopt(curl, CURLOPT_READDATA, poc);
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, &octet_upload);

    add_header(&headers, "X-Auth-Token", storage_token);
    add_header(&headers, "Transfer-Encoding", "chunked");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    res = curl_easy_perform(curl);
    if (CURLE_OK != res) {
        response = -1;
        debugf("Error, curl_easy_perform, %s", strerror(res));
        goto out;
    }

    res = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response);
    if (CURLE_OK != res) {
        debugf("Error, curl_easy_getinfo, %s", strerror(res));
    }

out:
    curl_slist_free_all(headers);
    curl_easy_reset(curl);
    return_connection(curl);

    if (response >= 200 && response < 400) { 
        retval = poc->put_cnt;    
        return (void *)retval;
    }

    if (response == 401) 
        cloudfs_connect();

    debugf("Error send_putfile_request exited with response %d", response);

    return (void *)retval;
}


static int send_request(char *method, const char *path, FILE *fp, xmlParserCtxtPtr xmlctx, dir_entry *de, curl_slist *extra_headers, int retries) 
{
    int debug = 0;
    char url[MAX_URL_SIZE];
    char *slash;
    long response = -1;
    int tries = 0;
    CURLcode res;

    if (!storage_url[0]) {
        debugf("send_request with no storage_url?");
        abort();
    }

    while ((slash = strstr(path, "%2F")) || (slash = strstr(path, "%2f"))) {
        *slash = '/';
        memmove(slash+1, slash+3, strlen(slash+3)+1);
    }

    while (*path == '/')
        path++;

    snprintf(url, sizeof(url), "%s/%s", storage_url, path);
  
    if (retries < 0 )
        retries = 0; 

    if (retries > REQUEST_RETRIES) 
        retries = REQUEST_RETRIES;

    do {
        CURL *curl = get_connection(path);
        if (!curl) {
            if (retries > 0 ) 
                sleep(1 << tries); 
            continue;
        }
        if (rhel5_mode)
            curl_easy_setopt(curl, CURLOPT_CAINFO, RHEL5_CERTIFICATE_FILE);
        curl_slist *headers = NULL;
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_HEADER, 0);
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
        curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, USER_AGENT);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, verify_ssl);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 2/*10*/);
        curl_easy_setopt(curl, CURLOPT_VERBOSE, debug);
        add_header(&headers, "X-Auth-Token", storage_token);
        if (!strcasecmp(method, "MKDIR")) {
            curl_easy_setopt(curl, CURLOPT_UPLOAD, 1);
            curl_easy_setopt(curl, CURLOPT_INFILESIZE, 0);
            add_header(&headers, "Content-Type", "application/directory");
        }
        else if (!strcasecmp(method, "GET")) {
            if (fp) {
                rewind(fp);
                fflush(fp);
                if (ftruncate(fileno(fp), 0) < 0) {
                    debugf("Error, ftruncate failed.  I don't know what to do about that.");
                    abort();
                }
                curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
            } else if (xmlctx) {
                curl_easy_setopt(curl, CURLOPT_WRITEDATA, xmlctx);
                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &xml_dispatch);
            }
        }
        else if (!strcasecmp(method, "HEAD")) {
            if (de) {
                curl_easy_setopt(curl, CURLOPT_NOBODY, 1);
                curl_easy_setopt(curl, CURLOPT_WRITEHEADER, de);
                curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, &parse_header);
            }
        }
        else
            curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);

        /* add the headers from extra_headers if any */
        curl_slist *extra;
        for (extra = extra_headers; extra; extra = extra->next) {
            headers = curl_slist_append(headers, extra->data);
        }
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        res = curl_easy_perform(curl);
        if (CURLE_OK != res) {
            debugf("Error, curl_easy_perform, %s", strerror(res));
        }
        res = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response);
        if (CURLE_OK != res) {
            response = -1;
            debugf("Error, curl_easy_getinfo, %s", strerror(res));
        }
        curl_slist_free_all(headers);
        curl_easy_reset(curl);
        return_connection(curl);
        if (response >= 200 && response < 400)
            return response;
        if (retries > 0 )
            sleep(1 << tries); 
        if (response == 401 && !cloudfs_connect()) 
            return response;
        if (xmlctx)
            xmlCtxtResetPush(xmlctx, NULL, 0, NULL, NULL);

    } while (++tries < retries);

    return response;
}

static size_t header_dispatch(void *ptr, size_t size, size_t nmemb, void *stream)
{
    char *header = (char *)alloca(size * nmemb + 1);
    char *head = (char *)alloca(size * nmemb + 1);
    char *value = (char *)alloca(size * nmemb + 1);

    memcpy(header, (char *)ptr, size * nmemb);
    header[size * nmemb] = '\0';
    if (sscanf(header, "%[^:]: %[^\r\n]", head, value) == 2) {
        if (!strncasecmp(head, "x-auth-token", size * nmemb))
            strncpy(storage_token, value, sizeof(storage_token));
        if (!strncasecmp(head, "x-storage-url", size * nmemb))
            strncpy(storage_url, value, sizeof(storage_url));
    }

    return size * nmemb;
}

/*
 * Public interface
 */
void cloudfs_init()
{
    int i;
    LIBXML_TEST_VERSION
    curl_global_init(CURL_GLOBAL_ALL);
    pthread_mutex_init(&curl_pool_mut, NULL);
    curl_version_info_data *cvid = curl_version_info(CURLVERSION_NOW);

    /* CentOS/RHEL 5 get stupid mode, because they have a broken libcurl*/
    if (cvid->version_num == RHEL5_LIBCURL_VERSION) {
        debugf("RHEL5 mode enabled.");
        rhel5_mode = 1;
    }

    if (!strncasecmp(cvid->ssl_version, "openssl", 7)) {
#ifdef HAVE_OPENSSL
        ssl_lockarray = (pthread_mutex_t *)OPENSSL_malloc(CRYPTO_num_locks() *
                                              sizeof(pthread_mutex_t));
        for (i = 0; i < CRYPTO_num_locks(); i++)
            pthread_mutex_init(&(ssl_lockarray[i]), NULL);
        CRYPTO_set_id_callback((unsigned long (*)())thread_id);
        CRYPTO_set_locking_callback((void (*)())lock_callback);
#endif
    }
    else if (!strncasecmp(cvid->ssl_version, "nss", 3)) {
        /*allow https to continue working after forking (for RHEL/CentOS 6)*/
        setenv("NSS_STRICT_NOFORK", "DISABLED", 1);
    }

    pthread_mutex_init(&de_pool_mut, NULL);

    i = build_hash_table();
    if (i == 0) 
        debugf("build cache system Okay");
    else
        debugf("Error build cache system");
}

int cloudfs_object_write_to_stream(const char *path, struct getObjectContext* goc)
{
    char tmp[64];
    char *ptr;
    int response;
    size_t count;
    size_t size;
    off_t offset;
    curl_slist *eheaders = NULL;

    if(!goc)
        return -1;

    size = goc->buf_size;
    offset = goc->current_off;
    goc->current_off = 0; /*must set to 0*/

    memset(tmp, 0, 64);
    memcpy(tmp, "bytes=", 6);
    ptr = tmp + 6;
    sprintf(ptr, "%ld-%ld", offset, (offset+size-1));
    ptr = tmp;
    add_header(&eheaders, "Range", ptr);

    response = send_getfile_request("GET", path, goc, eheaders);
    if(response >= 200 && response < 300)
        count = goc->got_cnt; /*OK*/
    else
        count = -1; /*FAILED*/

    curl_slist_free_all(eheaders);

    return count;
}

static void __reset_dir_entry(dir_entry *de)
{
    if (!de)
        return;

    pthread_mutex_lock(&(de->mtx));
    if (de->name) {
        free(de->name);
        de->name = NULL;
    }
    if (de->content_type) {
        free(de->content_type);
        de->content_type = NULL;
    }

    de->isdir = 0;
    de->name_len = 0;
    de->back_ptr = NULL;
    de->status = ENTRY_UNLOCKED; 
    de->last_modified = (time_t)(0); 
    de->cached_time = (time_t)(0);

    de->hash_list.next = &(de->hash_list); 
    de->hash_list.prev = &(de->hash_list); 
    de->lru_list.next = &(de->lru_list);
    de->lru_list.prev = &(de->lru_list);

    pthread_mutex_unlock(&(de->mtx));

    return;
}

static void __destroy_dir_entry(dir_entry *de)
{
    if (!de)
        return;

    if (de->name)
        free(de->name);
    if (de->content_type)
        free(de->content_type);
    pthread_mutex_destroy(&de->mtx);

    free(de);

    return;
}

static dir_entry* __malloc_dir_entry(void)
{
    dir_entry  *de;
    de = (dir_entry *)malloc(sizeof(dir_entry));
    if (!de) {
        debugf("Error, malloc dir_entry Failed.");
        return NULL;
    }
    de->name = NULL;
    de->name_len = 0;
    de->content_type = NULL;
    de->size = 0;
    de->isdir = 0;
    de->last_modified = (time_t)(0); 
    de->cached_time = (time_t)0;
    de->status = ENTRY_UNLOCKED;
    de->back_ptr = NULL;
    init_list_node(&(de->hash_list));
    init_list_node(&(de->lru_list));

    if(pthread_mutex_init(&de->mtx, NULL) != 0) {
        free(de);
        de = NULL;
    }

    return de;
}

dir_entry* get_dir_entry(void)
{
    int i;
    dir_entry *de = NULL;

    pthread_mutex_lock(&de_pool_mut);
    i = de_pool_count;
    if (de_pool_count > 0) {
        de = de_pool[--de_pool_count];
    }
    pthread_mutex_unlock(&de_pool_mut);

    if (!de) { 
        de = __malloc_dir_entry();
        if (!de) {
            debugf("Error, get_dir_entry failed");
            abort();
        }
    }

    if (_debug_mem_)
        debugf("+++memory info getdir @%ld, dir_entry_get[%d]", (unsigned long int)de, i);

    return de;
}

void return_dir_entry(dir_entry *de)
{
    int i;

    if(!de)
        return;

    pthread_mutex_lock(&de_pool_mut);
    i = de_pool_count;
    if (de_pool_count >= MAX_CNT_DE_POOL)
        __destroy_dir_entry(de);
    else {
        __reset_dir_entry(de);
        de_pool[de_pool_count++] = de;
    }

    pthread_mutex_unlock(&de_pool_mut);

    if (_debug_mem_)
        debugf("---memory info retdir @%ld, dir_entry_return[%d]", (unsigned long int)de, i);
}

void free_de_pool(void)
{
    int i;
    pthread_mutex_lock(&de_pool_mut);
    for (i = 0; i < MAX_CNT_DE_POOL; i++) {
        __destroy_dir_entry(de_pool[i]);
    }
    pthread_mutex_unlock(&de_pool_mut);
}

void cloudfs_get_co_info(const char *path, dir_entry **dentry)
{
    dir_entry *de = NULL;
    char co[MAX_PATH_SIZE * 3] = "";
    char last_subdir[MAX_PATH_SIZE] = "";
    int response = 0;
    int entry_count = 0;

    *dentry = NULL;

    if (!strcmp(path, "") || !strcmp(path, "/")) {
        path = "";
        strncpy(co, "/", sizeof(co));
        /*if (is_debug())
            debugf("cloudfs_get_co_info, path is root, container: %s", co);*/
    } else {
        sscanf(path, "/%[^\n]", co);
        char *encoded_co = curl_escape(co, 0);
        snprintf(co, sizeof(co), "%s", encoded_co);
        /*if (is_debug())
            debugf("cloudfs_get_co_info, path: %s, encoded_co: %s, co_path: %s", path, encoded_co, co);*/
        curl_free(encoded_co);
    }

    de = get_dir_entry();
    if (!de) {
        debugf("Error, cloudfs_get_co_info, path: %s, get_dir_entry Failed.");
        return;
    }

    response = send_request("HEAD", co, NULL, NULL, de, NULL, 0);
    if (!(response >= 200 && response < 300)) {
        if (de) {
            return_dir_entry(de);
            de = NULL;
        }
        if (is_debug())
            debugf("cloudfs_get_co_info, HEAD Error, path: %s, response: %d", path, response);
    }

    if (de) {
        if (de->name) {
            debugf("Error, de->name is NOT NULL");
            free(de->name);
        }
        de->name = strdup(path); 
        de->name_len = strlen(de->name); 
        de->cached_time = time(NULL);
    }

    *dentry = de;

    return;
}

void free_dir_info(dir_info *di)
{
    if (!di)
        return;
    if(di->name)
        free(di->name);
    free(di);
}

int cloudfs_list_directory(const char *path, dir_info **di_list)
{
    char container[MAX_PATH_SIZE * 3] = "";
    char object[MAX_PATH_SIZE] = "";
    char last_subdir[MAX_PATH_SIZE] = "";
    int prefix_length = 0;
    int response = 0;
    int retval = 0;
    int entry_count = 0;

    *di_list = NULL;
    xmlNode *onode = NULL, *anode = NULL, *text_node = NULL;
    xmlParserCtxtPtr xmlctx = xmlCreatePushParserCtxt(NULL, NULL, "", 0, NULL);
    if (!strcmp(path, "") || !strcmp(path, "/")) {
        path = "";
        strncpy(container, "/?format=xml", sizeof(container));
        if (is_debug())
            debugf("cloudfs_list_directory, path is root, container: %s", container);
    } else {
        sscanf(path, "/%[^/]/%[^\n]", container, object);
        char *encoded_container = curl_escape(container, 0);
        char *encoded_object = curl_escape(object, 0);

        char *trailing_slash;
        prefix_length = strlen(object);
        if (object[0] == 0)
            trailing_slash = "";
        else {
            trailing_slash = "/";
            prefix_length++;
        }

        snprintf(container, sizeof(container), "%s?format=xml&delimiter=/&prefix=%s%s", encoded_container, encoded_object, trailing_slash);
        if (is_debug())
            debugf("cloudfs_list_directory, path: %s, encoded_container: %s, encoded_object: %s, container: %s", path, encoded_container, encoded_object, container);
        curl_free(encoded_container);
        curl_free(encoded_object);
    }

    response = send_request("GET", container, NULL, xmlctx, NULL, NULL, 3);
    xmlParseChunk(xmlctx, "", 0, 1);
    if (xmlctx->wellFormed && response >= 200 && response < 300) {
        xmlNode *root_element = xmlDocGetRootElement(xmlctx->myDoc);
        for (onode = root_element->children; onode; onode = onode->next) {
            if (onode->type != XML_ELEMENT_NODE) 
                continue;

            char is_object = !strcasecmp((const char *)onode->name, "object");
            char is_container = !strcasecmp((const char *)onode->name, "container");
            char is_subdir = !strcasecmp((const char *)onode->name, "subdir");

            if (is_object || is_container || is_subdir) {
                char *content_type = NULL;
                int isdir = 0;

                dir_info *di = (dir_info *)malloc(sizeof(dir_info));
                di->next = NULL;
                di->name = NULL;
                if (is_container || is_subdir)
                    isdir = 1;
                for (anode = onode->children; anode; anode = anode->next) {
                    char *content = "<?!?>";
                    for (text_node = anode->children; text_node; text_node = text_node->next)
                        if (text_node->type == XML_TEXT_NODE)
                            content = (char *)text_node->content;
                    if (!strcasecmp((const char *)anode->name, "name")) {
                        di->name = strdup(content + prefix_length);

                        char *slash = strrchr(di->name, '/');
                        if (slash && (0 == *(slash + 1)))
                            *slash = 0;
                    }
                    if (!strcasecmp((const char *)anode->name, "content_type")) {
                        if((strstr(content, "application/folder") != NULL) ||
                           (strstr(content, "application/directory") != NULL))
                            isdir = 1;
                    }
                }
                if (isdir) {
                    if (!strncasecmp(di->name, last_subdir, sizeof(last_subdir))) {
                        free_dir_info(di);
                        continue;
                    }
                    strncpy(last_subdir, di->name, sizeof(last_subdir));
                }

                di->next = *di_list;
                *di_list = di;

            }else{
                debugf("Warning, unknown element: %s", onode->name);
            }
        }
        retval = 1;
    }

    xmlFreeDoc(xmlctx->myDoc);
    xmlFreeParserCtxt(xmlctx);

    return retval;
}

int cloudfs_delete_object(const char *path)
{
    int response;
    char *encoded = curl_escape(path, 0);

    if (is_debug())
        debugf("cloudfs_delete_object, path: %s", path);
    response = send_request("DELETE", encoded, NULL, NULL, NULL, NULL, 3);
    curl_free(encoded);

    return (response >= 200 && response < 300);
}

int cloudfs_copy_object(const char *src, const char *dst)
{
    int response;
    char *dst_encoded = curl_escape(dst, 0);
    curl_slist *headers = NULL;

    if (is_debug())
        debugf("cloudfs_copy_object, %s -> %s", src, dst);
    add_header(&headers, "X-Copy-From", src);
    add_header(&headers, "Content-Length", "0");
    response = send_request("PUT", dst_encoded, NULL, NULL, NULL, headers, 3);
    curl_free(dst_encoded);
    curl_slist_free_all(headers);

    return (response >= 200 && response < 300);
}

int cloudfs_create_directory(const char *path)
{ 
    int response;
    char *encoded = curl_escape(path, 0);

    if (is_debug())
        debugf("cloudfs_create_directory, path: %s", path);
    response = send_request("MKDIR", encoded, NULL, NULL, NULL, NULL, 3);
    curl_free(encoded);

    return (response >= 200 && response < 300);
}

void cloudfs_verify_ssl(int vrfy)
{
    verify_ssl = vrfy;
}

static struct {
    char username[MAX_HEADER_SIZE], password[MAX_HEADER_SIZE],
       tenant[MAX_HEADER_SIZE], authurl[MAX_URL_SIZE], use_snet;
} reconnect_args;

void cloudfs_set_credentials(char *username, char *tenant, char *password, char *authurl, int use_snet)
{
    strncpy(reconnect_args.username, username, sizeof(reconnect_args.username));
    strncpy(reconnect_args.tenant, tenant, sizeof(reconnect_args.tenant));
    strncpy(reconnect_args.password, password, sizeof(reconnect_args.password));
    strncpy(reconnect_args.authurl, authurl, sizeof(reconnect_args.authurl));
    reconnect_args.use_snet = use_snet;
}

int cloudfs_connect()
{
    int debug = 0;
    long response = -1;

    xmlNode *top_node = NULL, *service_node = NULL, *endpoint_node = NULL;
    xmlParserCtxtPtr xmlctx = NULL;

    char *postdata;
    if (reconnect_args.tenant[0]) {
        int count = asprintf(&postdata,
         "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
         "<auth xmlns=\"http://docs.openstack.org/identity/api/v2.0\" tenantName=\"%s\">"
         "<passwordCredentials username=\"%s\" password=\"%s\"/>"
         "</auth>",
         reconnect_args.tenant, reconnect_args.username, reconnect_args.password);
        if (count < 0) {
            debugf("Unable to asprintf");
            abort();
        }
    }

    pthread_mutex_lock(&curl_pool_mut);
    debugf("Authenticating...");
    storage_token[0] = storage_url[0] = '\0';

    CURL *curl = curl_easy_init();

    curl_slist *headers = NULL;
    if (reconnect_args.tenant[0]) {
        add_header(&headers, "Content-Type", "application/xml");
        add_header(&headers, "Accept", "application/xml");

        curl_easy_setopt(curl, CURLOPT_POST, 1);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postdata);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(postdata));

        xmlctx = xmlCreatePushParserCtxt(NULL, NULL, "", 0, NULL);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, xmlctx);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &xml_dispatch);
    } else {
        add_header(&headers, "X-Auth-User", reconnect_args.username);
        add_header(&headers, "X-Auth-Key", reconnect_args.password);
    }

    curl_easy_setopt(curl, CURLOPT_VERBOSE, debug);
    curl_easy_setopt(curl, CURLOPT_URL, reconnect_args.authurl);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, &header_dispatch);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, USER_AGENT);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, verify_ssl);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, verify_ssl);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10);
    curl_easy_setopt(curl, CURLOPT_FORBID_REUSE, 1);

    curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (reconnect_args.tenant[0]) {
        free(postdata);
        xmlParseChunk(xmlctx, "", 0, 1);
        if (xmlctx->wellFormed && response >= 200 && response < 300) {
            xmlNode *root_element = xmlDocGetRootElement(xmlctx->myDoc);
            for (top_node = root_element->children; top_node; top_node = top_node->next) {
                if ((top_node->type == XML_ELEMENT_NODE) &&
                    (!strcasecmp((const char *)top_node->name, "serviceCatalog"))) {
                    for (service_node = top_node->children; service_node; service_node = service_node->next)
                        if ((service_node->type == XML_ELEMENT_NODE) && 
                            (!strcasecmp((const char *)service_node->name, "service"))) {
                            xmlChar * serviceType = xmlGetProp(service_node, "type");
                            int isObjectStore = serviceType && !strcasecmp(serviceType, "object-store");
                            xmlFree(serviceType);

                            if (!isObjectStore)
                                continue;

                            for (endpoint_node = service_node->children; endpoint_node; endpoint_node = endpoint_node->next)
                                if ((endpoint_node->type == XML_ELEMENT_NODE) &&
                                    (!strcasecmp((const char *)endpoint_node->name, "endpoint"))) {
                                    xmlChar * publicURL = xmlGetProp(endpoint_node, "publicURL");
                                    if (publicURL) {
                                        char copy = 1;
                                        if (storage_url[0]) {
                                            if (strstr(publicURL, "cdn")) {
                                                copy = 0;
                                                debugf("Warning - found multiple object-store services; keeping %s, ignoring %s", storage_url, publicURL);
                                            }
                                            else
                                                debugf("Warning - found multiple object-store services; using %s instead of %s", publicURL, storage_url);
                                        }
                                        if (copy)
                                            strncpy(storage_url, publicURL, sizeof(storage_url));
                                    }
                                    xmlFree(publicURL);
                                }
                        }
                }

                if ((top_node->type == XML_ELEMENT_NODE) &&
                    (!strcasecmp((const char *)top_node->name, "token"))) {
                    xmlChar * tokenId = xmlGetProp(top_node, "id");
                    if (tokenId) {
                        if (storage_token[0])
                            debugf("Warning - found multiple authentication tokens.");
                        strncpy(storage_token, tokenId, sizeof(storage_token));
                    }
                    xmlFree(tokenId);
                }
            }
        }
        xmlFreeParserCtxt(xmlctx);
    }
    if (reconnect_args.use_snet && storage_url[0])
        rewrite_url_snet(storage_url);
    pthread_mutex_unlock(&curl_pool_mut);

    return (response >= 200 && response < 300 && storage_token[0] && storage_url[0]);
}

void debugf(char *fmt, ...)
{
    time_t t;
    char *cptr;
    va_list args;
    va_start(args, fmt);
    if(debughander.stream != NULL) {
        time(&t);
        pthread_mutex_lock(&debughander.mtx);
        cptr = ctime(&t);
        cptr[strlen(cptr)-1] = '\0';
        fputs(cptr, debughander.stream);
        vfprintf(debughander.stream, fmt, args);
        putc('\n', debughander.stream);
        fflush(debughander.stream);
        pthread_mutex_unlock(&debughander.mtx);
    } else{
        fputs("!!!", stderr);
        vfprintf(stderr, fmt, args);
        putc('\n', stderr);
   }
   va_end(args);
}

