#ifndef _CLOUDFSAPI_H
#define _CLOUDFSAPI_H

#include <curl/curl.h>
#include <curl/easy.h>
#include <semaphore.h>
#include "cloudfscache.h" 

#define MAX_CNT_CURL_POOL  1024

#define BUFFER_INITIAL_SIZE 4096
#define MAX_HEADER_SIZE 4096
#define MAX_PATH_SIZE (1024 + 256 + 3)
#define MAX_URL_SIZE (MAX_PATH_SIZE * 3)
#define USER_AGENT "CloudFuse"

typedef struct curl_slist curl_slist;

typedef struct _dir_info {
    struct _dir_info *next; 
    char *name; 
} dir_info;

struct debug_hander_t {
    pthread_mutex_t mtx;
    FILE *stream;
};
extern struct debug_hander_t debughander;

#define MAX_READBUFFER_SIZE  (1024 * 1024 + 0)
#define READBUFFER_CLEAN_RCNT (1) 

struct read_buffer {
    int enable;
    int rcnt;
    int buf_len;
    off_t offset;
    char *buffer;
};

struct getObjectContext {
    int flags;
    size_t buf_size;
    char *buf;
    off_t got_cnt;
    off_t current_off;
};

struct putObjTask {
    int  status;
    pthread_t tid;
    pthread_mutex_t  lock;
    sem_t can_write;
    sem_t write_can_return;
    sem_t can_cloud;
    sem_t can_release;
};

struct putObjectContext {
    CURL *curl;
    int flags;
    int isOkay;
    char *path;
    size_t buf_size;
    const char *buf;
    off_t put_cnt;
    off_t current_off;
    struct putObjTask *pot; 
};

#define OPENFILE_FOR_UNKNOWN   (0)
#define OPENFILE_FOR_READ      (1<<0)
#define OPENFILE_FOR_WRITE     (1<<1)

struct openfile {
    int open_for;
    off_t obj_size;
    struct read_buffer rbuf;
    struct getObjectContext *goc; 
    struct putObjectContext *poc; 
};

int reset_read_buffer(struct read_buffer* rbuf, int flag);
struct getObjectContext * get_getObjectContext(void);
struct putObjTask * get_putObjectTask_entry(void);
struct putObjectContext * get_putObjectContext(void);
struct openfile* get_openfile(void);

void destroy_getObjectContext(struct getObjectContext *goc);
void destroy_putObjTask_entry(struct putObjTask *pot);
void destroy_putObjectContext(struct putObjectContext *poc);
void destroy_openfile(struct openfile *of);

void cloudfs_init();
void cloudfs_set_credentials(char *username, char *tenant, char *password,
                             char *authurl, int snet_rewrite);
int cloufds_connect();

int cloudfs_object_write_to_stream(const char *path, struct getObjectContext* goc);
void cloudfs_get_co_info(const char *path, dir_entry **dentry);

void free_de_pool(void);
void return_dir_entry(dir_entry *de);
dir_entry* get_dir_entry(void);

void free_dir_info(dir_info *di);
int cloudfs_list_directory(const char *path, dir_info **);
int cloudfs_delete_object(const char *path);
int cloudfs_copy_object(const char *src, const char *dst);
int cloudfs_create_directory(const char *label);
void cloudfs_debug(void);
void cloudfs_verify_ssl(int dbg);

int is_debug();
void debugf(char *fmt, ...);

void *send_putfile_request(void *poc);

#endif

