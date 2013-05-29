#define FUSE_USE_VERSION 26
#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pthread.h>
#include <pwd.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stddef.h>
#include "cloudfsapi.h"
#include "config.h"


#define OPTION_SIZE 1024

static int cache_timeout;
static int __cloudfs_debug__ = 0;

static struct options {
    char username[OPTION_SIZE];
    char tenant[OPTION_SIZE];
    char api_key[OPTION_SIZE];
    char cache_timeout[OPTION_SIZE];
    char authurl[OPTION_SIZE];
    char use_snet[OPTION_SIZE];
    char verify_ssl[OPTION_SIZE];
} options = {
    .username = "",
    .api_key = "",
    .tenant = "",
    .cache_timeout = "3600",
    .authurl = "https://auth.api.rackspacecloud.com/v1.0",
    .use_snet = "false",
    .verify_ssl = "true",
};

static char *get_home_dir()
{
    char *home;
    if ((home = getenv("HOME")) && !access(home, R_OK))
        return home;
    struct passwd *pwd = getpwuid(geteuid());
    if ((home = pwd->pw_dir) && !access(home, R_OK))
        return home;
    return "~";
}

static void dir_for(const char *path, char *dir)
{
    strncpy(dir, path, MAX_PATH_SIZE);
    char *slash = strrchr(dir, '/');
    if (slash)
        *slash = '\0';
}

static dir_entry* path_info(const char *path, int *release)
{
    int i;
    dir_entry *de = NULL;

    *release = 0;

    de = check_cache_ex(path, strlen(path), NULL);
    if (de) {
        time_t the_time = time(NULL);
        if (cache_timeout > 0 && (the_time - de->cached_time) > cache_timeout) {
            if (is_debug())
                debugf("path_info, updating cache: %s", path);

            dir_entry *de2 = NULL;
            cloudfs_get_co_info(path, &de2);
            if (de2) {
                tmp_dir_entry tmp;
                tmp.size = de2->size;
                tmp.isdir = de2->isdir;
                tmp.status = de2->status;
                tmp.back_ptr = de2->back_ptr;
                tmp.last_modified = de2->last_modified;
                tmp.cached_time = time(NULL);
                tmp.name = NULL;
                tmp.content_type = NULL;
                return_dir_entry(de2);
                update_cached_de(de, &tmp);
            }else {
                if (is_debug())
                    debugf("cached object has been deleted in the cloud, %s", path);
                remove_de_from_cache(de);
                de = NULL;
            }
        }else {
            if (is_debug())
                debugf("path_info, Okay, cached: %s", path);
        }
    }else {
        cloudfs_get_co_info(path, &de);
        if (de) {
            i = insert_entry_to_cache(de);
            if (i < 0) {
                *release = 1;
            }
        }
    }

    return de;
}

static void dir_decache(const char *path)
{
    dir_entry *de;

    if (!path)
        return;
    de = check_cache_ex(path, strlen(path), NULL);
    if (de)
        remove_de_from_cache(de);

    return;
}

static int cfs_getattr(const char *path, struct stat *stbuf)
{
    int i = 0;
    dir_entry *de = NULL;

    stbuf->st_uid = geteuid();
    stbuf->st_gid = getegid();

    if (is_debug())
        debugf("cfs_getattr, path: %s", path);

    if (!strcmp(path, "/")) {
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
        return 0;
    }

    de = path_info(path, &i);
    if (!de) {
        if (is_debug())
            debugf("cfs_getattr FAILED, no %s co_info", path);
        return -ENOENT;
    }

    stbuf->st_ctime = stbuf->st_mtime = de->last_modified;
    /*stbuf->st_atime = de->last_modified;*/

    if (de->isdir) {
        stbuf->st_size = 0;
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
    }
    else {
        stbuf->st_size = de->size;
        /* calc. blocks as if 4K blocksize filesystem; stat uses units of 512B */
        stbuf->st_blocks = ((4095 + de->size) / 4096) * 8;
        stbuf->st_mode = S_IFREG | 0666;
        stbuf->st_nlink = 1;
    }

    if(i)
        return_dir_entry(de);

    return 0;
}

static int cfs_fgetattr(const char *path, struct stat *stbuf, struct fuse_file_info *info)
{
    struct openfile *of;

    if (is_debug())
        debugf("cfs_fgetattr, path: %s", path);
    of = (struct openfile *)(uintptr_t)info->fh;
    if (of) {
        stbuf->st_size = 0;
        stbuf->st_mode = S_IFREG | 0666;
        stbuf->st_nlink = 1;
        return 0;
    }
    return -ENOENT;
}

static int cfs_readdir(const char *path, void *buf, fuse_fill_dir_t filldir, off_t offset, struct fuse_file_info *info)
{
    dir_info *di = NULL;
    dir_info *tmp = NULL;

    if (is_debug())
        debugf("cfs_readdir, path: %s, offset: %ld", path, offset);

    if (!cloudfs_list_directory(path, &di))
      return -ENOLINK;

    filldir(buf, ".", NULL, 0);
    filldir(buf, "..", NULL, 0);
    while(di) {
        filldir(buf, di->name, NULL, 0);
        tmp = di;
        di = di->next;
        free_dir_info(tmp);
    }

    return 0;
}

static int cfs_mkdir(const char *path, mode_t mode)
{
    int i = 0;
    dir_entry *de;

    if (is_debug())
        debugf("cfs_mkdir, path: %s", path);

    if (cloudfs_create_directory(path)) {
        de = path_info(path, &i);
        if (i && de)
            return_dir_entry(de);
        return 0;
    }

    return -ENOENT;
}

static struct openfile* pre_init_upload_context(const char *path, int flags, struct fuse_file_info *info)
{
    int flag = 0;
    struct openfile *of;
    struct putObjectContext *poc;

    of = (struct openfile *)(uintptr_t)info->fh;
    if (!of) {
        flag = 1;
        of = get_openfile();
    }

    if (!of)
        return NULL;

    poc = get_putObjectContext();
    if (!poc) {
        if (flag == 1)
            destroy_openfile(of);
        return NULL; /*FAILED*/;
    }
    of->poc = poc;

    poc->path = strdup(path);
    if (NULL == poc->path) {
        if (flag == 1)
            destroy_openfile(of);
        return NULL;
    }

    of->open_for = OPENFILE_FOR_WRITE;
    poc->flags = flags;

    info->fh = (uintptr_t)of;

    return of;
}

static int build_putObject_thread(struct putObjectContext *poc)
{
    int err;
    pthread_attr_t attr;
    struct putObjTask *pot;

    if(poc == NULL) 
        return -1;

    pot = get_putObjectTask_entry();
    if(pot == NULL) 
        return -1;

    poc->pot = pot;

    err = pthread_attr_init(&attr);
    if(0 != err)
        return -1;

    err = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if(0 != err) 
        return -1;

    err = pthread_create(&(pot->tid), &attr, send_putfile_request, poc);
    if(0 != err) {
        pthread_attr_destroy(&attr);
        return -1;
    }

    pthread_attr_destroy(&attr);
    return 0;
   
}

static struct openfile* init_upload_context(const char *path, int flags, struct fuse_file_info *info)
{
    int ret;
    struct openfile* of;

    of = pre_init_upload_context(path, flags, info);
    if (!of)
        return NULL;

    ret = build_putObject_thread(of->poc);
    if (ret < 0) {
        destroy_openfile(of);
        info->fh = (uintptr_t)NULL;
        return NULL;
    }
    return of;
}

static int cfs_create(const char *path, mode_t mode, struct fuse_file_info *info)
{
    int ret;
    int flags;
    struct putObjectContext *poc;
    struct openfile *of;
    dir_entry *de;
    tmp_dir_entry tmp;

    flags = info->flags;

    if (is_debug())
        debugf("cfs_create, path: %s, flags: %x (O_RDONLY: %x, O_WRONLY: %x, O_RDWR: %x)", path, flags, O_RDONLY, O_WRONLY, O_RDWR);

    flags = info->flags;
    if (flags & O_RDWR) {
        debugf("Error, cfs_create, do not support creating file with O_RDWR, path: %s, flags: %x", path, flags);
        return -EACCES;
    }

    /*if (!(flags & O_RDONLY)) { */
    if (flags != O_RDONLY) {
        if ((of = init_upload_context(path, flags, info)) == NULL) {
            debugf("Error, cfs_create, init_upload_context FAILED, path: %s, flags: %d", path, flags);
            return -ENOMEM;
        }
    }

    tmp.size = 0;
    tmp.isdir = 0;
    tmp.status = ENTRY_LOCKED; 
    tmp.last_modified = time(NULL); 
    tmp.cached_time = tmp.last_modified; 
    tmp.name = NULL; 
    tmp.content_type = NULL; 
    tmp.back_ptr = NULL; 
    de = check_cache_ex(path, strlen(path), &tmp);
    if (!de)
        insert_dummy_entry_to_cache(path, 0, 0, ENTRY_LOCKED);

    info->direct_io = 1;
    if (is_debug())
        debugf("cfs_create exit, path: %s", path);

    return 0;
}

static int cfs_open(const char *path, struct fuse_file_info *info)
{
    int i;
    int flags = info->flags;
    struct openfile *of;
    struct getObjectContext *goc;
    struct putObjectContext *poc;
    dir_entry *de;

    if (flags & O_RDWR) {
        debugf("Error, cfs_open, do not support opening file with O_RDWR, path: %s, flags: %x", path, flags);
        return -EACCES;
    }

    if (is_debug())
        debugf("cfs_open, path: %s, flags: %x", path, flags);

    de = path_info(path, &i);
    if (de) 
        set_de_status(de, ENTRY_LOCKED);

    /*if (flags != O_WRONLY) {
    if (flags & O_RDONLY || flags & O_RDWR) {*/
    if (!(flags & O_WRONLY)) {
        if (is_debug())
            debugf("---cfs_open for read OK, path: %s, flags: %x", path, flags);

        of = get_openfile();
        if(!of) { 
            if (i && de)
                return_dir_entry(de);
            return -ENOMEM;
        }

        of->open_for |= OPENFILE_FOR_READ;
        if (de) {
            if (de->isdir)
                of->obj_size = 0;
            else
                of->obj_size = de->size;
        } else
            of->obj_size = 0; /*-1;*/

        info->fh = (uintptr_t)of;
    }

#if 1 
    /*if (flags & O_WRONLY || flags & O_RDWR) {
    if (!(flags & O_RDONLY)) {*/
    if (flags & O_WRONLY) {
        if ((of = init_upload_context(path, flags, info)) == NULL) {
            debugf("Error, cfs_open, init_upload_context FAILED, path: %s, flags: %d", path, flags);
            return -ENOMEM;
        }
        if (is_debug())
            debugf("---cfs_open for write OK, path: %s, flags: %X", path, flags);
    }
#endif

    info->direct_io = 1;
    return 0;
}

static int cfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *info)
{
    int ret;
    off_t osize, rsize;
    struct getObjectContext *goc = NULL;
    struct openfile *of = NULL;

    int use_buffer = 0;
    int buf_data = 0;
    int remnant = 0;
    char *ptr = buf;
    int flags = info->flags;

    if (is_debug())
        debugf("cfs_read, path: %s, size: %ld, offset: %ld", path, size, offset);

    of = (struct openfile *)(uintptr_t)info->fh;
    if(!of) {
        debugf("Error, cfs_read, !of");
        ret = -ENOMEM;
        goto out;
    }
    of->open_for |= OPENFILE_FOR_READ;

    osize = of->obj_size;
    if (osize < 0) {
        ret = 0;
        goto out;
    }

    if (offset >= osize) {
        if (is_debug())
            debugf("cfs_read, offset(%ld)  >= objectsize(%ld)", offset, osize);
        ret = 0;
        goto out;
    }
      
    if ((offset + size) > osize) {
        rsize = osize - offset;
        if (is_debug())
            debugf("cfs_read, offset(%ld) + size(%ld) > objectsize(%ld), change request size to %ld", offset, size, osize, rsize);
    } else
        rsize = size;

    if(rsize <= 0) {
        ret = 0;
        goto out;
    }

    ptr = buf;

    if (rsize < MAX_READBUFFER_SIZE && of->rbuf.enable && of->rbuf.rcnt > 3){
        use_buffer = 1;
        if (of->rbuf.buf_len != 0 && (offset >= of->rbuf.offset) && (offset < (of->rbuf.offset + of->rbuf.buf_len))) {
            if ((offset + rsize) <= (of->rbuf.offset + of->rbuf.buf_len)) {
                /*Okay, all in buffer*/
                memcpy(buf, (of->rbuf.buffer + (offset - of->rbuf.offset)), rsize);
                if (is_debug())
                    debugf("Okay cfs_read all cached, path: %s, size: %ld, offset: %ld, return %ld, extent: [%ld, %ld)", path, size, offset, rsize, of->rbuf.offset, (of->rbuf.offset + of->rbuf.buf_len));
                ret = rsize;
                goto out;
            }
            
            remnant = (offset + rsize) - (of->rbuf.offset + of->rbuf.buf_len); 
            buf_data = (of->rbuf.offset + of->rbuf.buf_len) - offset; 

            memcpy(buf, (of->rbuf.buffer + (offset - of->rbuf.offset)), buf_data);

            if (is_debug())
                debugf("cfs_read partial move %ld/%ld, offset: %ld, extent: [%ld, %ld)", buf_data, rsize, offset, of->rbuf.offset, (of->rbuf.offset+of->rbuf.buf_len));

        }

        reset_read_buffer(&(of->rbuf), 0);

        ptr = of->rbuf.buffer;
        rsize = MAX_READBUFFER_SIZE;
        if ((offset + rsize) > osize)
            rsize = osize - offset;

        if(rsize <= 0) {
            ret = 0;
            goto out;
        }

    }

    goc = get_getObjectContext();
    if(!goc) {
        ret = -ENOMEM;
        goto out;
    }

    goc->buf = ptr;
    goc->buf_size = rsize;
    goc->got_cnt = 0;
    goc->current_off = offset;

    of->goc = goc;

    ret = cloudfs_object_write_to_stream(path, goc);

    if(ret < 0) {
        reset_read_buffer(&(of->rbuf), READBUFFER_CLEAN_RCNT);
        debugf("Error, cfs_read, path: %s, size: %ld, offset: %ld, return %ld bytes", path, size, offset, goc->got_cnt);
        goto out;
    }

    of->rbuf.rcnt += 1;

    if(!use_buffer) {
        if (is_debug())
            debugf("cfs_read does not use buffer, path: %s, size: %ld, offset: %ld, return %ld", path, size, offset, ret);
        goto out;
    }

    of->rbuf.buf_len = goc->got_cnt;
    of->rbuf.offset = offset;

    ret = rsize < size ? rsize : size;
    if (remnant > 0) {
        if (remnant <= of->rbuf.buf_len) {
            memcpy((buf + buf_data), (of->rbuf.buffer + buf_data), remnant);
            ret = buf_data + remnant;
            if (is_debug())
                debugf("cfs_read remnant move %ld (%ld) bytes, extent: [%ld, %ld)", remnant, (remnant + buf_data), of->rbuf.offset, (of->rbuf.offset + of->rbuf.buf_len));
        }else
            ret = 0;

    }else {
        memcpy(buf, of->rbuf.buffer, ret);
    }
    if (is_debug())
        debugf("cfs_read from cloud, path: %s, request-size: %ld, cloud-return %ld, cfs_read-return: %ld, extent: [%ld, %ld)", path, rsize, of->rbuf.buf_len, ret, of->rbuf.offset, (of->rbuf.offset+of->rbuf.buf_len));

out:
    if (goc)
        destroy_getObjectContext(goc);
    if (of)
        of->goc = NULL;

    return ret;

}

static int cfs_flush(const char *path, struct fuse_file_info *info)
{
    int ret;
    int flags;
    off_t size;
    struct openfile *of = NULL;
    struct putObjectContext *poc = NULL;
    struct getObjectContext *goc = NULL;
    tmp_dir_entry tmp;
    dir_entry *de;

    if (is_debug())
        debugf("cfs_flush, path: %s", path);

    of = (struct openfile *)(uintptr_t)info->fh;
    if (!of)
        return 0;

    if (of->open_for & OPENFILE_FOR_READ) {
        goc = of->goc;
        size = of->obj_size;
        tmp.last_modified = (time_t)(0);
        if (is_debug())
            debugf("cfs_flush for read, path: %s", path);
    }
    if (of->open_for & OPENFILE_FOR_WRITE) {
        poc = of->poc;
        size = poc->put_cnt;
        tmp.last_modified = time(NULL);
        if (is_debug())
            debugf("cfs_flush for write, path: %s", path);
    }

    tmp.size = size;
    tmp.isdir = 0;
    tmp.status = ENTRY_UNLOCKED;
    tmp.cached_time = time(NULL);
    tmp.name = NULL;
    tmp.content_type = NULL;
    tmp.back_ptr = NULL;
    de = check_cache_ex(path, strlen(path), &tmp);
    if (!de) {
        debugf("Warning: cfs_flush, check_cache_ex %s, but de is NULL", path);
    }

    if (goc) {
        debugf("Error, Why of->goc is not NULL? cfs_flush for read, path: %s", path);
        flags = poc->flags;
        if (flags & O_RDWR || flags & O_RDONLY) {
            ;
        }
    }

    if (poc) {
        flags = poc->flags;

        if (poc->isOkay == 1) {
again:
            if ((ret = sem_wait(&(poc->pot->can_write))) < 0) {
                if(errno == EINTR)
                    goto again;

                debugf("Error, sem_wait can_write");
                return -1; 
            }
        }/* else {
            debugf("cfs_flush path: %s, alread writen %ld bytes to cloud", path, poc->put_cnt);
            if ((ret = sem_post(&(poc->pot->can_cloud))) < 0) {
                debugf("Error, cfs_flush sem_post can_cloud");
            }
            //destroy_openfile(of);
            //info->fh = (uintptr_t)NULL;
            return 0; 
        }*/

        pthread_mutex_lock(&(poc->pot->lock));

        poc->buf_size = 0; 
        poc->buf = NULL;
        poc->current_off = 0;

        pthread_mutex_unlock(&(poc->pot->lock));

        if ((ret = sem_post(&(poc->pot->can_cloud))) < 0) {
            debugf("Error, cfs_flush sem_post can_cloud");
            return -1; 
        }
        if (is_debug())
            debugf("cfs_flush, post(can_cloud), upload %ld bytes", poc->put_cnt);
    }

    return 0;
}

static int cfs_release(const char *path, struct fuse_file_info *info)
{
    int ret;
    struct openfile* of = NULL;
    struct putObjectContext *poc = NULL;
    struct getObjectContext *goc = NULL;

    if (is_debug()) 
        debugf("cfs_release path: %s", path);

    of = (struct openfile *)(uintptr_t)info->fh;
    if (!of)
        return 0;

    if (of->open_for & OPENFILE_FOR_READ) {
        goc = of->goc;
        if (is_debug()) 
            debugf("---cfs_release for read, path: %s", path);
    }

    if (of->open_for & OPENFILE_FOR_WRITE) {
        poc = of->poc;
        if (is_debug()) 
            debugf("---cfs_release for write, path: %s", path);
    }

    if (poc) {
again:
        if ((ret = sem_wait(&(poc->pot->can_release))) < 0) {
            if(errno == EINTR)
                goto again;
            debugf("Error, sem_wait can_release");
            sleep(2*60); /*ugly*/
        }
    }

    destroy_openfile(of);

    return 0;
}

static int cfs_rmdir(const char *path)
{
    if (is_debug())
        debugf("cfs_rmdir, path: %s", path);
    if (cloudfs_delete_object(path)) {
        dir_decache(path);
        return 0;
    }
    return -ENOENT;
}

static int cfs_ftruncate(const char *path, off_t size, struct fuse_file_info *info)
{
    if (is_debug())
        debugf("cfs_ftruncate, path: %s, size: %ld", path, size);
    return -ENOSYS; 
}

static int cfs_write(const char *path, const char *buf, size_t length, off_t offset, struct fuse_file_info *info)
{
    int ret;
    size_t cnt = 0;
    struct openfile *of = NULL;
    struct putObjectContext *poc = NULL;

    if (is_debug())
        debugf("cfs_write, path: %s, length: %ld, offset: %ld", path, length, offset);

    if (length == 0)
        return 0;

    of = (struct openfile *)(uintptr_t)info->fh;
    if (!of) {
        debugf("Error, cfs_write !of, path: %s, length: %ld, offset: %ld", path, length, offset);
        return -1;
    }

    of->open_for |= OPENFILE_FOR_WRITE;
    poc = of->poc;
    if (!poc) {
        debugf("Error, cfs_write !poc, path: %s, length: %ld, offset: %ld", path, length, offset);
        return -1;
    }

    poc->isOkay = 0;

again_1:
    if ((ret = sem_wait(&(poc->pot->can_write))) < 0) {
        if(errno == EINTR)
            goto again_1;

        debugf("Error, cfs_write, sem_wait can_write");
        return -1; 
    }

    pthread_mutex_lock(&(poc->pot->lock));

    poc->buf_size = length; 
    poc->buf = buf;
    poc->current_off = 0;

    pthread_mutex_unlock(&(poc->pot->lock));

    if (is_debug())
        debugf("cfs_write, post(can_cloud), path: %s, length: %ld, offset: %ld", path, length, offset);

    if ((ret = sem_post(&(poc->pot->can_cloud))) < 0) {
        debugf("Error, cfs_write sem_post can_cloud");
        return -1; 
    }

again_2:
    if ((ret = sem_wait(&(poc->pot->write_can_return))) < 0) {
        if(errno == EINTR)
            goto again_2;
        debugf("Error, cfs_write, sem_wait write_can_return");
        return -1; 
    }
  
    if (poc->isOkay == 1) {
        if (is_debug())
            debugf("Ok cfs_write, path: %s, length: %ld, offset: %ld", path, length, offset);
        return length;
    }

    debugf("Error cfs_write failed, path: %s, length: %ld, offset: %ld", path, length, offset);
    return -1;
}

static int cfs_unlink(const char *path)
{
    if (is_debug())
        debugf("cfs_unlink, path: %s", path);

    if (cloudfs_delete_object(path)) {
        dir_decache(path);
        return 0;
    }
  return -ENOENT;
}

static int cfs_fsync(const char *path, int idunno, struct fuse_file_info *info)
{
    if (is_debug())
        debugf("cfs_fsync, path: %s, idunno: %d", path, idunno);
  return 0;
}

static int cfs_truncate(const char *path, off_t size)
{
    if (is_debug())
        debugf("cfs_truncate, path: %s, size: %ld", path, size);
  return 0;
}

static int cfs_statfs(const char *path, struct statvfs *stat)
{
    stat->f_bsize = 4096;
    stat->f_frsize = 4096;
    stat->f_blocks = INT_MAX;
    stat->f_bfree = stat->f_blocks;
    stat->f_bavail = stat->f_blocks;
    stat->f_files = INT_MAX;
    stat->f_ffree = INT_MAX;
    stat->f_favail = INT_MAX;
    stat->f_namemax = INT_MAX;
    return 0;
}

static int cfs_chown(const char *path, uid_t uid, gid_t gid)
{
    if (is_debug())
        debugf("cfs_chown, path: %s", path);
    return 0;
}

static int cfs_chmod(const char *path, mode_t mode)
{
    if (is_debug())
        debugf("cfs_chmod, path: %s", path);
    return 0;
}

static int cfs_rename(const char *src, const char *dst)
{
    int i;
    dir_entry *src_de;

    if (is_debug())
        debugf("cfs_rename, %s -> %s", src, dst);

    src_de = path_info(src, &i);
    if (!src_de)
        return -ENOENT;
    if (src_de->isdir)
        return -EISDIR;
    if (cloudfs_copy_object(src, dst)) {
        /* FIXME this isn't quite right as doesn't preserve last modified */
        src_de = check_cache_ex(src, strlen(src), NULL);
        remove_de_from_cache(src_de);
        return cfs_unlink(src);
    }
    return -EIO;
}

static void init_debug_hander(struct debug_hander_t *dh)
{
    char *ptr;
    char debugfile[1024];

    memset(debugfile, 0, 1024);
    ptr = strrchr(options.username, ':');
    if (ptr != NULL) 
        snprintf(debugfile, sizeof(debugfile), "%s/swiftfuse_%s.log", get_home_dir(), (ptr+1));
    else 
        snprintf(debugfile, sizeof(debugfile), "%s/swiftfuse%ld.log", get_home_dir(), (unsigned long int)getpid());
    pthread_mutex_init(&(dh->mtx), NULL);
    dh->stream = fopen(debugfile, "a+");
    if(dh->stream == NULL) {
        perror("fopen");
        fprintf(stderr, "WARNNING: fopen %s failed\n", debugfile);
    }
    fprintf(stderr, "debug file %s OK!\n", debugfile);
    return;
}    

int is_debug(void)
{
    if (__cloudfs_debug__)
        return 1;
    return 0;
}

void cloudfs_debug(void)
{
    init_debug_hander(&debughander);
}

void cloudfs_unmount(int sig)
{
    int ret = -1;

    debugf("cloudfs_unmount %d", sig);
    ret = system("/bin/fusermount -u /home/rpy/cloudfile1");
    debugf("return from cloudfs_unmount %d", ret);
}

static void *cfs_init(struct fuse_conn_info *conn)
{
    signal(SIGPIPE, SIG_IGN);
    /*signal(SIGUSR1, cloudfs_unmount);*/
    return NULL;
}

int parse_option(void *data, const char *arg, int key, struct fuse_args *outargs)
{
    if (!strncmp(arg, "-f", 2) || !strncmp(arg, "-d", 2) || !strncmp(arg, "debug=1", 7)) {
        __cloudfs_debug__ = 1;
    }

    if (sscanf(arg, " username = %[^\r\n ]", options.username) ||
      sscanf(arg, " tenant = %[^\r\n ]", options.tenant) ||
      sscanf(arg, " api_key = %[^\r\n ]", options.api_key) ||
      sscanf(arg, " password = %[^\r\n ]", options.api_key) ||
      sscanf(arg, " cache_timeout = %[^\r\n ]", options.cache_timeout) ||
      sscanf(arg, " authurl = %[^\r\n ]", options.authurl) ||
      sscanf(arg, " use_snet = %[^\r\n ]", options.use_snet) ||
      sscanf(arg, " verify_ssl = %[^\r\n ]", options.verify_ssl))
          return 0;
    return 1;
}

int main(int argc, char **argv)
{
    int i;
    char settings_filename[MAX_PATH_SIZE] = "";
    FILE *settings;
    struct fuse_args args; 

    if (argc < 2) {
        fprintf(stderr, "%s --conf=/path/to/swiftfuse.conf mount_arguments\n", argv[0]);
        return 1; 
    }

    if (!strncmp(argv[1], "--conf=", 7)) {
        char *ptr = argv[1] + 7;
        for (i = 1; i < argc; i++) {
            argv[i] = argv[i+1];
        }
        argc -= 1;
        snprintf(settings_filename, sizeof(settings_filename), "%s", ptr);
    } else {
        snprintf(settings_filename, sizeof(settings_filename), "%s/.swiftfuse", get_home_dir());
    }

    args.argc = argc;
    args.argv = argv;
    args.allocated = 0;

    if ((settings = fopen(settings_filename, "r"))) {
        char line[OPTION_SIZE];
        while (fgets(line, sizeof(line), settings))
            parse_option(NULL, line, -1, &args);
        fclose(settings);
    }

    fuse_opt_parse(&args, &options, NULL, parse_option);

    cache_timeout = atoi(options.cache_timeout);

    if (!*options.username || !*options.api_key) {
        fprintf(stderr, "Unable to determine username and API key.\n\n");
        fprintf(stderr, "These can be set either as mount options or in"
                    "a file named %s\n\n", settings_filename);
        fprintf(stderr, "  username=[Account username]\n");
        fprintf(stderr, "  api_key=[API key (or password for Keystone API)]\n\n");
        fprintf(stderr, "The following settings are optional:\n\n");
        fprintf(stderr, "  authurl=[Authentication url - connect to non-Rackspace Swift]\n");
        fprintf(stderr, "  tenant=[Tenant for authentication with Keystone, enables Auth 2.0 API]\n");
        fprintf(stderr, "  password=[Alias for api_key, if using Keystone API]\n");
        fprintf(stderr, "  use_snet=[True to use Rackspace ServiceNet for connections]\n");
        fprintf(stderr, "  cache_timeout=[Seconds for caching, default 3600]\n");
        fprintf(stderr, "  verify_ssl=[False to disable SSL cert verification]\n");

        return 1;
    }

    cloudfs_debug();
    cloudfs_init();

    cloudfs_verify_ssl(!strcasecmp(options.verify_ssl, "true"));

    cloudfs_set_credentials(options.username, options.tenant, options.api_key,
        options.authurl, !strcasecmp(options.use_snet, "true"));
    if (!cloudfs_connect()) {
        fprintf(stderr, "Failed to authenticate.\n");
        return 1;
    }

#ifndef HAVE_OPENSSL
#warning Compiling without libssl, will run single-threaded.
    fuse_opt_add_arg(&args, "-s");
#endif

    struct fuse_operations cfs_oper = {
        .readdir = cfs_readdir,
        .mkdir = cfs_mkdir,
        .read = cfs_read,
        .create = cfs_create,
        .open = cfs_open,
        .fgetattr = cfs_fgetattr,
        .getattr = cfs_getattr,
        .flush = cfs_flush,
        .release = cfs_release,
        .rmdir = cfs_rmdir,
        .ftruncate = cfs_ftruncate,
        .truncate = cfs_truncate,
        .write = cfs_write,
        .unlink = cfs_unlink,
        .fsync = cfs_fsync,
        .statfs = cfs_statfs,
        .chmod = cfs_chmod,
        .chown = cfs_chown,
        .rename = cfs_rename,
        .init = cfs_init,
    };

    return fuse_main(args.argc, args.argv, &cfs_oper, &options);
}

