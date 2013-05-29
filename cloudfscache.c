
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include "cloudfsapi.h"
#include "cloudfscache.h" 

static struct hashtable_t  hashtable;
static int __enable_cache_system__ = 0;

static void disable_cache_system()
{
    __enable_cache_system__ = 0;
}

/**
 *0: matched;
 **/
static int key_cmp_func(const void *s1, size_t s1len, const void *s2, size_t s2len)
{
    int ret;
    if (s1len != s2len)
        return -1;
    ret = memcmp(s1, s2, s1len);
    return ret;
}

static unsigned long int name_hash(const char *key, size_t keylen)
{
    int i;
    unsigned long int hash = 98389;
    const char *p = key;

    if(!key || keylen <= 0)
        return hash % MAX_HASHENTRIES;

    for (i = 0; i < (keylen); i++, p++) {
        //hash = ((hash << 25) | (hash >> 7)) + (*p);
        hash = ((hash << 25) | (hash >> 22)) + (*p);
        if (i > 0)
            hash *= *(p-1);
    }
    hash = hash % MAX_HASHENTRIES;

    return hash;
}

static int __delete_entry_from_hashtable(dir_entry *de)
{
/**
 * step 1: delete hash_entry_head;
 * step 2: delete from the tail of lru_head; 
 * step 3: decrease hashtable.de_total_cnt;
 **/
    int h, i;
    struct hash_entry_head *heh;

    if(__enable_cache_system__ == 0)
        return 0;  /* Zero is Okay*/

    if (list_empty(&(de->lru_list))) {
        debugf("Warning, delete_entry_from_hashtable, but de->lru_list is empty, de->name: %s", de->name ? de->name : "NULL");
        return 0;
    }

    pthread_mutex_lock(&(de->mtx));
    if (de->status != ENTRY_UNLOCKED) {
        pthread_mutex_unlock(&(de->mtx));
        debugf("Warning, delete_entry_from_hashtable, de->name: %s is not unlocked (%d)", de->name, de->status);
        return -1;
    }
    pthread_mutex_unlock(&(de->mtx));

    h = hashtable.hash(de->name, strlen(de->name));
    heh = &hashtable.table[h];

    i = pthread_rwlock_wrlock(&(heh->hlist_lock));
    if (i != 0) {
        pthread_rwlock_unlock(&(heh->hlist_lock));
        debugf("Error, delete_entry_from_hashtable, pthread_rwlock_wrlock failed");
        return -2;
    }

    if (list_empty(&(heh->hlist))) {
        pthread_rwlock_unlock(&(heh->hlist_lock));
        debugf("Warning, delete_entry_from_hashtable: %s, but hashtable.table[%d].lru_list is empty", de->name ? de->name : "NULL", h);
        return 0;
    }

    list_del(&(de->hash_list));

    pthread_rwlock_unlock(&(heh->hlist_lock));

    pthread_mutex_lock(&(hashtable.lru_manager.lru_lock));
    list_del(&(de->lru_list));
    pthread_mutex_unlock(&(hashtable.lru_manager.lru_lock));

    pthread_mutex_lock(&(hashtable.de_total_lock));
    if (hashtable.de_total_cnt > 0);
        hashtable.de_total_cnt--;
    pthread_mutex_unlock(&(hashtable.de_total_lock));

    return_dir_entry(de);

    if (is_debug())
        debugf("Okay delete_entry_from_hashtable %s", de->name);
    
    return h; /*h >= 0*/
}

static int __revoke_dir_entry(int cnt)
{
    int i, j, ret;
    struct list_node *ln;
    dir_entry *de;

    ret = 0;
    pthread_mutex_lock(&(hashtable.lru_manager.lru_lock));
    ln = hashtable.lru_manager.lru_head.prev;
    pthread_mutex_unlock(&(hashtable.lru_manager.lru_lock));

    for (i = 0; i < cnt; i++) {
        if (list_empty(ln)) {
            debugf("Error, revoke_direntry %d/%d, the list_node is empty", i, cnt);
            break;
        }
        de = container_of(ln, dir_entry, lru_list); 
        j = __delete_entry_from_hashtable(de);
        if (j >= 0) {
            ret++;
            pthread_mutex_lock(&(hashtable.lru_manager.lru_lock));
            ln = hashtable.lru_manager.lru_head.prev;
            pthread_mutex_unlock(&(hashtable.lru_manager.lru_lock));
        }else if (j == -1){
            debugf("Warning, revoke_direntry %d/%d", i, cnt);
            ln = ln->prev;
        }else {
            debugf("Error, revoke_direntry %d/%d", i, cnt);
            break;
        }
    }

    debugf("revoke_dir_entry, revoked: %d/%d", ret, cnt);

    return ret;
} 

/**
 * step 1: insert to hash_entry_head;
 * step 2: increase hashtable.de_total_cnt;
 * step 3: insert to the head of lru_head; 
 **/
static int __insert_entry_to_hashtable(dir_entry *de)
{
    int h, i, j;
    struct hash_entry_head *heh;

    if(__enable_cache_system__ == 0)
        return 0;  /* Zero is Okay*/

    if (is_debug())
        debugf("+++Will inserting de: {name: %s, content-type: %s, size: %d, isdir: %d, status: %d}", (de->name ? de->name : "NULL"), (de->content_type ? de->content_type : "NULL"), de->size, de->isdir, de->status);
  
    i = 0;
    pthread_mutex_lock(&(hashtable.de_total_lock));
    if (hashtable.de_total_cnt >= MAX_DIRENTRIES_CNT)
        i = 1;
    pthread_mutex_unlock(&(hashtable.de_total_lock));

    if(i) {
        h = MAX_DIRENTRIES_CNT / 2;
        if (h <= 0)
            h = 1;
        j = __revoke_dir_entry(h);
        if (j <= 0) {
            debugf("Error, insert_entry_to_hashtable, but revoke_dir_entry Failed (%d)", h);
            return -1;
        }
    }

    h = hashtable.hash(de->name, strlen(de->name));
    heh = &hashtable.table[h];

    i = pthread_rwlock_wrlock(&(heh->hlist_lock));
    if (i != 0) {
        debugf("Error, insert_entry_to_hashtable, pthread_rwlock_wrlock failed");
        return -1;
    }

    pthread_mutex_lock(&(de->mtx));
    list_add(&(de->hash_list), &(heh->hlist));
    de->back_ptr = heh;
    pthread_mutex_unlock(&(de->mtx));

    i = pthread_rwlock_unlock(&(heh->hlist_lock));
    if (i != 0) {
        debugf("Error, cache_new_entry, pthread_rwlock_unlock failed");
    }

    pthread_mutex_lock(&(hashtable.de_total_lock));
    hashtable.de_total_cnt++;
    i = hashtable.de_total_cnt;
    pthread_mutex_unlock(&(hashtable.de_total_lock));
    
    pthread_mutex_lock(&(hashtable.lru_manager.lru_lock));
    list_add(&(de->lru_list), &(hashtable.lru_manager.lru_head));
    pthread_mutex_unlock(&(hashtable.lru_manager.lru_lock));

    if (is_debug())
        debugf("+++Okay insert_entry_to_hashtable[%d], heh: @%lu{next: %lu, prev: %lu} de: @%lu{next: %lu, prev: %lu}", h, (unsigned long int)&(heh->hlist), (unsigned long int)(heh->hlist.next), (unsigned long int)(heh->hlist.prev), (unsigned long int)(&de->hash_list), (unsigned long int)(de->hash_list.next), (unsigned long int)(de->hash_list.prev));

    return h; /*h >= 0*/
}

int build_hash_table(void)
{
    int i, j, ret;
    struct hash_entry_head *table;

    hashtable.de_total_cnt = 0;    
    pthread_mutex_init(&hashtable.de_total_lock, NULL);    

    hashtable.key_matcher = (key_cmp_func_t)(&key_cmp_func);    
    hashtable.hash = (hash_func_t)(&name_hash);    

    init_list_node(&hashtable.lru_manager.lru_head);    
    pthread_mutex_init(&hashtable.lru_manager.lru_lock, NULL);    

    table = (struct hash_entry_head *)malloc(sizeof(struct hash_entry_head) * MAX_HASHENTRIES);
    if (!table) {
        pthread_mutex_destroy(&hashtable.de_total_lock);
        pthread_mutex_destroy(&hashtable.lru_manager.lru_lock);    
        return -1;
    }

    hashtable.table = table;

    for (i = 0; i < MAX_HASHENTRIES; i++) {
        init_list_node(&(table[i].hlist));
        ret = pthread_rwlock_init(&(table[i].hlist_lock), NULL);
        if (ret != 0) 
            break;
    }

    if (i < MAX_HASHENTRIES) {
        for (j = 0; j < i; j++) 
            pthread_rwlock_destroy(&(table[j].hlist_lock));

        pthread_mutex_destroy(&hashtable.de_total_lock);
        pthread_mutex_destroy(&hashtable.lru_manager.lru_lock);    

        free(table);
        hashtable.table = NULL;

        return -1;
    }

    __enable_cache_system__ = 1;

    return 0;
}

dir_entry* check_cache_ex(const char *key, int key_len, tmp_dir_entry *dex)
{
    int h, i, j;
    dir_entry* de, *ret_de;
    struct list_node* ln;
    struct list_node* head;
    struct hash_entry_head *heh;

    if(__enable_cache_system__ == 0)
        return NULL;

    if (!key || key_len <= 0) {
        debugf("Error, check_cache, key: %s, key_len: %d", key ? key : "NULL", key_len);
        return NULL;
    }

    h = hashtable.hash(key, key_len);
    heh = &hashtable.table[h];

    i = pthread_rwlock_rdlock(&(heh->hlist_lock));
    if (i != 0) {
        debugf("Error, cache_new_entry, pthread_rwlock_wrlock failed");
        return NULL;
    }
    ret_de = NULL;
    head = &(heh->hlist);

    if (is_debug())
        debugf("check_cache %s, table[%d], heh: @%lu{next: %lu, prev: %lu}", key, h, (unsigned long int)&(heh->hlist), (unsigned long int)(heh->hlist.next), (unsigned long int)(heh->hlist.prev));

    j = 0;
    list_for_each(ln, head) {
        de = container_of(ln, dir_entry, hash_list); 

        if (is_debug())
            debugf("---list_for_each [%d]: @%lu{next: %lu, prev: %lu}, {name: %s, name_len: %d, content_type: %s, size: %ld, isdir: %d, status: %d}", h, (unsigned long int)ln, (unsigned long int)(ln->next), (unsigned long int)(ln->prev), de->name, de->name_len, (de->content_type ? de->content_type : "NULL"), de->size, de->isdir, de->status);

        i = hashtable.key_matcher(de->name, de->name_len, key, key_len); 
        if(i == 0) {
            ret_de = de;
            if (dex) { 
                dex->back_ptr = heh; 
                update_cached_de(de, dex);
            }
            break;
        }
        j++;
    }
    pthread_rwlock_unlock(&(heh->hlist_lock));

    if (j >= MAX_HASHLIST_LEN) 
        debugf("Warning: Bad hash function, (%05d,%05d)", h, j);

    return ret_de;
}

void set_de_status(dir_entry *de, int status)
{
    int i;
    if (de) {
        pthread_mutex_lock(&(de->mtx));
        i = de->status;
        de->status = status; 
        pthread_mutex_unlock(&(de->mtx));
        if (is_debug()) {
            if (i != de->status) 
                debugf("set_de_status: CHANGED: %d ---> %d", i, de->status);
        }
    }

    return;
}

void update_cached_de(dir_entry *de, tmp_dir_entry *src_de)
{
    time_t t;
    int i;

    if (__enable_cache_system__ == 0)
        return;  /* Zero is Okay*/

    if (de) {
        pthread_mutex_lock(&(de->mtx));
        de->size = src_de->size;
        de->isdir = src_de->isdir;
        i = de->status; 
        de->status = src_de->status; 
        if (src_de->back_ptr)
            de->back_ptr = src_de->back_ptr;
        if (src_de->last_modified != (time_t)0 )
            de->last_modified = src_de->last_modified;
        de->cached_time = src_de->cached_time;
        if (src_de->name) {
            if (de->name)
                free(de->name);
            de->name = strdup(src_de->name);
            de->name_len = strlen(de->name);
        }
        if (src_de->content_type) {
            if (de->content_type)
                free(de->content_type);
            de->content_type = strdup(src_de->content_type);
        }
        pthread_mutex_unlock(&(de->mtx));
        /*debugf("Okay, update_cache_de: {name: %s, size: %ld, isdir: %d, status: %d}", de->name ? de->name : "NULL", de->size, de->isdir, de->status);*/

        if (is_debug()) {
            if (i != de->status)
                debugf("update_cache_de: entry_lock_status CHANGED: %d ---> %d", i, de->status);
        }
    }

    return;
}

int insert_entry_to_cache(dir_entry *de)
{
    return __insert_entry_to_hashtable(de);
}

dir_entry* insert_dummy_entry_to_cache(const char *path, off_t size, int isdir, int status)
{
    dir_entry *de;

    de = get_dir_entry();
    if(de) {
        int i;
        pthread_mutex_lock(&(de->mtx));
        de->name = strdup(path);
        de->name_len = strlen(path);
        de->size = size;
        de->isdir = isdir; /*Dont to change isdir attribute of dir-entry*/
        de->status = status;
        de->cached_time = time(NULL);
        de->last_modified = de->cached_time;
        de->back_ptr = NULL;
        pthread_mutex_unlock(&(de->mtx));

        i = __insert_entry_to_hashtable(de);
        if (i < 0) {
            debugf("Warning, insert_dummy_entry_to_cache, but insert faild, calling return_dir_entry");
            return_dir_entry(de);
            de = NULL;
        }
    }

    return de;
}


void remove_de_from_cache(dir_entry *de)
{
    int i;

    if(__enable_cache_system__ == 0)
        return;  /* Zero is Okay*/

    if (!de)
        return;

    i = __delete_entry_from_hashtable(de);
    if (i < 0)
        debugf("Error, remove_de_from_cache failed, path: %s", de->name ? de->name : "NULL");

    return;
}

