#ifndef _CLOUDFSCACHE_H
#define _CLOUDFSCACHE_H

#include <string.h>
#include <pthread.h>

#define MAX_HASHENTRIES       (10301)
#define MAX_HASHLIST_LEN      (7)
#define MAX_DIRENTRIES_CNT    (MAX_HASHENTRIES * MAX_HASHLIST_LEN) 

#define ENTRY_UNLOCKED  0
#define ENTRY_LOCKED    1 
#define ENTRY_IDLE      2 

struct list_node {
    struct list_node *next;
    struct list_node *prev;
};

typedef int (*key_cmp_func_t)(const void *s1, size_t s1len, const void *s2, size_t keylen);
typedef int (*hash_func_t)(const char *key, size_t keylen);

struct hash_entry_head {
    pthread_rwlock_t  hlist_lock;
    struct list_node hlist;
};

struct lru_manager_t {
    pthread_mutex_t lru_lock;
    struct list_node lru_head;
};

struct hashtable_t {
    key_cmp_func_t  key_matcher;
    hash_func_t  hash;

    pthread_mutex_t de_total_lock;
    int de_total_cnt;

    struct hash_entry_head *table;

    struct lru_manager_t lru_manager; 
};

typedef struct __dir_entry
{
  char *name;
  int name_len;
  char *content_type;
  off_t size;
  time_t last_modified;
  time_t cached_time;
  int isdir;
  int status; /*locked: cannot be freed from lru-list, unlocked: can be freed from lru-list*/
  pthread_mutex_t mtx;

  struct hash_entry_head *back_ptr;

  struct list_node hash_list;
  struct list_node lru_list;

} dir_entry;

typedef struct __tmp_dir_entry
{
  char *name;
  int name_len;
  char *content_type;
  off_t size;
  time_t last_modified;
  time_t cached_time;
  int isdir;
  int status; /*locked: cannot be freed from lru-list, unlocked: can be freed from lru-list*/
  struct hash_entry_head *back_ptr;
} tmp_dir_entry;


#define the_offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)

/**
 ** container_of - cast a member of a structure out to the containing structure
 ** @ptr: the pointer to the member.
 ** @type: the type of the container struct this is embedded in.
 ** @member: the name of the member within the struct.
 **
 **/
#define container_of(ptr, type, member) ({                     \
    const typeof( ((type *)0)->member ) *__mptr = (ptr);       \
    (type *)( (char *)__mptr - the_offsetof(type,member) );})

#define list_entry(ptr, type, member) \
            container_of(ptr, type, member)

#define list_for_each(pos, head) \
    for (pos = (head)->next; pos != (head); pos = pos->next)

static inline void init_list_node(struct list_node *node)
{
    node->next = node;
    node->prev = node;
}

static inline void __list_add(struct list_node *new, struct list_node *prev, struct list_node *next)
{
    next->prev = new;
    new->next = next;
    new->prev = prev;
    prev->next = new;
}

/**
 ** list_add - add a new entry
 ** @new: new entry to be added
 ** @head: list head to add it after
 **
 ** Insert a new entry after the specified head.
 ** This is good for implementing stacks.
 **/
static inline void list_add(struct list_node *new, struct list_node *head)
{
    __list_add(new, head, head->next);
}

static inline void __list_del(struct list_node * prev, struct list_node * next)
{
    next->prev = prev;
    prev->next = next;
}

static inline void list_del(struct list_node *entry)
{
    __list_del(entry->prev, entry->next);
    init_list_node(entry);
}

/**
 ** list_empty - tests whether a list is empty
 ** @head: the list to test.
 **/
static inline int list_empty(const struct list_node *head)
{
    return head->next == head;
}

int build_hash_table(void);
dir_entry* check_cache_ex(const char *key, int key_len, tmp_dir_entry *de);
int insert_entry_to_cache(dir_entry *de);

void update_cached_de(dir_entry *de, tmp_dir_entry *src_de);
void set_de_status(dir_entry *de, int s);
void remove_de_from_cache(dir_entry *de);

#endif

