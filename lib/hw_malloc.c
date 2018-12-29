#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stddef.h>
#include <stdbool.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <fcntl.h>

#include "hw_malloc.h"

FILE *outputfile;

void *start_brk = NULL;
int chunk_num = 1; // count the number of chunk
int has_init=0;
int sp=1;
int mmap_init=1;

typedef void *chunk_ptr_t; //8bytes
//typedef long long chunk_info_t; //8bytes
typedef struct chunk_header chunk_header;
typedef struct chunk_info_t chunk_info_t;
typedef struct bin_t bin_t;
typedef struct mmap_node_t mmap_node_t;
typedef long long chunk_size_t;

struct mmap_node_t {
    chunk_ptr_t prev;
    chunk_ptr_t next;
    int size;
};

mmap_node_t mmap_head;
mmap_node_t *mmap_node;

struct bin_t {
    chunk_ptr_t prev;
    chunk_ptr_t next;
    int size;
};

bin_t s_bin[11] = {};
bin_t *bin[11];

struct chunk_info_t { //64bits=8bytes
    unsigned long int  prev_chunk_size:31;
    unsigned long int current_chunk_size:31;
    unsigned int alloc_flag:1;
    unsigned int mmap_flag:1;
};

struct chunk_header {
    chunk_ptr_t prev; //8bytes
    chunk_ptr_t next; //8bytes
    chunk_info_t size_and_flag; //8bytes
};

void *get_start_sbrk(void)
{
    return (void *)start_brk;
}

static int search_enbin(const chunk_size_t size)
{
    if(size==32)
        return 0;
    if(size==64)
        return 1;
    if(size==128)
        return 2;
    if(size==256)
        return 3;
    if(size==512)
        return 4;
    if(size==1024)
        return 5;
    if(size==2048)
        return 6;
    if(size==4096)
        return 7;
    if(size==8192)
        return 8;
    if(size==16384)
        return 9;
    if(size==32768)
        return 10;
}

static void en_bin(const int index, chunk_header *c_h)
{
    if (bin[index]->size == 0) {
        bin[index]->next = c_h;
        c_h->prev = bin[index];
        bin[index]->prev = c_h;
        c_h->next = bin[index];
    } else {
        chunk_header *tmp;
        chunk_header *cur;
        tmp = bin[index]->prev;
        bin[index]->prev = c_h;
        c_h->next = bin[index];
        tmp->next = c_h;
        c_h->prev = tmp;
    }
    bin[index]->size++;
}

static chunk_header *create_chunk(chunk_header *base, const chunk_size_t need)
{
    if ((void *)base - get_start_sbrk() + need > 64 * 1024) {
        printf("heap not enough\n");
        return NULL;
    }
    chunk_header *ret = base;
    ret->size_and_flag.current_chunk_size=need;
    ret->prev = NULL;
    ret->next = NULL;
    return ret;
}
static chunk_header *split(chunk_header **ori, const chunk_size_t need)
{
    chunk_header *upper;
    if(sp==1) {
        sp=0;
        upper=(void *)((intptr_t)(void*)(*ori) + 32768);
        upper->size_and_flag.prev_chunk_size=32768; //2^15
        upper->size_and_flag.current_chunk_size=32768; //2^15
        upper->size_and_flag.alloc_flag=0;
        upper->size_and_flag.mmap_flag=0;
        upper->prev=NULL;
        upper->next=NULL;
        en_bin(search_enbin(upper->size_and_flag.current_chunk_size), upper);
        chunk_num++;
    }
    //int n=32768;
    int n=(*ori)->size_and_flag.current_chunk_size;
    if(n==65536) {
        n=32768;
    }
    while(n>need) {
        upper=(void *)((intptr_t)(void*)(*ori) + n/2);
        upper->size_and_flag.prev_chunk_size=n/2;
        upper->size_and_flag.current_chunk_size=n/2;
        upper->size_and_flag.alloc_flag=0;
        upper->size_and_flag.mmap_flag=0;
        upper->prev=NULL;
        upper->next=NULL;
        en_bin(search_enbin(upper->size_and_flag.current_chunk_size), upper);
        chunk_num++;
        n=n/2;
    }
    chunk_header *ret = create_chunk((*ori), need);
    return ret;
}
int power(int a,int n)
{
    int r=1;
    for(int i=0; i<n; i++) {
        r=r*a;
    }
    return r;
}
static void rm_chunk_from_bin(chunk_header *c)
{
    /*Used to reconnect linked list when removing a chunk*/
    if (c->prev == bin[0] || c->prev == bin[1] ||
            c->prev == bin[2] || c->prev == bin[3] ||
            c->prev == bin[4] || c->prev == bin[5] ||
            c->prev == bin[6] || c->prev == bin[7] ||
            c->prev == bin[8] || c->prev == bin[9] ||c->prev == bin[10]) {
        ((bin_t *)c->prev)->next = c->next;
    } else {
        ((chunk_header *)c->prev)->next = c->next;
    }
    if (c->next == bin[0] || c->next == bin[1] ||
            c->next == bin[2] || c->next == bin[3] ||
            c->next == bin[4] || c->next == bin[5] ||
            c->next == bin[6] || c->next == bin[7] ||
            c->next == bin[8] || c->next == bin[9] ||c->next == bin[10]) {
        ((bin_t *)c->next)->prev = c->prev;
    } else {
        ((chunk_header *)c->next)->prev = c->prev;
    }
    c->prev = NULL;
    c->next = NULL;
}
static chunk_header *de_bin(const int index, const chunk_size_t need)
{
    if (bin[index]->size == 0) {
        printf("size = 0\n");
        return NULL;
    } else {
        chunk_header *ret;
        chunk_header *cur;
        ret = bin[index]->next;
        rm_chunk_from_bin(ret);
        bin[index]->size--;
        return ret;

        printf("de bin error\n");
        return NULL;
    }
}
static int search_debin(const chunk_size_t need)
{
    for (int i = 0; i <= 10; i++) {
        if (bin[i]->size == 0) {
            continue;
        }
        if (need <= power(2,i+5)) {
            return i;
        }
    }
    printf("not any free chunk\n");
    return -1;
}

void *hw_malloc(size_t bytes)
{
    //printf("%d\n",sizeof(chunk_header));
    //printf("%d\n",sizeof(chunk_ptr_t));
    //printf("%d\n",sizeof(chunk_info_t));
    //chunk_header t;
    //t.size_and_flag.prev_chunk_size=1;

    //fprintf(outputfile,"for test!\n");
    //chunk_size_t need = bytes + 40LL + (bytes % 8 != 0 ? (8 - (bytes % 8)) : 0);
    if(bytes+24<=32768) {
        chunk_size_t need;
        need=bytes+24;
        if(need<=32) {
            need=32;
        } else if(need<=64) {
            need=64;
        } else if(need<=128) {
            need=128;
        } else if(need<=256) {
            need=256;
        } else if(need<=512) {
            need=512;
        } else if(need<=1024) {
            need=1024;
        } else if(need<=2048) {
            need=2048;
        } else if(need<=4096) {
            need=4096;
        } else if(need<=8192) {
            need=8192;
        } else if(need<=16384) {
            need=16384;
        } else {
            need=32768;
        }

        if (!has_init) {
            has_init = true;
            for (int i = 0; i < 11; i++) {
                bin[i] = &s_bin[i];
                bin[i]->prev = bin[i];
                bin[i]->next = bin[i];
                bin[i]->size = 0;
            }
            start_brk = sbrk(64 * 1024);
            chunk_header *s = create_chunk(get_start_sbrk(), 64 * 1024);
            chunk_header *c = split(&s, need);
            c->size_and_flag.alloc_flag=1;
            c->size_and_flag.mmap_flag=0;
            c->size_and_flag.prev_chunk_size=0;
            outputfile=fopen("outputfile.txt","a");
            fprintf(outputfile,"0x%012" PRIxPTR "\n", (uintptr_t)(void *)((intptr_t)(void*)c +sizeof(chunk_header) - (intptr_t)(void*)get_start_sbrk()));
            //fprintf(outputfile,"0x%012lX\n",(uintptr_t)(void *)((intptr_t)(void*)c +sizeof(chunk_header) - (intptr_t)(void*)get_start_sbrk()));
            fclose(outputfile);
            return (void *)((intptr_t)(void*)c +sizeof(chunk_header));
        } else {
            chunk_header *r = NULL;
            int bin_num = search_debin(need);
            if (bin_num == -1) {
                printf("search debin error\n");
            } else {
                r = de_bin(bin_num, need);
                chunk_header *temp=NULL;
                temp=r;

                if(need<power(2,bin_num+5)) {
                    r=split(&r,need);
                }
                r->prev=NULL;
                r->next=NULL;
                r->size_and_flag.prev_chunk_size=temp->size_and_flag.prev_chunk_size;
                r->size_and_flag.alloc_flag=1;
                r->size_and_flag.mmap_flag=0;
                outputfile=fopen("outputfile.txt","a");
                fprintf(outputfile,"0x%012" PRIxPTR "\n", (uintptr_t)(void *)((intptr_t)(void*)r + sizeof(chunk_header) - (intptr_t)(void*)get_start_sbrk()));
                //fprintf(outputfile,"0x%012lX\n",(uintptr_t)(void *)((intptr_t)(void*)r + sizeof(chunk_header) - (intptr_t)(void*)get_start_sbrk()));
                fclose(outputfile);
                return (void *)((intptr_t)(void*)r + sizeof(chunk_header));
            }
        }
        return NULL;
    } else {
        chunk_header *mm=(chunk_header *)mmap(NULL,bytes+24,PROT_WRITE|PROT_READ,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
        mm->prev=NULL;
        mm->next=NULL;
        mm->size_and_flag.current_chunk_size=bytes+24;
        mm->size_and_flag.alloc_flag=1;
        mm->size_and_flag.mmap_flag=1;

        if(mmap_init==1) {
            mmap_init=0;
            mmap_node=&mmap_head;
            mmap_node->prev=mmap_node;
            mmap_node->next=mmap_node;
            mmap_node->size=0;
        }

        //insert mm into this mmap list
        if(mmap_node->size==0) {
            mmap_node->next=mm;
            mm->prev=mmap_node;
            mmap_node->prev=mm;
            mm->next=mmap_node;
        } else {
            int con=0;
            chunk_header *cur=mmap_node->next;
            while((void *)cur!=(void *)mmap_node) {
                if(cur->size_and_flag.current_chunk_size <= mm->size_and_flag.current_chunk_size) {
                    cur=cur->next;
                } else {
                    chunk_header *tmp=cur->prev;
                    tmp->next=mm;
                    mm->prev=tmp;
                    mm->next=cur;
                    cur->prev=mm;

                    con=1;
                    break;
                }
            }
            if(con==0) {
                chunk_header *tmp;
                tmp=mmap_node->prev;
                mmap_node->prev=mm;
                mm->next=mmap_node;
                tmp->next=mm;
                mm->prev=tmp;
            }
        }
        mmap_node->size++;

        outputfile=fopen("outputfile.txt","a");
        fprintf(outputfile,"0x%012" PRIxPTR "\n", (intptr_t)(void *)((intptr_t)(void*)mm + sizeof(chunk_header)-(intptr_t)(void*)get_start_sbrk()));
        fclose(outputfile);
        return (void *)((intptr_t)(void*)mm + sizeof(chunk_header));
    }
}

static int check_valid_free(const void *a_mem)
{
    chunk_header *cur = get_start_sbrk();
    int count = 0;
    while (count++ < chunk_num + 1) {
        if ((intptr_t)(void*)cur > (intptr_t)(void*)a_mem - 24) {
            return 0;
        }
        if (cur == a_mem - 24) {
            //void *nxt;
            //nxt = (void *)((intptr_t)(void*)cur + (intptr_t)(void*)cur->size_and_flag.current_chunk_size);
            if ((intptr_t)(void*)cur - (intptr_t)(void*)get_start_sbrk() <= 65536 && ((chunk_header *)cur)->size_and_flag.alloc_flag == 1) {
                return 1;
            } else {
                return 0;
            }
        }
        cur = (void *)((intptr_t)(void*)cur + (intptr_t)(void*)cur->size_and_flag.current_chunk_size);
    }
    return 0;
}

static chunk_header *merge(chunk_header *h)
{
    chunk_header *prv = (chunk_header *)((intptr_t)(void*)h - (intptr_t)(void*)((chunk_header *)h)->size_and_flag.current_chunk_size);
    chunk_header *nxt = (chunk_header *)((intptr_t)(void*)h + (intptr_t)(void*)((chunk_header *)h)->size_and_flag.current_chunk_size);
    chunk_header *nnxt = (chunk_header *)((intptr_t)(void*)nxt + (intptr_t)(void*)((chunk_header *)nxt)->size_and_flag.current_chunk_size);

    if (prv->size_and_flag.alloc_flag == 0 && h->size_and_flag.current_chunk_size==prv->size_and_flag.current_chunk_size) {
        //printf("1\n");
        nxt->size_and_flag.prev_chunk_size += prv->size_and_flag.current_chunk_size;
        //printf("2\n");
        rm_chunk_from_bin(prv);
        //printf("3\n");
        bin[search_enbin(prv->size_and_flag.current_chunk_size)]->size--;
        //printf("4\n");
        prv->size_and_flag.current_chunk_size += h->size_and_flag.current_chunk_size;
        //printf("5\n");
        h->size_and_flag.current_chunk_size = 0;
        //printf("8\n");
        chunk_num--;
        prv->prev=NULL;
        prv->next=NULL;
        prv->size_and_flag.alloc_flag=0;
        prv->size_and_flag.mmap_flag=0;
        return prv;
    }
    if (nxt->size_and_flag.alloc_flag == 0 && h->size_and_flag.current_chunk_size==nxt->size_and_flag.current_chunk_size) {
        /*If next chunk is free and its size is the same as current chunk(h), being able to merge*/
        //printf("9\n");
        //printf("nnxt->size_and_flag.prev_chunk_size=%d\n",nnxt->size_and_flag.prev_chunk_size);
        nnxt->size_and_flag.prev_chunk_size += h->size_and_flag.current_chunk_size;
        //printf("10\n");
        rm_chunk_from_bin(nxt);
        //printf("11\n");
        bin[search_enbin(nxt->size_and_flag.current_chunk_size)]->size--;
        //printf("12\n");
        h->size_and_flag.current_chunk_size += nxt->size_and_flag.current_chunk_size;
        //printf("13\n");
        nxt->size_and_flag.current_chunk_size = 0;
        //printf("16\n");
        chunk_num--;
        h->prev=NULL;
        h->next=NULL;
        h->size_and_flag.alloc_flag=0;
        h->size_and_flag.mmap_flag=0;
        return h;
    } else {
        //printf("17\n");
        h->prev = NULL;
        //printf("18\n");
        h->next = NULL;
        //printf("19\n");
        return h;
    }
}

int hw_free(void *mem)
{
    if(mmap_init==1) {
        mmap_init=0;
        mmap_node=&mmap_head;
        mmap_node->prev=mmap_node;
        mmap_node->next=mmap_node;
        mmap_node->size=0;
    }
    int heap_con=0;
    int mmap_con=0;
    //printf("111\n");
    void *a_mem = (void *)((intptr_t)(void*)mem + (intptr_t)(void*)get_start_sbrk());
    //printf("222\n");
    chunk_header *n = (chunk_header *)((intptr_t)(void*)a_mem - (intptr_t)(void*)sizeof(chunk_header));
    //printf("333\n");
    if(n!=NULL) {
        //printf("444\n");
        //printf("n->size_and_flag.mmap_flag=%d\n",n->size_and_flag.mmap_flag);
        if(n->size_and_flag.mmap_flag==0&&n->size_and_flag.alloc_flag==1) {
            heap_con=1;
        } else if(n->size_and_flag.mmap_flag==1&&n->size_and_flag.alloc_flag==1) {
            mmap_con=1;
        }
    }

    /*void *b_mem = (void *)((intptr_t)(void*)mem);
    chunk_header *nn = (chunk_header *)((intptr_t)(void*)b_mem - (intptr_t)(void*)sizeof(chunk_header));
    if(nn!=NULL)
    {
    	printf("555\n");
    	printf("nn->size_and_flag.mmap_flag=%d\n",nn->size_and_flag.mmap_flag);
    	if(nn->size_and_flag.mmap_flag==1)
    	{
    		mmap_con=1;
    	}
    }*/


    if(heap_con==1) {
        //printf("Into heap free\n");
        if (!has_init || !check_valid_free(a_mem)) {
            outputfile=fopen("outputfile.txt","a");
            fprintf(outputfile,"fail\n");
            fclose(outputfile);
            return 0;
        } else {
            chunk_header *h = (chunk_header *)((intptr_t)(void*)a_mem - (intptr_t)(void*)sizeof(chunk_header));
            //chunk_header *nxt = (chunk_header *)((intptr_t)(void*)h + (intptr_t)(void*)((chunk_header *)h)->size_and_flag.current_chunk_size);
            //nxt->prev_free_flag = 1;
            h->size_and_flag.alloc_flag=0;
            chunk_header *m=NULL;
            if(h->size_and_flag.current_chunk_size==32768) {
                h->prev = NULL;
                h->next = NULL;
                en_bin(search_enbin(h->size_and_flag.current_chunk_size), h);
                outputfile=fopen("outputfile.txt","a");
                fprintf(outputfile,"success\n");
                fclose(outputfile);
                return 1;
            } else {
start:
                m = merge(h);
                en_bin(search_enbin(m->size_and_flag.current_chunk_size), m);
                chunk_header *prv = (chunk_header *)((intptr_t)(void*)m - (intptr_t)(void*)((chunk_header *)m)->size_and_flag.current_chunk_size);
                chunk_header *nxt = (chunk_header *)((intptr_t)(void*)m + (intptr_t)(void*)((chunk_header *)m)->size_and_flag.current_chunk_size);
                if((prv->size_and_flag.alloc_flag == 0 && m->size_and_flag.current_chunk_size==prv->size_and_flag.current_chunk_size)||(nxt->size_and_flag.alloc_flag == 0 && m->size_and_flag.current_chunk_size==nxt->size_and_flag.current_chunk_size) ) {
                    if(m->size_and_flag.current_chunk_size<32768) {
                        h=m;
                        rm_chunk_from_bin(h);
                        bin[search_enbin(h->size_and_flag.current_chunk_size)]->size--;
                        goto start;
                    }
                }
                outputfile=fopen("outputfile.txt","a");
                fprintf(outputfile,"success\n");
                fclose(outputfile);
                return 1;
            }
        }
    }



    else if(mmap_con==1) {
        //printf("ddd\n");
        if(n->size_and_flag.alloc_flag==1&&n->size_and_flag.mmap_flag==1) {
            chunk_header *cur=mmap_node->next;
            //printf("d\n");
            while((void *)cur!=(void *)mmap_node) {
                //printf("e\n");
                if(cur==n&&cur->size_and_flag.current_chunk_size==n->size_and_flag.current_chunk_size&&cur->size_and_flag.alloc_flag==1&&cur->size_and_flag.mmap_flag==1) {
                    //printf("1\n");
                    chunk_header *p=cur->prev;
                    //printf("2\n");
                    chunk_header *nnn=cur->next;
                    //printf("3\n");
                    p->next=nnn;
                    //printf("4\n");
                    nnn->prev=p;
                    //printf("5\n");
                    cur->next=NULL;
                    //printf("6\n");
                    cur->prev=NULL;
                    //printf("7\n");
                    munmap((intptr_t)(void *)cur,cur->size_and_flag.current_chunk_size);
                    //printf("8\n");
                    //free(cur);
                    outputfile=fopen("outputfile.txt","a");
                    fprintf(outputfile,"success\n");
                    fclose(outputfile);
                    return 1;
                }
                cur=cur->next;
            }
        }

    }
    outputfile=fopen("outputfile.txt","a");
    fprintf(outputfile,"fail\n");
    fclose(outputfile);
    return 0;
}

void show_bin(const int i)
{
    if (!has_init) {
        return;
    }
    chunk_header *cur = bin[i]->next;
    while ((void *)cur != (void *)bin[i]) {
        void *r_cur = (void *)((intptr_t)(void*)cur - (intptr_t)(void*)get_start_sbrk());
        outputfile=fopen("outputfile.txt","a");
        fprintf(outputfile,"0x%012" PRIxPTR "--------%d\n", (uintptr_t)r_cur, cur->size_and_flag.current_chunk_size);
        //fprintf(outputfile,"0x%012lX--------%d\n",(uintptr_t)r_cur, cur->size_and_flag.current_chunk_size);
        fclose(outputfile);
        cur = cur->next;
    }
}

void show_mmap_alloc_list()
{
    if(mmap_init==1) {
        mmap_init=0;
        mmap_node=&mmap_head;
        mmap_node->prev=mmap_node;
        mmap_node->next=mmap_node;
        mmap_node->size=0;
    }

    if(mmap_node->size==0) {
        return;
    }
    chunk_header *cur=mmap_node->next;
    while((void *)cur!=(void *)mmap_node) {
        outputfile=fopen("outputfile.txt","a");
        fprintf(outputfile,"0x%012" PRIxPTR "--------%d\n", ((intptr_t)(void*)cur),cur->size_and_flag.current_chunk_size);
        fclose(outputfile);
        cur=cur->next;
    }
}
