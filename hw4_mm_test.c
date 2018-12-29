#include "lib/hw_malloc.h"
#include "hw4_mm_test.h"
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include <stddef.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdbool.h>
FILE *testfile;

int main(int argc, char *argv[])
{
    char a[100];
    char b[100];
    size_t N;
    testfile=fopen("testfile.txt","w");

    scanf(" %s %s", a, b);
    while(!feof(stdin)) {
        fprintf(testfile,"%s %s\n",a,b);
        if(strcmp("print",a)==0) {
            if(strcmp("mmap_alloc_list",b)==0) { //print mmap_alloc_list
                show_mmap_alloc_list();
            } else { //print bin[i]
                if(b[4]=='0') {
                    show_bin(0);
                } else if(b[4]=='1'&&b[5]!='0') {
                    show_bin(1);
                } else if(b[4]=='2') {
                    show_bin(2);
                } else if(b[4]=='3') {
                    show_bin(3);
                } else if(b[4]=='4') {
                    show_bin(4);
                } else if(b[4]=='5') {
                    show_bin(5);
                } else if(b[4]=='6') {
                    show_bin(6);
                } else if(b[4]=='7') {
                    show_bin(7);
                } else if(b[4]=='8') {
                    show_bin(8);
                } else if(b[4]=='9') {
                    show_bin(9);
                } else {
                    show_bin(10);
                }
            }
        } else if(strcmp("alloc",a)==0) { //alloc N
            N=atoi(b);
            hw_malloc(N);
        } else if(strcmp("free",a)==0) { //free 0x000000000018
            void *mem=(void *)(uintptr_t)strtol(b,NULL,16);
            hw_free(mem);
        } else {
            printf("command error!\n");
        }
        scanf(" %s %s", a, b);
    }
    fclose(testfile);
    return 0;
}
