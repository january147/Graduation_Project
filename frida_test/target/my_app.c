#include<stdio.h>
#include<unistd.h>

int funcUsedtoHook(int arg){
    arg++;
    printf("Number: %d\n",arg);
    return arg;
}

int main(){
    int i = 0;
    printf("the func is at %p",funcUsedtoHook);

    while(1){
        i = funcUsedtoHook(i);
        sleep(1);
    }

    return 0;
}
