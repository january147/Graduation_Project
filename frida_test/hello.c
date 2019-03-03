#include<stdio.h>
#include<unistd.h>

int funcUsedtoHook(int arg){
    arg++;
    printf("Number: %d",arg);
    return arg;
}

int main(){
    int i = 0;
    printf("the fun\nc is at %p",funcUsedtoHook);

    while(1){
        i = funcUsedtoHook(i);
        sleep(1);
    }

    return 0;
}
