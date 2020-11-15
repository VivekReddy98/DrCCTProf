#include <stdio.h>
#include <stdlib.h>

#define N 100

int main()
{
    int *A = (int *)malloc(N*sizeof(int));
    int *B = (int *)malloc(N*sizeof(int));

    int i;
    for (i = 0; i <= N; i++)
    {
        A[i] = 0;
        B[i] = i;
        A[i] += B[i];
    }
    return 0;
}