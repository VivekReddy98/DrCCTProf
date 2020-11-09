/*
 *  Copyright (c) 2020 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */

#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>

int main(){
   char *test_malloc = (char *)malloc(20*sizeof(char));
   char *test_calloc = (char *)calloc(20, sizeof(char));

   test_malloc[20] = 'a';
   test_calloc[20] = 'c';

   free(test_malloc);
   free(test_calloc);
   return 0;
}
