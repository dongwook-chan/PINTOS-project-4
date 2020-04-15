#include <stdio.h>
#include <stdlib.h>
#include <syscall.h>

int
main (int argc, char **argv)
{
  if(argc < 2)
    return EXIT_FAILURE;

  int int_argv[4] = {0};
  int i;

  for(i = 0; i < argc - 1 && i < 4; ++i)
    int_argv[i] = atoi(argv[i + 1]);
  
  printf ("%d ", pibonacci(int_argv[0]));
  printf ("%d\n", sum_of_four_integers(int_argv[0], int_argv[1], int_argv[2], int_argv[3]));

  return EXIT_SUCCESS;
}
