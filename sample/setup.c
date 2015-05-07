//****************************************************************************
//public_g  -> gen(g), gen1(g1), gen2(g2)
//public_u  -> u(u'), U
//secret  -> S
//****************************************************************************

#include <stdio.h>
#include <string.h>
#include <time.h>

#define usize 32

int main(void){
   char in1[256] = "./waters_test/public_file";
   char in2[256] = "./waters_test/secret_file";

   clock_t start, end;
   double extime;

	start = clock();
	setup(in1, in2, usize);
	end = clock();
	extime = (double)((end - start)*1000)/ CLOCKS_PER_SEC;

	printf("exec SETUP: %lf\n", extime);

}
