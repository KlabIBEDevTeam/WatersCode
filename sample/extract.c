//****************************************************************************
//public_g  -> gen(g), gen1(g1), gen2(g2)
//public_u  -> u(u'), U
//secret  -> S
//private -> d1, d2
//userID  -> u_id
//****************************************************************************

#include <stdio.h>
#include <string.h>
#include <time.h>

#define usize 32

int main(void){
   char in1[256] = "./waters_test/public_file";
   char in2[256] = "./waters_test/secret_file";
   char in3[256] = "./waters_test/private_file";
   char *in4 = "abcd";
   char in5[256] = "./waters_test/user_data/user_file";

   clock_t start, end;
   double extime;

	start = clock();
	extract(in1, in2, in3, in4, in5, usize);
	end = clock();
	extime = (double)((end - start)*1000)/ CLOCKS_PER_SEC;

	printf("exec EXTRACT: %lf\n", extime);

}

