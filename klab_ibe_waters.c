#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <tepla/ec.h>

#define MAX_STRLEN 1200 //ras&(extract,encrypt,decrypt)&256bit

#define rep(x) (*((mpz_t *)x->data))
#define rep0(x) (((Element *)x->data)[0])
#define rep1(x) (((Element *)x->data)[1])
#define rep2(x) (((Element *)x->data)[2])

#define field(x) (x->field)
#define order(x) (x->field->order)


char *b64_encode(char *s, int size);
char *b64_decode(char *s, int size);

char b64_itoc(int i);
int b64_ctoi(char c);

char btoc(char *b, int len);
void ctob(char *b, char *c, int ofst, int len);
char bitat(char *c, int ofst);

void setup(const unsigned char *public, const unsigned char *secret, const unsigned int u_bit);
void extract(const unsigned char *public, const unsigned char *secret, const unsigned char *private, const unsigned char *userID, const unsigned char *userfile, const unsigned int u_bit);
void encrypt(const unsigned char *public, const unsigned char *userID, const unsigned char *encrypt, const unsigned char *message, const size_t mlength);
void decrypt(const unsigned char *private, const unsigned char *encrypt, const unsigned char *decrypted);

void g3_to_mpz(mpz_t a, const Element x);
void g3_to_oct(unsigned char *os, size_t *size, const Element x);
void g3_from_oct(Element x, const unsigned char *os, const size_t size);

void setup(const unsigned char *public, const unsigned char *secret, const unsigned int u_bit) {
	
	EC_PAIRING p;
	pairing_init(p, "ECBN254");
	
	mpz_t a, order;
	int i;

	EC_POINT gen, gen1;	

	EC_POINT gen2, u;	
	EC_POINT U[u_bit];	
	EC_POINT S;	

	gmp_randstate_t state;
	gmp_randinit_default(state);
	gmp_randseed_ui(state, (unsigned long)time(NULL));

	mpz_init(order);
	mpz_set(order, *pairing_get_order(p));

	FILE *out_pub1, *out_sec;

	mpz_init(a);
	mpz_urandomm(a, state, order);

	point_init(gen, p->g1);
	point_init(gen1, p->g1);
	point_init(gen2, p->g2);
	point_init(u, p->g2);
	for(i=0; i<u_bit; i++) {
		point_init(U[i], p->g2);
	}
	
	point_random(gen);
	point_mul(gen1, a, gen);
	point_random(gen2);
	point_random(u);
	for(i=0; i<u_bit; i++) {
		point_random(U[i]);
	}

	point_init(S, p->g2);
	point_mul(S, a, gen2);

	out_pub1 = fopen(public, "w");
	if(out_pub1 == NULL) {
		printf("cannot open\n");
		exit(1);
	}

	int pub_len1 = point_get_str_length(gen);
	int pub_len2 = point_get_str_length(gen1);
	int pub_len3 = point_get_str_length(gen2);

	char *pub1 = (char *)malloc(sizeof(char)*pub_len1);
	char *pub2 = (char *)malloc(sizeof(char)*pub_len2);
	char *pub3 = (char *)malloc(sizeof(char)*pub_len3);

	point_get_str(pub1, gen);
	point_get_str(pub2, gen1);
	point_get_str(pub3, gen2);

	fprintf(out_pub1, "%s\n%s\n%s\n", pub1, pub2, pub3);
	
	int pub_len4 = point_get_str_length(u);
	char *pub4 = (char *)malloc(sizeof(char)*pub_len4);
	point_get_str(pub4, u);

	fprintf(out_pub1, "%s", pub4);

	int pub_len5;
	char *pub5;
	for(i=0; i<u_bit; i++) {
		pub_len5 = point_get_str_length(U[i]);
		pub5 = (char *)malloc(sizeof(char)*pub_len5);
		point_get_str(pub5, U[i]);

		fprintf(out_pub1, "\n%s", pub5);
	}

	fclose(out_pub1);

	out_sec = fopen(secret, "w");
	if(out_sec == NULL) {
		printf("cannot open\n");
		exit(1);
	}

	int sec_len = point_get_str_length(S);
	char *sec = (char *)malloc(sizeof(char)*sec_len);
	point_get_str(sec, S);

	fprintf(out_sec, "%s",sec);

	fclose(out_sec);

}
	
void extract(const unsigned char *public, const unsigned char *secret, const unsigned char *private, const unsigned char *userID, const unsigned char *userfile, const unsigned int u_bit) {

	EC_PAIRING p;
	pairing_init(p, "ECBN254");

	int i;

	FILE *in_pub1, *in_sec, *out_pri, *out_user;

	in_pub1 = fopen(public, "r");
	if(in_pub1 == NULL) {
		printf("cannot open\n");
		exit(1);
	}

	char readline1[MAX_STRLEN];
	char readline2[MAX_STRLEN];
	char readline3[MAX_STRLEN];

	fgets(readline1, MAX_STRLEN, in_pub1);
	fgets(readline2, MAX_STRLEN, in_pub1);
	fgets(readline3, MAX_STRLEN, in_pub1);

	EC_POINT gen, gen1;
	EC_POINT gen2;

	point_init(gen, p->g1);
	point_init(gen1, p->g1);
	point_init(gen2, p->g2);

	point_set_str(gen, readline1);
	point_set_str(gen1, readline2);
	point_set_str(gen2, readline3);

	char readline4[MAX_STRLEN];
	fgets(readline4, MAX_STRLEN, in_pub1);

	EC_POINT u;	
	point_init(u, p->g2);
	point_set_str(u, readline4);

	char readline[u_bit][MAX_STRLEN];
	for(i=0; i<u_bit; i++) {
		fgets(readline[i], MAX_STRLEN, in_pub1);
	}
	fclose(in_pub1);

	EC_POINT U[u_bit];
	for(i=0; i<u_bit; i++) {
		point_init(U[i], p->g2);
		point_set_str(U[i], readline[i]);
	}
	
	in_sec = fopen(secret, "r");
	if(in_sec == NULL) {
		printf("cannot open\n");
		exit(1);
	}

	char readline5[MAX_STRLEN];
	fgets(readline5, MAX_STRLEN, in_sec);

	fclose(in_sec);

	EC_POINT S;
	point_init(S, p->g2);
	point_set_str(S, readline5);

	mpz_t r, order;
	unsigned long n;

	EC_POINT d2;

	EC_POINT u_id;
	EC_POINT d1;
	EC_POINT tmp1;
	EC_POINT tmp2;

	gmp_randstate_t state;
	gmp_randinit_default(state);
	gmp_randseed_ui(state, (unsigned long)time(NULL));
	mpz_init(r);
	mpz_init(order);
	mpz_set(order, *pairing_get_order(p));

	mpz_urandomm(r, state, order);

    int idsize;
    idsize = (int)(u_bit/8.0);
    idsize = ((u_bit/8.0)-(double)idsize) ? idsize+1 : idsize;
    
	int v[u_bit];
	for(i=0; i<u_bit; i++) {
		v[i] = (userID[i/8] >> i%8) & 0x1;
	}

	point_init(u_id, p->g2);
	point_init(tmp1, p->g2);

	for(i=0; i<u_bit; i++) {
		if(v[i]!=0) {
			point_add(tmp1, tmp1, U[i]);
		}
	}
	point_add(u_id, u, tmp1);

	point_init(d1, p->g2);
	point_init(d2, p->g1);
	point_init(tmp2, p->g2);

	point_mul(tmp2, r, u_id);
	point_add(d1, S, tmp2);

	point_mul(d2, r, gen);

	out_pri = fopen(private, "w");
	if(out_pri == NULL) {
		printf("cannot open\n");
		exit(1);
	}

	int pri_len1 = point_get_str_length(d1);
	int pri_len2 = point_get_str_length(d2);
	char *pri1 = (char *)malloc(sizeof(char)*pri_len1);
	char *pri2 = (char *)malloc(sizeof(char)*pri_len2);
	point_get_str(pri1, d1);
	point_get_str(pri2, d2);

	fprintf(out_pri, "%s\n%s", pri1, pri2);

	fclose(out_pri);

	out_user = fopen(userfile, "w");
	if(out_user == NULL) {
		printf("cannot open\n");
		exit(1);
	}

	int user_len = point_get_str_length(u_id);
	char *user = (char *)malloc(sizeof(char)*user_len);
	point_get_str(user, u_id);

	fprintf(out_user, "%s", user);

	fclose(out_user);

}

void encrypt(const unsigned char *public, const unsigned char *userfile, const unsigned char *encrypt, const unsigned char *message, const size_t mlength) {

	EC_PAIRING p;
	pairing_init(p, "ECBN254");

	FILE *in_pub, *in_user, *out_enc;

	in_pub = fopen(public, "r");
	if(in_pub == NULL) {
		printf("cannot open\n");
		exit(1);
	}
	
	char readline1[MAX_STRLEN];
	char readline2[MAX_STRLEN];
	char readline3[MAX_STRLEN];

	fgets(readline1, MAX_STRLEN, in_pub);
	fgets(readline2, MAX_STRLEN, in_pub);
	fgets(readline3, MAX_STRLEN, in_pub);

	fclose(in_pub);

	EC_POINT gen, gen1;
	EC_POINT gen2;

	point_init(gen, p->g1);
	point_init(gen1, p->g1);
	point_init(gen2, p->g2);

	point_set_str(gen, readline1);
	point_set_str(gen1, readline2);
	point_set_str(gen2, readline3);


	in_user = fopen(userfile, "r");
	if(in_user == NULL) {
		printf("cannot open\n");
		exit(1);
	}

	char readline[MAX_STRLEN];
	fgets(readline, MAX_STRLEN, in_user);

	fclose(in_user);

	EC_POINT u_id;
	point_init(u_id, p->g2);
	point_set_str(u_id, readline);

	mpz_t t,order;
	EC_POINT c2;
	EC_POINT c3;
	Element tmp1;
	Element tmp2;
	Element m;

	gmp_randstate_t state;
	gmp_randinit_default(state);
	gmp_randseed_ui(state, (unsigned long)time(NULL));

	mpz_init(t);
	mpz_init(order);
	mpz_set(order, *pairing_get_order(p));

	mpz_urandomm(t, state, order);

	point_init(c2, p->g1);
	point_init(c3, p->g2);
	element_init(tmp1, p->g3);
	element_init(tmp2, p->g3);
	element_init(m, p->g3);

	pairing_map(tmp2, gen1, gen2, p);
	element_pow(tmp1, tmp2, t);

	int msize;
	//msize = element_get_oct_length(m);
	msize = 380;
	
	int c1size;
    c1size = (int)(mlength/(double)msize);
    c1size = ((mlength/(double)msize)-(double)c1size) ? c1size+1 : c1size;
	
	
	int m_split;
	int surplus;
	int ai, aj;
	m_split = strlen(message)/msize;
	surplus = strlen(message)%msize;

	if(surplus !=0)m_split++;

	Element *c1 = (Element *)malloc(sizeof(Element)*c1size);	
	
	int i;
	for(i=0;i<c1size;i++){
		element_init(c1[i], p->g3);
		unsigned char *M = (unsigned char *)malloc(msize);	
		int j;
		for(j=0;j<msize;j++){
			M[j] = 0x00;
		}
		
		strncpy(M, message+i*msize, msize);
		
		if(strlen(M)!=msize){
			int k;
			for(k=strlen(M);k<msize;k++){
				M[k] = 0;
			}
		}

		element_init(m, p->g3);
		g3_from_oct(m, M, msize);
		
		element_mul(c1[i], tmp1, m);
	}
	
	point_mul(c2, t, gen);
	point_mul(c3, t, u_id);

	out_enc = fopen(encrypt, "w");
	if(out_enc == NULL) {
		printf("cannot open\n");
		exit(1);
	}

	int enc_len2 = point_get_str_length(c2);
	int enc_len3 = point_get_str_length(c3);
	char *enc2 = (char *)malloc(sizeof(char)*enc_len2);
	char *enc3 = (char *)malloc(sizeof(char)*enc_len3);
	point_get_str(enc2, c2);
	point_get_str(enc3, c3);

	fprintf(out_enc, "%s\n%s\n", enc2, enc3);

	for(i=0;i<c1size;i++){
		
		int enc_len1 = element_get_str_length(c1[i]);
		char *enc1 = (char *)malloc(sizeof(char)*enc_len1);
		
		element_get_str(enc1, c1[i]);
		fprintf(out_enc,"%s", enc1);

		if(i<c1size-1){
			fprintf(out_enc,"\n");
		}
	}

	fclose(out_enc);

}

void decrypt(const unsigned char *private, const unsigned char *encrypt, const unsigned char *decrypted) {
	
	EC_PAIRING p;
	pairing_init(p, "ECBN254");
	
	FILE *in_pri, *in_enc, *out_dec;

	in_pri = fopen(private, "r");
	if(in_pri == NULL) {
		printf("cannot open\n");
		exit(1);
	}

	char readline1[MAX_STRLEN];
	char readline2[MAX_STRLEN];

	fgets(readline1, MAX_STRLEN, in_pri);
	fgets(readline2, MAX_STRLEN, in_pri);

	fclose(in_pri);

	EC_POINT d1;
	EC_POINT d2;
	point_init(d1, p->g2);
	point_init(d2, p->g1);
	point_set_str(d1, readline1);
	point_set_str(d2, readline2);

	in_enc = fopen(encrypt, "r");
	if(in_enc == NULL) {
		printf("cannot open\n");
		exit(1);
	}

	char readline3[MAX_STRLEN];
	char readline4[MAX_STRLEN];
	char readline5[MAX_STRLEN];

	fgets(readline4, MAX_STRLEN, in_enc);
	fgets(readline5, MAX_STRLEN, in_enc);

	Element c1;
	EC_POINT c2;
	EC_POINT c3;
	element_init(c1, p->g3);
	point_init(c2, p->g1);
	point_init(c3, p->g2);

	point_set_str(c2, readline4);
	point_set_str(c3, readline5);

	Element tmp1;
	Element tmp2;
	Element tmp3;
	Element tmp4;
	Element tmp5;

	element_init(tmp1, p->g3);
	element_init(tmp2, p->g3);
	element_init(tmp3, p->g3);
	element_init(tmp4, p->g3);
	element_init(tmp5, p->g3);

	pairing_map(tmp3, d2, c3, p);
	pairing_map(tmp4, c2, d1, p);
	element_inv(tmp5, tmp4);

	element_mul(tmp2, tmp3, tmp5);

	out_dec = fopen(decrypted, "wb");
	if(out_dec == NULL) {
		printf("cannot open\n");
		exit(1);
	}

	int g3size;
	g3size = 380;

	while(fgets(readline3, MAX_STRLEN, in_enc)!=NULL){
		element_init(c1, p->g3);
		element_set_str(c1, readline3);
		
		element_mul(tmp1, c1, tmp2);
		unsigned char *check = (unsigned char *)malloc(g3size);
		size_t check_len;
		
		g3_to_oct(check, &check_len, tmp1);

		int nullindex=check_len;
		int i;
		for(i=0;i<check_len;i++){
			if(check[i]==0x00){
				nullindex = i;
				i=check_len;
			}
		}
		fwrite(check, sizeof(unsigned char), nullindex, out_dec);
	}

	fclose(in_enc);
	fclose(out_dec);

}


char *b64_encode(char *s, int size){
   int i, ensize = (8 * size + 5) / 6; 
   char b[6 * ensize];
   int eqsize = (ensize + 3) / 4 * 4 - ensize; 
   char *en = (char *)malloc(sizeof(char) * (ensize + eqsize + 1));
   char s0[size + 1];
   memcpy(s0, s, size);
   s0[size] = 0;
   ctob(b, s0, 0, 6 * ensize); 
   for(i = 0; i < ensize; ++i) en[i] = b64_itoc((int)btoc(b + i * 6, 6)); 
   for(i = 0; i < eqsize; ++i) en[ensize + i] = '=';
   en[ensize + eqsize] = '\0';
   return en;
}

char *b64_decode(char *s, int size){
   int i, tsize = 4 * ((size * 3) / 4);
   char c[tsize];
   for(i = 0; i < size; ++i) c[i] = b64_ctoi(s[i]);
   for(i = size; i < tsize; ++i) c[i] = 0;
   char b[6 * tsize];
   for(i = 0; i < tsize; ++i) ctob(b + 6 * i, c + i, 2, 6); // read 6 char for each c with ofst 2
   char *de = (char *)malloc(sizeof(char) * (tsize / 4 * 3 + 1));
   for(i = 0; i < tsize / 4 * 3; ++i) de[i] = btoc(b + 8 * i, 8); // get c from b
   de[tsize / 4 * 3] = '\0';
   return de;
}


char b64_itoc(int i){
   if(i <= 25) return 'A' + i;
   if(i <= 51) return 'a' + i - 26;
   if(i <= 61) return '0' + i - 52;
   if(i == 62) return '+';
   return '/';
}

int b64_ctoi(char c){
   if('A' <= c && c <= 'Z') return c - 'A';
   if('a' <= c && c <= 'z') return c - 'a' + 26;
   if('0' <= c && c <= '9') return c - '0' + 52;
   if(c == '+') return 62;
   if(c == '/') return 63;
   return 0;
}

char btoc(char *b, int len){
   int i;
   char c = 0;
   for(i = 0; i < len; ++i){c <<= 1; c |= b[i];}
   return c;
}

void ctob(char *b, char *c, int ofst, int len){
   int k;
   for(k = 0; k < len; ++k) b[k] = bitat(c, ofst + k);
}

char bitat(char *c, int ofst){
   c += ofst / 8;
   return ((*c) >> (7 - ofst % 8)) & 1;
}


void g3_to_mpz(mpz_t a, const Element x)
{
	mpz_mul(a, rep(rep1(rep2(rep1(x)))), field(x)->base->base->base->order);   // a = rep121*p
	mpz_add(a, a, rep(rep1(rep1(rep1(x)))));   // a = a + rep111
	mpz_mul(a, a, field(x)->base->base->base->order);   //a = a*p
	mpz_add(a, a, rep(rep1(rep0(rep1(x)))));
	mpz_mul(a, a, field(x)->base->base->base->order);
	mpz_add(a, a, rep(rep1(rep2(rep0(x)))));
	mpz_mul(a, a, field(x)->base->base->base->order);
	mpz_add(a, a, rep(rep1(rep1(rep0(x)))));
	mpz_mul(a, a, field(x)->base->base->base->order);
	mpz_add(a, a, rep(rep1(rep0(rep0(x)))));
	mpz_mul(a, a, field(x)->base->base->base->order);
	mpz_add(a, a, rep(rep0(rep2(rep1(x)))));
	mpz_mul(a, a, field(x)->base->base->base->order);
	mpz_add(a, a, rep(rep0(rep1(rep1(x)))));
	mpz_mul(a, a, field(x)->base->base->base->order);
	mpz_add(a, a, rep(rep0(rep0(rep1(x)))));
	mpz_mul(a, a, field(x)->base->base->base->order);
	mpz_add(a, a, rep(rep0(rep2(rep0(x)))));
	mpz_mul(a, a, field(x)->base->base->base->order);
	mpz_add(a, a, rep(rep0(rep1(rep0(x)))));
	mpz_mul(a, a, field(x)->base->base->base->order);
	mpz_add(a, a, rep(rep0(rep0(rep0(x)))));
}

void g3_to_oct(unsigned char *os, size_t *size, const Element x)
{
	size_t s0;

	unsigned char b0[380];
	mpz_t z;

	mpz_init(z);

	g3_to_mpz(z,x);
	mpz_export(b0, &s0, 1, sizeof(*b0), 1, 0, z);

	memset(os, 0x00, 380);

	memcpy(&os[380-(int)s0], b0, s0);

	(*size) = 380;

	mpz_clear(z);
}

void g3_from_oct(Element x, const unsigned char *os, const size_t size){

	mpz_t quo, rem;

	if( size < 380 ){
		fprintf(stderr, "error: please set up the enought buffer for element\n"); exit(300); 
	}

	mpz_init(quo);
	mpz_init(rem);

	mpz_import(quo, size, 1, sizeof(*os), 1, 0, os);

	mpz_tdiv_qr(quo, rem, quo, field(x)->base->base->base->order);
	mpz_set(rep(rep0(rep0(rep0(x)))), rem);
	mpz_tdiv_qr(quo, rem, quo, field(x)->base->base->base->order);
	mpz_set(rep(rep0(rep1(rep0(x)))), rem);
	mpz_tdiv_qr(quo, rem, quo, field(x)->base->base->base->order);
	mpz_set(rep(rep0(rep2(rep0(x)))), rem);
	mpz_tdiv_qr(quo, rem, quo, field(x)->base->base->base->order);
	mpz_set(rep(rep0(rep0(rep1(x)))), rem);
	mpz_tdiv_qr(quo, rem, quo, field(x)->base->base->base->order);
	mpz_set(rep(rep0(rep1(rep1(x)))), rem);
	mpz_tdiv_qr(quo, rem, quo, field(x)->base->base->base->order);
	mpz_set(rep(rep0(rep2(rep1(x)))), rem);
	mpz_tdiv_qr(quo, rem, quo, field(x)->base->base->base->order);
	mpz_set(rep(rep1(rep0(rep0(x)))), rem);
	mpz_tdiv_qr(quo, rem, quo, field(x)->base->base->base->order);
	mpz_set(rep(rep1(rep1(rep0(x)))), rem);
	mpz_tdiv_qr(quo, rem, quo, field(x)->base->base->base->order);
	mpz_set(rep(rep1(rep2(rep0(x)))), rem);
	mpz_tdiv_qr(quo, rem, quo, field(x)->base->base->base->order);
	mpz_set(rep(rep1(rep0(rep1(x)))), rem);
	mpz_tdiv_qr(quo, rem, quo, field(x)->base->base->base->order);
	mpz_set(rep(rep1(rep1(rep1(x)))), rem);
	mpz_tdiv_qr(quo, rem, quo, field(x)->base->base->base->order);
	mpz_set(rep(rep1(rep2(rep1(x)))), rem);

	mpz_clear(quo);
	mpz_clear(rem);

}
