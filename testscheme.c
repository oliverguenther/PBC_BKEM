#include "bes_bgw.h"


int main(void) {

	FILE *param = fopen("a.param", "r");
	char buf[4096];
	fread(buf, 1, 4096, param);
    
    printf("\nSystem setup Key\n\n");

	bes_global_params_t gps;
	setup_global_system(&gps, (const char*) buf, 16);

	printf("Global System parameters: N = %d, A = %d, B = %d\n\n", gps->N, gps->A, gps->B);

	bes_system_t sys;
	setup(&sys, gps);
    
    printf("\nTesting system\n\n");
    
    
    int c,k;
    for (c = 2; c <= 16; ++c) {
//        if (c == 3) return;
        int S[c];
        printf("Testing with S = [ ");
        for (k = 0; k < c; ++k) {
            S[k] = k;
            printf("%d ", k);
        }
        printf("]\n");
        
        int j;
        for (j = 0; j < 16; ++j) {
            keypair_t keypair;
            encrypt(&keypair, S, c, sys, gps);
            element_t K;
            decrypt(K, gps, S, c, j, sys->d_i[j], keypair->HDR, sys->PK);
            if (!element_cmp(keypair->K, K)) {
                if (j >= c)
                    printf("ERROR: Decryption Key for [User %d] matches, but should NOT\n", j);
                else
                    printf("SUCCESS: Decryption Key for [User %d] matches\n", j);            
            } else {
                if (j < c)
                    printf("ERROR: Decryption Key for [User %d] does not match!\n", j);
            }
            element_clear(K);
            free(keypair);
        }
    }
    
//    // Set first subset as receivers
//    int S[] = {0,1};
//    int c = 2;
//    
//    keypair_t keypair;
//    encrypt(&keypair, S, c, sys, gps);
//        
//    
//    printf("\nTesting Decryption\n\n");
//    element_t K;
//    decrypt(K, gps, S, c, 0, sys->d_i[0], keypair->HDR, sys->PK);
//    
//    if (!element_cmp(keypair->K, K)) {
//        printf("Decryption successful. Key K matches\n");
//    } else {
//        printf("Key K does not match!\n");
//    }
    
}
