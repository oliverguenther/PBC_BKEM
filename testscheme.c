#include "pbc_bes.h"


int main(int argc, const char *argv[]) {

	FILE *param = fopen("a.param", "r");
	char buf[4096];
	fread(buf, 1, 4096, param);
    
    printf("\nSystem setup Key\n\n");

	bes_global_params_t gps;
	setup_global_system(&gps, (const char*) buf, (argc > 1) ? atoi(argv[1]) : 256);

	printf("Global System parameters: N = %d, A = %d, B = %d\n\n", gps->N, gps->A, gps->B);

	bes_system_t sys;
	setup(&sys, gps);
    
    printf("\nTesting system\n\n");
    
    
    unsigned int c,k,j;
    for (c = 2; c <= gps->N; c*=2) {
        //        if (c == 3) return;
        int S[c];
        printf("\nTesting with S = [ ");
        for (k = 0; k < c; ++k) {
            S[k] = k;
            printf("%d ", k);
        }
        printf("]\n\n");
        keypair_t keypair;
        get_encryption_key(&keypair, S, c, sys, gps);
        element_t K;

        
        for (j = 0; j < gps->N; ++j) {
            get_decryption_key(K, gps, S, c, j, sys->d_i[j], keypair->HDR, sys->PK);
            if (!element_cmp(keypair->K, K)) {
                if (j >= c)
                    printf("ERROR: Decryption Key for [User %d] matches, but should NOT\n", j);       
            } else {
                if (j < c)
                    printf("ERROR: Decryption Key for [User %d] does not match!\n", j);
            }
            element_clear(K);
        }
        free(keypair);
        
    }
    
}
