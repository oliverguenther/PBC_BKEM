/*
 * General construction of the 
 * Boneh-Gentry-Waters broadcast encryption scheme 
 * 
 * PBC_bes is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * PBC_bes is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with PBC_bes.  If not, see <http://www.gnu.org/licenses/>.
 * 
 * Oliver Guenther
 * mail@oliverguenther.de
 *
 * 
 * PBC_bes.c
 */


#include <string.h>
#include <stdio.h>
#include <math.h>

#include "pbc_bes.h"

void setup_global_system(bes_global_params_t *gps, const char *pstr, int N) {
	// init global parameters
	bes_global_params_t params;
	params = pbc_malloc(sizeof(struct bes_global_params_s));
    
	// Compute A, B system params
	params->B = (int) sqrt(N);
	params->A = (N + params->B - 1) / params->B;

	params->N = params->A * params->B;
    
	// Init pairing
	pairing_init_set_str(params->pairing, pstr);
    
	*gps = params;
}


void setup(bes_system_t *sys, bes_global_params_t gps) {
	// init broadcast system
	bes_system_t gbs;
	gbs = pbc_malloc(sizeof(struct bes_system_s));
    gbs->PK = pbc_malloc(sizeof(struct pubkey_s));
    
	// Choose random generator
	element_init_G1(gbs->PK->g, gps->pairing);
	element_random(gbs->PK->g);
    
	// random alpha Zn
	element_t alpha;
	element_init_Zr(alpha, gps->pairing);
	element_random(alpha);
    
	// Compute g_i's
	gbs->PK->g_i = pbc_malloc(2 * gps->B * sizeof(element_t));
    
	// Set the first element to g^(alpha^1)
	element_init_G1(gbs->PK->g_i[0], gps->pairing);
	element_pow_zn(gbs->PK->g_i[0],gbs->PK->g, alpha);
    
	int i;
	for(i = 1; i < 2*gps->B; i++) { 
		// g_(i+1) = g_i ^ alpha = (g^(alpha^i))^alpha
		element_init_G1(gbs->PK->g_i[i], gps->pairing);
		element_pow_zn(gbs->PK->g_i[i], gbs->PK->g_i[i-1], alpha);
	}
    
	// Choose random gamma_i and set v_i
	element_t *gamma_i;
    gamma_i = pbc_malloc(gps->A * sizeof(struct element_s));    
    gbs->PK->v_i = pbc_malloc(gps->A * sizeof(struct element_s));
	for (i = 0; i < gps->A; i++) {
		element_init_Zr(gamma_i[i], gps->pairing);
		element_init_G1(gbs->PK->v_i[i], gps->pairing);
        element_random(gamma_i[i]);
		element_pow_zn(gbs->PK->v_i[i], gbs->PK->g, gamma_i[i]);
	}
    
	// Compute private keys d_i
    gbs->d_i = pbc_malloc(gps->N * sizeof(struct element_s));
	for (i = 0; i < gps->N; i++) {
		int a = (int) i / gps->B;
		int b = (int) i % gps->B;
        
		element_init_G1(gbs->d_i[i], gps->pairing);
		element_pow_zn(gbs->d_i[i], gbs->PK->g_i[b], gamma_i[a]);
	}
    
	*sys = gbs;	
	element_clear(alpha);
    for (i = 0; i < gps->A; ++i) {
        element_clear(gamma_i[i]);
    }
}

void get_encryption_key(keypair_t *key, int *S, int num_recip, bes_system_t sys, bes_global_params_t gps) {
    
	keypair_t kp;
	kp = pbc_malloc(sizeof(struct keypair_s));
    
	// Init header, g^t , A instances
	kp->HDR = pbc_malloc((gps->A + 1) * sizeof(element_t));
    
	// Get random t
	element_t t;
    element_init_Zr(t, gps->pairing);
	element_random(t);
    
	// Compute K = e(g_B, g_0)^t
	element_init_GT(kp->K, gps->pairing);
	pairing_apply(kp->K, sys->PK->g_i[gps->B-1], sys->PK->g_i[0], gps->pairing);
    element_pow_zn(kp->K, kp->K, t);
    
	// Set first header element to g^t
    element_init_G1(kp->HDR[0], gps->pairing);
	element_pow_zn(kp->HDR[0], sys->PK->g, t);
    
	// Init HDR 1-A with v_i
	int i;
	for (i = 1; i <= gps->A; ++i) {
        element_init_G1(kp->HDR[i], gps->pairing);
		element_set(kp->HDR[i], sys->PK->v_i[i-1]);
	}
    
	// Define Subsets
	int line, pos;
	for (i = 0; i < num_recip; ++i) {
		if (S[i] < 0 || S[i] >= gps->N) {
			printf("Element %d of receivers out of range\n", i);
			return;
		}
        
		// Get relative position of member S[i] within its subset
		// Determine position in HDR (+1 offset from first element)
		line = (int) (S[i] / gps->B);
		// Determine position
		pos = (S[i] % gps->B); 	
		element_mul(kp->HDR[line + 1], kp->HDR[line + 1], sys->PK->g_i[gps->B - 1 - pos]);
	}
    
	// Pow each subinstance with t
	for (i = 1; i <= gps->A; ++i) {
		element_pow_zn(kp->HDR[i], kp->HDR[i], t);
	}
    
	*key = kp;
	element_clear(t);
    
}

void get_decryption_key(element_t K, bes_global_params_t gps, int *S, int num_recip, int index, 
                        element_t d_i, element_t *HDR, pubkey_t PK) { 

	// a is equal to instance
	int a = (int) (index / gps->B);
    
	// b is relative position in subset
	int b = index % gps->B;
    
    element_t nom, den, temp;
	element_init_GT(nom, gps->pairing);
    // Set nominator to e(g_b, HDR_a) (+1 offset)
	pairing_apply(nom, PK->g_i[b], HDR[a + 1], gps->pairing);
    
    element_init_same_as(temp, d_i);
	element_set(temp, d_i);
    
	int i, line, pos, pkpos;
	for (i = 0; i < num_recip; ++i) {
		if (S[i] < 0 || S[i] > gps->N) {
			printf("Element %d of receivers out of range\n", i);
			return;
		}
        
		// Get relative position of member S[i] within its subset
		line = (int) (S[i] / gps->B);
		// Determine position
		pos = (int) S[i] % gps->B;	
        
		if (line == a && pos != b) {
			pkpos = (gps->B) - pos+b; 
			element_mul(temp, temp, PK->g_i[pkpos]); 
		}
	}
    
	element_init_GT(den, gps->pairing);
	pairing_apply(den, temp, HDR[0], gps->pairing);
    
	element_init_GT(K, gps->pairing);
	element_div(K, nom, den);
    
	element_clear(temp);
	element_clear(nom);
	element_clear(den);
    
}


void free_global_params(bes_global_params_t gbs) {
    if (!gbs)
        return;
    
    pairing_clear(gbs->pairing);
    free(gbs);
}

void free_pubkey(pubkey_t pk, bes_global_params_t gbs) {
    if (!pk)
        return;
    
    element_clear(pk->g);
    
    int i;
    for (i = 0; i < 2 * gbs->B; ++i) {
        element_clear(pk->g_i[i]);
    }
    
    for (i = 0; i < gbs->A; ++i) {
        element_clear(pk->v_i[i]);
    }
    
}

void free_bes_system(bes_system_t sys, bes_global_params_t gbs) {
    if (!sys)
        return;
    
    free_pubkey(sys->PK, gbs);
    
    int i;
    for (i = 0; i < gbs->N; ++i) {
        element_clear(sys->d_i[i]);
    }
}
