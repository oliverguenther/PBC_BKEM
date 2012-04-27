/**
 * @file PBC_bes.h
 * @brief General construction of the Boneh-Gentry-Waters broadcast encryption scheme
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
 * PBC_bes.h
*/

#ifndef PBC_BES_H
#define PBC_BES_H

#include <string.h>
#include <pbc/pbc.h>

#define PBCBES_DEBUG 0

/**
  @typedef Global broadcast system parameters
 */
typedef struct bes_global_params_s {
	pairing_t pairing;
	int N;
	int B;
	int A;
}* bes_global_params_t;

/**
 * @typedef Public Key
 * Contains generator g, 2B-2 elements g[i] and A elements v[i]
 */
typedef struct pubkey_s {
    element_t g; // generator
    element_t *g_i; // 2B-2 elements
    element_t *v_i; // A elements
}* pubkey_t;

/**
 * @typedef broadcast system instance
 */
typedef struct bes_system_s {
	pubkey_t PK;
	/** Private key of user s */
	element_t *d_i;
}* bes_system_t;

/**
 * @typedef Keypair (HDR, K) [A+1, 1] elements
 */
typedef struct keypair_s {
    element_t *HDR;
    element_t K;
}* keypair_t;



/**
 * @brief Free a keypair_t
 */
void free_pubkey(pubkey_t pk, bes_global_params_t gbs);


/**
 * @brief Free a bes_system_t
 */
void free_bes_system(bes_system_t sys, bes_global_params_t gbs);


/**
 * @brief Free a global_broadcast_params_t
 */
void free_global_params(bes_global_params_t gbs);



/**
 * Setup global broadcast system parameters
 * @param[out] gps bes_global_params_t pointer
 * @param[in] params Pairing Type paramters as string
 * @param[in] n number of users in the system
 */
void setup_global_system(bes_global_params_t *gps, const char *params, int n);

/**
 * Setup broadcast encryption system
 * @param[out] sys bes_system_t pointer
 * @param[in] gps bes_global_params_t pointer
 */
void setup(bes_system_t *sys, bes_global_params_t gps);

/**
 * Output encryption Keypair
 * @param[out] keypair pointer to encryption pair output
 * @param[in] S receiver array [indices of participating users]
 * @param[in] num_recip Number of elements in S
 * @param[in] sys Broadcast encryption parameters
 */
void get_encryption_key(keypair_t *key, int *S, int num_recip, bes_system_t sys, bes_global_params_t gps);


/**
 * Output decryption Key
 * @param[out] K decryption key pointer
 * @param[in] gps global system parameters
 * @param[in] S receivers [indices of participating users]
 * @param[in] num_recip Number of elements in S
 * @param[in] i index of user
 * @param[in] d_i private key of user i
 * @param[in] HDR header
 * @param[in] PK public key
 */
void get_decryption_key(element_t K, bes_global_params_t gbs, int *S, int num_recip, int i, 
		element_t d_i, element_t *HDR, pubkey_t PK);


#endif
