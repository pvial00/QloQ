#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/bn.h>

struct qloq_ctx {
    BIGNUM *sk;
    BIGNUM *pk;
    BIGNUM *n;
    BIGNUM *M;
};

void cloak(struct qloq_ctx * ctx, BIGNUM *ctxt, const BIGNUM *ptxt) {
    BN_CTX *bnctx = BN_CTX_new();
    BIGNUM *phase1;
    phase1 = BN_new();
    BN_mod_exp(phase1, ptxt, ctx->pk, ctx->M, bnctx);
    BN_mod_exp(ctxt, phase1, ctx->pk, ctx->n, bnctx);
}

void decloak(struct qloq_ctx * ctx, BIGNUM *ptxt, BIGNUM *ctxt) {
    BN_CTX *bnctx = BN_CTX_new();
    BIGNUM *phase1;
    phase1 = BN_new();
    BN_mod_exp(phase1, ctxt, ctx->sk, ctx->n, bnctx);
    BN_mod_exp(ptxt, phase1, ctx->sk, ctx->M, bnctx);
}

void sign(struct qloq_ctx * ctx, BIGNUM *S, BIGNUM *ptxt) {
    BN_CTX *bnctx = BN_CTX_new();
    BIGNUM *phase1;
    phase1 = BN_new();
    BN_mod_exp(phase1, ptxt, ctx->sk, ctx->M, bnctx);
    BN_mod_exp(S, phase1, ctx->sk, ctx->n, bnctx);
}

int verify(struct qloq_ctx * ctx, BIGNUM *ctxt, BIGNUM *ptxt) {
    BN_CTX *bnctx = BN_CTX_new();
    BIGNUM *phase1;
    BIGNUM *phase2;
    phase1 = BN_new();
    phase2 = BN_new();
    BN_mod_exp(phase1, ptxt, ctx->pk, ctx->M, bnctx);
    BN_mod_exp(phase2, phase1, ctx->pk, ctx->n, bnctx);
    if (BN_cmp(phase2, ctxt) == 0) {
        return 0;
    }
    else {
        return 1;
    }
}

void pkg_keys(struct qloq_ctx * ctx, char * prefix) {
    char *pkfilename[256];
    char *skfilename[256];
    char *pknum[8];
    char *sknum[8];
    char *nnum[8];
    char *Mnum[8];
    char *newline = "\n";
    char *sep = ":";
    FILE *tmpfile;
    strcpy(pkfilename, prefix);
    strcat(pkfilename, ".pk");
    strcpy(skfilename, prefix);
    strcat(skfilename, ".sk");
    int pkbytes = BN_num_bytes(ctx->pk);
    int skbytes = BN_num_bytes(ctx->sk);
    int nbytes = BN_num_bytes(ctx->n);
    int Mbytes = BN_num_bytes(ctx->M);
    sprintf(pknum, "%d", pkbytes);
    sprintf(sknum, "%d", skbytes);
    sprintf(nnum, "%d", nbytes);
    sprintf(Mnum, "%d", Mbytes);
    unsigned char *pk[pkbytes];
    unsigned char *sk[skbytes];
    unsigned char *n[nbytes];
    unsigned char *M[Mbytes];
    BN_bn2bin(ctx->pk, pk);
    BN_bn2bin(ctx->sk, sk);
    BN_bn2bin(ctx->n, n);
    BN_bn2bin(ctx->M, M);
    tmpfile = fopen(pkfilename, "wb");
    fwrite(pk, 1, strlen(pknum), tmpfile);
    fwrite(pk, 1, pkbytes, tmpfile);
    fwrite(nnum, 1, strlen(nnum), tmpfile);
    fwrite(n, 1, nbytes, tmpfile);
    fwrite(Mnum, 1, strlen(Mnum), tmpfile);
    fwrite(M, 1, Mbytes, tmpfile);
    fclose(tmpfile);
    tmpfile = fopen(skfilename, "wb");
    fwrite(sknum, 1, strlen(sknum), tmpfile);
    fwrite(sk, 1, skbytes, tmpfile);
    fwrite(nnum, 1, strlen(nnum), tmpfile);
    fwrite(n, 1, nbytes, tmpfile);
    fwrite(Mnum, 1, strlen(Mnum), tmpfile);
    fwrite(M, 1, Mbytes, tmpfile);
    fclose(tmpfile);
}

void load_pkfile(char *filename, struct qloq_ctx * ctx) {
    unsigned char *pk;
    unsigned char *n;
    unsigned char *M;
    char *pknum[4];
    char *nnum[3];
    char *Mnum[3];
    FILE *keyfile;
    keyfile = open(filename, "rb");
    fread(pknum, 1, 4, keyfile);
    int pkn = atoi(pknum);
    fread(pk, 1, pkn, keyfile);
    fread(nnum, 1, 3, keyfile);
    int nn = atoi(nnum);
    fread(n, 1, nn, keyfile);
    fread(Mnum, 1, 3, keyfile);
    int Mn = atoi(Mnum);
    fread(M, 1, Mn, keyfile);
    fclose(keyfile);
    BN_bin2bn(pk, pkn, ctx->pk);
    BN_bin2bn(n, nn, ctx->n);
    BN_bin2bn(M, Mn, ctx->M);
}

void load_skfile(char * filename, struct qloq_ctx * ctx) {
    unsigned char *sk;
    unsigned char *n;
    unsigned char *M;
    char *sknum[4];
    char *nnum[3];
    char *Mnum[3];
    FILE *keyfile;
    keyfile = open(filename, "rb");
    fread(sknum, 1, 4, keyfile);
    int skn = atoi(sknum);
    fread(sk, 1, skn, keyfile);
    fread(nnum, 1, 3, keyfile);
    int nn = atoi(nnum);
    fread(n, 1, nn, keyfile);
    fread(Mnum, 1, 3, keyfile);
    int Mn = atoi(Mnum);
    fread(M, 1, Mn, keyfile);
    fclose(keyfile);
    BN_bin2bn(sk, skn, ctx->sk);
    BN_bin2bn(n, nn, ctx->n);
    BN_bin2bn(M, Mn, ctx->M);
}


int keygen(struct qloq_ctx * ctx, int psize) {
    unsigned char *prefix = "QloQ";
    BN_CTX *bnctx = BN_CTX_new();
    int good = 0;
    int randstat = 0;
    /* Initialize the struct */
    ctx->sk = BN_new();
    ctx->pk = BN_new();
    ctx->n = BN_new();
    ctx->M = BN_new();
    /* Initialize all bignum variables */
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *a;
    BIGNUM *b;
    BIGNUM *s;
    BIGNUM *t;
    BIGNUM *C;
    BIGNUM *K;
    BIGNUM *G;
    BIGNUM *tmp0;
    BIGNUM *tmp1;
    BIGNUM *tmp2;
    BIGNUM *tmp3;
    BIGNUM *tmp4;
    BIGNUM *rtmp;
    BIGNUM *ptxt;
    BIGNUM *ctxt;
    BIGNUM *z1;
    p = BN_new();
    q = BN_new();
    a = BN_new();
    b = BN_new();
    s = BN_new();
    t = BN_new();
    C = BN_new();
    K = BN_new();
    G = BN_new();
    tmp0 = BN_new();
    tmp1 = BN_new();
    tmp2 = BN_new();
    tmp3 = BN_new();
    tmp4 = BN_new();
    rtmp = BN_new();
    ctxt = BN_new();
    ptxt = BN_new();
    z1 = BN_new();
    /* Set Z1 to equal 1 */
    BN_one(z1);
    while (good != 1) {
        /* Generate primes, let them not be equal */
        while (randstat != 1) {
            unsigned char *seed[524288];
            FILE *randfile;
            randfile = fopen("/dev/urandom", "rb");
            fread(seed, 1, 524288, randfile);
            fclose(randfile);

            RAND_seed(seed, 524288);
            randstat = RAND_status();
        }
        BN_rand(p, psize, 0, 0);
        BN_generate_prime_ex(p, psize, 1, NULL, NULL, NULL);
        while ((BN_is_prime_ex(p, BN_prime_checks, NULL, NULL) != 1)) {
            BN_rand(p, psize, 0, 0);
            BN_generate_prime_ex(p, psize, 1, NULL, NULL, NULL);
        }
        char *pdec;
        BN_bn2dec(p);
        BN_rand(q, psize, 0, 0);
        BN_generate_prime_ex(q, psize, 1, NULL, NULL, NULL);
        while ((BN_cmp(p, q) == 0) && (BN_is_prime_ex(q, BN_prime_checks, NULL, NULL) != 1)) {
            BN_rand(q, psize, 0, 0);
            BN_generate_prime_ex(q, psize, 1, NULL, NULL, NULL);
        }
        char *qdec;
        BN_bn2dec(q);
        BN_rand(a, psize, 0, 0);
        BN_generate_prime_ex(a, psize, 1, NULL, NULL, NULL);
        while ((BN_cmp(a, q) == 0) && (BN_cmp(a, p) == 0)) {
            BN_rand(a, psize, 0, 0);
            BN_generate_prime_ex(a, psize, 1, NULL, NULL, NULL);
        }
        BN_rand(b, psize, 0, 0);
        BN_generate_prime_ex(b, psize, 1, NULL, NULL, NULL);
        while ((BN_cmp(b, q) == 0) && (BN_cmp(b, p) == 0) && (BN_cmp(b, a) == 0)) {
            BN_rand(b, psize, 0, 0);
            BN_generate_prime_ex(b, psize, 1, NULL, NULL, NULL);
        }
        /* Generate cloaking parameters */
        BN_mod(C, p, q, bnctx);
        BN_mod(K, q, p, bnctx);
        BN_add(G, q, C);
        /* Generate the modulus */
        BN_div(tmp0, rtmp, a, b, bnctx);
        BN_div(tmp1, rtmp, b, q, bnctx);
        BN_add(tmp2, tmp0, tmp1);
        BN_add(tmp3, K, C);
        BN_div(tmp4, rtmp, tmp2, tmp3, bnctx);
        BN_mul(tmp0, C, K, bnctx);
        BN_div(tmp1, rtmp, tmp0, C, bnctx);
        BN_mul(tmp2, tmp0, tmp1, bnctx);
        BN_add(ctx->n, tmp2, tmp4);
        /* Generate the mask */
        BN_div(tmp0, rtmp, p, q, bnctx);
        BN_div(tmp1, rtmp, q, p, bnctx);
        BN_add(tmp2, tmp0, tmp1);
        BN_add(tmp3, K, C);
        BN_div(tmp4, rtmp, tmp2, tmp3, bnctx);
        BN_mul(tmp0, K, G, bnctx);
        BN_div(tmp1, rtmp, tmp0, K, bnctx);
        BN_mul(tmp2, tmp0, tmp1, bnctx);
        BN_add(ctx->M, tmp2, tmp4);
        /* Build the totient */
        BN_sub(tmp0, p, z1);
        BN_sub(tmp1, q, z1);
        BN_mul(tmp2, tmp0, tmp1, bnctx);
        BN_mul(s, tmp2, p, bnctx);
        BN_sub(tmp0, a, z1);
        BN_sub(tmp1, b, z1);
        BN_mul(tmp2, tmp0 , tmp1, bnctx);
        BN_mul(tmp3, tmp2 , s, bnctx);
        BN_mul(tmp4, tmp3 , a, bnctx);
        BN_mul(t, tmp4 , q, bnctx);
        /* Generate the public key */
        BN_rand_range(ctx->pk, t);
        BN_gcd(tmp0, ctx->pk, t, bnctx);
        while ((BN_cmp(tmp0, z1) != 0)) {
            BN_rand_range(ctx->pk, t);
            BN_gcd(tmp0, ctx->pk, t, bnctx);
        }
        BN_mod_inverse(ctx->sk, ctx->pk, t, bnctx);
        cloak(ctx, ctxt, z1);
        decloak(ctx, ptxt, ctxt);
        if ((BN_cmp(ptxt, z1) == 0)) {
            good = 1;
        }
    }
    pkg_keys(ctx, prefix);
    BN_free(p);
    BN_free(q);
    BN_free(a);
    BN_free(b);
    BN_free(s);
    BN_free(t);
    BN_free(C);
    BN_free(K);
    BN_free(G);
    BN_free(tmp0);
    BN_free(tmp1);
    BN_free(tmp2);
    BN_free(tmp3);
    BN_free(tmp4);
    BN_free(rtmp);
    BN_free(ctxt);
    BN_free(ptxt);
    BN_free(z1);
    return good;
}
