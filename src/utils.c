/*
 * Copyright (c) 2020 by Vadims Zilnieks
 * https://github.com/vzilnieks/gos-ipc
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <libbase58.h>
#include <openssl/sha.h>
#include <sqlite3.h>

#include "main.h"

/********************************************************************/
extern int get_raw_rand(int x) {
  if (sodium_init() < 0) {
    return 0;
  }
  return randombytes_uniform(x);
}

/********************************************************************/
extern int set_ts(trx_t* trx) {
  int rc;
  struct timeval tv;

  rc = gettimeofday(&tv, NULL);
#ifdef DEBUG
  printf("rcode: %d seconds: %ld nano: %ld %ld\n", rc, tv.tv_sec, tv.tv_usec,
         tv.tv_sec * 1000 + tv.tv_usec / 1000);
  fflush(stdout);
#endif
  if (rc) return 1;
  if (trx == NULL) return 2;
  if (!trx->ts_create) {
    trx->ts_create = (uint32_t)tv.tv_sec;
    trx->nts_create = (uint32_t)tv.tv_usec / 1000;
  }
  trx->ts_access = (uint32_t)tv.tv_sec;
  trx->nts_access = (uint32_t)tv.tv_usec / 1000;
  return 0;
}

/********************************************************************/
extern int get_ts(ts_t* ts) {
  int rc;
  struct timeval tv;

  rc = gettimeofday(&tv, NULL);
  if (rc) return 1;
  ts->ts = (uint32_t)tv.tv_sec;
  ts->nts = (uint32_t)tv.tv_usec / 1000;
  return 0;
}

/********************************************************************/
/* Human readable random name like for Docker containers            */
/********************************************************************/
extern char* human_name() {
  char* name;

  name = malloc(80);
  strcpy(name, left[get_raw_rand(LEFT_NUM - 1)]);
  strcat(name, "_");
  strcat(name, right[get_raw_rand(RIGHT_NUM - 1)]);
  return name;
}

/********************************************************************/
/* Make socket for listening incoming connections or datagrams      */
/********************************************************************/
extern int listen_socket(int socket_type) {
  switch (socket_type) {
    case 0:
      return socket(AF_INET, SOCK_DGRAM, 0);
    case 1:
      return socket(AF_INET, SOCK_STREAM, 0);
    default:
      return -1;
  }
}

/********************************************************************/
/* Time stamp and hash for logging                                  */
/********************************************************************/
extern char* log_head() {
  time_t t;
  struct tm* tmp;
  char* outstr;
  char* peer_id;

  outstr = malloc(120);
  peer_id = malloc(40);
  t = time(NULL);
  tmp = localtime(&t);
  strftime(outstr, 80, LOG_FORMAT, tmp);
  if (0 == strcmp(host_ip, CLR_IP))
    sprintf(peer_id, "%s %s CLEARING", host_name, host_ip);
  else
    sprintf(peer_id, "%s %s ", host_name, host_ip);
  strcat(outstr, peer_id);
  return outstr;
}

/********************************************************************/
extern void get_lo_ip(int num, char* ip_addr) {
  char tail[3];

  memset(ip_addr, 0, INET_ADDRSTRLEN);
  strcpy(ip_addr, "127.0.0.");
  sprintf(tail, "%d", num);
  strcat(ip_addr, tail);
}

/********************************************************************/
extern char* get_sarg(int arg) {
  char* s;

  s = malloc(5);
  sprintf(s, "%d", arg);
  return s;
}

/********************************************************************/
extern int apipe_len(const char* pool, int* len) {
  char h[HASH_SIZE / SHORT_HASH_SIZE][SHORT_HASH_SIZE];
  char frg[SHORT_HASH_SIZE + 1] = "";
  const char gfill[SHORT_HASH_SIZE + 1] = "gggggggggggggggg";

  (*len) = 0;
  memset(h, 0, sizeof(h));
  strcpy(*h, pool);
  for (int j = 0; j < HASH_SIZE / SHORT_HASH_SIZE; ++j) {
    strncpy(frg, h[j], SHORT_HASH_SIZE);
    strcat(frg, "\0");
    if (strlen(frg) && strcmp(frg, gfill)) (*len)++;
#ifdef DEBUG
    printf("apipe_len %d %s %d\n", j, frg, *len);
    fflush(stdout);
#endif
  }
  return 0;
}

/********************************************************************/
extern int apipe_add(char* pool, const char* part, int len) {
  char h[HASH_SIZE / SHORT_HASH_SIZE][SHORT_HASH_SIZE];
  char frg[SHORT_HASH_SIZE + 1] = "";
  int* lp;
  int j;

  if (strlen(part) != SHORT_HASH_SIZE) return 1;
  if (len > HASH_SIZE / SHORT_HASH_SIZE) len = HASH_SIZE / SHORT_HASH_SIZE;
  lp = malloc(sizeof(int));
  if (0 != apipe_len(pool, lp)) return 2;
#ifdef DEBUG
  printf(
      "size of fragment: %ld, length: %ld pipe size: %d allowed len: %d "
      "capacity %d\n",
      sizeof(part), strlen(part), *lp, len, HASH_SIZE / SHORT_HASH_SIZE);
  fflush(stdout);
#endif
  memset(h, 0, HASH_SIZE);
  strcpy(*h, pool);
  j = (*lp);
  for (int i = j; i > 0; --i) {
    if (i == len) continue;
    strncpy(frg, h[i], SHORT_HASH_SIZE);
    strcat(frg, "\0");
    strncpy(h[i], h[i - 1], SHORT_HASH_SIZE);
  }
  strncpy(h[0], part, SHORT_HASH_SIZE);
  memset(pool, 0, HASH_SIZE);
  strncpy(pool, *h, HASH_SIZE);
  return 0;
}

/********************************************************************/
extern int apipe_to_sql_in(const char* pool, char* sql_str) {
  char h[HASH_SIZE / SHORT_HASH_SIZE][SHORT_HASH_SIZE];
  char frg[SHORT_HASH_SIZE + 1] = "";
  char sql_frg[SHORT_HASH_SIZE + 4] = "";
  int* lp;
  int j;

  lp = malloc(sizeof(int));
  if (0 != apipe_len(pool, lp)) return 1;
  memset(h, 0, sizeof(h));
  strcpy(*h, pool);
  memset(sql_str, 0, strlen(sql_str));
  j = (*lp);
  for (int i = j - 1; i >= 0; --i) {
    strncpy(frg, h[i], SHORT_HASH_SIZE);
    strcat(frg, "\0");
    if (i)
      sprintf(sql_frg, "'%s',", frg);
    else
      sprintf(sql_frg, "'%s'", frg);
    strncat(sql_str, sql_frg, SHORT_HASH_SIZE + 4);
  }
  return 0;
}

/********************************************************************/
extern char* encode(const char* in) {
  /* char* output = (char*)malloc(B58_SIZE - 1); */
  char output[B58_SIZE] = "";
  char input[HASH_SIZE + 1] = "";
  char* out;
  size_t s1 = sizeof(output);

  out = malloc(B58_SIZE);
  memset(out, 0, B58_SIZE);
  memset(input, 0, HASH_SIZE + 1);
  strncpy(input, in, HASH_SIZE + 1);
  b58enc(output, &s1, input, sizeof(input));
#ifdef DEBUG
  printf("encode %s %d %d %s %d\n", input, s1, sizeof(input), output,
         strlen(output));
  fflush(stdout);
#endif
  strcpy(out, output);
  return out;
}

/********************************************************************/
extern char* decode(const char* input) {
  char* output = (char*)malloc(HASH_SIZE + 1);
  char out[HASH_SIZE + 1] = "";
  char in[B58_SIZE] = "";
  size_t s1 = sizeof(out);

  strncpy(in, input, B58_SIZE);
  b58tobin(out, &s1, in, strlen(in));
#ifdef DEBUG
  printf("decode %s %s %d %d %d\n", in, out, s1, sizeof(in), strlen(in));
  fflush(stdout);
#endif
  strcpy(output, out);
  return output;
}

/********************************************************************/
extern int sha256_hex(void* input, unsigned long length,
                      unsigned char* output) {
  SHA256_CTX context;
  unsigned char* md;
  char* h;

  memset(output, 0, SHA256_DIGEST_LENGTH * 2 + 1);
  h = malloc(2);
  md = malloc(SHA256_DIGEST_LENGTH);
  if (!SHA256_Init(&context)) return 1;
  if (!SHA256_Update(&context, (unsigned char*)input, length)) return 1;
  if (!SHA256_Final(md, &context)) return 1;

  for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
    /* two places for hex from single digest byte */
    sprintf(h, "%02x", md[i]);
    /* digest 1 byte -> hex 2 bytes */
    output[i * 2] = h[0];
    output[i * 2 + 1] = h[1];
  }
  output[SHA256_DIGEST_LENGTH * 2 + 1] = 0;
  return 0;
}

