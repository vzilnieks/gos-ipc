/*
 * Copyright (c) 2020 by Vadims Zilnieks
 * https://github.com/vzilnieks/gos-ipc
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* #include <dmalloc.h> */
#include <openssl/sha.h>
#include <sqlite3.h>

#include "main.h"

static uint8_t total_spackets = 0;
static uint8_t total_rpackets = 0;
static uint8_t total_samount = 0;
static uint8_t total_ramount = 0;
static int interrupted = 0;
static uint8_t trx_num = 1;

/* forwards */
static int check_local_db(gossip_t *gossip_data);

/********************************************************************/
/* Open database if not exists and (re)fill with neighbour table.   */
/* Pointer to db became open until end of main process.             */
/********************************************************************/
static int init_local_db(int num_neigh) {
  int rc;
  char *sql;
  char *err = 0;
  char ip_addr[INET_ADDRSTRLEN];
  char tail[3];
  unsigned char md[SHA256_DIGEST_LENGTH * 2 + 1];

  /* Open/Create database */
  rc = sqlite3_open(host_db, &local_db);

  if (rc) {
    return 1;
  } else {
    sql =
        " DROP TABLE IF EXISTS neighbours; "
        " CREATE TABLE neighbours ( "
        " IP	CHAR(15)	NOT NULL, "
        " HASH	CHAR(64)	NOT NULL PRIMARY KEY ASC); "
        " DROP TABLE IF EXISTS transactions; "
        " CREATE TABLE transactions ( "
        " TRX_TS_CREATE		INT	NOT NULL, "
        " TRX_NTS_CREATE	INT	NOT NULL, "
        " TRX_TS_ACCESS		INT	NOT NULL, "
        " TRX_NTS_ACCESS	INT	NOT NULL, "
        " FROM_H	CHAR(64)	NOT NULL, "
        " TO_H		CHAR(64)	NOT NULL, "
        " AMOUNT	INT8	NOT NULL); ";
    rc = sqlite3_exec(local_db, sql, NULL, 0, &err);
    if (rc != SQLITE_OK) {
      return 2;
    }

    for (int i = 2; i <= num_neigh; ++i) {
      memset(ip_addr, 0, sizeof(ip_addr));
      strcpy(ip_addr, "127.0.0.");
      sprintf(tail, "%d", i);
      strcat(ip_addr, tail);
      if (0 != sha256_hex(ip_addr, strlen(ip_addr), md)) {
        printf("Error making hash for ip '%s' %ld %ld %s\n", ip_addr,
               strlen(ip_addr), sizeof(ip_addr), md);
        continue;
      }
      sql =
          " INSERT INTO neighbours (IP, HASH) "
          " VALUES (@1, @2); ";
      sqlite3_prepare_v2(local_db, sql, -1, (struct sqlite3_stmt **)&sql, NULL);
      sqlite3_bind_text((struct sqlite3_stmt *)sql, 1, ip_addr, -1, NULL);
      sqlite3_bind_text((struct sqlite3_stmt *)sql, 2, md, -1, NULL);
      rc = sqlite3_step((struct sqlite3_stmt *)sql);
      if ((rc != SQLITE_DONE) && (rc != SQLITE_ROW)) {
        printf("SQL error: %s\n", err);
        sqlite3_free(err);
        continue;
      }
    }
    return 0;
  }
}

/********************************************************************/
static int get_neigh_num() {
  int i;
  int rc;
  char *sql;

  /* Random Neighbour Hash */
  sqlite3_prepare_v2(local_db, "SELECT * FROM neighbours WHERE HASH <> @1;", -1,
                     (struct sqlite3_stmt **)&sql, NULL);
  sqlite3_bind_text((struct sqlite3_stmt *)sql, 1, host_hash, -1, NULL);

  i = 0;
  while ((rc = sqlite3_step((struct sqlite3_stmt *)sql)) == SQLITE_ROW) {
    i++;
  }
  return i;
}

/********************************************************************/
static int get_trx_num() {
  int i;
  int rc;
  char *sql;

  /* Random Neighbour Hash */
  sqlite3_prepare_v2(local_db, "SELECT * FROM transactions;", -1,
                     (struct sqlite3_stmt **)&sql, NULL);

  i = 0;
  while ((rc = sqlite3_step((struct sqlite3_stmt *)sql)) == SQLITE_ROW) {
    i++;
  }
  return i;
}

/********************************************************************/
/* Random neighbour hash                                            */
/********************************************************************/
static char *get_random_neigh(char *prev_hashes) {
  int i;
  int idx;
  int rc;
  char *sql;
  char *sql_in;
  int *lp;
  int j;

  i = 0;
  lp = malloc(sizeof(int));
  if (0 != apipe_len(prev_hashes, lp)) return NULL;
  j = (*lp);
  if (j == 0) {
    sql = "SELECT HASH FROM neighbours WHERE HASH <> @1 LIMIT 1 OFFSET @2;";
    printf("%s SQL %s\n", log_head(), sql);
    fflush(stdout);
  } else {
    sql = malloc(200);
    memset(sql, 0, strlen(sql));
    sql_in = malloc(80);
    memset(sql_in, 0, strlen(sql_in));
    if (0 != apipe_to_sql_in(prev_hashes, sql_in)) {
      printf("%s apipe sql in error\n", log_head());
      fflush(stdout);
      return NULL;
    }
    sprintf(sql,
            "SELECT HASH FROM neighbours WHERE HASH <> @1 AND "
            "substr(HASH, 1, 16) NOT IN (%s) LIMIT 1 OFFSET @2;",
            sql_in);
    printf("%s SQL %s\n", log_head(), sql);
    fflush(stdout);
  }
  while (1) {
    i++;
    /* (- 1) to make range [0:neighbour_count) */
    idx = get_raw_rand(get_neigh_num() - j - 1);
    sqlite3_prepare_v2(local_db, sql, -1, (struct sqlite3_stmt **)&sql, NULL);
    sqlite3_bind_text((struct sqlite3_stmt *)sql, 1, host_hash, -1, NULL);
    sqlite3_bind_int((struct sqlite3_stmt *)sql, 2, idx);
    if ((rc = sqlite3_step((struct sqlite3_stmt *)sql)) == SQLITE_ROW) {
      return sqlite3_column_text((struct sqlite3_stmt *)sql, 0);
    } else {
      printf("%s SQL error - no data %s\n", log_head(), sql);
      fflush(stdout);
      return NULL;
    }
    if (i > LOOP_LOCK) return NULL;
  }

  return NULL;
}

/********************************************************************/
/* Get ip from fragment of hash                                     */
/********************************************************************/
static char *get_neigh_ip(char *hash) {
  int rc;
  char *sql;
  char hash_like[SHORT_HASH_SIZE + 2] = "";

  strncpy(hash_like, hash, SHORT_HASH_SIZE);
  strcat(hash_like, "%");
  sqlite3_prepare_v2(
      local_db,
      "SELECT IP, substr(HASH, 1, 16) FROM neighbours WHERE HASH LIKE @1;", -1,
      (struct sqlite3_stmt **)&sql, NULL);
  sqlite3_bind_text((struct sqlite3_stmt *)sql, 1, hash_like, -1, NULL);

  /* when hash changed ip, record can be indexed by access time */
  while ((rc = sqlite3_step((struct sqlite3_stmt *)sql)) == SQLITE_ROW) {
    if (0 == strcmp((char *)sqlite3_column_text((struct sqlite3_stmt *)sql, 1),
                    hash))
      return sqlite3_column_text((struct sqlite3_stmt *)sql, 0);
  }
  return NULL;
}

/********************************************************************/
/* Random transaction for amount 1 - 100                            */
/********************************************************************/
static trx_t *make_trx(char *receiver) {
  trx_t *trx;

  if (receiver == NULL) {
    return NULL;
  }

  trx = malloc(sizeof(trx_t));
  memset(trx, 0, sizeof(trx_t));
  trx->amt = get_raw_rand(99) + 1;
  strcpy(trx->from, host_hash);
  strcpy(trx->to, receiver);
  if (0 != set_ts(trx)) {
    printf("%s error in setting timestamp\n", log_head());
    fflush(stdout);
  }
  return trx;
}

/********************************************************************/
static gossip_t *make_gossip(trx_t *trx) {
  gossip_t *gossip_data;

  if (trx == NULL) {
    return NULL;
  }

  gossip_data = malloc(sizeof(gossip_t));
  memset(gossip_data, 0, sizeof(gossip_t));
  strcpy(gossip_data->prev_host, G64);
  gossip_data->trx = *trx;
  printf(
      "%s Prepared new data: ts %d access %d prev1 %s trx amt %d trx from %s "
      "trx to "
      "%s\n",
      log_head(), gossip_data->trx.ts_create, gossip_data->trx.ts_access,
      gossip_data->prev_host, gossip_data->trx.amt, gossip_data->trx.from,
      gossip_data->trx.to);
  fflush(stdout);
  /* db_rc = check_local_db(gossip_data); */
  return gossip_data;
}

/********************************************************************/
static void report_trx() {
  int rc;
  char *sql;

  sqlite3_prepare_v2(
      local_db, "SELECT TRX_TS_CREATE, FROM_H, TO_H, AMOUNT FROM transactions;",
      -1, (struct sqlite3_stmt **)&sql, NULL);

  printf("Report of local db transactions:\n");
  while ((rc = sqlite3_step((struct sqlite3_stmt *)sql)) == SQLITE_ROW) {
    printf("ts: %d from: %s to: %s amount: %d\n",
           sqlite3_column_int((struct sqlite3_stmt *)sql, 0),
           sqlite3_column_text((struct sqlite3_stmt *)sql, 1),
           sqlite3_column_text((struct sqlite3_stmt *)sql, 2),
           sqlite3_column_int((struct sqlite3_stmt *)sql, 3));
  }
  fflush(stdout);
}

/********************************************************************/
static int clearing() {
  int cls; /* clearing socket */
  struct sockaddr_in claddr;
  int rc;
  char *sql;
  gossip_t *gossip_data;

  if (flg_socket_type == TCP) {
    cls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  } else {
    cls = socket(AF_INET, SOCK_DGRAM, 0);
  }
  claddr.sin_family = AF_INET;
  claddr.sin_port = htons(LISTEN_PORT);
  /* claddr.sin_addr.s_addr = inet_addr(CLR_IP); */
  inet_pton(AF_INET, CLR_IP, &claddr.sin_addr);

  if (flg_socket_type == TCP) {
    if (connect(cls, (struct sockaddr *)(&claddr), sizeof(claddr)) == -1) {
      printf("%s [ERROR] in connecting to clearing peer %s %s %d\n", log_head(),
             CLR_IP, inet_ntoa(claddr.sin_addr), errno);
      fflush(stdout);
      return 1;
    } else {
      printf("%s Connected to clearing peer %s\n", log_head(),
             inet_ntoa(claddr.sin_addr));
      fflush(stdout);
    }
  }

  sqlite3_prepare_v2(local_db,
                     "SELECT TRX_TS_CREATE, TRX_NTS_CREATE, TRX_TS_ACCESS, "
                     "TRX_NTS_ACCESS, FROM_H, TO_H, AMOUNT FROM transactions;",
                     -1, (struct sqlite3_stmt **)&sql, NULL);

  gossip_data = malloc(sizeof(gossip_t));
  while ((rc = sqlite3_step((struct sqlite3_stmt *)sql)) == SQLITE_ROW) {
    printf("%s Send to clearing ts: %d from: %s to: %s amount: %d\n",
           log_head(), sqlite3_column_int((struct sqlite3_stmt *)sql, 0),
           sqlite3_column_text((struct sqlite3_stmt *)sql, 4),
           sqlite3_column_text((struct sqlite3_stmt *)sql, 5),
           sqlite3_column_int((struct sqlite3_stmt *)sql, 6));
    fflush(stdout);
    memset(gossip_data, 0, sizeof(gossip_t));
    gossip_data->trx.ts_create =
        htonl(sqlite3_column_int((struct sqlite3_stmt *)sql, 0));
    gossip_data->trx.nts_create =
        htonl(sqlite3_column_int((struct sqlite3_stmt *)sql, 1));
    gossip_data->trx.ts_access =
        htonl(sqlite3_column_int((struct sqlite3_stmt *)sql, 2));
    gossip_data->trx.nts_access =
        htonl(sqlite3_column_int((struct sqlite3_stmt *)sql, 3));
    strcpy(gossip_data->trx.from,
           sqlite3_column_text((struct sqlite3_stmt *)sql, 4));
    strcpy(gossip_data->trx.to,
           sqlite3_column_text((struct sqlite3_stmt *)sql, 5));
    gossip_data->trx.amt =
        htons(sqlite3_column_int((struct sqlite3_stmt *)sql, 6));
    memset(gossip_data->prev_host, 0, B58_SIZE);
    strcpy(gossip_data->prev_host, encode(host_hash));
    strcpy(gossip_data->trx.from, encode(gossip_data->trx.from));
    strcpy(gossip_data->trx.to, encode(gossip_data->trx.to));
    printf(
        "%s gossip for CLR: %d %d host %s prev %s from: %s to: %s amount: %d\n",
        log_head(), ntohl(gossip_data->trx.ts_create),
        ntohl(gossip_data->trx.ts_access), host_hash,
        decode(gossip_data->prev_host), gossip_data->trx.from,
        gossip_data->trx.to, ntohs(gossip_data->trx.amt));
    fflush(stdout);
    if (flg_socket_type == TCP) {
      send(cls, (gossip_t *)gossip_data, sizeof(gossip_t), MSG_NOSIGNAL);
    } else {
      sendto(cls, (gossip_t *)gossip_data, sizeof(gossip_t), 0,
             (struct sockaddr *)(&claddr), sizeof(claddr));
    }
  }
  /* free(gossip_data); */
  sqlite3_finalize((struct sqlite3_stmt *)sql);
  if (flg_socket_type == TCP) {
    shutdown(cls, SHUT_RDWR);
    close(cls);
  }

  return 0;
}

/********************************************************************/
static int check_local_db(gossip_t *gossip_data) {
  int rc;
  char *sql;
  char *err;

  sql =
      "SELECT * FROM transactions WHERE TRX_TS_CREATE = @1 AND "
      "FROM_H = @2 AND TO_H = @3 AND AMOUNT = @4;";
  err = 0;
  sqlite3_prepare_v2(local_db, sql, -1, (struct sqlite3_stmt **)&sql, NULL);
  sqlite3_bind_int((struct sqlite3_stmt *)sql, 1, gossip_data->trx.ts_create);
  sqlite3_bind_text((struct sqlite3_stmt *)sql, 2, gossip_data->trx.from, -1,
                    NULL);
  sqlite3_bind_text((struct sqlite3_stmt *)sql, 3, gossip_data->trx.to, -1,
                    NULL);
  sqlite3_bind_int((struct sqlite3_stmt *)sql, 4, gossip_data->trx.amt);

  if ((rc = sqlite3_step((struct sqlite3_stmt *)sql)) == SQLITE_ROW) {
    return 0;
  }
  /* sqlite3_finalize((struct sqlite3_stmt *)sql); */

  sql =
      "INSERT INTO transactions (TRX_TS_CREATE, TRX_NTS_CREATE, TRX_TS_ACCESS, "
      "TRX_NTS_ACCESS, FROM_H, TO_H, "
      "AMOUNT) "
      "VALUES (@1, @2, @3, @4, @5, @6, @7); ";
  sqlite3_prepare_v2(local_db, sql, -1, (struct sqlite3_stmt **)&sql, NULL);
  sqlite3_bind_int((struct sqlite3_stmt *)sql, 1, gossip_data->trx.ts_create);
  sqlite3_bind_int((struct sqlite3_stmt *)sql, 2, gossip_data->trx.nts_create);
  if (0 != set_ts(&gossip_data->trx)) {
    printf("%s set timestamp error\n", log_head());
    fflush(stdout);
  }
  sqlite3_bind_int((struct sqlite3_stmt *)sql, 3, gossip_data->trx.ts_access);
  sqlite3_bind_int((struct sqlite3_stmt *)sql, 4, gossip_data->trx.nts_access);
  sqlite3_bind_text((struct sqlite3_stmt *)sql, 5, gossip_data->trx.from, -1,
                    NULL);
  sqlite3_bind_text((struct sqlite3_stmt *)sql, 6, gossip_data->trx.to, -1,
                    NULL);
  sqlite3_bind_int((struct sqlite3_stmt *)sql, 7, gossip_data->trx.amt);

  rc = sqlite3_step((struct sqlite3_stmt *)sql);
  if ((rc != SQLITE_DONE) && (rc != SQLITE_ROW)) {
    printf("SQL error: %s\n", err);
    fflush(stdout);
    sqlite3_free(err);
    return -1;
  } else {
    printf(
        "%s saved to local db. timestamp: %d access: %d from: %s to: %s "
        "amount: %d\n",
        log_head(), gossip_data->trx.ts_create, gossip_data->trx.ts_access,
        gossip_data->trx.from, gossip_data->trx.to, gossip_data->trx.amt);
    fflush(stdout);
    if (0 == strcmp(gossip_data->trx.from, host_hash))
      total_samount += gossip_data->trx.amt;
    if (0 == strcmp(gossip_data->trx.to, host_hash))
      total_ramount += gossip_data->trx.amt;
    sqlite3_finalize((struct sqlite3_stmt *)sql);
    return 1;
  }
}

/********************************************************************/
static int send_gossip(gossip_t *gossip_data) {
  int ns; /* neighbour socket */
  int j, k;
  struct sockaddr_in naddr;
  char neigh_ip[INET_ADDRSTRLEN];
  char next_pool[HASH_SIZE + 1] = "";
  char prev_pool[HASH_SIZE + 1] = "";
  char hh_frg[SHORT_HASH_SIZE + 1] = "";
  int db_rc;

  db_rc = check_local_db(gossip_data);

  /* if gossip is novel for the peer */
  if (flg_gossip_mode == LIKE_AND_SHARE_MODE && db_rc == 0) return 1;

  /* transformation of data before sending */
  memset(hh_frg, 0, SHORT_HASH_SIZE + 1);
  strncpy(hh_frg, host_hash, SHORT_HASH_SIZE);
  if (0 != apipe_add(gossip_data->prev_host, hh_frg, flg_prev_len)) {
    printf("%s error in adding fragment to prev array trx amount %d\n",
           log_head(), gossip_data->trx.amt);
    fflush(stdout);
    return 1;
  }
  printf("%s fragment %s added to prev array %s trx amount %d\n", log_head(),
         hh_frg, gossip_data->prev_host, gossip_data->trx.amt);
  fflush(stdout);

  strcpy(prev_pool, gossip_data->prev_host);
  strcpy(gossip_data->trx.from, encode(gossip_data->trx.from));
  strcpy(gossip_data->trx.to, encode(gossip_data->trx.to));
  strcpy(gossip_data->prev_host, encode(gossip_data->prev_host));
  gossip_data->trx.ts_create = htonl(gossip_data->trx.ts_create);
  gossip_data->trx.nts_create = htonl(gossip_data->trx.nts_create);
  gossip_data->trx.ts_access = htonl(gossip_data->trx.ts_access);
  gossip_data->trx.nts_access = htonl(gossip_data->trx.nts_access);
  gossip_data->trx.amt = htons(gossip_data->trx.amt);

  for (int i = 0; i < flg_next_len; ++i) {
    if (flg_socket_type == TCP) {
      ns = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    } else {
      ns = socket(AF_INET, SOCK_DGRAM, 0);
    }
    naddr.sin_family = AF_INET;
    naddr.sin_port = htons(LISTEN_PORT);

    /* choosing next peer */
    memset(hh_frg, 0, SHORT_HASH_SIZE + 1);
    j = 0;
    k = 0;
    while (1) {
      strncpy(hh_frg, get_random_neigh(prev_pool), SHORT_HASH_SIZE);
      j++;
      if (j > LOOP_LOCK) {
        /* clear buffer */
        printf("%s clearing prev buffer!\n", log_head());
        fflush(stdout);
        strcpy(gossip_data->prev_host, G64);
        strcpy(prev_pool, gossip_data->prev_host);
        j = 0;
        continue;
      }
      k++;
      if (k > LOOP_LOCK) {
        /* clear buffer */
        printf("%s clearing next buffer!\n", log_head());
        fflush(stdout);
        memset(next_pool, 0, HASH_SIZE + 1);
        k = 0;
        continue;
      }
      if (strstr(next_pool, hh_frg)) continue;
      if (0 != apipe_add(next_pool, hh_frg, flg_prev_len)) {
        printf("%s error in adding fragment to next array\n", log_head());
        fflush(stdout);
        return 1;
      }
      strcpy(neigh_ip, get_neigh_ip(hh_frg));
      break;
    }
    printf("%s random ip to send %s next_idx %d loop %d\n", log_head(),
           neigh_ip, i, j);
    fflush(stdout);
    /* naddr.sin_addr.s_addr = inet_addr(neigh_ip); */
    inet_pton(AF_INET, neigh_ip, &naddr.sin_addr);

    total_spackets++;
    if (flg_socket_type == TCP) {
      if (connect(ns, (struct sockaddr *)(&naddr), sizeof(naddr)) == -1) {
        printf("%s [ERROR] in connecting to neighbour peer %s on %d %s %d\n",
               log_head(), neigh_ip, ns, inet_ntoa(naddr.sin_addr), errno);
        fflush(stdout);
        return 3;
      } else {
        printf("%s Connected to neighbour peer %s\n", log_head(),
               inet_ntoa(naddr.sin_addr));
        fflush(stdout);
      }
    }
    if (flg_socket_type == TCP) {
      send(ns, (void *)gossip_data, sizeof(gossip_t), MSG_NOSIGNAL);
      shutdown(ns, SHUT_RDWR);
      close(ns);
    } else {
      sendto(ns, (void *)gossip_data, sizeof(gossip_t), 0,
             (struct sockaddr *)(&naddr), sizeof(naddr));
    }
  }

  return 0;
}

/********************************************************************/
static void catch_function(int signo) {
  ts_t ts;

  get_ts(&ts);
  printf("%s kill signal caught at %d.\n", log_head(), ts.ts);
  fflush(stdout);
  /* raise(SIGTERM); */
  interrupted = 1;
}

/********************************************************************/
int main(int argc, char *argv[]) {
  int log;
  int trx_to = 0;
  int rej_prc = 0;
  gossip_t *gossip_rcv;

  /* epoll */
  int epoll_fd;
  struct epoll_event ev;
  struct epoll_event events[MAX_EVENTS];
  int num_events;

  /* sockets */
  int ls; /* listening socket */
  int cs; /* client socket */
  struct sockaddr_in addr;
  int c_bytes;
  int opt = 1;
  struct sockaddr_in caddr;
  socklen_t clen = sizeof(caddr);

  /* gossip */
  int rc_resent;

  if (argc < 8) {
    printf(
        "arguments are needed: unique_ip4 unique_hash64B udp/tcp "
        "number_of_peers previous_len gossip_mode reject_prc \n");
    exit(1);
  }

  strcpy(host_ip, argv[1]);
  strcpy(host_hash, argv[2]);
  strncpy(host_shash, host_hash, SHORT_HASH_SIZE);
  strcpy(host_db, argv[2]);
  strcat(host_db, ".db");
  strcpy(host_name, human_name());
  flg_socket_type = atoi(argv[3]);
  flg_num_peers = atoi(argv[4]);
  flg_prev_len = atoi(argv[5]);
  flg_next_len = atoi(argv[6]);
  flg_gossip_mode = atoi(argv[7]);
  flg_reject_prc = atoi(argv[8]);

#ifdef DEBUG
  printf("Startup parameters: '%s' '%s' '%s' '%s' %d %d\n", host_ip, host_hash,
         host_db, host_name, flg_socket_type, flg_num_peers);
#endif

  if (0 != init_local_db(flg_num_peers)) {
    perror(host_db);
    exit(1);
  }

  log = open(LOG_FILE, O_CREAT | O_WRONLY | O_APPEND, 0666);
  if (log == -1) {
    perror(LOG_FILE);
    exit(1);
  }

  /* stdout to file */
  if (dup2(log, 1) == -1) {
    perror("stdout translating error");
    exit(1);
  }
  close(log);

  /* listening socket */
  ls = listen_socket(flg_socket_type);
  if (ls == -1) {
    perror("listening socket error");
    exit(1);
  }

  /* to reuse address after close */
  setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  /* non blocking socket */
  fcntl(ls, F_SETFL, fcntl(ls, F_GETFL) | O_NONBLOCK);

  addr.sin_family = AF_INET;
  addr.sin_port = htons(LISTEN_PORT);
  /* addr.sin_addr.s_addr = inet_addr(host_ip); */
  inet_pton(AF_INET, host_ip, &addr.sin_addr);

  if (bind(ls, (struct sockaddr *)(&addr), sizeof(addr)) == -1) {
    if (errno == EADDRINUSE)
      printf("bind: address in use!\n");
    else
      printf("bind: error in binding ip address\n");
    exit(1);
  }

  /* event listener for sockets */
  epoll_fd = epoll_create1(0);
  if (epoll_fd == -1) {
    perror("epoll_create1");
    exit(1);
  }
  /* ev.events = EPOLLIN | EPOLLET; */
  ev.events = EPOLLIN;
  ev.data.fd = ls;
  epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ls, &ev);

  /* start listening */
  if (flg_socket_type == TCP) {
    if (listen(ls, SOMAXCONN) == -1) {
      printf("Error in listening server startup\n");
      exit(1);
    }
    printf("%s Listening on %s:%d\n", log_head(), inet_ntoa(addr.sin_addr),
           ntohs(addr.sin_port));
  }

  /* to push from buffer */
  fflush(stdout);

  /* event waiting loop */
  while (1) {
    signal(SIGINT, catch_function);
    if (interrupted && trx_num) {
      trx_num--;
      printf("%s timeout %d for new transaction number %d of %d\n", log_head(),
             trx_to, trx_num, MAX_TRX);
      fflush(stdout);
      if (0 == send_gossip(make_gossip(make_trx(get_random_neigh(""))))) {
        printf("%s transaction is sent successfully!\n", log_head());
        fflush(stdout);
      }
      break;
    }
  }

  interrupted = 0;

  /* event waiting loop */
  while (1) {
    struct epoll_event cevent;

    signal(SIGINT, catch_function);
    if (interrupted) break;
    /* timeout of epoll used for random trx generation */
    /* trx_to = get_raw_rand(9) + 1; */
    /* num_events = epoll_wait(epoll_fd, events, MAX_EVENTS, trx_to * 1000); */
    num_events = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
    /* peer not working */
    rej_prc = get_raw_rand(100);
    if (rej_prc < flg_reject_prc) continue;
    /* extra break for transaction overflow */
    if (get_trx_num() >= MAX_TRX) break;
    for (int n = 0; n < num_events; ++n) {
      if (events[n].data.fd == ls) {
        /* open client socket */
        if (flg_socket_type == TCP) {
          cs = accept(ls, (struct sockaddr *)&caddr, &clen);
          fcntl(cs, F_SETFL, fcntl(ls, F_GETFL) | O_NONBLOCK);
          cevent.events = EPOLLIN;
          cevent.data.fd = cs;
          epoll_ctl(epoll_fd, EPOLL_CTL_ADD, cs, &cevent);
          printf("%s Incoming registered connection from %s!\n", log_head(),
                 inet_ntoa(caddr.sin_addr));
          fflush(stdout);
        } else {
          printf("%s Incoming connection!\n", log_head());
          fflush(stdout);
          /* read gossip from incoming client */
          gossip_rcv = malloc(sizeof(gossip_t));
          memset(gossip_rcv, 0, sizeof(gossip_t));
          c_bytes = recv(ls, (gossip_t *)gossip_rcv, sizeof(gossip_t), 0);
          if (c_bytes == -1) {
            printf("%s [ERROR] in receiving data: %d\n", log_head(), errno);
            fflush(stdout);
          } else {
            total_rpackets++;
            if (strstr(gossip_rcv->prev_host, host_shash)) {
              printf("%s Received possible ICMP answer %s From: %s To:%s ",
                     log_head(), gossip_rcv->prev_host, gossip_rcv->trx.from,
                     gossip_rcv->trx.to);
              fflush(stdout);
              continue;
            }
            /* transformations of received data: */
            gossip_rcv->trx.ts_create = ntohl(gossip_rcv->trx.ts_create);
            gossip_rcv->trx.nts_create = ntohl(gossip_rcv->trx.nts_create);
            /* if (0 != set_ts(&gossip_rcv->trx)) { */
            /*   printf("%s error in setting access timestamp\n", log_head());
             */
            /*   fflush(stdout); */
            /* } */
            gossip_rcv->trx.amt = ntohs(gossip_rcv->trx.amt);
            strcpy(gossip_rcv->prev_host, decode(gossip_rcv->prev_host));
            strcpy(gossip_rcv->trx.from, decode(gossip_rcv->trx.from));
            strcpy(gossip_rcv->trx.to, decode(gossip_rcv->trx.to));
            printf("%s Received ts %d From: %s To:%s Amount:%d!\n", log_head(),
                   gossip_rcv->trx.ts_create, gossip_rcv->trx.from,
                   gossip_rcv->trx.to, gossip_rcv->trx.amt);
            fflush(stdout);
            rc_resent = send_gossip(gossip_rcv);
            if (rc_resent == 0) {
              printf("%s trx resent: Amount %d\n", log_head(),
                     ntohs(gossip_rcv->trx.amt));
              fflush(stdout);
            } else if (rc_resent == 1) {
              printf("%s gossip not need to be resent\n", log_head());
              fflush(stdout);
            } else {
              printf("%s gossip not resent\n", log_head());
              fflush(stdout);
            }
          }
        }
      } else {
        /* read gossip from incoming client */
        gossip_rcv = malloc(sizeof(gossip_t));
        memset(gossip_rcv, 0, sizeof(gossip_t));
        c_bytes = recv(events[n].data.fd, (gossip_t *)gossip_rcv,
                       sizeof(gossip_t), 0);
        if (c_bytes == 0 && errno != EAGAIN) {
          shutdown(events[n].data.fd, SHUT_RDWR);
          close(events[n].data.fd);
          printf("%s disconnected from client.\n", log_head());
          fflush(stdout);
        } else if (c_bytes == -1) {
          printf("%s [ERROR] in receiving data: %d\n", log_head(), errno);
          fflush(stdout);
        } else {
          total_rpackets++;
          if (strstr(gossip_rcv->prev_host, host_shash)) {
            printf("%s Received possible ICMP answer %s From: %s To:%s ",
                   log_head(), gossip_rcv->prev_host, gossip_rcv->trx.from,
                   gossip_rcv->trx.to);
            fflush(stdout);
            continue;
          }
          /* transformations of received data: */
          gossip_rcv->trx.ts_create = ntohl(gossip_rcv->trx.ts_create);
          gossip_rcv->trx.nts_create = ntohl(gossip_rcv->trx.nts_create);
          /* if (0 != set_ts(&gossip_rcv->trx)) { */
          /*   printf("%s error in setting access timestamp\n", log_head());
           */
          /*   fflush(stdout); */
          /* } */
          gossip_rcv->trx.amt = ntohs(gossip_rcv->trx.amt);
          strcpy(gossip_rcv->prev_host, decode(gossip_rcv->prev_host));
          strcpy(gossip_rcv->trx.from, decode(gossip_rcv->trx.from));
          strcpy(gossip_rcv->trx.to, decode(gossip_rcv->trx.to));
          printf("%s Received ts %d From: %s To:%s Amount:%d!\n", log_head(),
                 gossip_rcv->trx.ts_create, gossip_rcv->trx.from,
                 gossip_rcv->trx.to, gossip_rcv->trx.amt);
          fflush(stdout);
          rc_resent = send_gossip(gossip_rcv);
          if (rc_resent == 0) {
            printf("%s trx resent: Amount %d\n", log_head(),
                   ntohs(gossip_rcv->trx.amt));
            fflush(stdout);
          } else if (rc_resent == 1) {
            printf("%s gossip not need to be resent\n", log_head());
            fflush(stdout);
          } else {
            printf("%s gossip not resent\n", log_head());
            fflush(stdout);
          }
        }
        /* free(gossip_rcv); */
        /* TCP: close client socket */
        /* if (flg_socket_type == TCP) { */
        /*   shutdown(cs, SHUT_RDWR); */
        /*   close(cs); */
        /* } */
      }
    }
  }

  close(epoll_fd);
  shutdown(ls, SHUT_RDWR);
  close(ls);

  printf(
      "%s End of main process\n------------------\nTotal sent packets: "
      "%d\nTotal received packets: %d\nTotal "
      "amount of sent: %d\nTotal amount of received: %d\nTotal transaction "
      "in "
      "local db: %d\n",
      log_head(), total_spackets, total_rpackets, total_samount, total_ramount,
      get_trx_num());
  fflush(stdout);

  report_trx();

  if (0 != clearing(flg_socket_type)) {
    printf("error in cleating process\n");
    fflush(stdout);
    return 1;
  }

  sqlite3_close(local_db);

  return 0;
}

