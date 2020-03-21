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
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* #include <dmalloc.h> */
#include <ev.h>
#include <openssl/sha.h>
#include <sqlite3.h>

#include "main.h"

/* shared variables - bad style */

static int ls; /* listening socket */
static int peers_pulled = 0;
static ts_t kill_ts;
static ev_io socket_watcher; /* socket event watcher */
static ev_timer timeout_watcher;

static int check_local_db(gossip_t* gossip_data, sqlite3* db);

/********************************************************************/
/* Open database if not exists and (re)fill with neighbour table.   */
/* Pointer to db stays open until end of main process.              */
/********************************************************************/
static int init_local_db() {
  int rc;
  char* sql;
  char* err = 0;

  /* Open/Create database */
  /* rc = sqlite3_enable_shared_cache(1); */
  /* if (rc != SQLITE_OK) { */
  /*   return 1; */
  /* } */

  rc = sqlite3_open(host_db, &local_db);
  if (rc) {
    return 2;
  } else {
    sql =
        " DROP TABLE IF EXISTS all_transactions; "
        " CREATE TABLE all_transactions ( "
        " TRX_TS_CREATE		INT	NOT NULL, "
        " TRX_NTS_CREATE	INT	NOT NULL, "
        " TRX_TS_ACCESS		INT	NOT NULL, "
        " TRX_NTS_ACCESS	INT	NOT NULL, "
        " TRX_TS_ROUND		INT	NOT NULL, "
        /* " TRX_NTS_ROUND		INT	NOT NULL, " */
        " AUTH_H	CHAR(64)	NOT NULL, "
        " FROM_H	CHAR(64)	NOT NULL, "
        " TO_H		CHAR(64)	NOT NULL, "
        " AMOUNT	INT8	NOT NULL); ";
    rc = sqlite3_exec(local_db, sql, NULL, 0, &err);
    if (rc != SQLITE_OK) {
      printf("init SQL error %s\n", err);
      return 3;
    }
    return 0;
  }
}

/********************************************************************/
static int callback(void* NotUsed, int argc, char** argv, char** azColName) {
  int i;

  printf("%s %d %d %d %d %d ", log_head(), flg_socket_type, flg_gossip_mode,
         flg_prev_len, flg_next_len, flg_num_peers);
  for (i = 0; i < argc; i++) {
    printf("%s = %s ", azColName[i], argv[i] ? argv[i] : "NULL");
  }
  printf("\n");
  fflush(stdout);
  return 0;
}

/********************************************************************/
static void cb_connect(EV_P_ ev_io* w, int revents) {
  int cs; /* client socket */
  gossip_t* gossip_rcv;
  struct sockaddr_in caddr;
  socklen_t clen = sizeof(caddr);

  gossip_rcv = malloc(sizeof(gossip_t));
  if (flg_socket_type == TCP) {
    cs = accept(ls, (struct sockaddr*)(&caddr), &clen);
    if (cs <= 0) return;

    printf("%s Incoming connection from %s!\n", log_head(),
           inet_ntoa(caddr.sin_addr));
    fflush(stdout);
    memset(gossip_rcv, 0, sizeof(gossip_t));
    /* read gossip from incoming client */
    while (recv(cs, (gossip_t*)gossip_rcv, sizeof(gossip_t), MSG_WAITALL)) {
      /* transformations of received data: */
      gossip_rcv->trx.ts_create = ntohl(gossip_rcv->trx.ts_create);
      gossip_rcv->trx.nts_create = ntohl(gossip_rcv->trx.nts_create);
      gossip_rcv->trx.ts_access = ntohl(gossip_rcv->trx.ts_access);
      gossip_rcv->trx.nts_access = ntohl(gossip_rcv->trx.nts_access);
      gossip_rcv->trx.amt = ntohs(gossip_rcv->trx.amt);
      strcpy(gossip_rcv->prev_host, decode(gossip_rcv->prev_host));
      strcpy(gossip_rcv->trx.from, decode(gossip_rcv->trx.from));
      strcpy(gossip_rcv->trx.to, decode(gossip_rcv->trx.to));
      printf(
          "%s Received ts %d access %d Auth: %s From:%s To:%s "
          "Amount:%d!\n",
          log_head(), gossip_rcv->trx.ts_create, gossip_rcv->trx.ts_access,
          gossip_rcv->prev_host, gossip_rcv->trx.from, gossip_rcv->trx.to,
          gossip_rcv->trx.amt);
      fflush(stdout);
      if (0 == check_local_db(gossip_rcv, local_db)) {
        printf("%s TCP after db Error SQL\n", log_head());
        fflush(stdout);
      }
    }
    /* TCP: close client socket */
    shutdown(cs, SHUT_RDWR);
    close(cs);
  } else {
    /* read gossip from incoming client */
    memset(gossip_rcv, 0, sizeof(gossip_t));
    while (recv(ls, (gossip_t*)gossip_rcv, sizeof(gossip_t), MSG_WAITALL) > 0) {
      /* transformations of received data: */
      gossip_rcv->trx.ts_create = ntohl(gossip_rcv->trx.ts_create);
      gossip_rcv->trx.nts_create = ntohl(gossip_rcv->trx.nts_create);
      gossip_rcv->trx.ts_access = ntohl(gossip_rcv->trx.ts_access);
      gossip_rcv->trx.nts_access = ntohl(gossip_rcv->trx.nts_access);
      gossip_rcv->trx.amt = ntohs(gossip_rcv->trx.amt);
      strcpy(gossip_rcv->prev_host, decode(gossip_rcv->prev_host));
      strcpy(gossip_rcv->trx.from, decode(gossip_rcv->trx.from));
      strcpy(gossip_rcv->trx.to, decode(gossip_rcv->trx.to));
      printf(
          "%s Received ts %d access %d Auth: %s From:%s To:%s "
          "Amount:%d!\n",
          log_head(), gossip_rcv->trx.ts_create, gossip_rcv->trx.ts_access,
          gossip_rcv->prev_host, gossip_rcv->trx.from, gossip_rcv->trx.to,
          gossip_rcv->trx.amt);
      fflush(stdout);
      if (0 == check_local_db(gossip_rcv, local_db)) {
        printf("%s UDP after db Error SQL\n", log_head());
        fflush(stdout);
        break;
      }
    }
  }
}

/********************************************************************/
static void cb_timeout(EV_P_ ev_timer* w, int revents) {
  if (peers_pulled >= MAJORITY(flg_num_peers - 1)) {
    printf("%s consensus round ended and majority was reached %d\n", log_head(),
           peers_pulled);
    fflush(stdout);
    ev_break(EV_A_ EVBREAK_ONE);
  } else {
    printf("%s consensus round ended and majority was not reached %d\n",
           log_head(), peers_pulled);
    fflush(stdout);
    ev_break(EV_A_ EVBREAK_ONE);
  }
}

/********************************************************************/
static int cb_get_count(void* NotUsed, int argc, char** argv,
                        char** azColName) {
  peers_pulled = atoi(argv[0]);
  return 0;
}

/********************************************************************/
static void unq_auth_count(sqlite3* db) {
  int rc;
  char* sql;
  char* err;

  sql = "SELECT COUNT(DISTINCT AUTH_H) FROM all_transactions;";

  rc = sqlite3_exec(db, sql, cb_get_count, 0, &err);
  if (rc != SQLITE_OK) {
    printf("%s unq_auth_count SQL error: %s\n", log_head(), err);
    fflush(stdout);
    /* sqlite3_free(err); */
  }
}

/********************************************************************/
static int check_local_db(gossip_t* gossip_data, sqlite3* db) {
  int rc;
  char* sql;

  sqlite3_prepare_v2(
      db,
      " INSERT INTO all_transactions (TRX_TS_ROUND, "
      " TRX_TS_CREATE, TRX_NTS_CREATE, TRX_TS_ACCESS, TRX_NTS_ACCESS, AUTH_H, "
      " FROM_H, TO_H, AMOUNT) "
      " VALUES (@1, @2, @3, @4, @5, @6, @7, @8, @9); ",
      -1, (struct sqlite3_stmt**)&sql, NULL);
  sqlite3_bind_int((struct sqlite3_stmt*)sql, 1, kill_ts.ts);
  /* sqlite3_bind_int((struct sqlite3_stmt*)sql, 2, kill_ts.nts); */
  sqlite3_bind_int((struct sqlite3_stmt*)sql, 2, gossip_data->trx.ts_create);
  sqlite3_bind_int((struct sqlite3_stmt*)sql, 3, gossip_data->trx.nts_create);
  sqlite3_bind_int((struct sqlite3_stmt*)sql, 4, gossip_data->trx.ts_access);
  sqlite3_bind_int((struct sqlite3_stmt*)sql, 5, gossip_data->trx.nts_access);
  sqlite3_bind_text((struct sqlite3_stmt*)sql, 6, gossip_data->prev_host, -1,
                    NULL);
  sqlite3_bind_text((struct sqlite3_stmt*)sql, 7, gossip_data->trx.from, -1,
                    NULL);
  sqlite3_bind_text((struct sqlite3_stmt*)sql, 8, gossip_data->trx.to, -1,
                    NULL);
  sqlite3_bind_int((struct sqlite3_stmt*)sql, 9, gossip_data->trx.amt);

  rc = sqlite3_step((struct sqlite3_stmt*)sql);
  if ((rc != SQLITE_DONE) && (rc != SQLITE_ROW)) {
    printf("%s check_local_db SQL error: %d\n", log_head(), rc);
    fflush(stdout);
    /* sqlite3_free(err); */
    return 0;
  } else {
    printf(
        "%s saved to local db. timestamp: %d auth: %s from: %s to: %s amount: "
        "%d\n",
        log_head(), gossip_data->trx.ts_create, gossip_data->prev_host,
        gossip_data->trx.from, gossip_data->trx.to, gossip_data->trx.amt);
    fflush(stdout);
    /* sqlite3_finalize((struct sqlite3_stmt*)sql); */
    unq_auth_count(db);
    printf("%s peers in local db %d\n", log_head(), peers_pulled);
    fflush(stdout);
    return 1;
  }
}

/********************************************************************/
/* -h           usage                                               */
/* -p 0|1   	protocol 0=UDP, 1=TCP (default: 0)                  */
/* -n N		number of peers                                     */
/* -P N		length of previous host chain (default: 0)          */
/* -N N		number of next hosts to gossip (default: 1)         */
/* -g 0|1	gossip mode 0=normal, 1=like-and-share (default: 0) */
/* -r N  	reject connection reject, % (default: 0)            */
/* -t N  	round time in seconds (default: 20)                 */
/********************************************************************/
int main(int argc, char* argv[]) {
  int log;
  struct ev_loop* loop = EV_DEFAULT;
  /* peers */
  char ip_addr[INET_ADDRSTRLEN];
  pid_t peer[MAX_PEERS];
  unsigned char md[SHA256_DIGEST_LENGTH * 2 + 1];
  int killed_peers = 0;
  int started_peers = 0;
  char* env[] = {"DMALLOC_OPTIONS=debug=0x2,log=leaks2.log",
                 "LD_PRELOAD=libdmalloc.so", NULL};
  /* sockets */
  struct sockaddr_in addr;
  int opt = 1;
  /* data */
  char* zErrMsg = 0;
  int rc;
  char* sql;
  /* flags/options */
  int arg;
  const char* short_opt = "hp:n:P:N:g:r:";
  struct option long_opt[] = {
      {"help", no_argument, NULL, 'h'},
      {"proto", required_argument, NULL, 'p'},
      {"number-of-peers", required_argument, NULL, 'n'},
      {"previous-peer-number", required_argument, NULL, 'P'},
      {"gossip-mode", required_argument, NULL, 'g'},
      {"next-peer-number", required_argument, NULL, 'N'},
      {"reject-prc", required_argument, NULL, 'r'},
      {"round-time", required_argument, NULL, 't'},
      {NULL, 0, NULL, 0}};

  while ((arg = getopt_long(argc, argv, short_opt, long_opt, NULL)) != -1) {
    switch (arg) {
      case -1: /* no more arguments */
      case 0:  /* long options toggles */
        break;
      case 'p':
        flg_socket_type = atoi(optarg);
        break;
      case 'n':
        flg_num_peers = atoi(optarg);
        break;
      case 'P':
        flg_prev_len = atoi(optarg);
        break;
      case 'g':
        flg_gossip_mode = atoi(optarg);
        break;
      case 'N':
        flg_next_len = atoi(optarg);
        break;
      case 'r':
        flg_reject_prc = atoi(optarg);
        break;
      case 't':
        flg_round_time = atoi(optarg);
        break;
      case 'h':
        printf("Usage: %s [OPTIONS]\n", argv[0]);
        printf("  -h, --help                print this help and exit\n");
        printf("  -p, --proto               protocol (0=UDP, 1=TCP)\n");
        printf("  -n, --number-of-peers     \n");
        printf("  -P, --previous-peer-number\n");
        printf("  -N, --next-peer-number    \n");
        printf("  -g, --gossip-mode         0=normal, 1=like-and-share\n");
        printf("  -r, --reject-prc          \n");
        printf("  -t, --round-time          time till end of round (s)\n");
        printf("\n");
        return 0;
      case ':':
      case '?':
        fprintf(stderr, "Try `%s --help' for more information.\n", argv[0]);
        return 2;
      default:
        fprintf(stderr, "%s: invalid option -- %c\n", argv[0], arg);
        fprintf(stderr, "Try `%s --help' for more information.\n", argv[0]);
        return 2;
    };
  };

  /* validation of mandatory arguments */
  if (flg_socket_type != UDP && flg_socket_type != TCP) {
    printf("socket type not allowed: %d\n", flg_socket_type);
    return 2;
  }
  if (flg_num_peers <= 0) {
    printf("number of nodes not correct: %d\n", flg_num_peers);
    return 2;
  }
  if (flg_prev_len < 0 || flg_prev_len > MAX_PREV) {
    printf("flag of previous hosts chain length is not correct: %d\n",
           flg_prev_len);
    return 2;
  }
  if (flg_next_len < 1 || flg_next_len > MAX_NEXT) {
    printf("flag of next hosts chain length is not correct: %d\n",
           flg_next_len);
    return 2;
  }
  if (flg_next_len > flg_num_peers - flg_prev_len - 1) {
    printf("flag of next hosts chain length is too long: %d\n", flg_next_len);
    return 2;
  }
  if (flg_gossip_mode != NORMAL_MODE &&
      flg_gossip_mode != LIKE_AND_SHARE_MODE) {
    printf("flag of gossip mode in not correct: %d\n", flg_gossip_mode);
    return 2;
  }
  if (flg_reject_prc > 100 || flg_reject_prc < 0) {
    printf("flag of reject procent in not correct: %d\n", flg_reject_prc);
    return 2;
  }

  strcpy(host_ip, CLR_IP);
  if (0 != sha256_hex(host_ip, strlen(host_ip), md)) {
    perror(host_ip);
    return 1;
  } else {
    strcpy(host_hash, md);
  }
  strcpy(host_db, host_hash);
  strcat(host_db, ".db");
  strcpy(host_name, human_name());

  if (0 != init_local_db()) {
    perror(host_db);
    exit(1);
  }

#ifdef DEBUG
  printf("Startup parameters: '%s' '%s' '%s' '%s' %d %d %d %d %d\n", host_ip,
         host_hash, host_db, host_name, flg_socket_type, flg_num_peers,
         flg_prev_len, flg_gossip_mode, flg_reject_prc);
#endif

  /* printf("b58 %s %s\n", host_hash, encode(host_hash)); */
  /* printf("b58 decoded %s\n", decode(encode(host_hash))); */

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
    fflush(stdout);
    exit(1);
  }

  /* to reuse address after close */
  setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  /* non blocking socket */
  fcntl(ls, F_SETFL, fcntl(ls, F_GETFL) | O_NONBLOCK);

  addr.sin_family = AF_INET;
  addr.sin_port = htons(LISTEN_PORT);
  /* addr.sin_addr.s_addr = inet_addr(CLR_IP); */
  inet_pton(AF_INET, CLR_IP, &addr.sin_addr);

  if (bind(ls, (struct sockaddr*)(&addr), sizeof(addr)) == -1) {
    if (errno == EADDRINUSE)
      printf("%s bind: address in use!\n", log_head());
    else
      printf("%s bind: error in binding ip address\n", log_head());
    fflush(stdout);
    exit(1);
  }

  /* Starting peers */
  for (int i = 1; i <= flg_num_peers; ++i) {
    get_lo_ip(i, ip_addr);
    /* not starting self peer */
    if (0 == strcmp(ip_addr, CLR_IP)) continue;
    if (0 != sha256_hex(ip_addr, strlen(ip_addr), md)) {
      printf("Error making hash for ip '%s' %ld %ld %s\n", ip_addr,
             strlen(ip_addr), sizeof(ip_addr), md);
      fflush(stdout);
      continue;
    }
    peer[i] = fork();
    if (peer[i] == 0) {
      printf("Executing %s '%s' %s %d %d %d %d %d\n", log_head(), ip_addr, md,
             flg_socket_type, flg_num_peers, flg_prev_len, flg_gossip_mode,
             flg_reject_prc);
      fflush(stdout);
      if (0 != execle("app", "app", ip_addr, md, get_sarg(flg_socket_type),
                      get_sarg(flg_num_peers), get_sarg(flg_prev_len),
                      get_sarg(flg_next_len), get_sarg(flg_gossip_mode),
                      get_sarg(flg_reject_prc), NULL, env)) {
        printf("Error executing '%s' %ld %ld %s %d\n", ip_addr, strlen(ip_addr),
               sizeof(ip_addr), md, flg_socket_type);
        fflush(stdout);
      }
      exit(0);
    } else {
      /* waitpid(peer[i], NULL, 0); */
      /* wait(NULL); */
    }
  }

  /* sleeps till start of clearing */
  printf("%s Sleeping %d seconds before GO signal of all peers.\n", log_head(),
         flg_round_time);
  fflush(stdout);

  /* !!BLOCKING */
  sleep(flg_round_time);

  if (!started_peers) {
    /* go signal to all peers */
    for (int i = 1; i <= flg_num_peers; ++i) {
      get_lo_ip(i, ip_addr);
      /* not killing self */
      if (0 == strcmp(ip_addr, CLR_IP)) continue;
      printf("%s GO signal to PID %d\n", log_head(), peer[i]);
      fflush(stdout);
      kill(peer[i], SIGINT);
    }
    started_peers = 1;
  }

  /* sleeps till start of clearing */
  printf("%s Sleeping %d seconds before KILL signal of all peers.\n",
         log_head(), flg_round_time);
  fflush(stdout);

  /* !!BLOCKING */
  sleep(flg_round_time);

  /* start listening before kill */
  if (flg_socket_type == TCP) {
    if (listen(ls, SOMAXCONN) == -1) {
      printf("%s Error in listening server startup\n", log_head());
      fflush(stdout);
      exit(1);
    }
    printf("%s Listening on %s:%d\n", log_head(), inet_ntoa(addr.sin_addr),
           ntohs(addr.sin_port));
    fflush(stdout);
  }

  if (!killed_peers) {
    /* kill signal to all peers */
    if (0 != get_ts(&kill_ts)) {
      printf("%s Kill timestamp error\n", log_head());
      fflush(stdout);
    }
    for (int i = 1; i <= flg_num_peers; ++i) {
      get_lo_ip(i, ip_addr);
      /* not killing self */
      if (0 == strcmp(ip_addr, CLR_IP)) continue;
      printf("%s Kill signal to PID %d\n", log_head(), peer[i]);
      fflush(stdout);
      kill(peer[i], SIGINT);
    }
    killed_peers = 1;
  }

  /* events */
  ev_io_init(&socket_watcher, cb_connect, ls, EV_READ);
  ev_io_start(loop, &socket_watcher);
  ev_timer_init(&timeout_watcher, cb_timeout, (double)CLR_TIMEOUT, 0.);
  ev_timer_start(loop, &timeout_watcher);

  ev_run(loop, 0);

  /* if (peers_pulled >= flg_num_peers - 1) break; */

  shutdown(ls, SHUT_RDWR);
  if (0 != close(ls)) {
    printf("error in close of listen socket close %d\n", errno);
    fflush(stdout);
    exit(9);
  }

  /* sql = malloc(300); */
  /* sprintf(sql, */
  /*         " SELECT TRX_TS_CREATE, " */
  /*         " AVG((TRX_TS_ACCESS * 1000 + TRX_NTS_ACCESS) - (TRX_TS_CREATE * "
   */
  /*  */
  /*         "1000 + TRX_NTS_CREATE)), " */
  /*         " substr(FROM_H,1,8), substr(TO_H,1,8), AMOUNT, COUNT(AUTH_H) " */
  /*         " FROM all_transactions WHERE TRX_TS_CREATE < TRX_TS_ROUND " */
  /*         " GROUP BY AUTH_H " */
  /*         " HAVING COUNT(AUTH_H) >= %d;", */
  /*         MAJORITY(flg_num_peers - 1)); */
  /* printf("%s\n", sql); */
  /* rc = sqlite3_exec(local_db, sql, callback, 0, &zErrMsg); */
  /* if (rc != SQLITE_OK) { */
  /*   printf("%s SQL error: %s\n", log_head(), zErrMsg); */
  /*   fflush(stdout); */
  /*   sqlite3_free(zErrMsg); */
  /* } */

  sql = malloc(400);
  sprintf(sql,
          "SELECT COUNT(TRX_TS_CREATE), AVG(TSA) FROM ("
          " SELECT TRX_TS_CREATE, "
          " AVG((TRX_TS_ACCESS * 1000 + TRX_NTS_ACCESS) - (TRX_TS_CREATE * "

          "1000 + TRX_NTS_CREATE)) AS TSA, "
          " substr(FROM_H,1,8), substr(TO_H,1,8), AMOUNT, COUNT(AUTH_H) "
          " FROM all_transactions WHERE TRX_TS_CREATE < TRX_TS_ROUND "
          " GROUP BY TRX_TS_CREATE, FROM_H, TO_H, AMOUNT "
          " HAVING COUNT(AUTH_H) >= %d);",
          MAJORITY(flg_num_peers - 1));
  printf("%s\n", sql);
  rc = sqlite3_exec(local_db, sql, callback, 0, &zErrMsg);
  if (rc != SQLITE_OK) {
    printf("%s avg SQL error: %s\n", log_head(), zErrMsg);
    fflush(stdout);
    sqlite3_free(zErrMsg);
  }

  sqlite3_close(local_db);
  return 0;
}

