/*
 * Copyright (c) 2020 by Vadims Zilnieks
 * https://github.com/vzilnieks/gos-ipc
 */

#ifndef MAIN_H
#define MAIN_H

/* limits: can be changed depending on system */

#define MAX_PEERS 9999
#define MAX_TRX 99999

#define UDP 0
#define TCP 1

#define MAX_PREV 4
#define MAX_NEXT 4

#define NORMAL_MODE 0
#define LIKE_AND_SHARE_MODE 1

#define LISTEN_PORT 7777
#define LOG_FILE "main.log"
#define LOG_FORMAT "%a %b %d %H:%M:%S %Y "

#define MAJORITY(X) ((X) / 2 + 1)

#define B58_SIZE 90
#define HASH_SIZE 64
#define SHORT_HASH_SIZE 16
#define HOSTNAME_SIZE 60

/* To protect from infinite loops */
#define LOOP_LOCK 1000

/* clearing node settings */
#define CLR_IP "127.0.0.1"
#define CLR_TIMEOUT 30

#define G64 "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg"

/* For epoll */
#define MAX_EVENTS 9999

typedef struct ts {
  uint32_t ts;
  uint32_t nts;
} ts_t;

typedef struct trx {
  char from[B58_SIZE]; /* sender */
  char to[B58_SIZE];   /* receiver */
  uint32_t ts_create;  /* time stamp in unix epoch format */
  uint32_t nts_create; /* nano seconds                    */
  uint32_t ts_access;  /* create for new, access on recv. */
  uint32_t nts_access; /* nano seconds                    */
  uint16_t amt;        /* amount */
} trx_t;

typedef struct gossip {
  char prev_host[B58_SIZE];
  trx_t trx;
} gossip_t;

typedef struct neigh_table {
  char neigh_ip[INET_ADDRSTRLEN];
  char neigh_hash[HASH_SIZE + 1];
} neigh_t;

char host_hash[HASH_SIZE + 1];
char host_shash[SHORT_HASH_SIZE + 1];
char host_name[HOSTNAME_SIZE];
char host_ip[INET_ADDRSTRLEN];
char host_db[HASH_SIZE + 3 + 1];

/* flags */
static int flg_socket_type = UDP;
static int flg_num_peers = 0;
static int flg_prev_len = 0;
static int flg_next_len = 1;
static int flg_gossip_mode = NORMAL_MODE;
static int flg_reject_prc = 0;
static int flg_round_time = 20;

/* shared resources */
sqlite3* local_db;

/********************************************************************/
/* Random number from dev rand                                      */
/********************************************************************/
extern int get_raw_rand(int x);

extern int set_ts(trx_t* trx);
extern int get_ts(ts_t* ts);

extern int sha256_hex(void* input, unsigned long length, unsigned char* output);

/******************************************************************************/
/* Taken from libb64 samples                                                  */
/******************************************************************************/
char* encode(const char* input);
char* decode(const char* input);

#define LEFT_NUM 108
#define RIGHT_NUM 237

/******************************************************************************/
/* Translated from GoLang: https://github.com/moby/moby -> namesgenerator     */
/******************************************************************************/

static const char* left[LEFT_NUM] = {
    "admiring",      "adoring",     "affectionate",  "agitated",
    "amazing",       "angry",       "awesome",       "beautiful",
    "blissful",      "bold",        "boring",        "brave",
    "busy",          "charming",    "clever",        "cool",
    "compassionate", "competent",   "condescending", "confident",
    "cranky",        "crazy",       "dazzling",      "determined",
    "distracted",    "dreamy",      "eager",         "ecstatic",
    "elastic",       "elated",      "elegant",       "eloquent",
    "epic",          "exciting",    "fervent",       "festive",
    "flamboyant",    "focused",     "friendly",      "frosty",
    "funny",         "gallant",     "gifted",        "goofy",
    "gracious",      "great",       "happy",         "hardcore",
    "heuristic",     "hopeful",     "hungry",        "infallible",
    "inspiring",     "interesting", "intelligent",   "jolly",
    "jovial",        "keen",        "kind",          "laughing",
    "loving",        "lucid",       "magical",       "mystifying",
    "modest",        "musing",      "naughty",       "nervous",
    "nice",          "nifty",       "nostalgic",     "objective",
    "optimistic",    "peaceful",    "pedantic",      "pensive",
    "practical",     "priceless",   "quirky",        "quizzical",
    "recursing",     "relaxed",     "reverent",      "romantic",
    "sad",           "serene",      "sharp",         "silly",
    "sleepy",        "stoic",       "strange",       "stupefied",
    "suspicious",    "sweet",       "tender",        "thirsty",
    "trusting",      "unruffled",   "upbeat",        "vibrant",
    "vigilant",      "vigorous",    "wizardly",      "wonderful",
    "xenodochial",   "youthful",    "zealous",       "zen"};

static const char* right[RIGHT_NUM] = {
    "albattani",     "allen",        "almeida",     "antonelli",
    "agnesi",        "archimedes",   "ardinghelli", "aryabhata",
    "austin",        "babbage",      "banach",      "banzai",
    "bardeen",       "bartik",       "bassi",       "beaver",
    "bell",          "benz",         "bhabha",      "bhaskara",
    "black",         "blackburn",    "blackwell",   "bohr",
    "booth",         "borg",         "bose",        "bouman",
    "boyd",          "brahmagupta",  "brattain",    "brown",
    "buck",          "burnell",      "cannon",      "carson",
    "cartwright",    "carver",       "cerf",        "chandrasekhar",
    "chaplygin",     "chatelet",     "chatterjee",  "chebyshev",
    "cohen",         "chaum",        "clarke",      "colden",
    "cori",          "cray",         "curran",      "curie",
    "darwin",        "davinci",      "dewdney",     "dhawan",
    "diffie",        "dijkstra",     "dirac",       "driscoll",
    "dubinsky",      "easley",       "edison",      "einstein",
    "elbakyan",      "elgamal",      "elion",       "ellis",
    "engelbart",     "euclid",       "euler",       "faraday",
    "feistel",       "fermat",       "fermi",       "feynman",
    "franklin",      "gagarin",      "galileo",     "galois",
    "ganguly",       "gates",        "gauss",       "germain",
    "goldberg",      "goldstine",    "goldwasser",  "golick",
    "goodall",       "gould",        "greider",     "grothendieck",
    "haibt",         "hamilton",     "haslett",     "hawking",
    "hellman",       "heisenberg",   "hermann",     "herschel",
    "hertz",         "heyrovsky",    "hodgkin",     "hofstadter",
    "hoover",        "hopper",       "hugle",       "hypatia",
    "ishizaka",      "jackson",      "jang",        "jemison",
    "jennings",      "jepsen",       "johnson",     "joliot",
    "jones",         "kalam",        "kapitsa",     "kare",
    "keldysh",       "keller",       "kepler",      "khayyam",
    "khorana",       "kilby",        "kirch",       "knuth",
    "kowalevski",    "lalande",      "lamarr",      "lamport",
    "leakey",        "leavitt",      "lederberg",   "lehmann",
    "lewin",         "lichterman",   "liskov",      "lovelace",
    "lumiere",       "mahavira",     "margulis",    "matsumoto",
    "maxwell",       "mayer",        "mccarthy",    "mcclintock",
    "mclaren",       "mclean",       "mcnulty",     "mendel",
    "mendeleev",     "meitner",      "meninsky",    "merkle",
    "mestorf",       "mirzakhani",   "moore",       "morse",
    "murdock",       "moser",        "napier",      "nash",
    "neumann",       "newton",       "nightingale", "nobel",
    "noether",       "northcutt",    "noyce",       "panini",
    "pare",          "pascal",       "pasteur",     "payne",
    "perlman",       "pike",         "poincare",    "poitras",
    "proskuriakova", "ptolemy",      "raman",       "ramanujan",
    "ride",          "montalcini",   "ritchie",     "rhodes",
    "robinson",      "roentgen",     "rosalind",    "rubin",
    "saha",          "sammet",       "sanderson",   "satoshi",
    "shamir",        "shannon",      "shaw",        "shirley",
    "shockley",      "shtern",       "sinoussi",    "snyder",
    "solomon",       "spence",       "stonebraker", "sutherland",
    "swanson",       "swartz",       "swirles",     "taussig",
    "tereshkova",    "tesla",        "tharp",       "thompson",
    "torvalds",      "tu",           "turing",      "varahamihira",
    "vaughan",       "visvesvaraya", "volhard",     "villani",
    "wescoff",       "wilbur",       "wiles",       "williams",
    "williamson",    "wilson",       "wing",        "wozniak",
    "wright",        "wu",           "yalow",       "yonath",
    "zhukovsky"};

extern char* human_name();

extern int listen_socket();

extern char* log_head();

extern void get_lo_ip(int num, char* ip_addr);

extern char* get_sarg(int arg);

/* array as pipe for hash fragments */
extern int apipe_len(const char* pool, int* len);
extern int apipe_add(char* pool, const char* part, int len);
extern int apipe_to_sql_in(const char* pool, char* sql_str);

#endif
