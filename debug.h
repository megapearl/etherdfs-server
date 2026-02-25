/*
 * Part of ethersrv-linux
 */

/* set to 1 to enable debug */
#define DEBUG 0

/* set to 1 for frame loss simulation (for tests only!) */
#define SIMLOSS 0

/* declare global debug variable */
extern int debug_mode;

#define DBG(...)                                                               \
  do {                                                                         \
    if (debug_mode) {                                                          \
      printf(__VA_ARGS__);                                                     \
    }                                                                          \
  } while (0)
