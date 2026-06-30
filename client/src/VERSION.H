/* program version and date */
/* PVER is the base version; the build (client/build-linux.sh) rewrites it to
 * the full "v0.1.0-dev.<git-sha>" so the client reports the SAME version as the
 * server (which builddocker.sh derives the same way). */
#define PVER "v0.1.0-dev"
#define PDATE "2017,2018" /* original release dates (Mateusz Viste) */

/* protocol version */
#define PROTOVER 2
