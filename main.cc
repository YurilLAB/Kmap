
/***************************************************************************
 * main.cc -- Contains the main() function of Kmap.  Note that main()      *
 * does very little except for calling kmap_main() (which is in kmap.cc)   *
 *                                                                         *
 ***********************IMPORTANT KMAP LICENSE TERMS************************
 *
 * The Kmap Security Scanner is (C) 1996-2026 Kmap Software LLC ("The Kmap
 * Project"). Kmap is also a registered trademark of the Kmap Project.
 *
 * This program is distributed under the terms of the Kmap Public Source
 * License (NPSL). The exact license text applying to a particular Kmap
 * release or source code control revision is contained in the LICENSE
 * file distributed with that version of Kmap or source code control
 * revision. More Kmap copyright/legal information is available from
 * https://kmap.org/book/man-legal.html, and further information on the
 * NPSL license itself can be found at https://kmap.org/npsl/ . This
 * header summarizes some key points from the Kmap license, but is no
 * substitute for the actual license text.
 *
 * Kmap is generally free for end users to download and use themselves,
 * including commercial use. It is available from https://kmap.org.
 *
 * The Kmap license generally prohibits companies from using and
 * redistributing Kmap in commercial products, but we sell a special Kmap
 * OEM Edition with a more permissive license and special features for
 * this purpose. See https://kmap.org/oem/
 *
 * If you have received a written Kmap license agreement or contract
 * stating terms other than these (such as an Kmap OEM license), you may
 * choose to use and redistribute Kmap under those terms instead.
 *
 * The official Kmap Windows builds include the Npcap software
 * (https://npcap.com) for packet capture and transmission. It is under
 * separate license terms which forbid redistribution without special
 * permission. So the official Kmap Windows builds may not be redistributed
 * without special permission (such as an Kmap OEM license).
 *
 * Source is provided to this software because we believe users have a
 * right to know exactly what a program is going to do before they run it.
 * This also allows you to audit the software for security holes.
 *
 * Source code also allows you to port Kmap to new platforms, fix bugs, and
 * add new features. You are highly encouraged to submit your changes as a
 * Github PR or by email to the dev@kmap.org mailing list for possible
 * incorporation into the main distribution. Unless you specify otherwise, it
 * is understood that you are offering us very broad rights to use your
 * submissions as described in the Kmap Public Source License Contributor
 * Agreement. This is important because we fund the project by selling licenses
 * with various terms, and also because the inability to relicense code has
 * caused devastating problems for other Free Software projects (such as KDE
 * and NASM).
 *
 * The free version of Kmap is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. Warranties,
 * indemnification and commercial support are all available through the
 * Npcap OEM program--see https://kmap.org/oem/
 *
 ***************************************************************************/

/* $Id$ */

#include <signal.h>
#include <locale.h>

#include "kmap.h"
#include "KmapOps.h"
#include "utils.h"
#include "kmap_error.h"

#ifdef MTRACE
#include "mcheck.h"
#endif

#ifdef __amigaos__
#include <proto/exec.h>
#include <proto/dos.h>
#include "kmap_amigaos.h"
struct Library *SocketBase = NULL, *MiamiBase = NULL, *MiamiBPFBase = NULL, *MiamiPCapBase = NULL;
static const char ver[] = "$VER:" KMAP_NAME " v"KMAP_VERSION " [Amiga.sf]";

static void CloseLibs(void) {
  if (MiamiPCapBase ) CloseLibrary( MiamiPCapBase );
  if (MiamiBPFBase  ) CloseLibrary(  MiamiBPFBase );
  if ( SocketBase   ) CloseLibrary(   SocketBase  );
  if (  MiamiBase   ) CloseLibrary(   MiamiBase   );
}

static BOOL OpenLibs(void) {
 if(!(    MiamiBase = OpenLibrary(MIAMINAME,21))) return FALSE;
 if(!(   SocketBase = OpenLibrary("bsdsocket.library", 4))) return FALSE;
 if(!( MiamiBPFBase = OpenLibrary(MIAMIBPFNAME,3))) return FALSE;
 if(!(MiamiPCapBase = OpenLibrary(MIAMIPCAPNAME,5))) return FALSE;
 atexit(CloseLibs);
 return TRUE;
}
#endif

/* global options */
extern KmapOps o;  /* option structure */

extern void set_program_name(const char *name);

int main(int argc, char *argv[]) {
  /* The "real" main is kmap_main().  This function hijacks control at the
     beginning to do the following:
     1) Check the environment variable KMAP_ARGS.
     2) Check if Kmap was called with --resume.
     3) Resume a previous scan or just call kmap_main.
  */
  char command[2048];
  int myargc;
  char **myargv = NULL;
  char *cptr;
  int ret;
  int i;

  o.locale = strdup(setlocale(LC_CTYPE, NULL));
  set_program_name(argv[0]);

#ifdef __amigaos__
        if(!OpenLibs()) {
                error("Couldn't open TCP/IP Stack Library(s)!");
                exit(20);
        }
        MiamiBPFInit((struct Library *)MiamiBase, (struct Library *)SocketBase);
        MiamiPCapInit((struct Library *)MiamiBase, (struct Library *)SocketBase);
#endif

#ifdef MTRACE
  // This glibc extension enables memory tracing to detect memory
  // leaks, frees of unallocated memory, etc.
  // See http://www.gnu.org/manual/glibc-2.2.5/html_node/Allocation-Debugging.html#Allocation%20Debugging .
  // It only works if the environment variable MALLOC_TRACE is set to a file
  // which a memory usage log will be written to.  After the program quits
  // I can analyze the log via the command 'mtrace [binaryiran] [logfile]'
  // MTRACE should only be defined during debug sessions.
  mtrace();
#endif

  if ((cptr = getenv("KMAP_ARGS"))) {
    if (Snprintf(command, sizeof(command), "kmap %s", cptr) >= (int) sizeof(command)) {
        error("Warning: KMAP_ARGS variable is too long, truncated");
    }
    /* copy rest of command-line arguments */
    for (i = 1; i < argc && strlen(command) + strlen(argv[i]) + 1 < sizeof(command); i++) {
      strcat(command, " ");
      strcat(command, argv[i]);
    }
    myargc = arg_parse(command, &myargv);
    if (myargc < 1) {
      fatal("KMAP_ARGS variable could not be parsed");
    }
    ret = kmap_main(myargc, myargv);
    arg_parse_free(myargv);
    return ret;
  }

  if (argc == 3 && strcmp("--resume", argv[1]) == 0) {
    /* OK, they want to resume an aborted scan given the log file specified.
       Lets gather our state from the log file */
    if (gather_logfile_resumption_state(argv[2], &myargc, &myargv) == -1) {
      fatal("Cannot resume from (supposed) log file %s", argv[2]);
    }
    o.resuming = true;
    return kmap_main(myargc, myargv);
  }

  return kmap_main(argc, argv);
}
