
/***************************************************************************
 * KmapOps.h -- The KmapOps class contains global options, mostly based on *
 * user-provided command-line settings.                                    *
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
 * https://github.com/YurilLAB/Kmap/blob/master/LICENSE, and further information on the
 * NPSL license itself can be found at https://github.com/YurilLAB/Kmap/blob/master/LICENSE . This
 * header summarizes some key points from the Kmap license, but is no
 * substitute for the actual license text.
 *
 * Kmap is generally free for end users to download and use themselves,
 * including commercial use. It is available from https://github.com/YurilLAB/Kmap.
 *
 * The Kmap license generally prohibits companies from using and
 * redistributing Kmap in commercial products, but we sell a special Kmap
 * OEM Edition with a more permissive license and special features for
 * this purpose. See https://github.com/YurilLAB/Kmap
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
 * Github PR at https://github.com/YurilLAB/Kmap for possible incorporation
 * into the main distribution. Unless you specify otherwise, it
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
 * Kmap project -- see https://github.com/YurilLAB/Kmap
 *
 ***************************************************************************/

/* $Id$ */

#ifndef KMAP_OPS_H
#define KMAP_OPS_H

#include "kmap.h" /* MAX_DECOYS */
#include "scan_lists.h"
#include "output.h" /* LOG_NUM_FILES */
#include <nbase.h>
#include <nsock.h>
#include <string>
#include <map>
#include <vector>

struct FingerPrintDB;
struct FingerMatch;

class KmapOps {
 public:
  KmapOps();
  ~KmapOps();
  void ReInit(); // Reinitialize the class to default state
  void setaf(int af) { addressfamily = af; }
  int af() { return addressfamily; }
  // no setpf() because it is based on setaf() values
  int pf();
  /* Returns 0 for success, nonzero if no source has been set or any other
     failure */
  int SourceSockAddr(struct sockaddr_storage *ss, size_t *ss_len);
  /* Returns a const pointer to the source address if set, or NULL if unset. */
  const struct sockaddr_storage *SourceSockAddr() const;
  /* Note that it is OK to pass in a sockaddr_in or sockaddr_in6 casted
     to sockaddr_storage */
  void setSourceSockAddr(struct sockaddr_storage *ss, size_t ss_len);

// The time this obj. was instantiated   or last ReInit()ed.
  const struct timeval *getStartTime() { return &start_time; }
  // Number of seconds since getStartTime().  The current time is an
  // optional argument to avoid an extra gettimeofday() call.
  float TimeSinceStart(const struct timeval *now=NULL);



  bool TCPScan(); /* Returns true if at least one chosen scan type is TCP */
  bool UDPScan(); /* Returns true if at least one chosen scan type is UDP */
  bool SCTPScan(); /* Returns true if at least one chosen scan type is SCTP */

  /* Returns true if at least one chosen scan type uses raw packets.
     It does not currently cover cases such as TCP SYN ping scan which
     can go either way based on whether the user is root or IPv6 is
     being used.  It will return false in those cases where a RawScan
     is not necessarily used. */
  bool RawScan();
  void ValidateOptions(); /* Checks that the options given are
                             reasonable and consistent.  If they aren't, the
                             function may bail out of Kmap or make small
                             adjustments (quietly or with a warning to the
                             user). */
  int isr00t;
  /* Whether we have pcap functions (can be false on Windows). */
  bool have_pcap;
  u8 debugging;
  bool resuming;

  int sendpref;
  bool packetTrace() { return (debugging >= 3)? true : pTrace;  }
  bool versionTrace() { return packetTrace()? true : vTrace;  }
#ifndef NOLUA
  bool scriptTrace() { return packetTrace()? true : scripttrace; }
#endif
  // Note that packetTrace may turn on at high debug levels even if
  // setPacketTrace(false) has been called
  void setPacketTrace(bool pt) { pTrace = pt;  }
  void setVersionTrace(bool vt) { vTrace = vt;  }
  bool openOnly() { return open_only; }
  void setOpenOnly(bool oo) { open_only = oo; }
  u8 verbose;
  /* The requested minimum packet sending rate, or 0.0 if unset. */
  float min_packet_send_rate;
  /* The requested maximum packet sending rate, or 0.0 if unset. */
  float max_packet_send_rate;
  /* The requested auto stats printing interval, or 0.0 if unset. */
  float stats_interval;
  bool randomize_hosts;
  bool randomize_ports;
  bool spoofsource; /* -S used */
  bool fastscan;
  char device[64];
  int ping_group_sz;
  bool nogcc; /* Turn off group congestion control with --nogcc */
  bool generate_random_ips; /* -iR option */
  FingerPrintDB *reference_FPs; /* Used in the new OS scan system. */
  std::vector<FingerMatch> os_labels_ipv6;
  u16 magic_port; /* The source port set by -g or --source-port. */
  bool magic_port_set; /* Was this set by user? */

  /* Scan timing/politeness issues */
  int timing_level; // 0-5, corresponding to Paranoid, Sneaky, Polite, Normal, Aggressive, Insane
  int max_parallelism; // 0 means it has not been set
  int min_parallelism; // 0 means it has not been set
  double topportlevel; // -1 means it has not been set

  /* The maximum number of OS detection (gen2) tries we will make
     without any matches before giving up on a host.  We may well give
     up after fewer tries anyway, particularly if the target isn't
     ideal for unknown fingerprint submissions */
  int maxOSTries() { return max_os_tries; }
  void setMaxOSTries(int mot);

  /* These functions retrieve and set the Round Trip Time timeouts, in
   milliseconds.  The set versions do extra processing to insure sane
   values and to adjust each other to insure consistence (e.g. that
   max is always at least as high as min) */
  int maxRttTimeout() { return max_rtt_timeout; }
  int minRttTimeout() { return min_rtt_timeout; }
  int initialRttTimeout() { return initial_rtt_timeout; }
  void setMaxRttTimeout(int rtt);
  void setMinRttTimeout(int rtt);
  void setInitialRttTimeout(int rtt);
  void setMaxRetransmissions(int max_retransmit);
  unsigned int getMaxRetransmissions() { return max_retransmissions; }

  /* Similar functions for Host group size */
  int minHostGroupSz() { return min_host_group_sz; }
  int maxHostGroupSz() { return max_host_group_sz; }
  void setMinHostGroupSz(unsigned int sz);
  void setMaxHostGroupSz(unsigned int sz);
  unsigned int maxTCPScanDelay() { return max_tcp_scan_delay; }
  unsigned int maxUDPScanDelay() { return max_udp_scan_delay; }
  unsigned int maxSCTPScanDelay() { return max_sctp_scan_delay; }
  void setMaxTCPScanDelay(unsigned int delayMS) { max_tcp_scan_delay = delayMS; }
  void setMaxUDPScanDelay(unsigned int delayMS) { max_udp_scan_delay = delayMS; }
  void setMaxSCTPScanDelay(unsigned int delayMS) { max_sctp_scan_delay = delayMS; }

  /* Sets the Name of the XML stylesheet to be printed in XML output.
     If this is never called, a default stylesheet distributed with
     Kmap is used.  If you call it with NULL as the xslname, no
     stylesheet line is printed. */
  void setXSLStyleSheet(const char *xslname);
  /* Returns the full path or URL that should be printed in the XML
     output xml-stylesheet element.  Returns NULL if the whole element
     should be skipped */
  char *XSLStyleSheet();

  /* Sets the spoofed MAC address */
  void setSpoofMACAddress(u8 *mac_data);
  /* Gets the spoofed MAC address, but returns NULL if it hasn't been set */
  const u8 *spoofMACAddress() { return spoof_mac_set? spoof_mac : NULL; }

  unsigned long max_ips_to_scan; // Used for Random input (-iR) to specify how
                       // many IPs to try before stopping. 0 means unlimited if generate_random_ips is true
  int extra_payload_length; /* These two are for --data-length op */
  char *extra_payload;
  unsigned long host_timeout;
  /* Delay between probes, in milliseconds */
  unsigned int scan_delay;
  bool open_only;

  int scanflags; /* if not -1, this value should dictate the TCP flags
                    for the core portscanning routine (eg to change a
                    FIN scan into a PSH scan.  Sort of a hack, but can
                    be very useful sometimes. */

  bool defeat_rst_ratelimit; /* Solaris 9 rate-limits RSTs so scanning is very
            slow against it. If we don't distinguish between closed and filtered ports,
            we can get the list of open ports very fast */

  bool defeat_icmp_ratelimit; /* If a host rate-limits ICMP responses, then scanning
            is very slow against it. This option prevents Kmap to adjust timing
            when it changes the port's state because of ICMP response, as the latter
            might be rate-limited. Doing so we can get scan results faster. */

  struct sockaddr_storage resume_ip; /* The last IP in the log file if user
                               requested --restore .  Otherwise
                               resume_ip.ss_family == AF_UNSPEC.  Also
                               Target::next_target will eventually set it
                               to AF_UNSPEC. */

  // Version Detection Options
  bool override_excludeports;
  int version_intensity;

  struct sockaddr_storage decoys[MAX_DECOYS];
  bool osscan_limit; /* Skip OS Scan if no open or no closed TCP ports */
  bool osscan_guess;   /* Be more aggressive in guessing OS type */
  int numdecoys;
  int decoyturn;
  bool osscan;
  bool servicescan;
  int pingtype;
  int listscan;
  int fragscan; /* 0 or MTU (without IPv4 header size) */
  int ackscan;
  int bouncescan;
  int connectscan;
  int finscan;
  int idlescan;
  char* idleProxy; /* The idle host used to "Proxy" an idle scan */
  int ipprotscan;
  int maimonscan;
  int nullscan;
  int synscan;
  int udpscan;
  int sctpinitscan;
  int sctpcookieechoscan;
  int windowscan;
  int xmasscan;
  bool noresolve;
  bool noportscan;
  bool append_output; /* Append to any output files rather than overwrite */
  FILE *logfd[LOG_NUM_FILES];
  FILE *kmap_stdout; /* Kmap standard output */
  char *json_output_file; /* Path to JSON output file (-oJ), or NULL if not set */
  /* --default-creds options */
  bool default_creds;     /* Run default credential checks */
  char *creds_file;       /* Custom creds wordlist, or NULL for built-in */
  int  creds_timeout_ms;  /* Per-attempt timeout in ms (default 3000) */
  /* --web-recon options */
  bool web_recon;         /* Run HTTP/S recon on detected web ports */
  char *web_paths_file;   /* Extra paths to probe, or NULL */
  /* --cve-map options */
  bool cve_map;           /* Cross-reference services with CVE database */
  float cve_min_score;    /* Minimum CVSS score to report (default 7.0) */
  /* --import-cves options */
  char *import_cves_file; /* File to import CVEs from, or NULL */
  char *import_cves_db;   /* Custom target DB path, or NULL for default */
  /* --report options */
  char *report_file;      /* Output report file (.txt or .md), or NULL */
  /* --screenshot options */
  bool screenshot;        /* Capture screenshots of web ports */
  char *screenshot_dir;   /* Directory for screenshots (default: kmap-screenshots) */
  /* --yuril-export options */
  char *yuril_export_dir; /* Directory for Yuril Security Suite export bundle, or NULL */
  /* --net-scan options */
  bool net_scan;            /* Enable net-scan mode */
  bool net_discover_only;   /* Only run discovery phase */
  bool net_enrich_only;     /* Only run enrichment phase */
  bool net_report_only;     /* Only run report generation */
  bool net_resume;          /* Resume interrupted scan */
  int  net_rate;            /* Packets per second (default 25000) */
  char *net_exclude_file;   /* Custom exclusion list */
  char *net_data_dir;       /* Shard database directory */
  char *net_findings_dir;   /* Findings output directory */
  char *net_watchlist;      /* Watchlist targets file */
  /* --net-query options */
  bool net_query;           /* Enable query mode */
  int  nq_port;             /* Filter by port (-1 = unset) */
  char *nq_service;         /* Filter by service name */
  char *nq_cve;             /* Filter by CVE ID */
  float nq_min_cvss;        /* Filter by min CVSS (-1 = unset) */
  char *nq_web_title;       /* Filter by web title */
  char *nq_web_server;      /* Filter by server header */
  char *nq_ip_range;        /* Filter by IP range */
  char *nq_output;          /* Export results to file */
  bool nq_count;            /* Count mode */
  int  nq_asn;              /* Filter by ASN (-1 = unset) */
  char *nq_country;         /* Filter by country code */
  /* --tracemap options */
  char *tracemap_targets;   /* Target IPs, CIDRs, or file path */
  char *tm_output;          /* Output file (NULL = stdout) */
  char *tm_format;          /* "txt", "dot", or "json" */
  int  tm_max_hops;         /* Max TTL (default 30) */
  int ttl; // Time to live
  bool badsum;
  char *datadir;
  /* A map from abstract data file names like "kmap-services" and "kmap-os-db"
     to paths which have been requested by the user. kmap_fetchfile will return
     the file names defined in this map instead of searching for a matching
     file. */
  std::map<std::string, std::string> requested_data_files;
  /* A map from data file names to the paths at which they were actually found.
     Only files that were actually read should be in this map. */
  std::map<std::string, std::string> loaded_data_files;
  bool mass_dns;
  bool always_resolve;
  bool resolve_all;
  bool unique;
  char *dns_servers;

  /* Do IPv4 ARP or IPv6 ND scan of directly connected Ethernet hosts, even if
     non-ARP host discovery options are used? This is normally more efficient,
     not only because ARP/ND scan is faster, but because we need the MAC
     addresses provided by ARP or ND scan in order to do IP-based host discovery
     anyway. But when a network uses proxy ARP, all hosts will appear to be up
     unless you do an IP host discovery on them. This option is true by default. */
  bool implicitARPPing;

  // If true, write <os><osclass/><osmatch/></os> as in xmloutputversion 1.03
  // rather than <os><osmatch><osclass/></osmatch></os> as in 1.04 and later.
  bool deprecated_xml_osclass;

  bool traceroute;
  bool reason;
  bool adler32;
  FILE *excludefd;
  char *exclude_spec;
  FILE *inputfd;
  char *portlist; /* Ports list specified by user */
  char *exclude_portlist; /* exclude-ports list specified by user */

  nsock_proxychain proxy_chain;
  bool discovery_ignore_rst; /* host discovery should not consider TCP RST packet responses as a live asset */

#ifndef NOLUA
  bool script;
  char *scriptargs;
  char *scriptargsfile;
  bool scriptversion;
  bool scripttrace;
  bool scriptupdatedb;
  bool scripthelp;
  double scripttimeout;
  void chooseScripts(char* argument);
  std::vector<std::string> chosenScripts;
#endif

  /* ip options used in build_*_raw() */
  u8 *ipoptions;
  int ipoptionslen;
  int ipopt_firsthop;	// offset in ipoptions where is first hop for source/strict routing
  int ipopt_lasthop;	// offset in ipoptions where is space for targets ip for source/strict routing

  // Statistics Options set in kmap.cc
  unsigned int numhosts_scanned;
  unsigned int numhosts_up;
  int numhosts_scanning;
  stype current_scantype;
  bool noninteractive;
  char *locale;

  bool release_memory;	/* suggest to release memory before quitting. used to find memory leaks. */
 private:
  int max_os_tries;
  int max_rtt_timeout;
  int min_rtt_timeout;
  int initial_rtt_timeout;
  unsigned int max_retransmissions;
  unsigned int max_tcp_scan_delay;
  unsigned int max_udp_scan_delay;
  unsigned int max_sctp_scan_delay;
  unsigned int min_host_group_sz;
  unsigned int max_host_group_sz;
  void Initialize();
  int addressfamily; /*  Address family:  AF_INET or AF_INET6 */
  struct sockaddr_storage sourcesock;
  size_t sourcesocklen;
  struct timeval start_time;
  bool pTrace; // Whether packet tracing has been enabled
  bool vTrace; // Whether version tracing has been enabled
  bool xsl_stylesheet_set;
  char *xsl_stylesheet;
  u8 spoof_mac[6];
  bool spoof_mac_set;
};

#endif
