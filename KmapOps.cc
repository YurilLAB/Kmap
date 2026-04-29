
/***************************************************************************
 * KmapOps.cc -- The KmapOps class contains global options, mostly based   *
 * on user-provided command-line settings.                                 *
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
#ifdef WIN32
#include "winfix.h"
#endif
#include "kmap.h"
#include "nbase.h"
#include "KmapOps.h"
#include "osscan.h"
#include "kmap_error.h"
#include "libnetutil/netutil.h"

KmapOps o;

KmapOps::KmapOps() {
  datadir = NULL;
  xsl_stylesheet = NULL;
  Initialize();
}

KmapOps::~KmapOps() {
  if (xsl_stylesheet) {
    free(xsl_stylesheet);
    xsl_stylesheet = NULL;
  }

  if (reference_FPs) {
    delete reference_FPs;
    reference_FPs = NULL;
  }

  if (dns_servers) {
    free(dns_servers);
    dns_servers = NULL;
  }
  if (extra_payload) {
    free(extra_payload);
    extra_payload = NULL;
  }
  if (ipoptions) {
    free(ipoptions);
    ipoptions = NULL;
  }
  if (portlist) {
    free(portlist);
    portlist = NULL;
  }
  if (exclude_portlist) {
    free(exclude_portlist);
    exclude_portlist = NULL;
  }
  if (proxy_chain) {
    nsock_proxychain_delete(proxy_chain);
    proxy_chain = NULL;
  }
  if (exclude_spec) {
    free(exclude_spec);
    exclude_spec = NULL;
  }
  if (idleProxy) {
    free(idleProxy);
    idleProxy = NULL;
  }
  if (datadir) {
    free(datadir);
    datadir = NULL;
  }
  if (locale) {
    free(locale);
    locale = NULL;
  }
  if (json_output_file) {
    free(json_output_file);
    json_output_file = NULL;
  }
  if (report_file) {
    free(report_file);
    report_file = NULL;
  }
  if (screenshot_dir) {
    free(screenshot_dir);
    screenshot_dir = NULL;
  }
  if (yuril_export_dir) {
    free(yuril_export_dir);
    yuril_export_dir = NULL;
  }
  if (net_exclude_file) { free(net_exclude_file); net_exclude_file = NULL; }
  if (net_data_dir) { free(net_data_dir); net_data_dir = NULL; }
  if (net_findings_dir) { free(net_findings_dir); net_findings_dir = NULL; }
  if (net_watchlist) { free(net_watchlist); net_watchlist = NULL; }
  if (nq_service) { free(nq_service); nq_service = NULL; }
  if (nq_cve) { free(nq_cve); nq_cve = NULL; }
  if (nq_web_title) { free(nq_web_title); nq_web_title = NULL; }
  if (nq_web_server) { free(nq_web_server); nq_web_server = NULL; }
  if (nq_ip_range) { free(nq_ip_range); nq_ip_range = NULL; }
  if (nq_output) { free(nq_output); nq_output = NULL; }
  if (nq_country) { free(nq_country); nq_country = NULL; }
  if (tracemap_targets) { free(tracemap_targets); tracemap_targets = NULL; }
  if (tm_output) { free(tm_output); tm_output = NULL; }
  if (tm_format) { free(tm_format); tm_format = NULL; }
  if (spoof_os) { free(spoof_os); spoof_os = NULL; }

#ifndef NOLUA
  if (scriptversion || script)
    close_nse();
  if (scriptargs) {
    free(scriptargs);
    scriptargs = NULL;
  }
#endif
}

void KmapOps::ReInit() {
  Initialize();
}

// no setpf() because it is based on setaf() values
int KmapOps::pf() {
  return (af() == AF_INET)? PF_INET : PF_INET6;
}

int KmapOps::SourceSockAddr(struct sockaddr_storage *ss, size_t *ss_len) {
  if (sourcesocklen <= 0)
    return 1;
  assert(sourcesocklen <= sizeof(*ss));
  if (ss)
    memcpy(ss, &sourcesock, sourcesocklen);
  if (ss_len)
    *ss_len = sourcesocklen;
  return 0;
}

/* Returns a const pointer to the source address if set, or NULL if unset. */
const struct sockaddr_storage *KmapOps::SourceSockAddr() const {
  if (sourcesock.ss_family == AF_UNSPEC)
    return NULL;
  else
    return &sourcesock;
}

/* Note that it is OK to pass in a sockaddr_in or sockaddr_in6 casted
     to sockaddr_storage */
void KmapOps::setSourceSockAddr(struct sockaddr_storage *ss, size_t ss_len) {
  assert(ss_len > 0 && ss_len <= sizeof(*ss));
  memcpy(&sourcesock, ss, ss_len);
  sourcesocklen = ss_len;
}

// Number of seconds since getStartTime().  The current time is an
// optional argument to avoid an extra gettimeofday() call.
float KmapOps::TimeSinceStart(const struct timeval *now) {
  struct timeval tv;
  if (!now)
    gettimeofday(&tv, NULL);
  else tv = *now;

  return TIMEVAL_FSEC_SUBTRACT(tv, start_time);
}

// Convert a filename to a file:// URL. The return value must be freed.
static char *filename_to_url(const char *filename) {
  std::string url(filename);
  char percent_buffer[10];

#if WIN32
  for (std::string::iterator p = url.begin(); p != url.end(); p++) {
    if (*p == '\\')
      *p = '/';
  }
  /* Put a pseudo-root directory before "C:/" or whatever. */
  url = "/" + url;
#endif

  /* Percent-encode any troublesome characters. */
  std::string::size_type i = 0;
  /* See RFC 3986, section 3.3 "Path" for allowed characters. */
  while ((i = url.find_first_of("?#[]%", i)) != std::string::npos) {
    Snprintf(percent_buffer, sizeof(percent_buffer), "%%%02X", url[i]);
    url.replace(i, 1, percent_buffer);
    i += strlen(percent_buffer);
  }

  url = "file://" + url;

  return strdup(url.c_str());
}

void KmapOps::Initialize() {
  setaf(AF_INET);
#if defined WIN32 || defined __amigaos__
  isr00t = 1;
#else
  if (getenv("KMAP_PRIVILEGED"))
    isr00t = 1;
  else if (getenv("KMAP_UNPRIVILEGED"))
    isr00t = 0;
  else
    isr00t = !(geteuid());
#endif
  have_pcap = true;
  debugging = 0;
  verbose = 0;
  min_packet_send_rate = 0.0; /* Unset. */
  max_packet_send_rate = 0.0; /* Unset. */
  stats_interval = 0.0; /* Unset. */
  randomize_hosts = false;
  randomize_ports = true;
  sendpref = PACKET_SEND_NOPREF;
  spoofsource = false;
  fastscan = false;
  device[0] = '\0';
  ping_group_sz = PING_GROUP_SZ;
  nogcc = false;
  generate_random_ips = false;
  reference_FPs = NULL;
  magic_port = 33000 + (get_random_uint() % 31000);
  magic_port_set = false;
  timing_level = 3;
  max_parallelism = 0;
  min_parallelism = 0;
  max_os_tries = 5;
  max_rtt_timeout = MAX_RTT_TIMEOUT;
  min_rtt_timeout = MIN_RTT_TIMEOUT;
  initial_rtt_timeout = INITIAL_RTT_TIMEOUT;
  max_retransmissions = MAX_RETRANSMISSIONS;
  min_host_group_sz = 1;
  max_host_group_sz = 100000; // don't want to be restrictive unless user sets
  max_tcp_scan_delay = MAX_TCP_SCAN_DELAY;
  max_udp_scan_delay = MAX_UDP_SCAN_DELAY;
  max_sctp_scan_delay = MAX_SCTP_SCAN_DELAY;
  max_ips_to_scan = 0;
  extra_payload_length = 0;
  extra_payload = NULL;
  host_timeout = 0;
  scan_delay = 0;
  open_only = false;
  scanflags = -1;
  defeat_rst_ratelimit = false;
  defeat_icmp_ratelimit = false;
  resume_ip.ss_family = AF_UNSPEC;
  osscan_limit = false;
  osscan_guess = false;
  numdecoys = 0;
  decoyturn = -1;
  osscan = false;
  servicescan = false;
  override_excludeports = false;
  version_intensity = 7;
  pingtype = PINGTYPE_UNKNOWN;
  listscan = ackscan = bouncescan = connectscan = 0;
  nullscan = xmasscan = fragscan = synscan = windowscan = 0;
  maimonscan = idlescan = finscan = udpscan = ipprotscan = 0;
  noportscan = noresolve = false;
  sctpinitscan = 0;
  sctpcookieechoscan = 0;
  append_output = false;
  json_output_file = nullptr;
  default_creds    = false;
  creds_file       = nullptr;
  creds_timeout_ms = 3000;
  web_recon        = false;
  web_paths_file   = nullptr;
  cve_map          = false;
  cve_min_score    = 7.0f;
  import_cves_file = nullptr;
  import_cves_db   = nullptr;
  report_file      = nullptr;
  screenshot       = false;
  screenshot_dir   = nullptr;
  yuril_export_dir = nullptr;
  net_scan         = false;
  net_discover_only = false;
  net_enrich_only  = false;
  net_report_only  = false;
  net_resume       = false;
  net_rate         = 25000;
  net_exclude_file = nullptr;
  net_data_dir     = nullptr;
  net_findings_dir = nullptr;
  net_watchlist    = nullptr;
  net_query        = false;
  nq_port          = -1;
  nq_service       = nullptr;
  nq_cve           = nullptr;
  nq_min_cvss      = -1.0f;
  nq_web_title     = nullptr;
  nq_web_server    = nullptr;
  nq_ip_range      = nullptr;
  nq_output        = nullptr;
  nq_count         = false;
  nq_asn           = -1;
  nq_country       = nullptr;
  tracemap_targets = nullptr;
  tm_output        = nullptr;
  tm_format        = nullptr;
  tm_max_hops      = 30;
  spoof_os         = nullptr;
  memset(logfd, 0, sizeof(FILE *) * LOG_NUM_FILES);
  ttl = -1;
  badsum = false;
  kmap_stdout = stdout;
  gettimeofday(&start_time, NULL);
  pTrace = vTrace = false;
  reason = false;
  adler32 = false;
  if (datadir) free(datadir);
  datadir = NULL;
  xsl_stylesheet_set = false;
  if (xsl_stylesheet) free(xsl_stylesheet);
  xsl_stylesheet = NULL;
  spoof_mac_set = false;
  mass_dns = true;
  deprecated_xml_osclass = false;
  always_resolve = false;
  resolve_all = false;
  unique = false;
  dns_servers = NULL;
  implicitARPPing = true;
  numhosts_scanned = 0;
  numhosts_up = 0;
  numhosts_scanning = 0;
  noninteractive = false;
  locale = NULL;
  current_scantype = STYPE_UNKNOWN;
  ipoptions = NULL;
  ipoptionslen = 0;
  ipopt_firsthop = 0;
  ipopt_lasthop  = 0;
  release_memory = false;
  topportlevel = -1;
#ifndef NOLUA
  script = false;
  scriptargs = NULL;
  scriptversion = false;
  scripttrace = false;
  scriptupdatedb = false;
  scripthelp = false;
  scripttimeout = 0;
  chosenScripts.clear();
#endif
  memset(&sourcesock, 0, sizeof(sourcesock));
  sourcesocklen = 0;
  excludefd = NULL;
  exclude_spec = NULL;
  inputfd = NULL;
  idleProxy = NULL;
  portlist = NULL;
  exclude_portlist = NULL;
  proxy_chain = NULL;
  resuming = false;
  discovery_ignore_rst = false;
}

bool KmapOps::SCTPScan() {
  return sctpinitscan|sctpcookieechoscan;
}

bool KmapOps::TCPScan() {
  return ackscan|bouncescan|connectscan|finscan|idlescan|maimonscan|nullscan|synscan|windowscan|xmasscan;
}

bool KmapOps::UDPScan() {
  return udpscan;
}

bool KmapOps::RawScan() {
  if (ackscan||finscan||idlescan||ipprotscan||maimonscan||nullscan||osscan||synscan||udpscan||windowscan||xmasscan||sctpinitscan||sctpcookieechoscan||traceroute)
    return true;
  if (pingtype & (PINGTYPE_ICMP_PING|PINGTYPE_ICMP_MASK|PINGTYPE_ICMP_TS|PINGTYPE_TCP_USE_ACK|PINGTYPE_UDP|PINGTYPE_PROTO|PINGTYPE_SCTP_INIT))
    return true;
  /* A SYN scan will only generate raw packets if kmap is running as root.
     Otherwise, it becomes a connect scan. */
  if ((pingtype & PINGTYPE_TCP_USE_SYN) && isr00t)
    return true;

   return false;
}


void KmapOps::ValidateOptions() {
        const char *privreq = "root privileges.";
#ifdef WIN32
        if (!have_pcap)
          privreq = "Npcap, but it seems to be missing.\n\
Npcap is available from https://npcap.com. The Npcap driver service must\n\
be started by an administrator before Npcap can be used. Running kmap.exe\n\
will open a UAC dialog where you can start the service if you have\n\
administrator privileges.";

#define YOU_ARE_ROOT "Npcap is installed"
#else
#define YOU_ARE_ROOT "you are root"
#endif


  /* Insure that at least one scantype is selected */
  if (!noportscan && !(TCPScan() || UDPScan() || SCTPScan() || ipprotscan)) {
    if (isr00t)
      synscan++;
    else connectscan++;
    //    if (verbose) error("No TCP, UDP, SCTP or ICMP scantype specified, assuming %s scan. Use -sn if you really don't want to portscan (and just want to see what hosts are up).", synscan? "SYN Stealth" : "vanilla tcp connect()");
  }

  if (pingtype != PINGTYPE_NONE && spoofsource) {
    error("WARNING: If -S is being used to fake your source address, you may also have to use -e <interface> and -Pn .  If you are using it to specify your real source address, you can ignore this warning.");
  }

  if (pingtype != PINGTYPE_NONE && idlescan) {
    error("WARNING: Many people use -Pn w/Idlescan to prevent pings from their true IP.  On the other hand, timing info Kmap gains from pings can allow for faster, more reliable scans.");
    sleep(2); /* Give ppl a chance for ^C :) */
  }

 if (numdecoys > 1 && idlescan) {
    error("WARNING: Your decoys won't be used in the Idlescan portion of your scanning (although all packets sent to the target are spoofed anyway");
  }

 if (connectscan && spoofsource) {
    error("WARNING: -S will only affect the source address used in a connect() scan if you specify one of your own addresses.  Use -sS or another raw scan if you want to completely spoof your source address, but then you need to know what you're doing to obtain meaningful results.");
  }

 if ((pingtype & PINGTYPE_UDP) && (!isr00t)) {
   fatal("Sorry, UDP Ping (-PU) only works if " YOU_ARE_ROOT " (because we need to read raw responses off the wire)");
 }

 if ((pingtype & PINGTYPE_SCTP_INIT) && (!isr00t)) {
   fatal("Sorry, SCTP INIT Ping (-PY) only works if " YOU_ARE_ROOT " (because we need to read raw responses off the wire)");
  }

 if ((pingtype & PINGTYPE_PROTO) && (!isr00t)) {
   fatal("Sorry, IPProto Ping (-PO) only works if " YOU_ARE_ROOT " (because we need to read raw responses off the wire)");
 }

 if (ipprotscan && (TCPScan() || UDPScan() || SCTPScan())) {
   fatal("Sorry, the IPProtoscan (-sO) must currently be used alone rather than combined with other scan types.");
 }

 if (noportscan && (TCPScan() || UDPScan() || SCTPScan() || ipprotscan)) {
   fatal("-sL and -sn (skip port scan) are not valid with any other scan types");
 }

 if (af() == AF_INET6 && (pingtype & (PINGTYPE_ICMP_MASK|PINGTYPE_ICMP_TS))) {
   fatal("ICMP Timestamp and Address Mask pings are only valid for IPv4.");
 }

 if (sendpref == PACKET_SEND_NOPREF) {
#ifdef WIN32
   sendpref = PACKET_SEND_ETH_STRONG;
#else
   sendpref = PACKET_SEND_IP_WEAK;
#endif
 }
/* We start with stuff users should not do if they are not root */
  if (!isr00t) {

    if (ackscan|finscan|idlescan|ipprotscan|maimonscan|nullscan|synscan|udpscan|windowscan|xmasscan|sctpinitscan|sctpcookieechoscan) {
      fatal("You requested a scan type which requires %s", privreq);
    }

    if (numdecoys > 0) {
      fatal("Sorry, but decoys (-D) require %s", privreq);
    }

    if (fragscan) {
      fatal("Sorry, but fragscan requires %s", privreq);
    }

    if (osscan) {
      fatal("TCP/IP fingerprinting (for OS scan) requires %s", privreq);
    }
  }


  if (bouncescan && pingtype != PINGTYPE_NONE)
    log_write(LOG_STDOUT, "Hint: if your bounce scan target hosts aren't reachable from here, remember to use -Pn so we don't try and ping them prior to the scan\n");

  if (ackscan+bouncescan+connectscan+finscan+idlescan+maimonscan+nullscan+synscan+windowscan+xmasscan > 1)
    fatal("You specified more than one type of TCP scan.  Please choose only one of -sA, -b, -sT, -sF, -sI, -sM, -sN, -sS, -sW, and -sX");

  if (numdecoys > 0 && (bouncescan || connectscan)) {
    error("WARNING: Decoys are irrelevant to the bounce or connect scans");
  }

  if (fragscan && !(ackscan|finscan|maimonscan|nullscan|synscan|windowscan|xmasscan) && \
      !(pingtype&(PINGTYPE_ICMP_TS|PINGTYPE_TCP)) && !(fragscan == 8 && pingtype&PINGTYPE_ICMP_MASK) && \
      !(extra_payload_length + 8 > fragscan)) {
    fatal("Fragscan only works with TCP, ICMP Timestamp or ICMP Mask (mtu=8) ping types or ACK, FIN, Maimon, NULL, SYN, Window, and XMAS scan types");
  }

  if (osscan && bouncescan)
    error("Combining bounce scan with OS scan seems silly, but I will let you do whatever you want!");

#if !defined(LINUX) && !defined(OPENBSD) && !defined(FREEBSD) && !defined(NETBSD)
  if (fragscan) {
    error("Warning: Packet fragmentation selected on a host other than Linux, OpenBSD, FreeBSD, or NetBSD.  This may or may not work.");
  }
#endif

  if (osscan && noportscan) {
    fatal("WARNING: OS Scan is unreliable without a port scan.  You need to use a scan type along with it, such as -sS, -sT, -sF, etc instead of -sn");
  }

  if (osscan && ipprotscan) {
    error("WARNING: Disabling OS Scan (-O) as it is incompatible with the IPProto Scan (-sO)");
    osscan = false;
  }

  if (servicescan && ipprotscan) {
    error("WARNING: Disabling Service Scan (-sV) as it is incompatible with the IPProto Scan (-sO)");
    servicescan = false;
  }

  if (servicescan && noportscan)
    servicescan = false;

  if (defeat_rst_ratelimit && !synscan && !openOnly()) {
    fatal("Option --defeat-rst-ratelimit works only with a SYN scan (-sS)");
  }

  if (defeat_icmp_ratelimit && !udpscan) {
    fatal("Option --defeat-icmp-ratelimit works only with a UDP scan (-sU)");
  }

  if (resume_ip.ss_family != AF_UNSPEC && generate_random_ips)
    resume_ip.ss_family = AF_UNSPEC;

  if (magic_port_set && connectscan) {
    error("WARNING: -g is incompatible with the default connect() scan (-sT).  Use a raw scan such as -sS if you want to set the source port.");
  }

  if (max_parallelism && min_parallelism && (min_parallelism > max_parallelism)) {
    fatal("--min-parallelism=%i must be less than or equal to --max-parallelism=%i",min_parallelism,max_parallelism);
  }

  if (min_packet_send_rate != 0.0 && max_packet_send_rate != 0.0 && min_packet_send_rate > max_packet_send_rate) {
    fatal("--min-rate=%g must be less than or equal to --max-rate=%g", min_packet_send_rate, max_packet_send_rate);
  }

  if (af() == AF_INET6 && (generate_random_ips||bouncescan||fragscan)) {
    fatal("Random targets, FTP bounce scan, and fragmentation are not supported with IPv6.");
  }

  if(ipoptions && osscan)
    error("WARNING: IP options are NOT used while OS scanning!");

#ifndef NOLUA
  /* Make sure kmap.registry.args is available (even if it's empty) */
  if (!scriptargs)
    scriptargs = strdup("");
#endif
}

void KmapOps::setMaxOSTries(int mot) {
  if (mot <= 0)
    fatal("%s: value must be at least 1", __func__);
  max_os_tries = mot;
}

void KmapOps::setMaxRttTimeout(int rtt)
{
  if (rtt <= 0) fatal("%s: maximum round trip time must be greater than 0", __func__);
  max_rtt_timeout = rtt;
  if (rtt < min_rtt_timeout) min_rtt_timeout = rtt;
  if (rtt < initial_rtt_timeout) initial_rtt_timeout = rtt;
}

void KmapOps::setMinRttTimeout(int rtt)
{
  if (rtt < 0) fatal("%s: minimum round trip time must be at least 0", __func__);
  min_rtt_timeout = rtt;
  if (rtt > max_rtt_timeout) max_rtt_timeout = rtt;
  if (rtt > initial_rtt_timeout) initial_rtt_timeout = rtt;
}

void KmapOps::setInitialRttTimeout(int rtt)
{
  if (rtt <= 0) fatal("%s: initial round trip time must be greater than 0", __func__);
  initial_rtt_timeout = rtt;
  if (rtt > max_rtt_timeout) max_rtt_timeout = rtt;
  if (rtt < min_rtt_timeout) min_rtt_timeout = rtt;
}

void KmapOps::setMaxRetransmissions(int max_retransmit)
{
    if (max_retransmit < 0)
        fatal("%s: must be positive", __func__);
    max_retransmissions = max_retransmit;
}


void KmapOps::setMinHostGroupSz(unsigned int sz) {
  if (sz > max_host_group_sz)
    fatal("Minimum host group size may not be set to greater than maximum size (currently %d)\n", max_host_group_sz);
  min_host_group_sz = sz;
}

void KmapOps::setMaxHostGroupSz(unsigned int sz) {
  if (sz < min_host_group_sz)
    fatal("Maximum host group size may not be set to less than the minimum size (currently %d)\n", min_host_group_sz);
  if (sz <= 0)
    fatal("Max host size must be at least 1");
  max_host_group_sz = sz;
}

  /* Sets the Name of the XML stylesheet to be printed in XML output.
     If this is never called, a default stylesheet distributed with
     Kmap is used.  If you call it with NULL as the xslname, no
     stylesheet line is printed. */
void KmapOps::setXSLStyleSheet(const char *xslname) {
  if (xsl_stylesheet) free(xsl_stylesheet);
  xsl_stylesheet = xslname? strdup(xslname) : NULL;
  xsl_stylesheet_set = true;
}

/* Returns the full path or URL that should be printed in the XML
   output xml-stylesheet element.  Returns NULL if the whole element
   should be skipped */
char *KmapOps::XSLStyleSheet() {
  char tmpxsl[MAXPATHLEN];

  if (xsl_stylesheet_set)
    return xsl_stylesheet;

  if (kmap_fetchfile(tmpxsl, sizeof(tmpxsl), "kmap.xsl") == 1) {
    xsl_stylesheet = filename_to_url(tmpxsl);
  } else {
    /* Use a relative URL if kmap_fetchfile failed. It won't work,
       but it gives a clue that there is an kmap.xsl somewhere. */
    xsl_stylesheet = strdup("kmap.xsl");
  }

  return xsl_stylesheet;
}

void KmapOps::setSpoofMACAddress(u8 *mac_data) {
  memcpy(spoof_mac, mac_data, 6);
  spoof_mac_set = true;
}

#ifndef NOLUA
void KmapOps::chooseScripts(char* argument) {
        char *p;

        for (;;) {
                p = strchr(argument, ',');
                if (p == NULL) {
                        chosenScripts.push_back(std::string(argument));
                        break;
                } else {
                        chosenScripts.push_back(std::string(argument, p - argument));
                        argument = p + 1;
                }
        }
}
#endif
