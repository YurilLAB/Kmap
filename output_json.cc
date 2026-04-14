
/***************************************************************************
 * output_json.cc -- JSON output serializer for Kmap scan results.         *
 * Builds a structured JSON document using nlohmann/json and writes it     *
 * to the file specified via json_initialize().                             *
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

#include "output_json.h"

#include "third-party/nlohmann/json.hpp"

#include "kmap.h"
#include "Target.h"
#include "portlist.h"
#include "portreasons.h"
#include "protocols.h"
#include "FingerPrintResults.h"
#include "osscan.h"
#include "MACLookup.h"
#include "libnetutil/netutil.h"
#include "nbase.h"

#include <fstream>
#include <string>
#include <cstdio>

/* -----------------------------------------------------------------------
 * Module-level state
 * ----------------------------------------------------------------------- */

static nlohmann::json g_doc;        // The single JSON document built during a scan
static std::string   g_filename;    // Where to write it at finalize time

/* -----------------------------------------------------------------------
 * Public API implementation
 * ----------------------------------------------------------------------- */

void json_initialize(const char *filename) {
    g_filename = filename ? filename : "";
    g_doc = {
        {"kmap",  nlohmann::json::object()},
        {"hosts", nlohmann::json::array()},
        {"stats", nlohmann::json::object()}
    };
}

void json_write_scaninfo(const char *version, const char *args, long start_time) {
    g_doc["kmap"]["version"]    = version ? std::string(version) : std::string();
    g_doc["kmap"]["args"]       = args    ? std::string(args)    : std::string();
    g_doc["kmap"]["start"]      = start_time;
}

/* Build the port array for a host. */
static nlohmann::json build_ports_json(const Target *t) {
    nlohmann::json ports_arr = nlohmann::json::array();

    const PortList &plist = t->ports;

    Port  port_storage;
    Port *current = nullptr;

    /* Iterate all TCP/UDP/SCTP ports. */
    while ((current = plist.nextPort(current, &port_storage,
                                     TCPANDUDPANDSCTP, 0)) != nullptr) {
        if (plist.isIgnoredState(current->state, nullptr))
            continue;

        nlohmann::json pobj;

        pobj["portid"]   = static_cast<int>(current->portno);
        pobj["protocol"] = std::string(IPPROTO2STR(current->proto));

        /* state sub-object */
        {
            nlohmann::json state_obj;
            state_obj["state"]  = std::string(statenum2str(current->state));
            state_obj["reason"] = std::string(reason_str(current->reason.reason_id,
                                                          SINGULAR));
            pobj["state"] = std::move(state_obj);
        }

        /* service sub-object (only if detected) */
        {
            struct serviceDeductions sd;
            plist.getServiceDeductions(current->portno, current->proto, &sd);

            if (sd.name || sd.service_fp ||
                sd.service_tunnel != SERVICE_TUNNEL_NONE) {
                nlohmann::json svc;
                svc["name"]    = sd.name    ? std::string(sd.name)    : std::string();
                svc["product"] = sd.product ? std::string(sd.product) : std::string();
                svc["version"] = sd.version ? std::string(sd.version) : std::string();
                if (sd.extrainfo)
                    svc["extrainfo"] = std::string(sd.extrainfo);
                if (sd.hostname)
                    svc["hostname"] = std::string(sd.hostname);
                if (sd.ostype)
                    svc["ostype"] = std::string(sd.ostype);
                if (sd.devicetype)
                    svc["devicetype"] = std::string(sd.devicetype);
                if (sd.service_tunnel == SERVICE_TUNNEL_SSL)
                    svc["tunnel"] = std::string("ssl");
                pobj["service"] = std::move(svc);
            }
        }

        ports_arr.push_back(std::move(pobj));
    }

    /* IP protocol scan ports */
    current = nullptr;
    while ((current = plist.nextPort(current, &port_storage,
                                     IPPROTO_IP, 0)) != nullptr) {
        if (plist.isIgnoredState(current->state, nullptr))
            continue;

        nlohmann::json pobj;
        pobj["portid"]   = static_cast<int>(current->portno);
        pobj["protocol"] = std::string("ip");

        {
            nlohmann::json state_obj;
            state_obj["state"]  = std::string(statenum2str(current->state));
            state_obj["reason"] = std::string(reason_str(current->reason.reason_id,
                                                          SINGULAR));
            pobj["state"] = std::move(state_obj);
        }

        const struct nprotoent *proto = kmap_getprotbynum(current->portno);
        if (proto && proto->p_name && *proto->p_name) {
            nlohmann::json svc;
            svc["name"] = std::string(proto->p_name);
            pobj["service"] = std::move(svc);
        }

        ports_arr.push_back(std::move(pobj));
    }

    return ports_arr;
}

/* Build the OS detection sub-object for a host. */
static nlohmann::json build_os_json(const Target *t) {
    nlohmann::json os_obj = nlohmann::json::object();

    if (!t->osscanPerformed() || t->FPR == nullptr)
        return os_obj;

    FingerPrintResults *FPR = t->FPR;
    if (FPR->overall_results != OSSCAN_SUCCESS)
        return os_obj;

    nlohmann::json matches_arr = nlohmann::json::array();

    /* Number of matches to emit: perfect matches, or up to 10 near-matches. */
    int num_to_emit = FPR->num_perfect_matches > 0
                        ? FPR->num_perfect_matches
                        : FPR->num_matches;
    if (num_to_emit > 10)
        num_to_emit = 10;

    for (int i = 0; i < num_to_emit; i++) {
        if (FPR->matches[i] == nullptr)
            break;
        /* Drop near-matches that are more than 10 percentage points below best. */
        if (FPR->num_perfect_matches == 0 &&
            FPR->accuracy[i] < FPR->accuracy[0] - 0.10)
            break;

        nlohmann::json m;
        m["name"]     = FPR->matches[i]->OS_name
                            ? std::string(FPR->matches[i]->OS_name)
                            : std::string();
        m["accuracy"] = static_cast<int>(FPR->accuracy[i] * 100.0);

        matches_arr.push_back(std::move(m));
    }

    os_obj["osmatch"] = std::move(matches_arr);
    return os_obj;
}

void json_write_host(const Target *t) {
    if (t == nullptr)
        return;

    nlohmann::json host;

    /* ------------------------------------------------------------------
     * status
     * ------------------------------------------------------------------ */
    {
        nlohmann::json status;
        status["state"]  = (t->flags & HOST_UP) ? "up" : "down";
        status["reason"] = std::string(reason_str(t->reason.reason_id, SINGULAR));
        host["status"] = std::move(status);
    }

    /* ------------------------------------------------------------------
     * addresses
     * ------------------------------------------------------------------ */
    {
        nlohmann::json addrs = nlohmann::json::array();

        /* IP address */
        {
            nlohmann::json a;
            a["addr"]     = std::string(t->targetipstr());
            a["addrtype"] = (t->af() == AF_INET6) ? "ipv6" : "ipv4";
            addrs.push_back(std::move(a));
        }

        /* MAC address (present when target is on local ethernet) */
        const u8 *mac = t->MACAddress();
        if (mac) {
            char macbuf[32];
            Snprintf(macbuf, sizeof(macbuf),
                     "%02X:%02X:%02X:%02X:%02X:%02X",
                     mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            nlohmann::json a;
            a["addr"]     = std::string(macbuf);
            a["addrtype"] = "mac";
            const char *vendor = MACPrefix2Corp(mac);
            if (vendor)
                a["vendor"] = std::string(vendor);
            addrs.push_back(std::move(a));
        }

        host["addresses"] = std::move(addrs);
    }

    /* ------------------------------------------------------------------
     * hostnames
     * ------------------------------------------------------------------ */
    {
        nlohmann::json names = nlohmann::json::array();

        /* User-supplied name from the command line */
        if (t->TargetName() != nullptr) {
            nlohmann::json n;
            n["name"] = std::string(t->TargetName());
            n["type"] = "user";
            names.push_back(std::move(n));
        }

        /* Reverse-DNS (PTR) name */
        if (t->HostName() && *t->HostName()) {
            nlohmann::json n;
            n["name"] = std::string(t->HostName());
            n["type"] = "PTR";
            names.push_back(std::move(n));
        }

        host["hostnames"] = std::move(names);
    }

    /* ------------------------------------------------------------------
     * ports
     * ------------------------------------------------------------------ */
    host["ports"] = build_ports_json(t);

    /* ------------------------------------------------------------------
     * OS detection
     * ------------------------------------------------------------------ */
    {
        nlohmann::json os = build_os_json(t);
        if (!os.empty())
            host["os"] = std::move(os);
    }

    g_doc["hosts"].push_back(std::move(host));
}

void json_write_stats(int up, int down, int total, float elapsed) {
    g_doc["stats"]["hosts_up"]    = up;
    g_doc["stats"]["hosts_down"]  = down;
    g_doc["stats"]["hosts_total"] = total;
    g_doc["stats"]["elapsed"]     = static_cast<double>(elapsed);
}

void json_finalize() {
    if (g_filename.empty())
        return;

    std::ofstream ofs(g_filename);
    if (!ofs.is_open()) {
        /* Non-fatal: just report and move on so the rest of the scan output
           is not disrupted. */
        fprintf(stderr, "KMAP WARNING: Could not open JSON output file %s for writing.\n",
                g_filename.c_str());
        return;
    }

    try {
        ofs << g_doc.dump(2) << "\n";
    } catch (...) {
        fprintf(stderr, "KMAP WARNING: Failed to write JSON output to %s (serialization error).\n",
                g_filename.c_str());
    }
    if (ofs.fail()) {
        fprintf(stderr, "KMAP WARNING: Write error on JSON output file %s (disk full?).\n",
                g_filename.c_str());
    }
    ofs.close();

    /* Release memory. */
    g_doc  = nlohmann::json{};
    g_filename.clear();
}

/* =======================================================================
 * Scan Report Generator (--report)
 *
 * Produces either styled plain text (.txt) or Markdown (.md) depending
 * on the file extension.  Collects data from all hosts and writes
 * everything at finalize time.
 * ======================================================================= */

#include "default_creds.h"
#include "web_recon.h"
#include "cve_map.h"

#include <ctime>
#include <sstream>
#include <iomanip>

/* Module state */
static std::string rpt_filename;
static bool        rpt_markdown = false;

/* Accumulated host data for the report */
struct RptPort {
    int portno;
    std::string proto;
    std::string state;
    std::string service;
    std::string version;
};
struct RptHost {
    std::string ip;
    std::string hostname;
    std::string status;
    std::vector<RptPort> ports;
    /* Feature data pointers — may be null */
    const void *cred_data;
    const void *web_data;
    const void *cve_data;
};
static std::vector<RptHost> rpt_hosts;
static int rpt_up = 0, rpt_down = 0, rpt_total = 0;
static float rpt_elapsed = 0.0f;

void report_initialize(const char *filename) {
    rpt_filename = filename ? filename : "";
    rpt_hosts.clear();
    rpt_up = rpt_down = rpt_total = 0;
    rpt_elapsed = 0.0f;
    /* Detect markdown from extension */
    rpt_markdown = false;
    if (rpt_filename.size() >= 3) {
        std::string ext = rpt_filename.substr(rpt_filename.size() - 3);
        if (ext == ".md") rpt_markdown = true;
    }
}

void report_write_host(const Target *t) {
    if (!t) return;
    RptHost h;
    h.ip = t->targetipstr();
    if (t->HostName() && *t->HostName())
        h.hostname = t->HostName();
    h.status = (t->flags & HOST_UP) ? "up" : "down";

    /* Collect ports */
    const PortList &plist = t->ports;
    Port pstore;
    Port *cur = nullptr;
    while ((cur = plist.nextPort(cur, &pstore, TCPANDUDPANDSCTP, 0)) != nullptr) {
        if (plist.isIgnoredState(cur->state, nullptr))
            continue;
        RptPort rp;
        rp.portno = cur->portno;
        rp.proto  = IPPROTO2STR(cur->proto);
        rp.state  = statenum2str(cur->state);
        struct serviceDeductions sd;
        plist.getServiceDeductions(cur->portno, cur->proto, &sd);
        rp.service = sd.name    ? sd.name    : "";
        rp.version = sd.product ? sd.product : "";
        if (sd.version && sd.version[0]) {
            if (!rp.version.empty()) rp.version += " ";
            rp.version += sd.version;
        }
        h.ports.push_back(rp);
    }

    /* Grab feature data pointers */
    h.cred_data = t->attribute.get("kmap_default_creds");
    h.web_data  = t->attribute.get("kmap_web_recon");
    h.cve_data  = t->attribute.get("kmap_cve_map");

    rpt_hosts.push_back(std::move(h));
}

void report_write_stats(int up, int down, int total, float elapsed) {
    rpt_up = up; rpt_down = down; rpt_total = total; rpt_elapsed = elapsed;
}

/* ---- Internal writers ---- */

static std::string timestamp_str() {
    time_t now = time(nullptr);
    struct tm *tm = localtime(&now);
    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm);
    return buf;
}

static void write_txt_report(std::ofstream &f) {
    const std::string sep(80, '=');
    const std::string thin(80, '-');

    f << sep << "\n";
    f << "                         KMAP SCAN REPORT\n";
    f << sep << "\n";
    f << "  Date:       " << timestamp_str() << "\n";
    f << "  Targets:    " << rpt_total << " host(s) scanned\n";
    f << "  Hosts up:   " << rpt_up << "\n";
    f << sep << "\n\n";

    for (const auto &h : rpt_hosts) {
        f << sep << "\n";
        f << "  TARGET: " << h.ip;
        if (!h.hostname.empty()) f << " (" << h.hostname << ")";
        f << "  [" << h.status << "]\n";
        f << sep << "\n\n";

        /* Port table */
        if (!h.ports.empty()) {
            f << "  PORT TABLE\n";
            f << "  " << thin << "\n";
            f << "  " << std::left << std::setw(14) << "PORT"
              << std::setw(10) << "STATE"
              << std::setw(16) << "SERVICE"
              << "VERSION\n";
            f << "  " << thin << "\n";
            for (const auto &p : h.ports) {
                std::string portstr = std::to_string(p.portno) + "/" + p.proto;
                f << "  " << std::left << std::setw(14) << portstr
                  << std::setw(10) << p.state
                  << std::setw(16) << p.service
                  << p.version << "\n";
            }
            f << "\n";
        }

        /* Default credentials */
        if (h.cred_data) {
            const auto *cd = static_cast<const std::vector<PortCredResults>*>(
                &(static_cast<const TargetCredData *>(h.cred_data)->results));
            if (cd && !cd->empty()) {
                f << "  DEFAULT CREDENTIALS\n";
                f << "  " << thin << "\n";
                for (const auto &pcr : *cd) {
                    for (const auto &r : pcr.hits) {
                        if (r.found) {
                            f << "  [!] " << pcr.portno << "/"
                              << ((pcr.proto == IPPROTO_TCP) ? "tcp" : "udp")
                              << " " << r.service << ": "
                              << r.username << ":"
                              << (r.password.empty() ? "(empty)" : r.password)
                              << "  [FOUND]\n";
                        }
                    }
                }
                f << "\n";
            }
        }

        /* Web recon */
        if (h.web_data) {
            const auto *wd = &(static_cast<const TargetWebData *>(h.web_data)->results);
            if (wd && !wd->empty()) {
                f << "  WEB RECON\n";
                f << "  " << thin << "\n";
                for (const auto &r : *wd) {
                    f << "  Port " << r.portno << "/" << (r.is_https ? "https" : "http") << ":\n";
                    if (!r.title.empty())
                        f << "    Title:   " << r.title << "\n";
                    if (!r.server.empty())
                        f << "    Server:  " << r.server << "\n";
                    if (!r.powered_by.empty())
                        f << "    Tech:    " << r.powered_by << "\n";
                    if (r.is_https && !r.tls.subject_cn.empty()) {
                        f << "    TLS CN:  " << r.tls.subject_cn
                          << (r.tls.self_signed ? " [self-signed]" : "") << "\n";
                        if (!r.tls.not_after.empty())
                            f << "    Expiry:  " << r.tls.not_after << "\n";
                    }
                    if (!r.robots_disallowed.empty()) {
                        f << "    Robots:  ";
                        for (size_t i = 0; i < r.robots_disallowed.size(); ++i)
                            f << r.robots_disallowed[i]
                              << (i + 1 < r.robots_disallowed.size() ? ", " : "");
                        f << "\n";
                    }
                    for (const auto &wp : r.paths) {
                        f << "    [" << wp.status_code << "] " << wp.path;
                        if (!wp.redirect_to.empty())
                            f << " -> " << wp.redirect_to;
                        else if (!wp.title.empty())
                            f << " - " << wp.title;
                        f << "\n";
                    }
                }
                f << "\n";
            }
        }

        /* CVE map */
        if (h.cve_data) {
            const auto *cvd = &(static_cast<const TargetCveData *>(h.cve_data)->port_results);
            if (cvd && !cvd->empty()) {
                f << "  CVE MAP\n";
                f << "  " << thin << "\n";
                for (const auto &pr : *cvd) {
                    f << "  " << pr.portno << "/" << pr.proto
                      << " " << pr.service;
                    if (!pr.version.empty())
                        f << " (" << pr.version << ")";
                    f << ":\n";
                    for (const auto &cve : pr.cves) {
                        char score[8];
                        snprintf(score, sizeof(score), "%.1f", cve.cvss_score);
                        f << "    " << cve.cve_id
                          << "  CVSS:" << score
                          << "  " << cve.severity << "\n";
                        std::string desc = cve.description;
                        if (desc.size() > 72) desc = desc.substr(0, 69) + "...";
                        f << "      " << desc << "\n";
                    }
                }
                f << "\n";
            }
        }
    }

    /* Summary */
    f << sep << "\n";
    f << "  SUMMARY\n";
    f << sep << "\n";
    f << "  Hosts scanned: " << rpt_total << "\n";
    f << "  Hosts up:      " << rpt_up << "\n";
    f << "  Hosts down:    " << rpt_down << "\n";

    int total_ports = 0, total_creds = 0, total_cves = 0;
    for (const auto &h : rpt_hosts) {
        total_ports += static_cast<int>(h.ports.size());
        if (h.cred_data) {
            const auto *cd = &(static_cast<const TargetCredData *>(h.cred_data)->results);
            if (cd) for (const auto &pcr : *cd) total_creds += static_cast<int>(pcr.hits.size());
        }
        if (h.cve_data) {
            const auto *cvd = &(static_cast<const TargetCveData *>(h.cve_data)->port_results);
            if (cvd) for (const auto &pr : *cvd) total_cves += static_cast<int>(pr.cves.size());
        }
    }

    f << "  Ports found:   " << total_ports << "\n";
    if (total_creds > 0)
        f << "  Creds found:   " << total_creds << "\n";
    if (total_cves > 0)
        f << "  CVEs found:    " << total_cves << "\n";
    char tbuf[16];
    snprintf(tbuf, sizeof(tbuf), "%.2f", rpt_elapsed);
    f << "  Scan time:     " << tbuf << "s\n";
    f << sep << "\n";
    f << "  Generated by Kmap - https://github.com/YurilLAB/Kmap\n";
    f << sep << "\n";
}

static void write_md_report(std::ofstream &f) {
    f << "# Kmap Scan Report\n\n";
    f << "**Date:** " << timestamp_str() << "  \n";
    f << "**Targets:** " << rpt_total << " host(s) scanned  \n";
    f << "**Hosts up:** " << rpt_up << "\n\n";
    f << "---\n\n";

    for (const auto &h : rpt_hosts) {
        f << "## Target: " << h.ip;
        if (!h.hostname.empty()) f << " (" << h.hostname << ")";
        f << "\n\n";
        f << "**Status:** " << h.status << "\n\n";

        /* Port table */
        if (!h.ports.empty()) {
            f << "### Port Table\n\n";
            f << "| Port | State | Service | Version |\n";
            f << "|------|-------|---------|--------|\n";
            for (const auto &p : h.ports) {
                f << "| " << p.portno << "/" << p.proto
                  << " | " << p.state
                  << " | " << p.service
                  << " | " << p.version << " |\n";
            }
            f << "\n";
        }

        /* Default credentials */
        if (h.cred_data) {
            const auto *cd = &(static_cast<const TargetCredData *>(h.cred_data)->results);
            if (cd && !cd->empty()) {
                f << "### Default Credentials Found\n\n";
                f << "| Port | Service | Username | Password | Status |\n";
                f << "|------|---------|----------|----------|--------|\n";
                for (const auto &pcr : *cd) {
                    for (const auto &r : pcr.hits) {
                        if (r.found) {
                            f << "| " << pcr.portno << "/"
                              << ((pcr.proto == IPPROTO_TCP) ? "tcp" : "udp")
                              << " | " << r.service
                              << " | " << r.username
                              << " | " << (r.password.empty() ? "(empty)" : r.password)
                              << " | FOUND |\n";
                        }
                    }
                }
                f << "\n";
            }
        }

        /* Web recon */
        if (h.web_data) {
            const auto *wd = &(static_cast<const TargetWebData *>(h.web_data)->results);
            if (wd && !wd->empty()) {
                f << "### Web Recon\n\n";
                for (const auto &r : *wd) {
                    f << "**Port " << r.portno << "/" << (r.is_https ? "https" : "http") << "**\n\n";
                    if (!r.title.empty())  f << "- **Title:** " << r.title << "\n";
                    if (!r.server.empty()) f << "- **Server:** " << r.server << "\n";
                    if (!r.powered_by.empty()) f << "- **Tech:** " << r.powered_by << "\n";
                    if (r.is_https && !r.tls.subject_cn.empty()) {
                        f << "- **TLS CN:** " << r.tls.subject_cn
                          << (r.tls.self_signed ? " (self-signed)" : "") << "\n";
                        if (!r.tls.not_after.empty())
                            f << "- **Expiry:** " << r.tls.not_after << "\n";
                    }
                    if (!r.robots_disallowed.empty()) {
                        f << "- **Robots:** ";
                        for (size_t i = 0; i < r.robots_disallowed.size(); ++i)
                            f << "`" << r.robots_disallowed[i] << "`"
                              << (i + 1 < r.robots_disallowed.size() ? ", " : "");
                        f << "\n";
                    }
                    if (!r.paths.empty()) {
                        f << "\n| Status | Path | Details |\n";
                        f << "|--------|------|---------|\n";
                        for (const auto &wp : r.paths) {
                            f << "| " << wp.status_code << " | " << wp.path << " | ";
                            if (!wp.redirect_to.empty())
                                f << "-> " << wp.redirect_to;
                            else if (!wp.title.empty())
                                f << wp.title;
                            f << " |\n";
                        }
                    }
                    f << "\n";
                }
            }
        }

        /* CVE map */
        if (h.cve_data) {
            const auto *cvd = &(static_cast<const TargetCveData *>(h.cve_data)->port_results);
            if (cvd && !cvd->empty()) {
                f << "### CVE Map\n\n";
                for (const auto &pr : *cvd) {
                    f << "**" << pr.portno << "/" << pr.proto
                      << " " << pr.service;
                    if (!pr.version.empty())
                        f << " (" << pr.version << ")";
                    f << "**\n\n";
                    f << "| CVE | CVSS | Severity | Description |\n";
                    f << "|-----|------|----------|-------------|\n";
                    for (const auto &cve : pr.cves) {
                        char score[8];
                        snprintf(score, sizeof(score), "%.1f", cve.cvss_score);
                        std::string desc = cve.description;
                        if (desc.size() > 60) desc = desc.substr(0, 57) + "...";
                        f << "| " << cve.cve_id
                          << " | " << score
                          << " | " << cve.severity
                          << " | " << desc << " |\n";
                    }
                    f << "\n";
                }
            }
        }
        f << "---\n\n";
    }

    /* Summary */
    f << "## Summary\n\n";
    int total_ports = 0, total_creds = 0, total_cves = 0;
    for (const auto &h : rpt_hosts) {
        total_ports += static_cast<int>(h.ports.size());
        if (h.cred_data) {
            const auto *cd = &(static_cast<const TargetCredData *>(h.cred_data)->results);
            if (cd) for (const auto &pcr : *cd) total_creds += static_cast<int>(pcr.hits.size());
        }
        if (h.cve_data) {
            const auto *cvd = &(static_cast<const TargetCveData *>(h.cve_data)->port_results);
            if (cvd) for (const auto &pr : *cvd) total_cves += static_cast<int>(pr.cves.size());
        }
    }
    f << "| Metric | Value |\n";
    f << "|--------|-------|\n";
    f << "| Hosts scanned | " << rpt_total << " |\n";
    f << "| Hosts up | " << rpt_up << " |\n";
    f << "| Hosts down | " << rpt_down << " |\n";
    f << "| Ports found | " << total_ports << " |\n";
    if (total_creds > 0) f << "| Creds found | " << total_creds << " |\n";
    if (total_cves > 0)  f << "| CVEs found | " << total_cves << " |\n";
    char tbuf[16];
    snprintf(tbuf, sizeof(tbuf), "%.2f", rpt_elapsed);
    f << "| Scan time | " << tbuf << "s |\n";
    f << "\n---\n\n";
    f << "*Generated by [Kmap](https://github.com/YurilLAB/Kmap)*\n";
}

void report_finalize() {
    if (rpt_filename.empty())
        return;

    std::ofstream ofs(rpt_filename);
    if (!ofs.is_open()) {
        fprintf(stderr, "KMAP WARNING: Could not open report file %s for writing.\n",
                rpt_filename.c_str());
        /* Non-fatal: clean up and continue so the rest of scan output
           is not disrupted. */
        rpt_hosts.clear();
        rpt_filename.clear();
        return;
    }

    if (rpt_markdown)
        write_md_report(ofs);
    else
        write_txt_report(ofs);

    if (ofs.fail()) {
        fprintf(stderr, "KMAP WARNING: Write error on report file %s (disk full?).\n",
                rpt_filename.c_str());
    }
    ofs.close();

    log_write(LOG_STDOUT, "Report written to %s\n", rpt_filename.c_str());

    rpt_hosts.clear();
    rpt_filename.clear();
}
