
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

    ofs << g_doc.dump(2) << "\n";
    ofs.close();

    /* Release memory. */
    g_doc  = nlohmann::json{};
    g_filename.clear();
}
