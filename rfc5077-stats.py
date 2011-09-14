#!/usr/bin/env python

# Copyright (c) 2011 Vincent Bernat <bernat@luffy.cx>
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

"""
Generate some graphics from the output of `rfc5077-pcap`.
"""

import sys
import os
import gzip
import time
import sqlite3

from matplotlib.pylab import *
matplotlib.rcParams['font.size'] = 8

data = sys.argv[1]
browsers = len(sys.argv) > 2 and sys.argv[2] or None
base = ".".join(os.path.basename(data).split(".")[:-1])
sql = "%s.sqlite" % base

conn = sqlite3.connect(sql)
cur = conn.cursor()

def create_database_hello(cur, data):
    print "[+] Build `hello` table"
    cur.execute("DROP TABLE IF EXISTS hello")
    cur.execute("CREATE TABLE hello (date INTEGER, client TEXT, server TEXT,"
                "  ssl2 INTEGER, version TEXT, sessionid TEXT, ciphers TEXT,"
                "  compression TEXT, servername TEXT, ticket INTEGER, ticketlen INTEGER)")
    cur.execute("DROP TABLE IF EXISTS ciphers")
    cur.execute("CREATE TABLE ciphers (client TEXT, cipher TEXT)")
    i = 0
    for row in gzip.open(data):
        row = row.strip()
        if i == 0:
            i = i + 1
            continue
        date, client, server, ssl2, version, sessionid, ciphers, \
            compression, servername, ticket, ticketlen = row.split(";")
        cur.execute("INSERT INTO hello (date, client, server, ssl2, version,"
                    "  sessionid, ciphers, compression, servername,"
                    "  ticket, ticketlen) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (int(float(date)), client, server, int(ssl2), version, sessionid,
                     ciphers, compression, servername or None, int(ticket), int(ticketlen)))
        for cipher in ciphers.split(":"):
            cur.execute("INSERT INTO ciphers (client, cipher) VALUES (?,?)",
                        (client, cipher))
        i = i + 1

def create_database_browsers(cur, browsers):
    print "[+] Build `browsers` table"
    cur.execute("DROP TABLE IF EXISTS browsers")
    cur.execute("CREATE TABLE browsers (ip TEXT, ua TEXT)")
    for row in gzip.open(browsers):
        row = row.strip()
        ip, ua = row.split(";", 1)
        cur.execute("INSERT INTO browsers (ip, ua) VALUES (?,?)", (ip, ua))
    # Remove IP with several browsers
    cur.execute("DELETE FROM browsers WHERE ip IN "
                "  (SELECT ip FROM (SELECT COUNT(ua) AS uas, ip FROM browsers GROUP BY ip) WHERE uas > 1);")

exist = os.path.exists(sql)
if not exist or os.path.getmtime(data) > os.path.getmtime(sql):
    create_database_hello(cur, data)
if browsers and \
        (not exist or os.path.getmtime(browsers) > os.path.getmtime(sql)):
    create_database_browsers(cur, browsers)
conn.commit()

figure(num=None, figsize=(8.27, 11.69), dpi=100)

# Plot 1: number of clients supporting resume with tickets
print("[+] Plot 1")
cur.execute("SELECT COUNT(client), ticket  FROM hello WHERE ssl2 = 0 GROUP BY ticket ORDER by ticket")

r = cur.fetchall()
ax1 = subplot2grid((4, 2), (0, 0))
ax1.set_aspect(1./ax1.get_data_ratio())
pie((r[0][0], r[1][0]),
    explode=(0, 0.1),
    colors=("#FF7373", "#00CC00"),
    labels=("No tickets", "Tickets"),
    labeldistance=1.15,
    autopct='%1.1f%%', shadow=True)
title("Support of RFC 5077")

# Plot 2: number of clients supporting SNI
print("[+] Plot 2")
cur.execute("SELECT COUNT(client), sni FROM "
            "  (SELECT client, CASE WHEN length(servername)>0 THEN 1 ELSE 0 END AS sni FROM hello WHERE ssl2 = 0)"
            " GROUP BY sni ORDER BY sni")

r = cur.fetchall()
ax2 = subplot2grid((4, 2), (0, 1))
ax2.set_aspect(1./ax2.get_data_ratio())
pie((r[0][0], r[1][0]),
    explode=(0, 0.1),
    colors=("#FF7373", "#00CC00"),
    labels=("No SNI", "SNI"),
    labeldistance=1.15,
    autopct='%1.1f%%', shadow=True)
title("Server Name Indication support")

# Plot 3: SSL version
print("[+] Plot 3")
cur.execute("SELECT COUNT(client) AS c, version FROM hello WHERE ssl2 = 0 GROUP BY version ORDER BY c DESC")

r = cur.fetchall()
ax3 = subplot2grid((4,2), (1, 0))
ax3.set_aspect(1./ax3.get_data_ratio())
pie([x[0] for x in r],
    colors=("#62E200", "#AA00A2", "#C9F600", "#E60042"),
    explode=(0.1,)*len(r),
    labels=[x[1] for x in r],
    labeldistance=1.15,
    autopct='%1.1f%%', shadow=True)
title("Most common TLS versions")

# Plot 4: Resumed sessions
print("[+] Plot 4")
cur.execute("SELECT COUNT(client), length(sessionid)>0, ticketlen>0 FROM hello "
            "   GROUP BY length(sessionid)>0, ticketlen>0 "
            "   ORDER BY length(sessionid)>0, ticketlen>0 ")

r = dict([((x[1], x[2]), x[0]) for x in cur.fetchall()])
results = { "No resume": r[0,0],
            "Resume without tickets": r[1,0],
            "Resume with tickets": r.get((0,1),0) + r[1,1]}
ax4 = subplot2grid((4,2), (1, 1))
ax4.set_aspect(1./ax3.get_data_ratio())
pie(results.values(),
    colors=("#62E200", "#AA00A2", "#C9F600", "#E60042"),
    explode=["with tickets" in x and 0.1 or 0 for x in results.keys()],
    labels=results.keys(),
    labeldistance=1.15,
    autopct='%1.1f%%', shadow=True)
title("Session resumed")

# Plot 5: most commonly proposed ciphers
print("[+] Plot 5")
cur.execute("SELECT COUNT(client) AS clients, cipher FROM ciphers GROUP BY cipher ORDER BY clients DESC LIMIT 15")

pretty = dict(
    TLS_RSA_WITH_3DES_EDE_CBC_SHA="3DES+SHA",
    TLS_RSA_WITH_RC4_128_MD5="RC4+MD5",
    TLS_RSA_WITH_RC4_128_SHA="RC4+SHA",
    TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA="DHE-DSS-3DES+SHA",
    TLS_RSA_WITH_AES_128_CBC_SHA="AES128+SHA",
    TLS_RSA_WITH_AES_256_CBC_SHA="AES256+SHA",
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA="DHE-DSS-AES128+SHA",
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA="DHE-DSS-AES256+SHA",
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA="ECDHE-DSA-AES128+SHA",
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA="ECDHE-DSA-AES256+SHA",
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA="ECDHE-AES128+SHA",
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA="ECDHE-AES256+SHA",
    TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA="DHE-3DES+SHA",
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA="DHE-AES128+SHA",
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA="DHE-AES256+SHA",
    )
r = cur.fetchall()
ax5 = subplot2grid((4,2), (2, 0))
bar(range(1, len(r)+1),
    [r[i][0] for i in range(len(r))],
    color="#99FF00",
    width=0.7,
    align="center")
ylabel("Clients")
xticks(range(1, len(r) + 1),
       [pretty.get(y[1], y[1])
        for y in r],
       rotation=90, size=7)
title("Most common cipher suites")

# Statistics
print("[+] Statistics")
ax6 = subplot2grid((4,2), (3,1))
ax6.get_xaxis().set_visible(False)
ax6.get_yaxis().set_visible(False)
cur.execute("SELECT MAX(date), MIN(date) FROM hello")
r = cur.fetchall()
text(0.05, 0.9, "Start date:")
text(0.3, 0.9, time.strftime("%a, %d %b %Y %H:%M:%S",
                             time.localtime(r[0][1])), weight="demibold")
text(0.05, 0.82, "End date:")
text(0.3, 0.82, time.strftime("%a, %d %b %Y %H:%M:%S",
                             time.localtime(r[0][0])), weight="demibold")
cur.execute("SELECT COUNT(client) FROM hello")
r = cur.fetchall()
requests = r[0][0]
text(0.05, 0.68, "Number of requests:")
text(0.7, 0.68, "%d" % requests, weight="demibold")
cur.execute("SELECT COUNT(client) FROM (SELECT DISTINCT client FROM hello)")
r = cur.fetchall()
clients = r[0][0]
text(0.05, 0.58, "Number of clients:")
text(0.7, 0.58, "%d" % clients, weight="demibold")
cur.execute("SELECT COUNT(client) FROM (SELECT DISTINCT client FROM hello)")
r = cur.fetchall()
text(0.05, 0.48, "Number of servers:")
text(0.7, 0.48, "%d" % r[0][0], weight="demibold")
cur.execute("SELECT COUNT(client) FROM (SELECT DISTINCT client FROM hello)")
r = cur.fetchall()
text(0.05, 0.38, "Average requests by client:")
text(0.7, 0.38, "%d" % (requests/clients), weight="demibold")
cur.execute("SELECT COUNT(client) FROM hello WHERE ssl2 = 1")
r = cur.fetchall()
text(0.05, 0.28, "Number of SSLv2 requests:")
text(0.7, 0.28, "%d" % r[0][0], weight="demibold")
cur.execute("SELECT COUNT(ua) FROM (SELECT DISTINCT ua FROM browsers)")
r = cur.fetchall()
text(0.05, 0.18, "Number of browsers UA:")
text(0.7, 0.18, "%d" % r[0][0], weight="demibold")

text(0.05, 0.05, "Source:")
text(0.3, 0.05, "%s" % sys.argv[1], weight="demibold")

print("[+] Build PDF")
savefig("%s.pdf" % base)
