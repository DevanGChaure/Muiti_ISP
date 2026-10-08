// Minimal DHCP server (RFC 2131/2132 subset) for the Enterprise LAN.
// Handles DISCOVER -> OFFER, REQUEST -> ACK/NAK. Static lease pool, MAC-keyed.
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <string>
#include <map>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <ctime>

#pragma pack(push, 1)
struct DhcpPacket {
    uint8_t  op;        // 1 = BOOTREQUEST, 2 = BOOTREPLY
    uint8_t  htype;      // 1 = Ethernet
    uint8_t  hlen;        // 6
    uint8_t  hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr;
    uint32_t giaddr;
    uint8_t  chaddr[16];
    uint8_t  sname[64];
    uint8_t  file[128];
    uint32_t magic;       // 0x63825363
    uint8_t  options[312];
};
#pragma pack(pop)

static const uint32_t DHCP_MAGIC = 0x63825363;

// ---- Config: edit to match your lab ----
static const char* SERVER_IP_STR  = "10.10.0.2";   // dhcp-server's own IP on enterprise-lan
static const char* GATEWAY_STR    = "10.10.0.254";   // Enterprise router, same as SERVER_IP here
static const char* SUBNET_MASK    = "255.255.255.0";
static const char* DNS_SERVER     = "10.10.0.254";   // point at gateway; change if you add a resolver
static const uint32_t LEASE_TIME_SEC = 3600;
static const uint32_t POOL_START = 100;  // 10.10.0.100
static const uint32_t POOL_END   = 120;  // 10.10.0.120
static const char* DIRECTED_BCAST = "10.10.0.255"; // LAN's directed broadcast (resolves via the connected route; 255.255.255.255 does not, absent a default route)
// -----------------------------------------

enum DhcpMsgType : uint8_t {
    DHCPDISCOVER = 1, DHCPOFFER = 2, DHCPREQUEST = 3,
    DHCPDECLINE  = 4, DHCPACK   = 5, DHCPNAK     = 6, DHCPRELEASE = 7
};

static std::map<std::string, uint32_t> leases; // mac -> host-order IP
static std::map<uint32_t, std::string> inUse;   // full IP (host order) -> mac

static std::string macToStr(const uint8_t* chaddr) {
    char buf[18];
    snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
        chaddr[0], chaddr[1], chaddr[2], chaddr[3], chaddr[4], chaddr[5]);
    return std::string(buf);
}

static uint32_t baseNet() {
    struct in_addr a;
    inet_aton("10.10.0.0", &a);
    return ntohl(a.s_addr);
}

// Find or assign a lease for this MAC. Returns full IP in host order, or 0 if pool exhausted.
static uint32_t getOrAssignLease(const std::string& mac) {
    auto it = leases.find(mac);
    if (it != leases.end()) return it->second;

    uint32_t base = baseNet();
    for (uint32_t octet = POOL_START; octet <= POOL_END; ++octet) {
        uint32_t candidate = base | octet;
        if (inUse.find(candidate) == inUse.end()) {
            leases[mac] = candidate;
            inUse[candidate] = mac;
            return candidate;
        }
    }
    return 0; // pool exhausted
}

static void appendOption(uint8_t* opts, size_t& pos, uint8_t code, const uint8_t* data, uint8_t len) {
    opts[pos++] = code;
    opts[pos++] = len;
    memcpy(opts + pos, data, len);
    pos += len;
}

static uint8_t getMsgType(const DhcpPacket& pkt) {
    const uint8_t* o = pkt.options;
    size_t i = 0;
    while (i < sizeof(pkt.options) && o[i] != 0xFF) {
        uint8_t code = o[i++];
        if (code == 0) continue; // pad
        uint8_t len = o[i++];
        if (code == 53 && len == 1) return o[i];
        i += len;
    }
    return 0;
}

// Pull requested IP (option 50) if present, else 0.
static uint32_t getRequestedIp(const DhcpPacket& pkt) {
    const uint8_t* o = pkt.options;
    size_t i = 0;
    while (i < sizeof(pkt.options) && o[i] != 0xFF) {
        uint8_t code = o[i++];
        if (code == 0) continue;
        uint8_t len = o[i++];
        if (code == 50 && len == 4) {
            uint32_t v;
            memcpy(&v, o + i, 4);
            return ntohl(v);
        }
        i += len;
    }
    return 0;
}

static void buildReply(DhcpPacket& reply, const DhcpPacket& req, uint8_t type, uint32_t offeredIpHost) {
    memset(&reply, 0, sizeof(reply));
    reply.op = 2; // BOOTREPLY
    reply.htype = 1;
    reply.hlen = 6;
    reply.xid = req.xid;
    reply.flags = req.flags;
    reply.giaddr = req.giaddr;
    memcpy(reply.chaddr, req.chaddr, 16);
    reply.magic = htonl(DHCP_MAGIC);

    if (type != DHCPNAK) {
        reply.yiaddr = htonl(offeredIpHost);
    }

    struct in_addr srv, mask, gw, dns;
    inet_aton(SERVER_IP_STR, &srv);
    inet_aton(SUBNET_MASK, &mask);
    inet_aton(GATEWAY_STR, &gw);
    inet_aton(DNS_SERVER, &dns);

    size_t pos = 0;
    uint8_t* opts = reply.options;

    appendOption(opts, pos, 53, &type, 1);                                   // DHCP msg type
    appendOption(opts, pos, 54, (uint8_t*)&srv.s_addr, 4);                   // server identifier

    if (type == DHCPOFFER || type == DHCPACK) {
        uint32_t lease_n = htonl(LEASE_TIME_SEC);
        appendOption(opts, pos, 51, (uint8_t*)&lease_n, 4);                  // lease time
        appendOption(opts, pos, 1,  (uint8_t*)&mask.s_addr, 4);              // subnet mask
        appendOption(opts, pos, 3,  (uint8_t*)&gw.s_addr, 4);                // router
        appendOption(opts, pos, 6,  (uint8_t*)&dns.s_addr, 4);               // DNS
    }
    opts[pos++] = 0xFF; // end
}

int main() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { perror("socket"); return 1; }

    int on = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on));

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(67);

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind"); return 1;
    }

    printf("[dhcp-server] listening on 0.0.0.0:67, pool %s.%u-%u, gw=%s\n",
        "10.10.0", POOL_START, POOL_END, GATEWAY_STR);

    while (true) {
        DhcpPacket pkt{};
        struct sockaddr_in cliaddr{};
        socklen_t clilen = sizeof(cliaddr);
        ssize_t n = recvfrom(sock, &pkt, sizeof(pkt), 0, (struct sockaddr*)&cliaddr, &clilen);
        if (n < (ssize_t)offsetof(DhcpPacket, options)) continue;
        if (pkt.op != 1) continue; // only BOOTREQUEST
        if (ntohl(pkt.magic) != DHCP_MAGIC) continue;

        uint8_t msgType = getMsgType(pkt);
        std::string mac = macToStr(pkt.chaddr);

        DhcpPacket reply{};
        struct sockaddr_in dst{};
        dst.sin_family = AF_INET;
        dst.sin_port = htons(68);

        if (msgType == DHCPDISCOVER) {
            uint32_t ip = getOrAssignLease(mac);
            if (ip == 0) { printf("[dhcp-server] pool exhausted for %s\n", mac.c_str()); continue; }
            buildReply(reply, pkt, DHCPOFFER, ip);
            struct in_addr a; a.s_addr = htonl(ip);
            printf("[dhcp-server] OFFER %s -> %s\n", mac.c_str(), inet_ntoa(a));
            inet_aton(DIRECTED_BCAST, &dst.sin_addr);

        } else if (msgType == DHCPREQUEST) {
            uint32_t reqIp = getRequestedIp(pkt);
            auto it = leases.find(mac);
            uint32_t ourOffer = (it != leases.end()) ? it->second : 0;

            if (ourOffer != 0 && (reqIp == 0 || reqIp == ourOffer)) {
                buildReply(reply, pkt, DHCPACK, ourOffer);
                struct in_addr a; a.s_addr = htonl(ourOffer);
                printf("[dhcp-server] ACK %s -> %s\n", mac.c_str(), inet_ntoa(a));
            } else {
                buildReply(reply, pkt, DHCPNAK, 0);
                printf("[dhcp-server] NAK %s (requested mismatch)\n", mac.c_str());
            }
            inet_aton(DIRECTED_BCAST, &dst.sin_addr);
        } else {
            continue; // ignore DECLINE/RELEASE/INFORM for this minimal server
        }

        if (sendto(sock, &reply, sizeof(reply), 0, (struct sockaddr*)&dst, sizeof(dst)) < 0) {
	    perror("[dhcp-server] sendto failed");
	}
    }
    return 0;
}
