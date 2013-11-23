/*
 * Obtain information about wireless interfaces from MAC80211 stack. Based
 * on the "iw" tool.
 *
 * Copyright (C) 2013 Jernej Kos <jernej@kos.mx>
 * Copyright (C) 2007-2008 Johannes Berg
 * Copyright (C) 2007 Andy Lutomirski
 * Copyright (C) 2007 Mike Kershaw
 * Copyright (C) 2008-2009 Luis R. Rodriguez
 * 
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/
#include <net/if.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>

#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>

#include "nl80211.h"
#include "compatibility.h"

#define ETH_ALEN 6

/**
 * Structure containing the connection to mac80211 via netlink.
 */
struct nl80211_state {
  struct nl_sock *nl_sock;
  int nl80211_id;
};

/**
 * Bookkeeping for an interface that is being queried.
 */
struct interface_context {
  bool found_essid;
  int32_t phy_id;
  uint8_t bssid[8];
  char dev[20];
};

/// Callback type for adding arguments to netlink commands
typedef int (*msg_cb_t)(struct nl_msg*, void*);

/**
 * Performs initialization of nl80211.
 */
static int nl80211_init(struct nl80211_state *state)
{
  int err;

  state->nl_sock = nl_socket_alloc();
  if (!state->nl_sock) {
    fprintf(stderr, "ERROR: Failed to allocate netlink socket.\n");
    return -ENOMEM;
  }

  nl_socket_set_buffer_size(state->nl_sock, 8192, 8192);

  if (genl_connect(state->nl_sock)) {
    fprintf(stderr, "ERROR: Failed to connect to generic netlink.\n");
    err = -ENOLINK;
    goto out_handle_destroy;
  }

  state->nl80211_id = genl_ctrl_resolve(state->nl_sock, NL80211_GENL_NAME);
  if (state->nl80211_id < 0) {
    fprintf(stderr, "ERROR: nl80211 not found.\n");
    err = -ENOENT;
    goto out_handle_destroy;
  }

  return 0;

out_handle_destroy:
  nl_socket_free(state->nl_sock);
  return err;
}

/**
 * Performs cleanup of nl80211.
 */
static void nl80211_cleanup(struct nl80211_state *state)
{
  nl_socket_free(state->nl_sock);
}

/**
 * Default error handler.
 */
static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err,
       void *arg)
{
  int *ret = arg;
  *ret = err->error;
  return NL_STOP;
}

/**
 * Default finish handler.
 */
static int finish_handler(struct nl_msg *msg, void *arg)
{
  int *ret = arg;
  *ret = 0;
  return NL_SKIP;
}

/**
 * Default ack handler.
 */
static int ack_handler(struct nl_msg *msg, void *arg)
{
  int *ret = arg;
  *ret = 0;
  return NL_STOP;
}

void print_ssid_escaped(const uint8_t len, const uint8_t *data)
{
  int i;

  for (i = 0; i < len; i++) {
    if (isprint(data[i]) && data[i] != ' ' && data[i] != '\\')
      printf("%c", data[i]);
    else if (data[i] == ' ' &&
       (i != 0 && i != len -1))
      printf(" ");
    else
      printf("\\x%.2x", data[i]);
  }
}

void mac_addr_n2a(char *mac_addr, unsigned char *arg)
{
  int i, l;

  l = 0;
  for (i = 0; i < ETH_ALEN ; i++) {
    if (i == 0) {
      sprintf(mac_addr+l, "%02x", arg[i]);
      l += 2;
    } else {
      sprintf(mac_addr+l, ":%02x", arg[i]);
      l += 3;
    }
  }
}

static const char *ifmodes[NL80211_IFTYPE_MAX + 1] = {
  "unspecified",
  "ibss",
  "managed",
  "ap",
  "ap-vlan",
  "wds",
  "monitor",
  "mesh-point",
  "p2p-client",
  "p2p-go",
  "p2p-device",
};

static char modebuf[100];

const char *iftype_name(enum nl80211_iftype iftype)
{
  if (iftype <= NL80211_IFTYPE_MAX && ifmodes[iftype])
    return ifmodes[iftype];
  sprintf(modebuf, "unknown");
  return modebuf;
}

int ieee80211_frequency_to_channel(int freq)
{
  /* see 802.11-2007 17.3.8.3.2 and Annex J */
  if (freq == 2484)
    return 14;
  else if (freq < 2484)
    return (freq - 2407) / 5;
  else if (freq >= 4910 && freq <= 4980)
    return (freq - 4000) / 5;
  else if (freq <= 45000) /* DMG band lower limit */
    return (freq - 5000) / 5;
  else if (freq >= 58320 && freq <= 64800)
    return (freq - 56160) / 2160;
  else
    return 0;
}

char *channel_width_name(enum nl80211_chan_width width)
{
  switch (width) {
  case NL80211_CHAN_WIDTH_20_NOHT:
    return "20";
  case NL80211_CHAN_WIDTH_20:
    return "20";
  case NL80211_CHAN_WIDTH_40:
    return "40";
  case NL80211_CHAN_WIDTH_80:
    return "80";
  case NL80211_CHAN_WIDTH_80P80:
    return "80";
  case NL80211_CHAN_WIDTH_160:
    return "160";
  default:
    return "unknown";
  }
}

static char *channel_type_name(enum nl80211_channel_type channel_type)
{
  switch (channel_type) {
  case NL80211_CHAN_NO_HT:
    return "20";
  case NL80211_CHAN_HT20:
    return "20";
  case NL80211_CHAN_HT40MINUS:
    return "40";
  case NL80211_CHAN_HT40PLUS:
    return "40";
  default:
    return "unknown";
  }
}

static int link_bss_handler(struct nl_msg *msg, void *arg)
{
  struct nlattr *tb[NL80211_ATTR_MAX + 1];
  struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
  struct nlattr *bss[NL80211_BSS_MAX + 1];
  static struct nla_policy bss_policy[NL80211_BSS_MAX + 1] = {
    [NL80211_BSS_TSF] = { .type = NLA_U64 },
    [NL80211_BSS_FREQUENCY] = { .type = NLA_U32 },
    [NL80211_BSS_BSSID] = { },
    [NL80211_BSS_BEACON_INTERVAL] = { .type = NLA_U16 },
    [NL80211_BSS_CAPABILITY] = { .type = NLA_U16 },
    [NL80211_BSS_INFORMATION_ELEMENTS] = { },
    [NL80211_BSS_SIGNAL_MBM] = { .type = NLA_U32 },
    [NL80211_BSS_SIGNAL_UNSPEC] = { .type = NLA_U8 },
    [NL80211_BSS_STATUS] = { .type = NLA_U32 },
  };
  struct interface_context *ctx = arg;
  char mac_addr[20], dev[20];

  nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

  if (!tb[NL80211_ATTR_BSS])
    return NL_SKIP;
  if (nla_parse_nested(bss, NL80211_BSS_MAX, tb[NL80211_ATTR_BSS], bss_policy))
    return NL_SKIP;

  if (!bss[NL80211_BSS_BSSID])
    return NL_SKIP;

  if (!bss[NL80211_BSS_STATUS])
    return NL_SKIP;

  mac_addr_n2a(mac_addr, nla_data(bss[NL80211_BSS_BSSID]));
  if_indextoname(nla_get_u32(tb[NL80211_ATTR_IFINDEX]), dev);

  printf("wireless.radios.%s.bssid: %s\n", dev, mac_addr);
  memcpy(ctx->bssid, nla_data(bss[NL80211_BSS_BSSID]), 6);

  if (bss[NL80211_BSS_INFORMATION_ELEMENTS]) {
    unsigned char *ie = nla_data(bss[NL80211_BSS_INFORMATION_ELEMENTS]);
    int ielen = nla_len(bss[NL80211_BSS_INFORMATION_ELEMENTS]);
    while (ielen >= 2 && ielen >= ie[1]) {
      // ie[0] is type
      // ie[1] is length
      // ie[2..] is data
      if (ie[0] == 0 && !ctx->found_essid) {
        // SSID
        printf("wireless.radios.%s.essid: ", dev);
        print_ssid_escaped(ie[1], ie + 2);
        printf("\n");
      }

      ielen -= ie[1] + 2;
      ie += ie[1] + 2;
    }
  }

  return NL_SKIP;
}

static int interface_info_handler(struct nl_msg *msg, void *arg)
{
  struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
  struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];
  struct interface_context *ctx = arg;
  char *iface_name;

  nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

  if (tb_msg[NL80211_ATTR_IFNAME])
    iface_name = strdup(nla_get_string(tb_msg[NL80211_ATTR_IFNAME]));
  else
    return NL_SKIP;

  memset(ctx->dev, 0, sizeof(ctx->dev));
  strncpy(ctx->dev, iface_name, 19);

  if (tb_msg[NL80211_ATTR_MAC]) {
    char mac_addr[20];
    mac_addr_n2a(mac_addr, nla_data(tb_msg[NL80211_ATTR_MAC]));
    printf("wireless.radios.%s.mac: %s\n", iface_name, mac_addr);
  }
  if (tb_msg[NL80211_ATTR_SSID]) {
    printf("wireless.radios.%s.essid: ", iface_name);
    print_ssid_escaped(nla_len(tb_msg[NL80211_ATTR_SSID]),
           nla_data(tb_msg[NL80211_ATTR_SSID]));
    printf("\n");
    ctx->found_essid = true;
  }
  if (tb_msg[NL80211_ATTR_IFTYPE]) {
    enum nl80211_iftype iftype = nla_get_u32(tb_msg[NL80211_ATTR_IFTYPE]);
    printf("wireless.radios.%s.mode: %s\n", iface_name, iftype_name(iftype));
  }
  if (tb_msg[NL80211_ATTR_WIPHY]) {
    ctx->phy_id = nla_get_u32(tb_msg[NL80211_ATTR_WIPHY]);
    printf("wireless.radios.%s.phy: phy%d\n", iface_name, ctx->phy_id);
  }

  if (tb_msg[NL80211_ATTR_WIPHY_FREQ]) {
    uint32_t freq = nla_get_u32(tb_msg[NL80211_ATTR_WIPHY_FREQ]);

    printf("wireless.radios.%s.channel: %d\n", iface_name, ieee80211_frequency_to_channel(freq));
    printf("wireless.radios.%s.frequency: %d\n", iface_name, freq);

    if (tb_msg[NL80211_ATTR_CHANNEL_WIDTH]) {
      printf("wireless.radios.%s.channel_width: %s\n", iface_name,
        channel_width_name(nla_get_u32(tb_msg[NL80211_ATTR_CHANNEL_WIDTH])));
    } else if (tb_msg[NL80211_ATTR_WIPHY_CHANNEL_TYPE]) {
      enum nl80211_channel_type channel_type;

      channel_type = nla_get_u32(tb_msg[NL80211_ATTR_WIPHY_CHANNEL_TYPE]);
      printf("wireless.radios.%s.channel_width: %s\n", iface_name, channel_type_name(channel_type));
    }
  }

  free(iface_name);
  return NL_SKIP;
}

int link_sta_msg_setup(struct nl_msg *msg, void *arg)
{
  struct interface_context *ctx = arg;
  NLA_PUT(msg, NL80211_ATTR_MAC, ETH_ALEN, ctx->bssid);
  return 0;
nla_put_failure:
  return -ENOBUFS;
}

void parse_bitrate(struct nlattr *bitrate_attr, char *buf, int buflen)
{
  int rate = 0;
  char *pos = buf;
  struct nlattr *rinfo[NL80211_RATE_INFO_MAX + 1];
  static struct nla_policy rate_policy[NL80211_RATE_INFO_MAX + 1] = {
    [NL80211_RATE_INFO_BITRATE] = { .type = NLA_U16 },
    [NL80211_RATE_INFO_BITRATE32] = { .type = NLA_U32 },
    [NL80211_RATE_INFO_MCS] = { .type = NLA_U8 },
    [NL80211_RATE_INFO_40_MHZ_WIDTH] = { .type = NLA_FLAG },
    [NL80211_RATE_INFO_SHORT_GI] = { .type = NLA_FLAG },
  };

  if (nla_parse_nested(rinfo, NL80211_RATE_INFO_MAX,
           bitrate_attr, rate_policy)) {
    return;
  }

  if (rinfo[NL80211_RATE_INFO_BITRATE32])
    rate = nla_get_u32(rinfo[NL80211_RATE_INFO_BITRATE32]);
  else if (rinfo[NL80211_RATE_INFO_BITRATE])
    rate = nla_get_u16(rinfo[NL80211_RATE_INFO_BITRATE]);
  if (rate > 0)
    pos += snprintf(pos, buflen - (pos - buf), "%d.%d", rate / 10, rate % 10);
}

static int link_sta_handler(struct nl_msg *msg, void *arg)
{
  struct nlattr *tb[NL80211_ATTR_MAX + 1];
  struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
  struct nlattr *sinfo[NL80211_STA_INFO_MAX + 1];
  struct nlattr *binfo[NL80211_STA_BSS_PARAM_MAX + 1];
  static struct nla_policy stats_policy[NL80211_STA_INFO_MAX + 1] = {
    [NL80211_STA_INFO_INACTIVE_TIME] = { .type = NLA_U32 },
    [NL80211_STA_INFO_RX_BYTES] = { .type = NLA_U32 },
    [NL80211_STA_INFO_TX_BYTES] = { .type = NLA_U32 },
    [NL80211_STA_INFO_RX_PACKETS] = { .type = NLA_U32 },
    [NL80211_STA_INFO_TX_PACKETS] = { .type = NLA_U32 },
    [NL80211_STA_INFO_SIGNAL] = { .type = NLA_U8 },
    [NL80211_STA_INFO_TX_BITRATE] = { .type = NLA_NESTED },
    [NL80211_STA_INFO_LLID] = { .type = NLA_U16 },
    [NL80211_STA_INFO_PLID] = { .type = NLA_U16 },
    [NL80211_STA_INFO_PLINK_STATE] = { .type = NLA_U8 },
  };
  static struct nla_policy bss_policy[NL80211_STA_BSS_PARAM_MAX + 1] = {
    [NL80211_STA_BSS_PARAM_CTS_PROT] = { .type = NLA_FLAG },
    [NL80211_STA_BSS_PARAM_SHORT_PREAMBLE] = { .type = NLA_FLAG },
    [NL80211_STA_BSS_PARAM_SHORT_SLOT_TIME] = { .type = NLA_FLAG },
    [NL80211_STA_BSS_PARAM_DTIM_PERIOD] = { .type = NLA_U8 },
    [NL80211_STA_BSS_PARAM_BEACON_INTERVAL] = { .type = NLA_U16 },
  };

  nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
      genlmsg_attrlen(gnlh, 0), NULL);

  char dev[20];
  if_indextoname(nla_get_u32(tb[NL80211_ATTR_IFINDEX]), dev);

  if (!tb[NL80211_ATTR_STA_INFO])
    return NL_SKIP;
  if (nla_parse_nested(sinfo, NL80211_STA_INFO_MAX,
           tb[NL80211_ATTR_STA_INFO],
           stats_policy)) {
    return NL_SKIP;
  }

  if (sinfo[NL80211_STA_INFO_SIGNAL])
    printf("wireless.radios.%s.signal: %d\n", dev,
      (int8_t) nla_get_u8(sinfo[NL80211_STA_INFO_SIGNAL]));

  if (sinfo[NL80211_STA_INFO_TX_BITRATE]) {
    char buf[100];

    parse_bitrate(sinfo[NL80211_STA_INFO_TX_BITRATE], buf, sizeof(buf));
    printf("wireless.radios.%s.bitrate: %s\n", dev, buf);
  }

  return NL_SKIP;
}

static int interface_survey_handler(struct nl_msg *msg, void *arg)
{
  struct nlattr *tb[NL80211_ATTR_MAX + 1];
  struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
  struct nlattr *sinfo[NL80211_SURVEY_INFO_MAX + 1];
  char dev[20];

  static struct nla_policy survey_policy[NL80211_SURVEY_INFO_MAX + 1] = {
    [NL80211_SURVEY_INFO_FREQUENCY] = { .type = NLA_U32 },
    [NL80211_SURVEY_INFO_NOISE] = { .type = NLA_U8 },
  };

  nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
      genlmsg_attrlen(gnlh, 0), NULL);

  if_indextoname(nla_get_u32(tb[NL80211_ATTR_IFINDEX]), dev);

  if (!tb[NL80211_ATTR_SURVEY_INFO])
    return NL_SKIP;

  if (nla_parse_nested(sinfo, NL80211_SURVEY_INFO_MAX,
           tb[NL80211_ATTR_SURVEY_INFO],
           survey_policy)) {
    return NL_SKIP;
  }

  if (!sinfo[NL80211_SURVEY_INFO_IN_USE])
    return NL_SKIP;

  if (sinfo[NL80211_SURVEY_INFO_NOISE])
    printf("wireless.radios.%s.noise: %d\n", dev,
      (int8_t) nla_get_u8(sinfo[NL80211_SURVEY_INFO_NOISE]));
  if (sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME])
    printf("wireless.radios.%s.survey.time_active: %llu\n", dev,
      (unsigned long long) nla_get_u64(sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME]));
  if (sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME_BUSY])
    printf("wireless.radios.%s.survey.time_busy: %llu\n", dev,
      (unsigned long long)nla_get_u64(sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME_BUSY]));
  if (sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME_RX])
    printf("wireless.radios.%s.survey.time_rx: %llu\n", dev,
      (unsigned long long)nla_get_u64(sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME_RX]));
  if (sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME_TX])
    printf("wireless.radios.%s.survey.time_tx: %llu\n", dev,
      (unsigned long long)nla_get_u64(sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME_TX]));
  
  return NL_SKIP;
}

static int interface_phy_handler(struct nl_msg *msg, void *arg)
{
  struct nlattr *tb[NL80211_ATTR_MAX + 1];
  struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
  struct interface_context *ctx = arg;

  nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
      genlmsg_attrlen(gnlh, 0), NULL);

  if (tb[NL80211_ATTR_WIPHY_FRAG_THRESHOLD]) {
    unsigned int frag;
    frag = nla_get_u32(tb[NL80211_ATTR_WIPHY_FRAG_THRESHOLD]);
    if (frag != (unsigned int)-1)
      printf("wireless.radios.%s.frag_threshold: %d\n", ctx->dev, frag);
    else
      printf("wireless.radios.%s.frag_threshold: 0\n", ctx->dev);
  }

  if (tb[NL80211_ATTR_WIPHY_RTS_THRESHOLD]) {
    unsigned int rts;

    rts = nla_get_u32(tb[NL80211_ATTR_WIPHY_RTS_THRESHOLD]);
    if (rts != (unsigned int)-1)
      printf("wireless.radios.%s.rts_threshold: %d\n", ctx->dev, rts);
    else
      printf("wireless.radios.%s.rts_threshold: 0\n", ctx->dev);
  }

  return NL_SKIP;
}

static int request_info(struct nl80211_state *state, signed long long devidx, enum nl80211_commands cmd,
                        int nl_msg_flags, nl_recvmsg_msg_cb_t handler, void *arg,
                        msg_cb_t msg_setup, int phy)
{
  int err;
  struct nl_cb *cb;
  struct nl_cb *s_cb;
  struct nl_msg *msg;

  msg = nlmsg_alloc();
  if (!msg) {
    fprintf(stderr, "ERROR: Failed to allocate netlink message.\n");
    return 2;
  }

  cb = nl_cb_alloc(NL_CB_DEFAULT);
  s_cb = nl_cb_alloc(NL_CB_DEFAULT);
  if (!cb || !s_cb) {
    fprintf(stderr, "ERROR: Failed to allocate netlink callbacks.\n");
    err = 2;
    goto out_free_msg;
  }

  genlmsg_put(msg, 0, 0, state->nl80211_id, 0, nl_msg_flags, cmd, 0);
  
  if (phy == 0)
    NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, devidx);
  else
    NLA_PUT_U32(msg, NL80211_ATTR_WIPHY, devidx);

  if (msg_setup != NULL) {
    err = msg_setup(msg, arg);
    if (err != 0)
      goto out_free_msg;
  }

  nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, handler, arg);

  nl_socket_set_cb(state->nl_sock, s_cb);

  err = nl_send_auto_complete(state->nl_sock, msg);
  if (err < 0)
    goto out;

  err = 1;

  nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
  nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
  nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);

  while (err > 0)
    nl_recvmsgs(state->nl_sock, cb);
out:
  nl_cb_put(cb);
out_free_msg:
  nlmsg_free(msg);
  return err;
nla_put_failure:
  return 2;
}

/**
 * Entry point.
 */
int main(int argc, char **argv)
{
  struct nl80211_state nlstate;
  int err;
  signed long long devidx;

  if (argc != 2) {
    fprintf(stderr, "ERROR: Missing interface name!\n");
    return 1;
  }

  devidx = if_nametoindex(argv[1]);
  if (devidx == 0) {
    fprintf(stderr, "ERROR: Interface '%s' does not exist!\n", argv[1]);
    return 1;
  }

  err = nl80211_init(&nlstate);
  if (err)
    return 1;

  struct interface_context ctx;
  ctx.found_essid = false;

  // Obtain general interface information
  request_info(&nlstate, devidx, NL80211_CMD_GET_INTERFACE, 0, interface_info_handler, &ctx, NULL, 0);

  // Obtain link information (when connected to some ap or in ibss mode)
  request_info(&nlstate, devidx, NL80211_CMD_GET_SCAN, NLM_F_DUMP, link_bss_handler, &ctx, NULL, 0);

  // Obtain additional link information
  request_info(&nlstate, devidx, NL80211_CMD_GET_STATION, 0, link_sta_handler, &ctx, link_sta_msg_setup, 0);

  // Obtain channel survey information
  request_info(&nlstate, devidx, NL80211_CMD_GET_SURVEY, NLM_F_DUMP, interface_survey_handler, &ctx, NULL, 0);

  // Obtain phy information
  request_info(&nlstate, ctx.phy_id, NL80211_CMD_GET_WIPHY, 0, interface_phy_handler, &ctx, NULL, 1);

  nl80211_cleanup(&nlstate);

  return 0;
}