#include <ftlib.h>

static const char* ftpaths[] = {
  [_FT_PATH_CFG_MAP] = SYSCONFDIR "/cfg/map.cfg",
  [_FT_PATH_CFG_TAG] = SYSCONFDIR "/cfg/tag.cfg",
  [_FT_PATH_CFG_FILTER] = SYSCONFDIR "/cfg/filter.cfg",
  [_FT_PATH_CFG_STAT] = SYSCONFDIR "/cfg/stat.cfg",
  [_FT_PATH_CFG_MASK] = SYSCONFDIR "/cfg/mask.cfg",
  [_FT_PATH_CFG_XLATE] = SYSCONFDIR "/cfg/xlate.cfg",

  [_FT_PATH_SYM_IP_PROT] = SYSCONFDIR "/sym/ip-prot.sym",
  [_FT_PATH_SYM_IP_TYPE] = SYSCONFDIR "/sym/ip-type.sym",
  [_FT_PATH_SYM_TCP_PORT] = SYSCONFDIR "/sym/tcp-port.sym",
  [_FT_PATH_SYM_ASN] = SYSCONFDIR "/sym/asn.sym",
  [_FT_PATH_SYM_TAG] = SYSCONFDIR "/sym/tag.sym"
};

const char *ft_get_path(enum ft_config_path pathid) {
  return ftpaths[pathid];
}
