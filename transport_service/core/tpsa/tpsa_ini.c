/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: tpsa ini file interface
 * Author: Chen Wen
 * Create: 2022-08-25
 * Note:
 * History:
 */

#include <arpa/inet.h>

#include "tpsa_log.h"
#include "tpsa_net.h"
#include "tpsa_ini.h"

#define TPSA_MAX_CURRENT_ERR 5
#define TPSA_MAX_ENDS 2
#define TPSA_ETC_MAX_LINE 256
#define TPSA_ETC_MAX_ENTRY 512
#define TPSA_MAX_SAFETY_LOOPS 1000
#define TPSA_HEX  (16)
#define TPSA_IPV4_MAP_IPV6_PREFIX (0x0000ffff)

static int tpsa_etc_locate_section(FILE *fp, const char *pSection, FILE *bak_fp);
static int tpsa_etc_locate_key_value(FILE *fp, const char *pKey, char *pValue, size_t len, FILE *bak_fp);
static char *tpsa_get_section_name(char *section_line, size_t section_len);
static int tpsa_get_key_value(char *key_line, char **mykey, char **myvalue, char delimiter);
static int tpsa_get_kv_check_para(const char *key_line, const char **mykey, const char **myvalue);

/*
 * @brief reads a value of a key in a section
 */
int tpsa_read_value_by_etc_file(file_info_t *file, char *pValue, size_t len)
{
    FILE *fp;

    char *absolute_path;
    absolute_path = realpath(file->path, NULL);
    if (absolute_path == NULL) {
        return TPSA_ETC_FILENOTFOUND;
    }

    if (!(fp = fopen(absolute_path, "r"))) {
        free(absolute_path);
        return TPSA_ETC_FILENOTFOUND;
    }
    if (tpsa_etc_locate_section(fp, file->section, NULL) != TPSA_ETC_OK) {
        (void)fclose(fp);
        free(absolute_path);
        return TPSA_ETC_SECTIONNOTFOUND;
    }
    if (tpsa_etc_locate_key_value(fp, file->key, pValue, len, NULL) != TPSA_ETC_OK) {
        (void)fclose(fp);
        free(absolute_path);
        return TPSA_ETC_KEYNOTFOUND;
    }

    (void)fclose(fp);
    free(absolute_path);
    return TPSA_ETC_OK;
}

/*
 * @brief locate a section by name
 */
static int tpsa_etc_locate_section(FILE *fp, const char *pSection, FILE *bak_fp)
{
    char szBuff[TPSA_ETC_MAX_LINE];
    char *name = NULL;

    int max_safety_loops = 0;
    while (max_safety_loops < TPSA_MAX_SAFETY_LOOPS) {
        if (!fgets(szBuff, TPSA_ETC_MAX_LINE, fp)) {
            if (feof(fp) != 0) {
                return TPSA_ETC_SECTIONNOTFOUND;
            } else {
                return TPSA_ETC_FILEIOFAILED;
            }
        } else if (bak_fp && fputs(szBuff, bak_fp) == EOF) {
            return TPSA_ETC_FILEIOFAILED;
        }

        name = tpsa_get_section_name(szBuff, strlen(szBuff));
        if (!name) {
            continue;
        }

        if (strcmp(name, pSection) == 0) {
            return TPSA_ETC_OK;
        }
        max_safety_loops++;
    }

    return TPSA_ETC_SECTIONNOTFOUND;
}

/*
 * @brief locate a specified key in the etc file.
 */
static int tpsa_etc_locate_key_value(FILE *fp, const char *pKey, char *pValue, size_t len, FILE *bak_fp)
{
    char szBuff[TPSA_ETC_MAX_LINE + 1 + 1];
    char *current = NULL;
    char *value = NULL;
    int ret;

    int max_safety_loops = 0;
    while (max_safety_loops < TPSA_MAX_SAFETY_LOOPS) {
        int bufflen;

        if (!fgets(szBuff, TPSA_ETC_MAX_LINE, fp)) {
            return TPSA_ETC_FILEIOFAILED;
        }
        bufflen = (int)strlen(szBuff);
        if (bufflen <= 0 || bufflen > TPSA_ETC_MAX_LINE) {
            return TPSA_ETC_KEYNOTFOUND;
        }
        if (szBuff[bufflen - 1] == '\n') {
            szBuff[bufflen - 1] = '\0';
        }

        ret = tpsa_get_key_value(szBuff, &current, &value, '=');
        if (ret < 0) {
            continue;
        } else if (ret > 0) {
            (void)fseek(fp, -bufflen, SEEK_CUR);
            return TPSA_ETC_KEYNOTFOUND;
        }

        if (strcmp(current, pKey) == 0) {
            if (pValue) {
                (void)strncpy(pValue, value, len - 1);
            }
            return TPSA_ETC_OK;
        } else if (bak_fp && *current != '\0') {
            if (value && strlen(value) >= 1) {
                (void)fprintf(bak_fp, "%s=%s\n", current, value);
            }
        }
        max_safety_loops++;
    }

    return TPSA_ETC_KEYNOTFOUND;
}

static char *tpsa_get_section_name(char *section_line, size_t section_len)
{
    char *name = NULL;
    size_t i = 0;

    if (!section_line) {
        return NULL;
    }

    while ((i < section_len) && (section_line[i] == ' ' || section_line[i] == '\t')) {
        i++;
    }

    if (section_line[i] == ';' || section_line[i] == '#') {
        return NULL;
    }

    if (section_line[i++] == '[') {
        while (section_line[i] == ' ' || section_line[i] == '\t') {
            i++;
        }
    } else {
        return NULL;
    }

    name = section_line + i;
    while ((i < section_len) && section_line[i] != ']' && section_line[i] != '\n' && section_line[i] != ';' &&
        section_line[i] != '#' && section_line[i] != '\0') {
        i++;
    }
    section_line[i] = '\0';
    while (section_line[i] == ' ' || section_line[i] == '\t') {
        section_line[i] = '\0';
        i--;
    }

    return name;
}

static bool tpsa_is_valid_kv(char current)
{
    char err[TPSA_MAX_CURRENT_ERR] = {';', '#', '\n', '\0', ','};
    int i;

    for (i = 0; i < TPSA_MAX_CURRENT_ERR; i++) {
        if (current == err[i]) {
            return false;
        }
    }
    return true;
}

static bool tpsa_is_end_of_value(char current, bool array)
{
    char ends[TPSA_MAX_ENDS] = {'\n', '\0'};
    int i;

    for (i = 0; i < TPSA_MAX_ENDS; i++) {
        if (current == ends[i]) {
            return true;
        }
    }
    if (!array) {
        return current == ',';
    } else {
        return current == ']';
    }
}

static int tpsa_get_key_value(char *key_line, char **mykey, char **myvalue, char delimiter)
{
    char *current = NULL;
    char *tail = NULL;
    char *value = NULL;

    if (tpsa_get_kv_check_para((const char *)key_line, (const char **)mykey, (const char **)myvalue) != 0) {
        return -1;
    }

    /* First, get key */
    current = key_line;

    while (*current == ' ' || *current == '\t') {
        current++;
    }

    if (!tpsa_is_valid_kv(*current)) {
        return -1;
    }

    if (*current == '[') {
        return 1;
    }

    /* Second, get value */
    tail = current;
    while (*tail != delimiter && tpsa_is_valid_kv(*tail)) {
        tail++;
    }
    if (*tail == '\0') {
        return -1;
    }

    value = tail + 1;
    if (*tail != delimiter) {
        *value = '\0';
    }

    /* Skip '' in the head of value */
    while (*value == ' ') {
        value++;
    }

    /* Pend \0 to the key string */
    *tail = '\0';
    if (strlen(current) == 0) {
        return -1;
    }
    tail--;
    while (*tail == ' ' || *tail == '\t') {
        *tail = '\0';
        tail--;
    }

    /* Pend \0 to the value string */
    tail = value;
    while (!tpsa_is_end_of_value(*tail, *value == '[')) {
        tail++;
    }
    *tail = '\0';

    *mykey = current;
    *myvalue = (*value == '[' ? value + 1 : value);

    return 0;
}

static int tpsa_get_kv_check_para(const char *key_line, const char **mykey, const char **myvalue)
{
    if (key_line == NULL || mykey == NULL || myvalue == NULL) {
        return -1;
    }
    return 0;
}

static int tpsa_read_line(FILE *fp, char szBuff[TPSA_ETC_MAX_LINE])
{
    int bufflen;

    if (!fgets(szBuff, TPSA_ETC_MAX_LINE, fp)) {
        if (feof(fp) != 0) {
            return TPSA_ETC_EOF;
        } else {
            return TPSA_ETC_FILEIOFAILED;
        }
    }
    bufflen = (int)strlen(szBuff);
    if (bufflen <= 0 || bufflen > TPSA_ETC_MAX_LINE) {
        return TPSA_ETC_INVALIDOBJ;
    }
    if (szBuff[bufflen - 1] == '\n') {
        szBuff[bufflen - 1] = '\0';
        bufflen--;
    }
    if (szBuff[0] == '#') {
        return tpsa_read_line(fp, szBuff);
    }
    return bufflen;
}


static int tpsa_parse_netaddrs(char *str, tpsa_underlay_info_t *info)
{
    char *p, *next;
    char seps[] = ", ";

    char *net_p, *net_next;
    char net_seps[] = "-";

    char *mac_p, *mac_next;
    char mac_seps[] = ":";
    int i;
    urma_eid_t *eid;

    info->netaddr_cnt = 0;
    p = strtok_r(str, seps, &next);
    while (p != NULL) {
        if (info->netaddr_cnt >= TPSA_MAX_NETADDR_CNT) {
            TPSA_LOG_ERR("There can be at most %d netaddrs in a map entry", TPSA_MAX_NETADDR_CNT);
            return -1;
        }
        /* fill eid */
        net_p = strtok_r(p, net_seps, &net_next);
        if (net_p == NULL || str_to_eid(net_p, &info->netaddr[info->netaddr_cnt].eid) != 0) {
            return -1;
        }
        eid = &info->netaddr[info->netaddr_cnt].eid;
        if (eid->in4.reserved == 0 && eid->in4.prefix == htonl(TPSA_IPV4_MAP_IPV6_PREFIX)) {
            info->netaddr[info->netaddr_cnt].type = TPSA_NET_ADDR_TYPE_IPV4;
        } else {
            info->netaddr[info->netaddr_cnt].type = TPSA_NET_ADDR_TYPE_IPV6;
        }
        net_p = strtok_r(NULL, net_seps, &net_next);
        if (net_p == NULL) {
            return -1;
        }
        /* fill mac addr */
        mac_p = net_p;
        mac_p = strtok_r(mac_p, mac_seps, &mac_next);
        for (i = 0; i < TPSA_MAC_BYTES; i++) {
            if (mac_p != NULL) {
                info->netaddr[info->netaddr_cnt].mac[i] = strtoul(mac_p, NULL, TPSA_HEX);
            }
            mac_p = strtok_r(NULL, mac_seps, &mac_next);
        }
        /* fill vlan */
        net_p = strtok_r(NULL, net_seps, &net_next);
        if (net_p == NULL || ub_str_to_u64(net_p, &info->netaddr[info->netaddr_cnt].vlan) != 0) {
            return -1;
        }
        info->netaddr_cnt++;
        p = strtok_r(NULL, seps, &next);
    }
    return 0;
}

typedef struct tpsa_map_table_parser {
    char *match;
    int (*cb)(char *value, urma_eid_t *eid, tpsa_underlay_info_t *info);
} tpsa_map_tbl_parser_t;

static int tpsa_map_tbl_parse_key(char *value, urma_eid_t *eid, tpsa_underlay_info_t *info)
{
    return str_to_eid(value, eid);
}

static int tpsa_map_tbl_parse_peer_tps(char *value, urma_eid_t *eid, tpsa_underlay_info_t *info)
{
    return str_to_eid(value, &info->peer_tps);
}

static int tpsa_map_tbl_parse_spray_en(char *value, urma_eid_t *eid, tpsa_underlay_info_t *info)
{
    uint64_t tmp;
    int ret;

    ret = ub_str_to_u64(value, &tmp);
    info->cfg.flag.bs.spray_en = tmp > 0 ? 1 : 0;

    return ret;
}

static int tpsa_map_tbl_parse_oor_en(char *value, urma_eid_t *eid, tpsa_underlay_info_t *info)
{
    uint64_t tmp;
    int ret;

    ret = ub_str_to_u64(value, &tmp);
    info->cfg.flag.bs.oor_en = tmp > 0 ? 1 : 0;

    return ret;
}

static int tpsa_map_tbl_parse_sr_en(char *value, urma_eid_t *eid, tpsa_underlay_info_t *info)
{
    uint64_t tmp;
    int ret;

    ret = ub_str_to_u64(value, &tmp);
    info->cfg.flag.bs.sr_en = tmp > 0 ? 1 : 0;

    return ret;
}

static int tpsa_map_tbl_parse_data_rctp_start(char *value, urma_eid_t *eid, tpsa_underlay_info_t *info)
{
    return ub_str_to_u16(value, &info->cfg.data_rctp_start);
}

static int tpsa_map_tbl_parse_ack_rctp_start(char *value, urma_eid_t *eid, tpsa_underlay_info_t *info)
{
    return ub_str_to_u16(value, &info->cfg.ack_rctp_start);
}

static int tpsa_map_tbl_parse_data_rmtp_start(char *value, urma_eid_t *eid, tpsa_underlay_info_t *info)
{
    return ub_str_to_u16(value, &info->cfg.data_rmtp_start);
}

static int tpsa_map_tbl_parse_ack_rmtp_start(char *value, urma_eid_t *eid, tpsa_underlay_info_t *info)
{
    return ub_str_to_u16(value, &info->cfg.ack_rmtp_start);
}

static int tpsa_map_tbl_parse_tp_range(char *value, urma_eid_t *eid, tpsa_underlay_info_t *info)
{
    return ub_str_to_u8(value,  &info->cfg.udp_range);
}

static int tpsa_map_tbl_parse_tp_cc_en(char *value, urma_eid_t *eid, tpsa_underlay_info_t *info)
{
    uint64_t tmp;
    int ret;

    ret = ub_str_to_u64(value, &tmp);
    info->cfg.flag.bs.cc_en = tmp > 0 ? 1 : 0;

    return ret;
}

static int tpsa_map_tbl_parse_underlay_eid(char *value, urma_eid_t *eid, tpsa_underlay_info_t *info)
{
    return str_to_eid(value, &info->eid);
}

static int tpsa_map_tbl_parse_netaddr(char *value, urma_eid_t *eid, tpsa_underlay_info_t *info)
{
    return tpsa_parse_netaddrs(value, info);
}

const static tpsa_map_tbl_parser_t g_map_tbl_parser[] = {
    [TPSA_MAP_TBL_KEY] = {"eid", tpsa_map_tbl_parse_key},
    [TPSA_MAP_TBL_PEER_TPS] = {"peer_tps", tpsa_map_tbl_parse_peer_tps},
    [TPSA_MAP_TBL_APRAY_EN] = {"spray_en", tpsa_map_tbl_parse_spray_en},
    [TPSA_MAP_TBL_OOR_EN] = {"oor_en", tpsa_map_tbl_parse_oor_en},
    [TPSA_MAP_TBL_SR_EN] = {"sr_en", tpsa_map_tbl_parse_sr_en},
    [TPSA_MAP_TBL_RCTP_START] = {"data_rctp_start", tpsa_map_tbl_parse_data_rctp_start},
    [TPSA_MAP_TBL_ACK_RCTP_START] = {"ack_rctp_start", tpsa_map_tbl_parse_ack_rctp_start},
    [TPSA_MAP_TBL_RMTP_START] = {"data_rmtp_start", tpsa_map_tbl_parse_data_rmtp_start},
    [TPSA_MAP_TBL_ACK_RMTP_START] = {"ack_rmtp_start", tpsa_map_tbl_parse_ack_rmtp_start},
    [TPSA_MAP_TBL_TP_RANGE] = {"udp_range", tpsa_map_tbl_parse_tp_range},
    [TPSA_MAP_TBL_TP_CC_EN] = {"cc_en", tpsa_map_tbl_parse_tp_cc_en},
    [TPSA_MAP_TBL_UNDERLAY_EID] = {"underlay_eid", tpsa_map_tbl_parse_underlay_eid},
    [TPSA_MAP_TBL_NETADDR] = {"underlay_netaddr", tpsa_map_tbl_parse_netaddr},
};

static int tpsa_parse_map_entry_kv(char *key, char *value, urma_eid_t *eid, tpsa_underlay_info_t *info,
    bool parsed[TPSA_MAP_TBL_MAX])
{
    int i;

    for (i = 0; i < TPSA_MAP_TBL_MAX; i++) {
        if (strcmp(key, g_map_tbl_parser[i].match) == 0) {
            break;
        }
    }
    if (i == TPSA_MAP_TBL_MAX) {
        return -1;
    }
    if (g_map_tbl_parser[i].cb(value, eid, info) != 0) {
        TPSA_LOG_ERR("Failed to parse %s", g_map_tbl_parser[i].match);
        return -1;
    }
    parsed[i] = true;
    return 0;
}

static int tpsa_parse_add_map_entry(char *entry)
{
    urma_eid_t eid;
    tpsa_underlay_info_t *info = calloc(1, sizeof(tpsa_underlay_info_t) +
        TPSA_MAX_NETADDR_CNT * sizeof(tpsa_net_addr_t));
    if (info == NULL) {
        TPSA_LOG_INFO("Failed to calloc underlay info");
        return -1;
    }

    bool parsed[TPSA_MAP_TBL_MAX] = {0};
    char *p = entry, *key = NULL, *value = NULL;

    while (*p != '\n' && *p != '\0') {
        if (tpsa_get_key_value(p, &key, &value, ':') != 0) {
            TPSA_LOG_ERR("Failed to get key and value in the line: %s", entry);
            free(info);
            return -1;
        }
        p = value + strlen(value) + 1;
        if (tpsa_parse_map_entry_kv(key, value, &eid, info, parsed) != 0) {
            free(info);
            return -1;
        }
    }

    /* Validate match entry in the etc file */
    if (!parsed[TPSA_MAP_TBL_KEY] || !parsed[TPSA_MAP_TBL_NETADDR]) {
        TPSA_LOG_ERR("Key (i.e. eid) or netaddr is missing");
        free(info);
        return -1;
    }
    /* Set peer tps with underlay netaddr[0] if peer tps is missing */
    if (!parsed[TPSA_MAP_TBL_PEER_TPS]) {
        info->peer_tps = info->netaddr[0].eid;
    }
    /* Set under eid with underlay netaddr[0] if under eid is missing */
    if (!parsed[TPSA_MAP_TBL_UNDERLAY_EID]) {
        info->eid = info->netaddr[0].eid;
    }

    if (tpsa_add_underlay_info(&eid, info) != 0) {
        free(info);
        return -1;
    }
    free(info);
    return 0;
}

static int tpsa_parse_add_map_entries(FILE *fp)
{
    char szBuff[TPSA_ETC_MAX_LINE];
    char entry[TPSA_ETC_MAX_ENTRY] = {0};
    char *line;
    int max_safety_loops = 0;
    int cnt = 0;
    bool new_entry = false;

    while (max_safety_loops < TPSA_MAX_SAFETY_LOOPS) {
        int bufflen = tpsa_read_line(fp, szBuff);
        if (bufflen == 0) {
            continue;
        } else if (bufflen < 0) {
            break;
        }
        line = szBuff;
        /* Skip ' ' in the head of line */
        while (*line == ' ' && *(line + 1) == ' ') {
            line++;
            bufflen--;
        }

        if (line[0] == '{') {
            new_entry = true;
            continue;
        } else if (line[0] == '}') {
            if (tpsa_parse_add_map_entry(entry) != 0) {
                return TPSA_ETC_INVALIDOBJ;
            }
            cnt++;
            new_entry = false;
            entry[0] = '\0';
        }
        if (!new_entry) {
            continue;
        }
        (void)strcat(entry, line);
        max_safety_loops++;
    }
    if (cnt == 0) {
        TPSA_LOG_WARN("None underlay entry added");
    }
    return new_entry ? TPSA_ETC_INVALIDOBJ : TPSA_ETC_OK;
}

int tpsa_read_map_table(file_info_t *file)
{
    FILE *fp;
    char *absolute_path;
    absolute_path = realpath(file->path, NULL);
    if (absolute_path == NULL) {
        return TPSA_ETC_FILENOTFOUND;
    }

    if (!(fp = fopen(file->path, "r"))) {
        free(absolute_path);
        return TPSA_ETC_FILENOTFOUND;
    }

    if (tpsa_etc_locate_section(fp, "EID", NULL) != TPSA_ETC_OK) {
        (void)fclose(fp);
        free(absolute_path);
        TPSA_LOG_WARN("Failed to locate EID section");
        return TPSA_ETC_SECTIONNOTFOUND;
    }
    if (tpsa_parse_add_map_entries(fp) != TPSA_ETC_OK) {
        (void)fclose(fp);
        free(absolute_path);
        return TPSA_ETC_INVALIDOBJ;
    }

    (void)fclose(fp);
    free(absolute_path);
    return TPSA_ETC_OK;
}