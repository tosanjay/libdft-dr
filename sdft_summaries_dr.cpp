/*
 * sdft_summaries_dr.cpp -- DR port of libdft64/sdft_summaries.cpp (Phase 4).
 * Parser + table for libc_summaries.conf. Parsing logic is verbatim from the
 * Pin version; only I/O and logging are retargeted to DR (dr_open_file +
 * dr_read_file for the conf, dr_fprintf for diagnostics) to avoid the
 * private-loader stdio/iostream hazard.
 */
#include "sdft_summaries_dr.h"

#include "dr_api.h"

#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <map>

namespace sdft {

/* ---------- internal state ---------- */

static Policy s_policy = POLICY_OPTIMISTIC;
static std::map<std::string, Summary> s_funcs;
static std::vector<AliasRule> s_aliases;
static Summary s_conservative_default;

/* ---------- string utilities (verbatim) ---------- */

static void rstrip(std::string &s) {
    while (!s.empty()) {
        char c = s[s.size() - 1];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            s.erase(s.size() - 1);
        } else break;
    }
}

static void lstrip(std::string &s) {
    size_t i = 0;
    while (i < s.size() && (s[i] == ' ' || s[i] == '\t')) ++i;
    if (i > 0) s.erase(0, i);
}

static void strip(std::string &s) { rstrip(s); lstrip(s); }

static std::vector<std::string>
split_ws(const std::string &s) {
    std::vector<std::string> out;
    size_t i = 0;
    while (i < s.size()) {
        while (i < s.size() && (s[i] == ' ' || s[i] == '\t')) ++i;
        if (i >= s.size()) break;
        size_t j = i;
        while (j < s.size() && s[j] != ' ' && s[j] != '\t') ++j;
        out.push_back(s.substr(i, j - i));
        i = j;
    }
    return out;
}

static std::vector<int>
parse_csv_ints(const std::string &csv) {
    std::vector<int> out;
    size_t i = 0;
    while (i < csv.size()) {
        size_t j = i;
        while (j < csv.size() && csv[j] != ',') ++j;
        std::string tok = csv.substr(i, j - i);
        if (!tok.empty()) {
            out.push_back(std::atoi(tok.c_str()));
        }
        i = (j < csv.size()) ? j + 1 : j;
    }
    return out;
}

static bool split_kv(const std::string &kv,
                     std::string &key, std::string &val) {
    size_t eq = kv.find('=');
    if (eq == std::string::npos) return false;
    key = kv.substr(0, eq);
    val = kv.substr(eq + 1);
    return true;
}

static Ref parse_ref(const std::string &val) {
    Ref r;
    if (val == "ret") {
        r.kind = REF_RET;
    } else if (val == "strlen") {
        r.kind = REF_STRLEN;
    } else if (val == "wcslen") {
        r.kind = REF_WCSLEN;
    } else if (!val.empty() &&
               (val[0] == '-' || (val[0] >= '0' && val[0] <= '9'))) {
        int v = std::atoi(val.c_str());
        if (v >= 0 && v <= 5) {
            r.kind = REF_ARG;
            r.value = v;
        } else {
            r.kind = REF_LITERAL;
            r.value = v;
        }
    } else {
        dr_fprintf(STDERR, "[sdft] WARNING: unknown ref value '%s'\n",
                   val.c_str());
    }
    return r;
}

static bool glob_match(const std::string &pat, const std::string &name) {
    if (pat.empty()) return false;
    if (pat[pat.size() - 1] == '*') {
        std::string prefix = pat.substr(0, pat.size() - 1);
        if (name.size() < prefix.size()) return false;
        return std::strncmp(name.c_str(), prefix.c_str(), prefix.size()) == 0;
    }
    return pat == name;
}

/* ---------- directive parsers ---------- */

static void parse_policy(const std::vector<std::string> &toks) {
    if (toks.size() < 2) {
        dr_fprintf(STDERR, "[sdft] WARNING: POLICY missing value\n");
        return;
    }
    if (toks[1] == "optimistic") {
        s_policy = POLICY_OPTIMISTIC;
    } else if (toks[1] == "conservative") {
        s_policy = POLICY_CONSERVATIVE;
    } else {
        dr_fprintf(STDERR, "[sdft] WARNING: unknown POLICY '%s'\n",
                   toks[1].c_str());
    }
}

static void parse_alias(const std::vector<std::string> &toks) {
    if (toks.size() < 3) {
        dr_fprintf(STDERR, "[sdft] WARNING: ALIAS needs <pattern> <canonical>\n");
        return;
    }
    AliasRule r;
    r.pattern = toks[1];
    r.canonical = toks[2];
    s_aliases.push_back(r);
}

static bool parse_shape(const std::string &name, Summary &out) {
    if      (name == "SOURCE")             out.shape = SHAPE_SOURCE;
    else if (name == "SOURCE_RETURN_PTR")  out.shape = SHAPE_SOURCE_RET_PTR;
    else if (name == "PROP_PTR2PTR")       out.shape = SHAPE_PROP_PTR2PTR;
    else if (name == "PROP_PTR2VAL")       out.shape = SHAPE_PROP_PTR2VAL;
    else if (name == "PROP_SCALAR")        out.shape = SHAPE_PROP_SCALAR;
    else if (name == "CLOBBER_ONLY")       out.shape = SHAPE_CLOBBER_ONLY;
    else return false;
    return true;
}

static void parse_func(const std::vector<std::string> &toks) {
    if (toks.size() < 3) {
        dr_fprintf(STDERR, "[sdft] WARNING: FUNC needs <name> <shape>\n");
        return;
    }
    Summary s;
    if (!parse_shape(toks[2], s)) {
        dr_fprintf(STDERR, "[sdft] WARNING: FUNC %s unknown shape '%s'\n",
                   toks[1].c_str(), toks[2].c_str());
        return;
    }
    for (size_t i = 3; i < toks.size(); ++i) {
        std::string key, val;
        if (!split_kv(toks[i], key, val)) {
            if (!toks[i].empty() && toks[i][0] == '#') break;
            continue;
        }
        if (key == "buf") {
            s.buf = std::atoi(val.c_str());
        } else if (key == "len") {
            s.len = parse_ref(val);
        } else if (key == "dst") {
            s.dst = parse_ref(val);
        } else if (key == "src") {
            s.src = parse_csv_ints(val);
        } else if (key == "args") {
            s.args = parse_csv_ints(val);
        } else {
            dr_fprintf(STDERR, "[sdft] WARNING: FUNC %s unknown key '%s'\n",
                       toks[1].c_str(), key.c_str());
        }
    }
    s_funcs[toks[1]] = s;
}

/* Feed one already-stripped logical line to the directive parsers. */
static void parse_line(const std::string &raw, const std::string &conf_path,
                       size_t lineno) {
    std::string line = raw;
    strip(line);
    if (line.empty() || line[0] == '#') return;
    std::vector<std::string> toks = split_ws(line);
    if (toks.empty()) return;
    const std::string &kw = toks[0];
    if      (kw == "POLICY") parse_policy(toks);
    else if (kw == "ALIAS")  parse_alias(toks);
    else if (kw == "FUNC")   parse_func(toks);
    else {
        dr_fprintf(STDERR, "[sdft] WARNING: %s:%zu: unknown directive '%s'\n",
                   conf_path.c_str(), lineno, kw.c_str());
    }
}

/* ---------- public API ---------- */

bool load(const std::string &conf_path) {
    file_t f = dr_open_file(conf_path.c_str(), DR_FILE_READ);
    if (f == INVALID_FILE) {
        dr_fprintf(STDERR, "[sdft] ERROR: cannot open %s\n", conf_path.c_str());
        return false;
    }
    /* Slurp the whole conf (DR file API; no FILE* stdio). */
    std::string content;
    char buf[4096];
    ssize_t n;
    while ((n = dr_read_file(f, buf, sizeof(buf))) > 0)
        content.append(buf, (size_t)n);
    dr_close_file(f);

    size_t pos = 0, lineno = 0;
    while (pos <= content.size()) {
        size_t nl = content.find('\n', pos);
        size_t end = (nl == std::string::npos) ? content.size() : nl;
        ++lineno;
        parse_line(content.substr(pos, end - pos), conf_path, lineno);
        if (nl == std::string::npos) break;
        pos = nl + 1;
    }

    // Conservative default = PROP_PTR2VAL over args 0..5 (union into RAX).
    s_conservative_default.shape = SHAPE_PROP_PTR2VAL;
    s_conservative_default.src.clear();
    for (int i = 0; i < 6; ++i) s_conservative_default.src.push_back(i);

    dr_fprintf(STDERR, "[sdft] loaded %s: policy=%s funcs=%zu aliases=%zu\n",
               conf_path.c_str(),
               (s_policy == POLICY_OPTIMISTIC ? "optimistic" : "conservative"),
               s_funcs.size(), s_aliases.size());
    return true;
}

const Summary *find(const std::string &rtn_name) {
    std::map<std::string, Summary>::const_iterator it = s_funcs.find(rtn_name);
    if (it != s_funcs.end()) return &it->second;

    for (size_t i = 0; i < s_aliases.size(); ++i) {
        if (glob_match(s_aliases[i].pattern, rtn_name)) {
            std::map<std::string, Summary>::const_iterator it2 =
                s_funcs.find(s_aliases[i].canonical);
            if (it2 != s_funcs.end()) return &it2->second;
        }
    }

    if (s_policy == POLICY_CONSERVATIVE) return &s_conservative_default;
    return NULL;
}

Policy policy(void) { return s_policy; }
size_t func_count(void) { return s_funcs.size(); }
size_t alias_count(void) { return s_aliases.size(); }

void log_summary(void) {
    dr_fprintf(STDERR, "[sdft] summary table: policy=%s funcs=%zu aliases=%zu\n",
               (s_policy == POLICY_OPTIMISTIC ? "optimistic" : "conservative"),
               s_funcs.size(), s_aliases.size());
}

}  // namespace sdft
