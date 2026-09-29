/*
 * nuvio_account.c — see nuvio_account.h.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>

#include "nuvio_account.h"
#include "nuvio_json.h"
#include "evo_net.h"
#include "evo_provider_log.h"
#include "cJSON.h"

#define MAX_WAITERS 8

static struct {
    char    path[512];
    char    server[256];
    char    backend[512];
    char    key[640];
    char    link_page[256];     /* device-login approval page, optional */
    char    email[160];
    char    password[160];      /* in memory only until the first sign-in */
    char    refresh[512];
    char    access[2400];
    int64_t access_exp_ms;
    char    user_id[64];
    char    client_id[48];
    int     profile;
    char    status[160];

    int     ensuring;
    struct { nuvio_account_cb cb; void *ud; } waiters[MAX_WAITERS];
    int     waiter_count;
} A;

static int64_t now_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static void set_status(const char *s)
{
    snprintf(A.status, sizeof A.status, "%s", s);
    PROV_LOG("nuvio account: %s", s);
}

static void trim_slash(char *s)
{
    size_t n = strlen(s);
    while (n && s[n - 1] == '/') s[--n] = '\0';
}

/* ------------------------------------------------------------------------- */
/* Config                                                                    */
/* ------------------------------------------------------------------------- */

static void make_client_id(void)
{
    static const char ALPHA[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t x = ((uint64_t)tv.tv_sec << 20) ^ (uint64_t)tv.tv_usec ^
                 ((uint64_t)getpid() << 40) ^ 0x9E3779B97F4A7C15ull;
    int o = snprintf(A.client_id, sizeof A.client_id, "evo-ps5-");
    for (int i = 0; i < 32 && o + 1 < (int)sizeof A.client_id; ++i) {
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;          /* xorshift64 */
        A.client_id[o++] = ALPHA[x % (sizeof ALPHA - 1)];
    }
    A.client_id[o] = '\0';
}

static void save_conf(void)
{
    if (!A.path[0]) return;
    FILE *f = fopen(A.path, "w");
    if (!f) return;
    fprintf(f, "# Nuvio account for EVO. The password line is removed after the\n"
               "# first successful sign-in; the refresh token below replaces it.\n");
    if (A.server[0])    fprintf(f, "server=%s\n", A.server);
    if (A.backend[0])   fprintf(f, "backend_url=%s\n", A.backend);
    if (A.key[0])       fprintf(f, "publishable_key=%s\n", A.key);
    if (A.link_page[0]) fprintf(f, "link_page=%s\n", A.link_page);
    if (A.email[0])     fprintf(f, "email=%s\n", A.email);
    if (A.password[0] && !A.refresh[0])
                        fprintf(f, "password=%s\n", A.password);
    fprintf(f, "profile=%d\n", A.profile);
    if (A.refresh[0])   fprintf(f, "refresh_token=%s\n", A.refresh);
    if (A.user_id[0])   fprintf(f, "user_id=%s\n", A.user_id);
    fprintf(f, "client_id=%s\n", A.client_id);
    fclose(f);
}

static void link_reset(void);

void nuvio_account_init(const char *path)
{
    link_reset();
    int ensuring = A.ensuring;          /* a rebind must not strand waiters */
    memset(&A.server, 0, (size_t)((char *)&A.ensuring - (char *)&A.server));
    A.ensuring = ensuring;
    snprintf(A.path, sizeof A.path, "%s", path ? path : "");
    A.profile = 1;

    FILE *f = A.path[0] ? fopen(A.path, "r") : NULL;
    if (f) {
        char line[3072];
        while (fgets(line, sizeof line, f)) {
            line[strcspn(line, "\r\n")] = '\0';
            char *eq = strchr(line, '=');
            if (!eq || line[0] == '#') continue;
            *eq = '\0';
            const char *k = line, *v = eq + 1;
            if      (!strcmp(k, "server"))          snprintf(A.server,   sizeof A.server,   "%s", v);
            else if (!strcmp(k, "backend_url"))     snprintf(A.backend,  sizeof A.backend,  "%s", v);
            else if (!strcmp(k, "publishable_key")) snprintf(A.key,      sizeof A.key,      "%s", v);
            else if (!strcmp(k, "link_page"))       snprintf(A.link_page, sizeof A.link_page, "%s", v);
            else if (!strcmp(k, "email"))           snprintf(A.email,    sizeof A.email,    "%s", v);
            else if (!strcmp(k, "password"))        snprintf(A.password, sizeof A.password, "%s", v);
            else if (!strcmp(k, "refresh_token"))   snprintf(A.refresh,  sizeof A.refresh,  "%s", v);
            else if (!strcmp(k, "user_id"))         snprintf(A.user_id,  sizeof A.user_id,  "%s", v);
            else if (!strcmp(k, "client_id"))       snprintf(A.client_id, sizeof A.client_id, "%s", v);
            else if (!strcmp(k, "profile"))         A.profile = atoi(v) > 0 ? atoi(v) : 1;
        }
        fclose(f);
    }
    trim_slash(A.server);
    trim_slash(A.backend);
    if (!A.client_id[0]) make_client_id();
    set_status(nuvio_account_is_configured() ? "configured"
               : nuvio_account_can_link() ? "not signed in - link it from the Nuvio screen"
               : "not set up");
}

int nuvio_account_is_configured(void)
{
    int where = A.server[0] || (A.backend[0] && A.key[0]);
    int who   = A.refresh[0] || (A.email[0] && A.password[0]);
    return where && who;
}

int nuvio_account_has_session(void) { return A.refresh[0] != 0; }
const char *nuvio_account_status(void) { return A.status; }
int nuvio_account_profile(void) { return A.profile; }
const char *nuvio_account_client_id(void) { return A.client_id; }

/* ------------------------------------------------------------------------- */
/* Sign-in                                                                   */
/* ------------------------------------------------------------------------- */

static void ensure_done(int ok)
{
    A.ensuring = 0;
    int n = A.waiter_count;
    A.waiter_count = 0;
    /* Copy first: a callback may start another ensure. */
    struct { nuvio_account_cb cb; void *ud; } w[MAX_WAITERS];
    memcpy(w, A.waiters, sizeof w);
    for (int i = 0; i < n; ++i)
        if (w[i].cb) w[i].cb(ok, NULL, 0, w[i].ud);
}

static void apikey_hdr(char *out, size_t cap) { snprintf(out, cap, "apikey: %s", A.key); }

static void on_token(int ok, int status, const char *body, size_t len, void *ud);

static void request_token(int use_refresh)
{
    char url[640];
    snprintf(url, sizeof url, "%s/auth/v1/token?grant_type=%s", A.backend,
             use_refresh ? "refresh_token" : "password");

    nuvio_jw_t w;
    nuvio_jw_init(&w);
    nuvio_jw_obj(&w, NULL);
    if (use_refresh) {
        nuvio_jw_str(&w, "refresh_token", A.refresh);
    } else {
        nuvio_jw_str(&w, "email", A.email);
        nuvio_jw_str(&w, "password", A.password);
    }
    nuvio_jw_end_obj(&w);
    char *body = nuvio_jw_finish(&w);

    char ak[700];
    apikey_hdr(ak, sizeof ak);
    const char *h[1] = { ak };
    int rc = body ? evo_net_request_async("POST", url, body, h, 1, on_token,
                                          (void *)(intptr_t)use_refresh)
                  : -1;
    free(body);
    if (rc != 0) { set_status("could not reach the server"); ensure_done(0); }
}

/*
 * Take a GoTrue token response - the password and refresh grants, and the
 * tv-logins-exchange function, all answer in this shape - into the session.
 * Returns 1 if it held a usable session.
 */
static int store_tokens(const cJSON *r)
{
    const cJSON *at = cJSON_GetObjectItemCaseSensitive(r, "access_token");
    const cJSON *rt = cJSON_GetObjectItemCaseSensitive(r, "refresh_token");
    const cJSON *ex = cJSON_GetObjectItemCaseSensitive(r, "expires_in");
    const cJSON *user = cJSON_GetObjectItemCaseSensitive(r, "user");
    const cJSON *uid = cJSON_GetObjectItemCaseSensitive(user, "id");

    if (!cJSON_IsString(at) || !at->valuestring || !at->valuestring[0] ||
        !cJSON_IsString(rt) || !rt->valuestring || !rt->valuestring[0] ||
        strlen(at->valuestring) >= sizeof A.access || strlen(rt->valuestring) >= sizeof A.refresh)
        return 0;

    snprintf(A.access, sizeof A.access, "%s", at->valuestring);
    snprintf(A.refresh, sizeof A.refresh, "%s", rt->valuestring);
    int64_t secs = cJSON_IsNumber(ex) ? (int64_t)ex->valuedouble : 3600;
    A.access_exp_ms = now_ms() + secs * 1000;
    if (cJSON_IsString(uid) && uid->valuestring)
        snprintf(A.user_id, sizeof A.user_id, "%s", uid->valuestring);

    /* A password has done its job once there is a session; it does not stay
     * on disk. */
    A.password[0] = '\0';
    save_conf();
    return 1;
}

static void on_token(int ok, int status, const char *body, size_t len, void *ud)
{
    int was_refresh = (int)(intptr_t)ud;
    cJSON *r = (ok && body) ? cJSON_ParseWithLength(body, len) : NULL;
    int stored = store_tokens(r);
    cJSON_Delete(r);

    if (!stored) {
        if (was_refresh && A.email[0] && A.password[0]) {
            /* A refresh token can be revoked; the password, if we still have
             * it this session, is the way back in. */
            A.refresh[0] = '\0';
            request_token(0);
            return;
        }
        char s[96];
        snprintf(s, sizeof s, "sign-in failed (HTTP %d)", status);
        set_status(s);
        if (was_refresh) A.refresh[0] = '\0';
        save_conf();
        ensure_done(0);
        return;
    }
    set_status("signed in");
    ensure_done(1);
}

static void sign_in(void)
{
    if (A.refresh[0])                       request_token(1);
    else if (A.email[0] && A.password[0])   request_token(0);
    else { set_status("no credentials - add email= and password= to account.conf"); ensure_done(0); }
}

/* NuvioTV's ServerDiscoveryPolicy.parse: version 1, service "nuvio", an
 * http(s) backend and a key. Returns 1 and adopts them if the document is
 * good. */
static int apply_discovery(int ok, const char *body, size_t len)
{
    cJSON *r = (ok && body) ? cJSON_ParseWithLength(body, len) : NULL;
    const cJSON *ver = cJSON_GetObjectItemCaseSensitive(r, "version");
    const cJSON *svc = cJSON_GetObjectItemCaseSensitive(r, "service");
    const cJSON *bu  = cJSON_GetObjectItemCaseSensitive(r, "backend_url");
    const cJSON *pk  = cJSON_GetObjectItemCaseSensitive(r, "publishable_key");
    int good = cJSON_IsNumber(ver) && (int)ver->valuedouble == 1 &&
               cJSON_IsString(svc) && svc->valuestring &&
               (!strcmp(svc->valuestring, "nuvio") || !strcmp(svc->valuestring, "Nuvio")) &&
               cJSON_IsString(bu) && bu->valuestring &&
               (!strncmp(bu->valuestring, "https://", 8) || !strncmp(bu->valuestring, "http://", 7)) &&
               cJSON_IsString(pk) && pk->valuestring && pk->valuestring[0];
    if (good) {
        snprintf(A.backend, sizeof A.backend, "%s", bu->valuestring);
        snprintf(A.key, sizeof A.key, "%s", pk->valuestring);
        trim_slash(A.backend);
        save_conf();
    }
    cJSON_Delete(r);
    return good;
}

static void discovery_url(char *url, size_t cap)
{
    if (!strncmp(A.server, "http://", 7) || !strncmp(A.server, "https://", 8))
        snprintf(url, cap, "%s/.well-known/nuvio", A.server);
    else
        snprintf(url, cap, "https://%s/.well-known/nuvio", A.server);
}

static void on_discovery(int ok, int status, const char *body, size_t len, void *ud)
{
    (void)ud;
    if (!apply_discovery(ok, body, len)) {
        char s[96];
        snprintf(s, sizeof s, "server discovery failed (HTTP %d)", status);
        set_status(s);
        ensure_done(0);
        return;
    }
    sign_in();
}

int nuvio_account_ensure(nuvio_account_cb cb, void *ud)
{
    if (!nuvio_account_is_configured()) return -1;
    if (A.access[0] && now_ms() < A.access_exp_ms - 60 * 1000) {
        if (cb) cb(1, NULL, 0, ud);
        return 0;
    }
    if (A.waiter_count >= MAX_WAITERS) return -2;
    A.waiters[A.waiter_count].cb = cb;
    A.waiters[A.waiter_count].ud = ud;
    A.waiter_count++;
    if (A.ensuring) return 0;
    A.ensuring = 1;

    if (!A.backend[0] || !A.key[0]) {
        char url[320];
        discovery_url(url, sizeof url);
        if (evo_net_request_async("GET", url, NULL, NULL, 0, on_discovery, NULL) != 0) {
            set_status("could not reach the server");
            A.waiter_count--;
            A.ensuring = 0;
            return -3;
        }
        return 0;
    }
    sign_in();
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Authenticated requests                                                    */
/* ------------------------------------------------------------------------- */

typedef struct req {
    char  method[8];
    char  path[1024];     /* after /rest/v1/ */
    char *body;
    int   retried;
    nuvio_account_cb cb;
    void *ud;
} req_t;

static void req_finish(req_t *q, int ok, const char *body, size_t len)
{
    nuvio_account_cb cb = q->cb;
    void *ud = q->ud;
    free(q->body);
    free(q);
    if (cb) cb(ok, body, len, ud);
}

static void on_ready(int ok, const char *b, size_t l, void *ud);

static void on_req(int ok, int status, const char *body, size_t len, void *ud)
{
    req_t *q = (req_t *)ud;
    if (!ok && status == 401 && !q->retried) {
        /* The JWT expired under us: drop it, refresh once, and go again. */
        q->retried = 1;
        A.access[0] = '\0';
        A.access_exp_ms = 0;
        if (nuvio_account_ensure(on_ready, q) != 0) req_finish(q, 0, NULL, 0);
        return;
    }
    if (!ok) PROV_LOG("nuvio account: %s %s -> HTTP %d", q->method, q->path, status);
    req_finish(q, ok, body, len);
}

static void req_send(req_t *q)
{
    char url[1700];
    snprintf(url, sizeof url, "%s/rest/v1/%s", A.backend, q->path);
    char ak[700], auth[2500];
    apikey_hdr(ak, sizeof ak);
    snprintf(auth, sizeof auth, "Authorization: Bearer %s", A.access);
    const char *h[3] = { ak, auth, "Accept: application/json" };
    if (evo_net_request_async(q->method, url, q->body, h, 3, on_req, q) != 0)
        req_finish(q, 0, NULL, 0);
}

static void on_ready(int ok, const char *b, size_t l, void *ud)
{
    (void)b; (void)l;
    req_t *q = (req_t *)ud;
    if (!ok) { req_finish(q, 0, NULL, 0); return; }
    req_send(q);
}

static int start_req(const char *method, const char *path, const char *body,
                     nuvio_account_cb cb, void *ud)
{
    if (!nuvio_account_is_configured() || strlen(path) >= sizeof(((req_t *)0)->path))
        return -1;
    req_t *q = (req_t *)calloc(1, sizeof *q);
    if (!q) return -2;
    snprintf(q->method, sizeof q->method, "%s", method);
    snprintf(q->path, sizeof q->path, "%s", path);
    if (body) {
        size_t n = strlen(body) + 1;
        q->body = (char *)malloc(n);
        if (!q->body) { free(q); return -2; }
        memcpy(q->body, body, n);
    }
    q->cb = cb;
    q->ud = ud;
    if (nuvio_account_ensure(on_ready, q) != 0) {
        free(q->body);
        free(q);
        return -3;
    }
    return 0;
}

int nuvio_account_rpc(const char *name, const char *json_body,
                      nuvio_account_cb cb, void *ud)
{
    char path[160];
    snprintf(path, sizeof path, "rpc/%s", name);
    return start_req("POST", path, json_body ? json_body : "{}", cb, ud);
}

int nuvio_account_select(const char *path_and_query, nuvio_account_cb cb, void *ud)
{
    return start_req("GET", path_and_query, NULL, cb, ud);
}

/* ------------------------------------------------------------------------- */
/* Device login: a code on the TV, approved on a phone                      */
/* ------------------------------------------------------------------------- */
/*
 * NuvioTV's QR login without the QR (AccountViewModel.startQrLogin, AuthManager):
 *
 *   1. rpc/start_device_login_session  {p_device_nonce, p_redirect_base_url,
 *      p_device_type, p_device_name}  -> device_code, user_code,
 *      verification_uri(_complete), expires_at, poll_interval_seconds.
 *      A server without that function (PostgREST "Could not find the
 *      function") gets the older rpc/start_tv_login_session instead, and one
 *      without its p_device_name parameter gets it again without that.
 *   2. The user opens verification_uri on a phone, signs in, enters user_code.
 *   3. rpc/poll_tv_login_session {p_code, p_device_nonce} -> status:
 *      pending | approved | expired | used | cancelled.
 *   4. functions/v1/tv-logins-exchange {code, device_nonce} -> tokens.
 *
 * All of it is unauthenticated apart from the publishable key. The nonce never
 * leaves the console except in these requests, so a code read off the screen
 * is useless to anyone else without it.
 *
 * There is no timer: a provider only runs when the UI asks it for a level, so
 * each nuvio_account_link_step() call is one step - start, poll, or exchange -
 * and the UI calls it again when the user presses X.
 */

static struct {
    int     state;
    char    nonce[48];
    char    device_code[160];
    char    user_code[48];
    char    verify_uri[256];
    int64_t expires_ms;         /* 0 = unknown */
    int     legacy;
    char    message[192];

    int     busy;
    int     try_no_name;        /* legacy retry without p_device_name */
    nuvio_account_cb cb;
    void   *ud;
} D;

/* A new account.conf is a new login: forget any code in progress - unless a
 * step is in flight, whose callback still has to land. */
static void link_reset(void)
{
    if (!D.busy) memset(&D, 0, sizeof D);
}

static void link_done(int ok)
{
    nuvio_account_cb cb = D.cb;
    void *ud = D.ud;
    D.busy = 0;
    D.cb = NULL;
    D.ud = NULL;
    if (cb) cb(ok, NULL, 0, ud);
}

static void link_fail(const char *why, int status)
{
    D.state = NUVIO_LINK_FAILED;
    if (status > 0) snprintf(D.message, sizeof D.message, "%s (HTTP %d)", why, status);
    else            snprintf(D.message, sizeof D.message, "%s", why);
    PROV_LOG("nuvio account: link: %s", D.message);
    link_done(1);
}

/* Days since 1970-01-01 for a civil date (Howard Hinnant's algorithm): there
 * is no timegm() in the native libc to lean on. */
static int64_t days_from_civil(int64_t y, int m, int d)
{
    y -= m <= 2;
    int64_t era = (y >= 0 ? y : y - 399) / 400;
    int64_t yoe = y - era * 400;
    int64_t doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    int64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

/* "2026-09-29T17:05:34.123456+00:00" or "...Z" -> unix ms; 0 if unparseable. */
int64_t nuvio_account_parse_iso_ms(const char *s)
{
    int Y, M, Dd, h, mi, se;
    if (!s || sscanf(s, "%d-%d-%dT%d:%d:%d", &Y, &M, &Dd, &h, &mi, &se) != 6) return 0;
    int64_t t = days_from_civil(Y, M, Dd) * 86400 + (int64_t)h * 3600 + mi * 60 + se;
    const char *z = s + 19;
    while (*z == '.' || (*z >= '0' && *z <= '9')) ++z;
    if ((*z == '+' || *z == '-') && z[1] && z[2]) {
        int oh = (z[1] - '0') * 10 + (z[2] - '0'), om = 0;
        const char *m = z + 3;
        if (*m == ':') ++m;
        if (m[0] >= '0' && m[0] <= '9' && m[1] >= '0' && m[1] <= '9')
            om = (m[0] - '0') * 10 + (m[1] - '0');
        int64_t off = (int64_t)oh * 3600 + om * 60;
        t += (*z == '+') ? -off : off;
    }
    return t * 1000;
}

static void make_nonce(void)
{
    /* NuvioTV: 24 random bytes, base64url without padding. */
    unsigned char b[24];
    int have = 0;
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        have = fread(b, 1, sizeof b, f) == sizeof b;
        fclose(f);
    }
    if (!have) {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        static uint64_t ctr;
        uint64_t x = ((uint64_t)tv.tv_sec << 20) ^ (uint64_t)tv.tv_usec ^
                     ((uint64_t)getpid() << 40) ^ (++ctr * 0x9E3779B97F4A7C15ull) ^
                     (uint64_t)(uintptr_t)&b;
        for (size_t i = 0; i < sizeof b; ++i) {
            x ^= x << 13; x ^= x >> 7; x ^= x << 17;
            b[i] = (unsigned char)(x >> 24);
        }
    }
    static const char B64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t o = 0;
    for (size_t i = 0; i < sizeof b; i += 3) {
        uint32_t v = ((uint32_t)b[i] << 16) | ((uint32_t)b[i + 1] << 8) | b[i + 2];
        D.nonce[o++] = B64[(v >> 18) & 63];
        D.nonce[o++] = B64[(v >> 12) & 63];
        D.nonce[o++] = B64[(v >> 6) & 63];
        D.nonce[o++] = B64[v & 63];
    }
    D.nonce[o] = '\0';
}

/* The approval pages. NuvioTV: nuvio.tv/link and /tv-login for the official
 * server, <backend>/link and /tv-login for a custom one. */
static void link_pages(char *device, size_t dcap, char *legacy, size_t lcap)
{
    if (A.link_page[0]) {
        snprintf(device, dcap, "%s", A.link_page);
        snprintf(legacy, lcap, "%s", A.link_page);
    } else if (A.server[0]) {
        snprintf(device, dcap, "%s/link", A.backend);
        snprintf(legacy, lcap, "%s/tv-login", A.backend);
    } else {
        snprintf(device, dcap, "https://nuvio.tv/link");
        snprintf(legacy, lcap, "https://nuvio.tv/tv-login");
    }
}

static int anon_post(const char *path, const char *body, evo_net_cb cb)
{
    char url[900], ak[700];
    snprintf(url, sizeof url, "%s%s", A.backend, path);
    apikey_hdr(ak, sizeof ak);
    const char *h[2] = { ak, "Accept: application/json" };
    return evo_net_request_async("POST", url, body, h, 2, cb, NULL);
}

static int missing_function(const char *body, const char *name)
{
    if (!body) return 0;
    char low[1024];
    size_t n = 0;
    for (; body[n] && n + 1 < sizeof low; ++n)
        low[n] = (char)((body[n] >= 'A' && body[n] <= 'Z') ? body[n] + 32 : body[n]);
    low[n] = '\0';
    return strstr(low, "could not find the function") && strstr(low, name);
}

static const cJSON *first_row(const cJSON *r)
{
    if (cJSON_IsArray(r)) return r->child;
    return cJSON_IsObject(r) ? r : NULL;
}

static void copy_json_str(const cJSON *o, const char *k, char *out, size_t cap)
{
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(o, k);
    if (cJSON_IsString(v) && v->valuestring) snprintf(out, cap, "%s", v->valuestring);
}

static void start_legacy(void);

static void adopt_start(const cJSON *row, int legacy)
{
    D.device_code[0] = D.user_code[0] = D.verify_uri[0] = '\0';
    char exp[64] = "";
    copy_json_str(row, "expires_at", exp, sizeof exp);
    D.expires_ms = nuvio_account_parse_iso_ms(exp);
    if (!legacy) {
        copy_json_str(row, "device_code", D.device_code, sizeof D.device_code);
        copy_json_str(row, "user_code", D.user_code, sizeof D.user_code);
        copy_json_str(row, "verification_uri", D.verify_uri, sizeof D.verify_uri);
    } else {
        /* The legacy session has one code for both roles, and its page is
         * the redirect base it was started with. */
        copy_json_str(row, "code", D.device_code, sizeof D.device_code);
        copy_json_str(row, "code", D.user_code, sizeof D.user_code);
        char dev[256];
        link_pages(dev, sizeof dev, D.verify_uri, sizeof D.verify_uri);
    }
}

static void on_link_started(int ok, int status, const char *body, size_t len, void *ud)
{
    int legacy = D.legacy;
    (void)ud;
    if (!ok) {
        if (!legacy && missing_function(body, "start_device_login_session")) {
            start_legacy();
            return;
        }
        if (legacy && !D.try_no_name && missing_function(body, "p_device_name")) {
            D.try_no_name = 1;
            start_legacy();
            return;
        }
        link_fail("could not start sign-in", status);
        return;
    }
    cJSON *r = body ? cJSON_ParseWithLength(body, len) : NULL;
    const cJSON *row = first_row(r);
    if (row) adopt_start(row, legacy);
    cJSON_Delete(r);
    if (!D.device_code[0] || !D.user_code[0]) {
        link_fail("the server sent no code", 0);
        return;
    }
    D.state = NUVIO_LINK_PENDING;
    snprintf(D.message, sizeof D.message, "Waiting for you to approve");
    PROV_LOG("nuvio account: link code %s at %s (%s flow)", D.user_code, D.verify_uri,
             legacy ? "legacy" : "device");
    link_done(1);
}

static void start_legacy(void)
{
    D.legacy = 1;
    char dev[256], leg[256];
    link_pages(dev, sizeof dev, leg, sizeof leg);
    nuvio_jw_t w;
    nuvio_jw_init(&w);
    nuvio_jw_obj(&w, NULL);
    nuvio_jw_str(&w, "p_device_nonce", D.nonce);
    nuvio_jw_str(&w, "p_redirect_base_url", leg);
    if (!D.try_no_name) nuvio_jw_str(&w, "p_device_name", "PlayStation 5");
    nuvio_jw_end_obj(&w);
    char *body = nuvio_jw_finish(&w);
    int rc = body ? anon_post("/rest/v1/rpc/start_tv_login_session", body, on_link_started) : -1;
    free(body);
    if (rc != 0) link_fail("could not reach the server", 0);
}

static void start_device(void)
{
    make_nonce();
    D.legacy = 0;
    D.try_no_name = 0;
    char dev[256], leg[256];
    link_pages(dev, sizeof dev, leg, sizeof leg);
    nuvio_jw_t w;
    nuvio_jw_init(&w);
    nuvio_jw_obj(&w, NULL);
    nuvio_jw_str(&w, "p_device_nonce", D.nonce);
    nuvio_jw_str(&w, "p_redirect_base_url", dev);
    nuvio_jw_str(&w, "p_device_type", "tv");
    nuvio_jw_str(&w, "p_device_name", "PlayStation 5");
    nuvio_jw_end_obj(&w);
    char *body = nuvio_jw_finish(&w);
    int rc = body ? anon_post("/rest/v1/rpc/start_device_login_session", body, on_link_started) : -1;
    free(body);
    if (rc != 0) link_fail("could not reach the server", 0);
}

static void on_link_discovery(int ok, int status, const char *body, size_t len, void *ud)
{
    (void)ud;
    if (!apply_discovery(ok, body, len)) { link_fail("server discovery failed", status); return; }
    start_device();
}

static void on_link_exchanged(int ok, int status, const char *body, size_t len, void *ud)
{
    (void)ud;
    cJSON *r = (ok && body) ? cJSON_ParseWithLength(body, len) : NULL;
    int stored = store_tokens(r);
    cJSON_Delete(r);
    if (!stored) { link_fail("approved, but the sign-in exchange failed", status); return; }
    D.state = NUVIO_LINK_DONE;
    snprintf(D.message, sizeof D.message, "Signed in");
    set_status("signed in (device login)");
    link_done(1);
}

static void on_link_polled(int ok, int status, const char *body, size_t len, void *ud)
{
    (void)ud;
    if (!ok) { link_fail("could not check the code", status); return; }
    cJSON *r = body ? cJSON_ParseWithLength(body, len) : NULL;
    const cJSON *row = first_row(r);
    char st[32] = "", exp[64] = "";
    copy_json_str(row, "status", st, sizeof st);
    copy_json_str(row, "expires_at", exp, sizeof exp);
    cJSON_Delete(r);
    for (char *c = st; *c; ++c) if (*c >= 'A' && *c <= 'Z') *c += 32;
    if (exp[0]) D.expires_ms = nuvio_account_parse_iso_ms(exp);

    if (!strcmp(st, "approved")) {
        nuvio_jw_t w;
        nuvio_jw_init(&w);
        nuvio_jw_obj(&w, NULL);
        nuvio_jw_str(&w, "code", D.device_code);
        nuvio_jw_str(&w, "device_nonce", D.nonce);
        nuvio_jw_end_obj(&w);
        char *b = nuvio_jw_finish(&w);
        int rc = b ? anon_post("/functions/v1/tv-logins-exchange", b, on_link_exchanged) : -1;
        free(b);
        if (rc != 0) link_fail("could not reach the server", 0);
        return;
    }
    if (!strcmp(st, "pending")) {
        snprintf(D.message, sizeof D.message, "Not approved yet");
        link_done(1);
        return;
    }
    D.state = NUVIO_LINK_EXPIRED;
    snprintf(D.message, sizeof D.message, "That code %s",
             !strcmp(st, "used") ? "was already used" :
             !strcmp(st, "cancelled") ? "was cancelled" : "expired");
    link_done(1);
}

int nuvio_account_can_link(void)
{
    int where = A.server[0] || (A.backend[0] && A.key[0]);
    return where && !A.refresh[0];
}

int nuvio_account_link_state(void) { return A.refresh[0] ? NUVIO_LINK_DONE : D.state; }
const char *nuvio_account_link_code(void) { return D.user_code; }
const char *nuvio_account_link_page(void) { return D.verify_uri; }
const char *nuvio_account_link_message(void) { return D.message; }

int nuvio_account_link_minutes_left(void)
{
    if (!D.expires_ms) return -1;
    int64_t left = D.expires_ms - now_ms();
    return left <= 0 ? 0 : (int)((left + 59999) / 60000);
}

int nuvio_account_link_step(nuvio_account_cb cb, void *ud)
{
    if (D.busy) return -2;
    if (A.refresh[0]) {                         /* already signed in */
        D.state = NUVIO_LINK_DONE;
        if (cb) cb(1, NULL, 0, ud);
        return 0;
    }
    int where = A.server[0] || (A.backend[0] && A.key[0]);
    if (!where) return -1;

    D.busy = 1;
    D.cb = cb;
    D.ud = ud;

    int stale = D.state == NUVIO_LINK_PENDING && D.expires_ms && now_ms() >= D.expires_ms;
    if (D.state == NUVIO_LINK_PENDING && !stale) {
        nuvio_jw_t w;
        nuvio_jw_init(&w);
        nuvio_jw_obj(&w, NULL);
        nuvio_jw_str(&w, "p_code", D.device_code);
        nuvio_jw_str(&w, "p_device_nonce", D.nonce);
        nuvio_jw_end_obj(&w);
        char *b = nuvio_jw_finish(&w);
        int rc = b ? anon_post("/rest/v1/rpc/poll_tv_login_session", b, on_link_polled) : -1;
        free(b);
        if (rc != 0) { D.busy = 0; D.cb = NULL; D.ud = NULL; return -3; }
        return 0;
    }

    /* Idle, failed, expired or stale: a fresh code. */
    D.state = NUVIO_LINK_STARTING;
    D.user_code[0] = '\0';
    if (!A.backend[0] || !A.key[0]) {
        char url[320];
        discovery_url(url, sizeof url);
        if (evo_net_request_async("GET", url, NULL, NULL, 0, on_link_discovery, NULL) != 0) {
            D.busy = 0; D.cb = NULL; D.ud = NULL;
            D.state = NUVIO_LINK_FAILED;
            return -3;
        }
        return 0;
    }
    start_device();
    return 0;
}
