/*
 * Written by Alexey Tourbin <at@altlinux.org>.
 *
 * The author has dedicated the code to the public domain.  Anyone is free
 * to copy, modify, publish, use, compile, sell, or distribute the original
 * code, either in source code form or as a compiled binary, for any purpose,
 * commercial or non-commercial, and by any means.
 */
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <pcre.h>
extern "C" {
#include "pcrs.h,in"
}
#include <sqlite3ext.h>
SQLITE_EXTENSION_INIT1

typedef struct {
    char *s;
    pcre *p;
    pcre_extra *e;
} cache_entry;

#ifndef CACHE_SIZE
#define CACHE_SIZE 16
#endif



static
void regexp(sqlite3_context *ctx, int argc, sqlite3_value **argv)
{
    const char *re, *str;
    pcre *p;
    pcre_extra *e;

    assert(argc == 2);

    re = (const char *) sqlite3_value_text(argv[0]);
    if (!re) {
        sqlite3_result_error(ctx, "no regexp", -1);
        return;
    }

    str = (const char *) sqlite3_value_text(argv[1]);
    if (!str) {
        sqlite3_result_error(ctx, "no string", -1);
        return;
    }

    /* simple LRU cache */
    {
        int i;
        int found = 0;
        auto *cache = static_cast<cache_entry *>(sqlite3_user_data(ctx));

        assert(cache);

        for (i = 0; i < CACHE_SIZE && cache[i].s; i++)
            if (strcmp(re, cache[i].s) == 0) {
                found = 1;
                break;
            }
        if (found) {
            if (i > 0) {
                cache_entry c = cache[i];
                memmove(cache + 1, cache, i * sizeof(cache_entry));
                cache[0] = c;
            }
        }
        else {
            cache_entry c;
            const char *err;
            int pos;
            c.p = pcre_compile(re, 0, &err, &pos, nullptr);
            if (!c.p) {
                char *e2 = sqlite3_mprintf("%s: %s (offset %d)", re, err, pos);
                sqlite3_result_error(ctx, e2, -1);
                sqlite3_free(e2);
                return;
            }
            c.e = pcre_study(c.p, 0, &err);
            c.s = strdup(re);
            if (!c.s) {
                sqlite3_result_error(ctx, "strdup: ENOMEM", -1);
                pcre_free(c.p);
                pcre_free(c.e);
                return;
            }
            i = CACHE_SIZE - 1;
            if (cache[i].s) {
                free(cache[i].s);
                assert(cache[i].p);
                pcre_free(cache[i].p);
                pcre_free(cache[i].e);
            }
            memmove(cache + 1, cache, i * sizeof(cache_entry));
            cache[0] = c;
        }
        p = cache[0].p;
        e = cache[0].e;
    }

    {
        int rc;
        assert(p);
        rc = pcre_exec(p, e, str, strlen(str), 0, 0, nullptr, 0);
        sqlite3_result_int(ctx, rc >= 0);
        return;
    }
}

static
void regexp_replace(sqlite3_context *ctx, int argc, sqlite3_value **argv)
{
    char *re,  *replace;
    char* str, *arg;
    pcre *p;
    pcre_extra *e;

    assert(argc == 4);

    re = (char *) sqlite3_value_text(argv[0]);
    if (!re) {
        sqlite3_result_error(ctx, "no regexp", -1);
        return;
    }

    str = (char *) sqlite3_value_text(argv[1]);
    if (!str) {
        sqlite3_result_error(ctx, "no string", -1);
        return;
    }

    replace = (char *) sqlite3_value_text(argv[2]);
    if (!replace) {
        sqlite3_result_error(ctx, "no string", -1);
        return;
    }

    arg = (char *) sqlite3_value_text(argv[3]);
    if (!arg) {
        sqlite3_result_error(ctx, "no arg", -1);
        return;
    }

    /* simple LRU cache */
    {
        int i;
        int found = 0;
        auto *cache = static_cast<cache_entry *>(sqlite3_user_data(ctx));

        assert(cache);

        for (i = 0; i < CACHE_SIZE && cache[i].s; i++)
            if (strcmp(re, cache[i].s) == 0) {
                found = 1;
                break;
            }
        if (found) {
            if (i > 0) {
                cache_entry c = cache[i];
                memmove(cache + 1, cache, i * sizeof(cache_entry));
                cache[0] = c;
            }
        }
        else {
            cache_entry c;
            const char *err;
            int pos;
            c.p = pcre_compile(re, 0, &err, &pos, nullptr);
            if (!c.p) {
                char *e2 = sqlite3_mprintf("%s: %s (offset %d)", re, err, pos);
                sqlite3_result_error(ctx, e2, -1);
                sqlite3_free(e2);
                return;
            }
            c.e = pcre_study(c.p, 0, &err);
            c.s = strdup(re);
            if (!c.s) {
                sqlite3_result_error(ctx, "strdup: ENOMEM", -1);
                pcre_free(c.p);
                pcre_free(c.e);
                return;
            }
            i = CACHE_SIZE - 1;
            if (cache[i].s) {
                free(cache[i].s);
                assert(cache[i].p);
                pcre_free(cache[i].p);
                pcre_free(cache[i].e);
            }
            memmove(cache + 1, cache, i * sizeof(cache_entry));
            cache[0] = c;
        }
        p = cache[0].p;
        e = cache[0].e;
    }

    {
        int rc;
        assert(p);
        char *result;
        int capturecount = 0;
        int errptr2 = 0;
        pcrs_job *newjob = pcrs_compile( re,replace, arg, &errptr2);;

        size_t length =strlen(str);
        if (0 > (errptr2 = pcrs_execute(newjob, str, length, &result, &length)))
        {
            char *e2 = sqlite3_mprintf("%s: Exec error, subject: %s, regex: %s, replace: %s, option: %s\n", pcrs_strerror(errptr2),str,re,replace,arg);
            sqlite3_result_error(ctx, e2, -1);
            sqlite3_free(e2);
            sqlite3_free(ctx);
            return;
        }
        //rc = pcre_exec(p, e, str, static_cast<int>(strlen(str)), 0, 0, nullptr, 0);
        sqlite3_result_text(ctx, result, static_cast<int>(strlen(result)), nullptr);
        sqlite3_free(ctx);
        return;
    }
}
#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCUnusedGlobalDeclarationInspection"
extern "C" int __declspec(dllexport) sqlite3_extension_init(sqlite3 *db, char **err, const sqlite3_api_routines *api)
{
    SQLITE_EXTENSION_INIT2(api)
    auto *cache = static_cast<cache_entry *>(calloc(CACHE_SIZE, sizeof(cache_entry)));
    if (!cache) {
        *err = const_cast<char *>("calloc: ENOMEM");
        return 1;
    }
    sqlite3_create_function(db, "REGEXP", 2, SQLITE_UTF8, cache, regexp, nullptr, nullptr);
    sqlite3_create_function(db, "regexp_replace", 4, SQLITE_UTF8, cache, regexp_replace, nullptr, nullptr);
    return 0;
}
#pragma clang diagnostic pop

