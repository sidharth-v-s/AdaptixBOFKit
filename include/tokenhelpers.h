/*
 * AdaptixBOFKit - token inspection helpers.
 */
#ifndef ADAPTIX_TOKENHELPERS_H
#define ADAPTIX_TOKENHELPERS_H

#include <windows.h>

/* "DOMAIN\user" for a token handle. Returns 0 on success. */
static inline int bof_token_name(HANDLE tok, char *out, int outsz)
{
    BYTE buf[1024];
    DWORD need = 0;
    char dom[256], user[256];
    DWORD dsz = sizeof(dom), usz = sizeof(user);
    SID_NAME_USE use;
    TOKEN_USER *tu;

    out[0] = 0;
    if (!ADVAPI32$GetTokenInformation(tok, TokenUser, buf, sizeof(buf), &need))
        return -1;
    tu = (TOKEN_USER *)buf;
    if (!ADVAPI32$LookupAccountSidA(NULL, tu->User.Sid, user, &usz, dom, &dsz, &use))
        return -1;

    if (dom[0]) {
        bof_strncpy(out, dom, outsz);
        bof_strncat(out, "\\", outsz - bof_strlen(out) - 1);
        bof_strncat(out, user, outsz - bof_strlen(out) - 1);
    } else {
        bof_strncpy(out, user, outsz);
    }
    return 0;
}

/* "S-1-5-..." for a token handle. Returns 0 on success. */
static inline int bof_token_sid(HANDLE tok, char *out, int outsz)
{
    BYTE buf[1024];
    DWORD need = 0;
    TOKEN_USER *tu;
    LPSTR s = NULL;

    out[0] = 0;
    if (!ADVAPI32$GetTokenInformation(tok, TokenUser, buf, sizeof(buf), &need))
        return -1;
    tu = (TOKEN_USER *)buf;
    if (!ADVAPI32$ConvertSidToStringSidA(tu->User.Sid, &s))
        return -1;
    bof_strncpy(out, s, outsz);
    KERNEL32$LocalFree(s);
    return 0;
}

/* 1 elevated, 0 not elevated, -1 unknown. */
static inline int bof_token_elevated(HANDLE tok)
{
    TOKEN_ELEVATION el;
    DWORD need = 0;
    if (!ADVAPI32$GetTokenInformation(tok, TokenElevation, &el, sizeof(el), &need))
        return -1;
    return el.TokenIsElevated ? 1 : 0;
}

/* One-line description: DOMAIN\user (S-1-5-..) elevated=yes */
static inline void bof_token_line(HANDLE tok, char *out, int outsz)
{
    char name[256], sid[128];
    int el;

    if (bof_token_name(tok, name, sizeof(name)) != 0)
        bof_strncpy(name, "?", sizeof(name));
    if (bof_token_sid(tok, sid, sizeof(sid)) != 0)
        bof_strncpy(sid, "?", sizeof(sid));
    el = bof_token_elevated(tok);

    bof_strncpy(out, name, outsz);
    bof_strncat(out, " (", outsz - bof_strlen(out) - 1);
    bof_strncat(out, sid, outsz - bof_strlen(out) - 1);
    bof_strncat(out, ") elevated=", outsz - bof_strlen(out) - 1);
    bof_strncat(out, el == 1 ? "yes" : (el == 0 ? "no" : "?"),
                outsz - bof_strlen(out) - 1);
}

#endif /* ADAPTIX_TOKENHELPERS_H */
