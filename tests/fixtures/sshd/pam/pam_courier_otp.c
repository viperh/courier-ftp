/*
 * pam_courier_otp: the scripted "OTP" step of the `kbd` sshd profile (TEST ONLY).
 * Prompts "Verification code: " and accepts only 424242. Built in the image.
 */
#define PAM_SM_AUTH
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <stdlib.h>
#include <string.h>

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                                   const char **argv) {
    (void)flags;
    (void)argc;
    (void)argv;
    const struct pam_conv *conv = NULL;
    if (pam_get_item(pamh, PAM_CONV, (const void **)&conv) != PAM_SUCCESS || conv == NULL) {
        return PAM_AUTH_ERR;
    }
    struct pam_message msg = {PAM_PROMPT_ECHO_OFF, "Verification code: "};
    const struct pam_message *msgp = &msg;
    struct pam_response *resp = NULL;
    if (conv->conv(1, &msgp, &resp, conv->appdata_ptr) != PAM_SUCCESS || resp == NULL) {
        return PAM_AUTH_ERR;
    }
    int ok = resp->resp != NULL && strcmp(resp->resp, "424242") == 0;
    if (resp->resp != NULL) {
        free(resp->resp);
    }
    free(resp);
    return ok ? PAM_SUCCESS : PAM_AUTH_ERR;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_SUCCESS;
}
