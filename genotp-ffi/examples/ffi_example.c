#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/genotp.h"

void print_error(GenOtpErrorCode err) {
    GenOtpString msg;
    if (genotp_error_message(err, &msg) == GenOtpErrorCode_Success) {
        printf("Error: %.*s\n", (int)msg.len, msg.data);
        genotp_string_free(msg);
    } else {
        printf("Error code: %d\n", err);
    }
}

int main() {
    GenOtpErrorCode err;
    GenOtpBytes secret;
    GenOtpString code;
    GenOtpTotp* totp = NULL;
    bool valid;

    printf("=== genotp FFI Example ===\n\n");

    // Generate secret
    printf("1. Generating 160-bit secret...\n");
    err = genotp_generate_default_secret(&secret);
    if (err != GenOtpErrorCode_Success) {
        print_error(err);
        return 1;
    }
    printf("   Secret generated (%zu bytes)\n", secret.len);

    // Encode to Base32
    printf("\n2. Encoding secret to Base32...\n");
    GenOtpString b32;
    err = genotp_base32_encode(secret.data, secret.len, &b32);
    if (err != GenOtpErrorCode_Success) {
        print_error(err);
        genotp_bytes_free(secret);
        return 1;
    }
    printf("   Base32: %.*s\n", (int)b32.len, b32.data);
    genotp_string_free(b32);

    // Create TOTP instance
    printf("\n3. Creating TOTP instance (SHA1, 6 digits, 30s period)...\n");
    err = genotp_totp_new(secret.data, secret.len, GenOtpAlgorithm_Sha1, 6, 30, &totp);
    if (err != GenOtpErrorCode_Success) {
        print_error(err);
        genotp_bytes_free(secret);
        return 1;
    }
    printf("   TOTP instance created\n");

    // Generate TOTP code
    printf("\n4. Generating TOTP code...\n");
    err = genotp_totp_generate(totp, GENOTP_TIME_NOW, &code);
    if (err != GenOtpErrorCode_Success) {
        print_error(err);
        genotp_totp_free(totp);
        genotp_bytes_free(secret);
        return 1;
    }
    printf("   Code: %.*s\n", (int)code.len, code.data);

    // Verify TOTP code
    printf("\n5. Verifying TOTP code...\n");
    /* NOTE: code.data is NOT null-terminated. We must build a proper C
     * string before passing to genotp_totp_verify (which expects a
     * null-terminated input). */
    char code_cstr[16];
    size_t copy_len = code.len < sizeof(code_cstr) - 1 ? code.len : sizeof(code_cstr) - 1;
    memcpy(code_cstr, code.data, copy_len);
    code_cstr[copy_len] = '\0';
    err = genotp_totp_verify(totp, code_cstr, GENOTP_TIME_NOW, 1, &valid);
    if (err != GenOtpErrorCode_Success) {
        print_error(err);
        genotp_string_free(code);
        genotp_totp_free(totp);
        genotp_bytes_free(secret);
        return 1;
    }
    printf("   Verification result: %s\n", valid ? "VALID" : "INVALID");

    // Generate otpauth:// URI for QR code provisioning
    printf("\n6. Generating otpauth:// URI for Google Authenticator...\n");

    GenOtpString secret_b32;
    err = genotp_base32_encode(secret.data, secret.len, &secret_b32);
    if (err != GenOtpErrorCode_Success) {
        print_error(err);
        genotp_string_free(code);
        genotp_totp_free(totp);
        genotp_bytes_free(secret);
        return 1;
    }

    /* Convert length-prefixed secret_b32 to null-terminated for the URI API. */
    char secret_cstr[64];
    size_t secret_copy_len = secret_b32.len < sizeof(secret_cstr) - 1
                                 ? secret_b32.len
                                 : sizeof(secret_cstr) - 1;
    memcpy(secret_cstr, secret_b32.data, secret_copy_len);
    secret_cstr[secret_copy_len] = '\0';

    GenOtpOtpAuthUri* uri = NULL;
    err = genotp_otpauth_uri_new(GenOtpOtpType_Totp,
                                 "ACME Corp:alice@example.com",
                                 secret_cstr, &uri);
    if (err != GenOtpErrorCode_Success) {
        print_error(err);
        genotp_string_free(secret_b32);
        genotp_string_free(code);
        genotp_totp_free(totp);
        genotp_bytes_free(secret);
        return 1;
    }

    genotp_otpauth_uri_set_issuer(uri, "ACME Corp");
    genotp_otpauth_uri_set_algorithm(uri, GenOtpAlgorithm_Sha1);
    genotp_otpauth_uri_set_digits(uri, 6);
    genotp_otpauth_uri_set_period(uri, 30);

    GenOtpString uri_string;
    err = genotp_otpauth_uri_build(uri, &uri_string);
    if (err == GenOtpErrorCode_Success) {
        printf("   URI: %.*s\n", (int)uri_string.len, uri_string.data);
        printf("   (Feed this into a QR encoder to provision Google Authenticator)\n");
        genotp_string_free(uri_string);
    } else {
        print_error(err);
    }

    genotp_otpauth_uri_free(uri);
    genotp_string_free(secret_b32);

    // Cleanup
    printf("\n7. Cleaning up...\n");
    genotp_string_free(code);
    genotp_totp_free(totp);
    genotp_bytes_free(secret);
    printf("   Done\n");

    printf("\n=== Example completed successfully ===\n");
    return 0;
}
