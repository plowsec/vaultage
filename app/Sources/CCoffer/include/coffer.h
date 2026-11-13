// C ABI of the Rust core (crates/ffi/src/lib.rs).
#ifndef COFFER_H
#define COFFER_H

#include <stddef.h>
#include <stdint.h>

char *coffer_harden(void);
char *coffer_call(const char *request_json, const uint8_t *secret, size_t secret_len);
uint8_t *coffer_read(const char *request_json, size_t *out_len, char **error);
void coffer_free_string(char *s);
void coffer_free_bytes(uint8_t *ptr, size_t len);

#endif
