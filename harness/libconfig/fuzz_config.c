#include <libconfig.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Recursively walk the parsed config tree to exercise getters and
   aggregate accessors. Side-effect-free; just touches lookup paths. */
static void walk(const config_setting_t *s) {
    if (!s) return;
    (void)config_setting_type(s);
    (void)config_setting_name(s);
    if (config_setting_is_aggregate(s)) {
        int n = config_setting_length(s);
        for (int i = 0; i < n; i++)
            walk(config_setting_get_elem(s, i));
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Cap input to keep memory bounded; libconfig is meant for config
       files, not megabyte blobs. */
    if (size > (1u << 20)) return 0;

    char *buf = (char *)malloc(size + 1);
    if (!buf) return 0;
    memcpy(buf, data, size);
    buf[size] = '\0';

    config_t cfg;
    config_init(&cfg);

    if (config_read_string(&cfg, buf) == CONFIG_TRUE) {
        walk(config_root_setting(&cfg));
        /* Exercise the writer path too. /dev/null avoids I/O cost. */
        FILE *null = fopen("/dev/null", "w");
        if (null) {
            config_write(&cfg, null);
            fclose(null);
        }
    }

    config_destroy(&cfg);
    free(buf);
    return 0;
}
