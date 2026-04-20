// object.c — Content-addressable object store

#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>

// ─── PROVIDED ────────────────────────────────────────────────────────────────

void hash_to_hex(const ObjectID *id, char *hex_out) {
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(hex_out + i * 2, "%02x", id->hash[i]);
    }
    hex_out[HASH_HEX_SIZE] = '\0';
}

int hex_to_hash(const char *hex, ObjectID *id_out) {
    if (strlen(hex) < HASH_HEX_SIZE) return -1;
    for (int i = 0; i < HASH_SIZE; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        id_out->hash[i] = (uint8_t)byte;
    }
    return 0;
}

void compute_hash(const void *data, size_t len, ObjectID *id_out) {
    unsigned int hash_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, id_out->hash, &hash_len);
    EVP_MD_CTX_free(ctx);
}

void object_path(const ObjectID *id, char *path_out, size_t path_size) {
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);
    snprintf(path_out, path_size, "%s/%.2s/%s", OBJECTS_DIR, hex, hex + 2);
}

int object_exists(const ObjectID *id) {
    char path[512];
    object_path(id, path, sizeof(path));
    return access(path, F_OK) == 0;
}

// ─── OBJECT WRITE (FIXED VERSION) ───────────────────────────────────────────

int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {

    const char *type_str;

    if (type == OBJ_BLOB) type_str = "blob";
    else if (type == OBJ_TREE) type_str = "tree";
    else if (type == OBJ_COMMIT) type_str = "commit";
    else return -1;

    // header: "type size\0"
    char header[64];
    int header_len = snprintf(header, sizeof(header), "%s %zu", type_str, len) + 1;

    size_t total_len = header_len + len;

    unsigned char *buffer = malloc(total_len);
    if (!buffer) return -1;

    memcpy(buffer, header, header_len);
    memcpy(buffer + header_len, data, len);

    // compute hash of full object
    compute_hash(buffer, total_len, id_out);

    // deduplication
    if (object_exists(id_out)) {
        free(buffer);
        return 0;
    }

    // get final path
    char path[512];
    object_path(id_out, path, sizeof(path));

    // directory
    char dir[512];
    strcpy(dir, path);
    char *slash = strrchr(dir, '/');
    if (!slash) {
        free(buffer);
        return -1;
    }
    *slash = '\0';

    mkdir(".pes", 0755);
    mkdir(OBJECTS_DIR, 0755);
    mkdir(dir, 0755);

    // temp file
    char temp_path[512];
    snprintf(temp_path, sizeof(temp_path), "%s.tmp", path);

    int fd = open(temp_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) {
        free(buffer);
        return -1;
    }

    if (write(fd, buffer, total_len) != (ssize_t)total_len) {
        close(fd);
        free(buffer);
        return -1;
    }

    fsync(fd);
    close(fd);

    rename(temp_path, path);

    free(buffer);
    return 0;
}

// ─── TODO ────────────────────────────────────────────────────────────────────

int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {

    char path[512];
    object_path(id, path, sizeof(path));

    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    rewind(f);

    unsigned char *buffer = malloc(file_size);
    if (!buffer) {
        fclose(f);
        return -1;
    }

    fread(buffer, 1, file_size, f);
    fclose(f);

    // 🔴 STEP 1: VERIFY HASH (VERY IMPORTANT)
    ObjectID new_id;
    compute_hash(buffer, file_size, &new_id);

    if (memcmp(new_id.hash, id->hash, HASH_SIZE) != 0) {
        free(buffer);
        return -1;  // integrity fail
    }

    // 🔴 STEP 2: PARSE HEADER
    char *header_end = memchr(buffer, '\0', file_size);
    if (!header_end) {
        free(buffer);
        return -1;
    }

    *header_end = '\0';

    char type_str[10];
    size_t size;

    if (sscanf((char *)buffer, "%s %zu", type_str, &size) != 2) {
        free(buffer);
        return -1;
    }

    // 🔴 STEP 3: TYPE
    if (strcmp(type_str, "blob") == 0) *type_out = OBJ_BLOB;
    else if (strcmp(type_str, "tree") == 0) *type_out = OBJ_TREE;
    else if (strcmp(type_str, "commit") == 0) *type_out = OBJ_COMMIT;
    else {
        free(buffer);
        return -1;
    }

    // 🔴 STEP 4: COPY DATA
    unsigned char *data_start = (unsigned char *)header_end + 1;

    *data_out = malloc(size);
    if (!(*data_out)) {
        free(buffer);
        return -1;
    }

    memcpy(*data_out, data_start, size);
    *len_out = size;

    free(buffer);
    return 0;
}
