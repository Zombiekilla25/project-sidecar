/* Static trust boundary: verify the Python/native runtime before Python starts. */
#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef FK0957_BOOTSTRAP_PATH
#define FK0957_BOOTSTRAP_PATH "/usr/local/lib/sidecar/fk0957/fk0957_safe_bootstrap.py"
#endif
#ifndef FK0957_BOOTSTRAP_SHA256
#define FK0957_BOOTSTRAP_SHA256 ""
#endif

#define PIN(path_, sha_, build_) { (path_), (sha_), (build_) }
struct runtime_pin { const char *path; const char *sha256; const char *build_id; };
static const struct runtime_pin runtime_pins[] = {
    PIN("/usr/bin/python3.12", "e50d468e8b0adfb05733f5b87b3cff34829c4a8c1aea50c865aa8bdfe4bb150f", "337d65cf00021797985cc9f77c0cc334a9fbeb38"),
    PIN("/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", "5fc0940888e9d2e1a00e66d6b1a559c36364ee867683652e1074fa576952cc3f", "231ab65dd867a89dce29cb958fd5ca50abb1aa34"),
    PIN("/usr/lib/x86_64-linux-gnu/libc.so.6", "755a371e86cc9f564ab54f66140747700fb0a103f698f659f2060f707897e09a", "8cebda42d140fc2b09639f8b13a5d5f2e617ef09"),
    PIN("/usr/lib/x86_64-linux-gnu/libftdi1.so.2.5.0", "0e5332df54c66f14ef9107934365b47b9429df02e3ff3402436bd85e9e3e84fe", "5d7c81b08d369b6ea8654c825cbdff7fdce1f87c"),
    PIN("/usr/lib/x86_64-linux-gnu/libusb-1.0.so.0.4.0", "751349e3def1808981dc26bbeb746e2d6ff4ca97fc2c8bc8faaa8f46c879057f", "47533e904f636332fab2f1ca8847ad7759ed19ec"),
};

static int read_exact_at(int fd, void *buffer, size_t size, off_t offset) {
    unsigned char *out = buffer;
    size_t done = 0;
    while (done < size) {
        ssize_t got = pread(fd, out + done, size - done, offset + (off_t)done);
        if (got <= 0) return 0;
        done += (size_t)got;
    }
    return 1;
}

static int hash_fd(int fd, char output[65]) {
    SHA256_CTX ctx;
    if (SHA256_Init(&ctx) != 1) return 0;
    unsigned char buffer[65536], digest[SHA256_DIGEST_LENGTH];
    int ok = 1;
    off_t offset = 0;
    while (ok) {
        ssize_t got = pread(fd, buffer, sizeof(buffer), offset);
        if (got < 0 && errno == EINTR) continue;
        if (got < 0) { ok = 0; break; }
        if (got == 0) break;
        if (SHA256_Update(&ctx, buffer, (size_t)got) != 1) { ok = 0; break; }
        offset += got;
    }
    if (ok) ok = SHA256_Final(digest, &ctx) == 1;
    if (!ok) return 0;
    static const char hex[] = "0123456789abcdef";
    for (unsigned int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        output[i * 2] = hex[digest[i] >> 4];
        output[i * 2 + 1] = hex[digest[i] & 15];
    }
    output[64] = '\0';
    return 1;
}

static int build_id_fd(int fd, const struct stat *file_info, char output[129]) {
    Elf64_Ehdr header;
    if (!read_exact_at(fd, &header, sizeof(header), 0) ||
        memcmp(header.e_ident, ELFMAG, SELFMAG) != 0 ||
        header.e_ident[EI_CLASS] != ELFCLASS64 || header.e_ident[EI_DATA] != ELFDATA2LSB ||
        header.e_phentsize != sizeof(Elf64_Phdr) || header.e_phnum == 0 || header.e_phnum > 256 ||
        header.e_phoff > (uint64_t)file_info->st_size ||
        (uint64_t)header.e_phnum * sizeof(Elf64_Phdr) > (uint64_t)file_info->st_size - header.e_phoff)
        return 0;
    for (uint16_t i = 0; i < header.e_phnum; ++i) {
        Elf64_Phdr ph;
        off_t phoff = (off_t)header.e_phoff + (off_t)i * (off_t)sizeof(ph);
        if (!read_exact_at(fd, &ph, sizeof(ph), phoff)) return 0;
        if (ph.p_type != PT_NOTE || ph.p_filesz < sizeof(Elf64_Nhdr) ||
            ph.p_filesz > 1024 * 1024 || ph.p_offset > (uint64_t)file_info->st_size ||
            ph.p_filesz > (uint64_t)file_info->st_size - ph.p_offset)
            continue;
        unsigned char notes[1024 * 1024];
        if (!read_exact_at(fd, notes, (size_t)ph.p_filesz, (off_t)ph.p_offset)) return 0;
        size_t cursor = 0, limit = (size_t)ph.p_filesz;
        while (cursor + sizeof(Elf64_Nhdr) <= limit) {
            Elf64_Nhdr note;
            memcpy(&note, notes + cursor, sizeof(note)); cursor += sizeof(note);
            size_t namesz = (note.n_namesz + 3U) & ~3U;
            size_t descsz = (note.n_descsz + 3U) & ~3U;
            if (namesz > limit - cursor || descsz > limit - cursor - namesz) return 0;
            const unsigned char *name = notes + cursor;
            const unsigned char *desc = notes + cursor + namesz;
            if (note.n_type == NT_GNU_BUILD_ID && note.n_namesz == 4 &&
                memcmp(name, "GNU\0", 4) == 0 && note.n_descsz > 0 && note.n_descsz <= 64) {
                static const char hex[] = "0123456789abcdef";
                for (uint32_t j = 0; j < note.n_descsz; ++j) {
                    output[j * 2] = hex[desc[j] >> 4];
                    output[j * 2 + 1] = hex[desc[j] & 15];
                }
                output[note.n_descsz * 2] = '\0';
                return 1;
            }
            cursor += namesz + descsz;
        }
    }
    return 0;
}

static int verify_runtime_pin(const struct runtime_pin *pin) {
    char resolved[4096], digest[65], build_id[129];
    if (!realpath(pin->path, resolved) || strcmp(resolved, pin->path) != 0) return 0;
    int fd = open(pin->path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NOCTTY);
    if (fd < 0) return 0;
    struct stat before, after;
    int ok = fstat(fd, &before) == 0 && S_ISREG(before.st_mode) && before.st_uid == 0 &&
             before.st_nlink == 1 && !(before.st_mode & 0022) && before.st_size > 0 &&
             hash_fd(fd, digest) && strcmp(digest, pin->sha256) == 0 &&
             build_id_fd(fd, &before, build_id) && strcmp(build_id, pin->build_id) == 0 &&
             fstat(fd, &after) == 0 && before.st_dev == after.st_dev &&
             before.st_ino == after.st_ino && before.st_size == after.st_size &&
             before.st_mtim.tv_sec == after.st_mtim.tv_sec && before.st_mtim.tv_nsec == after.st_mtim.tv_nsec;
    close(fd);
    return ok;
}

static int open_verified_bootstrap(void) {
    char resolved[4096], digest[65];
    if (strlen(FK0957_BOOTSTRAP_SHA256) != 64 ||
        !realpath(FK0957_BOOTSTRAP_PATH, resolved) ||
        strcmp(resolved, FK0957_BOOTSTRAP_PATH) != 0) return -1;
    int fd = open(FK0957_BOOTSTRAP_PATH, O_RDONLY | O_NOFOLLOW | O_NOCTTY);
    if (fd < 0) return -1;
    struct stat before, after;
    int ok = fstat(fd, &before) == 0 && S_ISREG(before.st_mode) &&
             (before.st_uid == 0 || before.st_uid == geteuid()) && before.st_nlink == 1 &&
             !(before.st_mode & 0022) && before.st_size > 0 && before.st_size <= 1024 * 1024 &&
             hash_fd(fd, digest) && strcmp(digest, FK0957_BOOTSTRAP_SHA256) == 0 &&
             fstat(fd, &after) == 0 && before.st_dev == after.st_dev &&
             before.st_ino == after.st_ino && before.st_size == after.st_size &&
             before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
             before.st_mtim.tv_nsec == after.st_mtim.tv_nsec;
    if (!ok) { close(fd); return -1; }
    return fd;
}

static int refuse_runtime(void) {
    static const char message[] = "{\"status\":\"REFUSED\",\"phase\":\"PRESTART_VALIDATION\",\"code\":\"NATIVE_RUNTIME_PIN_MISMATCH\"}\n";
    size_t offset = 0;
    while (offset < sizeof(message) - 1) {
        ssize_t written = write(STDOUT_FILENO, message + offset, sizeof(message) - 1 - offset);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) break;
        offset += (size_t)written;
    }
    return 126;
}

int main(int argc, char **argv) {
    for (size_t i = 0; i < sizeof(runtime_pins) / sizeof(runtime_pins[0]); ++i)
        if (!verify_runtime_pin(&runtime_pins[i])) return refuse_runtime();
    int bootstrap_fd = open_verified_bootstrap();
    if (bootstrap_fd < 0) return refuse_runtime();

    char **child_argv = calloc((size_t)argc + 5, sizeof(char *));
    if (child_argv == NULL) { close(bootstrap_fd); return 126; }
    char bootstrap_fd_path[64];
    snprintf(bootstrap_fd_path, sizeof(bootstrap_fd_path), "/proc/self/fd/%d", bootstrap_fd);
    child_argv[0] = "/usr/bin/python3.12";
    child_argv[1] = "-I";
    child_argv[2] = "-S";
    child_argv[3] = bootstrap_fd_path;
    for (int i = 1; i < argc; ++i) child_argv[i + 3] = argv[i];
    child_argv[argc + 3] = NULL;

    char *const clean_env[] = {
        "PATH=/usr/bin:/bin",
        "LANG=C.UTF-8",
        "FK0957_TRUSTED_LAUNCHER=1",
        NULL
    };
    execve("/usr/bin/python3.12", child_argv, clean_env);
    return 126;
}
