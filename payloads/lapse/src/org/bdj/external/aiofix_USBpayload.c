#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <pthread.h>
#include <errno.h>
#include <stdint.h>
#include <ps4/kernel.h>

typedef unsigned char u8;

typedef struct notify_request {
    char useless1[45];
    char message[3075];
} notify_request_t;

int sceKernelSendNotificationRequest(int, notify_request_t*, size_t, int);

#define PAGE_SIZE 0x1000
#define MAX_PAYLOAD_SIZE (4 * 1024 * 1024)  // 4MB
#define COPY_CHUNK_SIZE 8192
#define PAYLOAD_NAME_STR "payload.bin"
#define ELF_MAGIC 0x464c457f  // 0x7F 'E' 'L' 'F' in little endian
#define PT_LOAD 1

static char USB_PAYLOAD_PATHS[5][32];
static char DATA_PAYLOAD_PATH[32];

typedef struct {
    uint64_t e_entry;
    uint64_t e_phoff;
    uint16_t e_phentsize;
    uint16_t e_phnum;
} elf_header_t;

typedef struct {
    uint32_t p_type;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
} program_header_t;

static void* mmap_base = NULL;
static size_t mmap_size = 0;
static void* entry_point = NULL;
static pthread_t payload_thread = 0;

void send_notification(const char* message) {
    notify_request_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.message, message, sizeof(req.message) - 1);
    sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
}

// aio fix by abc
int patch_aio(void * kbase) {
    char search_pattern[] = "7449e9df000000";
    
    unsigned long found = kernel_find_pattern((unsigned long)kbase, 0xC00000, search_pattern);
    
    if (!found) {
        return 1;
    }
    
    size_t base_offset = found - (unsigned long)kbase;
    
    {
        unsigned long addr = (unsigned long)kbase + base_offset;
        u8 patch[] = {0xeb, 0x48};
        kernel_copyin(patch, addr, sizeof(patch));
    }
    {
        unsigned long addr = (unsigned long)kbase + base_offset + 0x42;
        u8 nop_patch[] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
        kernel_copyin(nop_patch, addr, sizeof(nop_patch));
    }
    {
        unsigned long addr = (unsigned long)kbase + base_offset + 0x4a;
        u8 patch[] = {0x41, 0x83, 0xbf, 0xa0, 0x04, 0x00, 0x00, 0x00};
        kernel_copyin(patch, addr, sizeof(patch));
    }
    {
        unsigned long addr = (unsigned long)kbase + base_offset + 0x58;
        u8 patch[] = {0x49, 0x8b, 0x87, 0xd0, 0x04, 0x00, 0x00};
        kernel_copyin(patch, addr, sizeof(patch));
    }
    {
        unsigned long addr = (unsigned long)kbase + base_offset + 0x65;
        u8 patch[] = {0x49, 0x8b, 0xb7, 0xb0, 0x04, 0x00, 0x00};
        kernel_copyin(patch, addr, sizeof(patch));
    }
    {
        unsigned long addr = (unsigned long)kbase + base_offset + 0x7d;
        u8 patch[] = {0x49, 0x8b, 0x87, 0x40, 0x05, 0x00, 0x00};
        kernel_copyin(patch, addr, sizeof(patch));
    }
    {
        unsigned long addr = (unsigned long)kbase + base_offset + 0x8a;
        u8 patch[] = {0x49, 0x8b, 0xb7, 0x20, 0x05, 0x00, 0x00};
        kernel_copyin(patch, addr, sizeof(patch));
    }
    {
        unsigned long addr = (unsigned long)kbase + base_offset + 0xa2;
        u8 patch[] = {0x49, 0x8d, 0xbf, 0xc0, 0x00, 0x00, 0x00};
        kernel_copyin(patch, addr, sizeof(patch));
    }
    {
        unsigned long addr = (unsigned long)kbase + base_offset + 0xae;
        u8 patch[] = {0x49, 0x8d, 0xbf, 0xe0, 0x00, 0x00, 0x00};
        kernel_copyin(patch, addr, sizeof(patch));
    }
    {
        unsigned long addr = (unsigned long)kbase + base_offset + 0xc1;
        u8 patch[] = {0x49, 0x8d, 0xbf, 0x00, 0x01, 0x00, 0x00};
        kernel_copyin(patch, addr, sizeof(patch));
    }
    {
        unsigned long addr = (unsigned long)kbase + base_offset + 0xcd;
        u8 patch[] = {0x49, 0x8d, 0xbf, 0x20, 0x01, 0x00, 0x00};
        kernel_copyin(patch, addr, sizeof(patch));
    }
    {
        unsigned long addr = (unsigned long)kbase + base_offset + 0xde;
        u8 patch[] = {0x49, 0x8b, 0xff};
        kernel_copyin(patch, addr, sizeof(patch));
    }
    
    send_notification("AIO patch completed successfully");
    return 0;
}

void setup_payload_paths(const char* payload_filename) {
    snprintf(USB_PAYLOAD_PATHS[0], sizeof(USB_PAYLOAD_PATHS[0]), "/mnt/usb0/%s", payload_filename);
    snprintf(USB_PAYLOAD_PATHS[1], sizeof(USB_PAYLOAD_PATHS[1]), "/mnt/usb1/%s", payload_filename);
    snprintf(USB_PAYLOAD_PATHS[2], sizeof(USB_PAYLOAD_PATHS[2]), "/mnt/usb2/%s", payload_filename);
    snprintf(USB_PAYLOAD_PATHS[3], sizeof(USB_PAYLOAD_PATHS[3]), "/mnt/usb3/%s", payload_filename);
    snprintf(USB_PAYLOAD_PATHS[4], sizeof(USB_PAYLOAD_PATHS[4]), "/mnt/usb4/%s", payload_filename);
    snprintf(DATA_PAYLOAD_PATH, sizeof(DATA_PAYLOAD_PATH), "/data/%s", payload_filename);
}

size_t round_up(size_t value, size_t boundary) {
    return ((value + boundary - 1) / boundary) * boundary;
}

int file_exists(const char* path) {
    struct stat st;
    if (stat(path, &st) == 0) {
        if (S_ISREG(st.st_mode)) {
            return 1;
        }
    }
    return 0;  // File doesn't exist
}

int copy_file(const char* src, const char* dst) {
    int in = -1, out = -1, res = -1;
    char buf[COPY_CHUNK_SIZE];
    ssize_t n;
    struct stat st;

    if (stat(src, &st) || !S_ISREG(st.st_mode) || st.st_size > MAX_PAYLOAD_SIZE)
        return -1;

    if ((in = open(src, O_RDONLY)) < 0) return -1;
    if ((out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644)) < 0) goto cleanup;

    while ((n = read(in, buf, sizeof(buf))) > 0) {
        if (write(out, buf, n) != n) goto cleanup;
    }
    if (n == 0) res = 0; // success

cleanup:
    if (in >= 0) close(in);
    if (out >= 0) close(out);
    return res;
}

uint8_t* read_file(const char *path, size_t *size_out) {
    int fd = -1;
    struct stat st;
    uint8_t *buf = NULL;
    ssize_t n, total = 0;

    if (stat(path, &st) || !S_ISREG(st.st_mode) || st.st_size == 0 || st.st_size > MAX_PAYLOAD_SIZE)
        return NULL;

    if ((fd = open(path, O_RDONLY)) < 0) return NULL;
    if (!(buf = malloc(st.st_size))) goto cleanup;

    while (total < st.st_size) {
        n = read(fd, buf + total, st.st_size - total);
        if (n <= 0) { free(buf); buf = NULL; goto cleanup; }
        total += n;
    }
    *size_out = st.st_size;

cleanup:
    if (fd >= 0) close(fd);
    return buf;
}

// ELF parsing functions
void read_elf_header(void* addr, elf_header_t* header) {
    uint8_t* ptr = (uint8_t*)addr;
    header->e_entry = *(uint64_t*)(ptr + 0x18);
    header->e_phoff = *(uint64_t*)(ptr + 0x20);
    header->e_phentsize = *(uint16_t*)(ptr + 0x36);
    header->e_phnum = *(uint16_t*)(ptr + 0x38);
}

void read_program_header(void* addr, program_header_t* phdr) {
    uint8_t* ptr = (uint8_t*)addr;
    phdr->p_type = *(uint32_t*)(ptr + 0x00);
    phdr->p_offset = *(uint64_t*)(ptr + 0x08);
    phdr->p_vaddr = *(uint64_t*)(ptr + 0x10);
    phdr->p_filesz = *(uint64_t*)(ptr + 0x20);
    phdr->p_memsz = *(uint64_t*)(ptr + 0x28);
}

void* load_elf_segments(uint8_t* data, size_t data_size) {
    // Create temporary mapping for ELF parsing
    void* temp_buf = mmap(NULL, data_size, PROT_READ | PROT_WRITE, 
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (temp_buf == MAP_FAILED) {
        return NULL;
    }

    memcpy(temp_buf, data, data_size);

    elf_header_t elf_header;
    read_elf_header(temp_buf, &elf_header);

    // Load program segments
    for (int i = 0; i < elf_header.e_phnum; i++) {
        void* phdr_addr = (uint8_t*)temp_buf + elf_header.e_phoff + (i * elf_header.e_phentsize);
        program_header_t phdr;
        read_program_header(phdr_addr, &phdr);

        if (phdr.p_type == PT_LOAD && phdr.p_memsz > 0) {
            // Calculate segment address (use relative offset)
            void* seg_addr = (uint8_t*)mmap_base + (phdr.p_vaddr % 0x1000000);

            // Copy segment data from original data
            if (phdr.p_filesz > 0) {
                memcpy(seg_addr, data + phdr.p_offset, phdr.p_filesz);
            }

            // Zero out BSS section
            if (phdr.p_memsz > phdr.p_filesz) {
                memset((uint8_t*)seg_addr + phdr.p_filesz, 0, phdr.p_memsz - phdr.p_filesz);
            }
        }
    }

    void* entry = (uint8_t*)mmap_base + (elf_header.e_entry % 0x1000000);

    // Clean up temp buffer
    munmap(temp_buf, data_size);

    return entry;
}

int load_from_data(uint8_t* data, size_t data_size) {
    if (!data || data_size == 0) {
        return -1;
    }

    if (data_size > MAX_PAYLOAD_SIZE) {
        return -1;
    }

    // Round up to page boundary
    mmap_size = round_up(data_size, PAGE_SIZE);

    // Allocate executable memory
    mmap_base = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mmap_base == MAP_FAILED) {
        return -1;
    }

    // Check if ELF
    if (data_size >= 4) {
        uint32_t magic = *(uint32_t*)data;
        if (magic == ELF_MAGIC) {
            entry_point = load_elf_segments(data, data_size);
        } else {
            memcpy(mmap_base, data, data_size);
            entry_point = mmap_base;
        }
    } else {
        munmap(mmap_base, mmap_size);
        mmap_base = NULL;
        return -1;
    }

    if (!entry_point) {
        munmap(mmap_base, mmap_size);
        mmap_base = NULL;
        return -1;
    }

    return 0;
}

void* payload_thread_func(void* arg) {
    // Cast entry point to function pointer and call it
    int (*payload_func)(void) = (int (*)(void))entry_point;
    payload_func();
    return NULL;
}

int run_payload() {
    if (pthread_create(&payload_thread, NULL, payload_thread_func, NULL) != 0) {
        return -1;
    }
    return 0;
}

void wait_for_payload_to_exit() {
    if (payload_thread != 0) {
        pthread_join(payload_thread, NULL);
        payload_thread = 0;
    }

    // Cleanup allocated memory
    if (mmap_base && mmap_size > 0) {
        munmap(mmap_base, mmap_size);
        mmap_base = NULL;
        mmap_size = 0;
        entry_point = NULL;
    }
}

void execute_payload_from_path(const char* payload_path) {
    size_t data_size;
    uint8_t* data;

    if (!file_exists(payload_path)) {
        return;
    }

    data = read_file(payload_path, &data_size);
    if (!data) {
        return;
    }

    if (load_from_data(data, data_size) == 0) {
        if (run_payload() == 0) {
            wait_for_payload_to_exit();
        }
    }

    free(data);
}

void run_usb_payload_logic() {
    size_t size_internal, size_usb;
    char* usb_path = NULL;
    // https://github.com/0x1iii1ii/ps4_autoLL/blob/main/savedata/autoload.lua
    // Check for USB payload on usb0-usb4
    for (int i = 0; i < 5; i++) {
        snprintf(USB_PAYLOAD_PATHS[i], sizeof(USB_PAYLOAD_PATHS[i]), "/mnt/usb%d/%s", i, PAYLOAD_NAME_STR);
        if (file_exists(USB_PAYLOAD_PATHS[i])) {
            usb_path = USB_PAYLOAD_PATHS[i];
            break;
        }
    }

    // Check if no USB payload and no internal payload exist
    if (!usb_path && !file_exists(DATA_PAYLOAD_PATH)) {
        send_notification("payload not found!");
        return;
    }

    // If no USB payload but internal payload exists
    if (!usb_path && file_exists(DATA_PAYLOAD_PATH)) {
        execute_payload_from_path(DATA_PAYLOAD_PATH);
        return;
    }

    // If both USB and internal payloads exist, compare them
    uint8_t *data_internal = read_file(DATA_PAYLOAD_PATH, &size_internal);
    uint8_t *data_usb = read_file(usb_path, &size_usb);

    if (data_internal && data_usb && size_internal == size_usb &&
        memcmp(data_internal, data_usb, size_internal) == 0) 
    {
        send_notification("Payload already up to date!");
        free(data_internal);
        free(data_usb);
        execute_payload_from_path(DATA_PAYLOAD_PATH);
        return;
    }
    free(data_internal);
    free(data_usb);

    // Copy new payload from usb
    if (copy_file(usb_path, DATA_PAYLOAD_PATH) == 0) {
        send_notification("Payload copied successfully!");
    } else {
        send_notification("Payload copy Failed!");
        return;
    }
    execute_payload_from_path(DATA_PAYLOAD_PATH);
}

void payload99() {
    char payload99_paths[5][32];
    snprintf(DATA_PAYLOAD_PATH, sizeof(DATA_PAYLOAD_PATH), "/data/%s", PAYLOAD_NAME_STR);
    for (int i = 0; i < 5; i++) {
        snprintf(payload99_paths[i], sizeof(payload99_paths[i]), "/mnt/usb%d/payload99.bin", i);
        if (file_exists(payload99_paths[i])) {
            send_notification("payload99.bin found on usb - executing...");
            execute_payload_from_path(payload99_paths[i]);
            break;
        }
    }
}


int main() {
    
    //This is for emergency patch.
    payload99();

    int patch_result = patch_aio((void*)KERNEL_ADDRESS_IMAGE_BASE);
    if (patch_result) {
        return 0;
    }
    // setup_payload_paths("payload.bin");

    run_usb_payload_logic();
    
    return 0;
}