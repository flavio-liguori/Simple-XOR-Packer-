#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

// Structures communes
typedef struct {
    char filename[256];
    uint8_t *data;
    size_t size;
    uint32_t checksum;
} file_info_t;

typedef struct {
    uint32_t magic;
    uint32_t original_size;
    uint32_t packed_size;
    uint32_t checksum;
    uint8_t key_size;
    uint8_t flags;
    uint16_t reserved;
} __attribute__((packed)) pack_header_t;

typedef struct {
    uint8_t *key;
    size_t size;
} xor_key_t;

#define MAGIC_SIGNATURE 0x50414B45  // "PAKE"
#define FLAG_ENCRYPTED  0x02

// Prototypes des fonctions
file_info_t* read_file(const char* filename);
void free_file_info(file_info_t *info);
xor_key_t* generate_xor_key(size_t key_size);
void free_xor_key(xor_key_t *key_info);
void xor_encrypt_decrypt(uint8_t *data, size_t data_size, const xor_key_t *key_info);
uint32_t calculate_checksum(const uint8_t *data, size_t size);
int generate_stub_file(const char *payload_file, const char *output_file);

// Fonction pour calculer un checksum simple
uint32_t calculate_checksum(const uint8_t *data, size_t size) {
    uint32_t checksum = 0;
    for (size_t i = 0; i < size; i++) {
        checksum += data[i];
        checksum = (checksum << 1) | (checksum >> 31);
    }
    return checksum;
}

// Fonction pour lire un fichier en mémoire
file_info_t* read_file(const char* filename) {
    FILE *file;
    file_info_t *info;
    
    printf("[+] Reading file: %s\n", filename);
    
    file = fopen(filename, "rb");
    if (!file) {
        printf("[-] Error: Cannot open file %s\n", filename);
        return NULL;
    }
    
    info = (file_info_t*)malloc(sizeof(file_info_t));
    if (!info) {
        printf("[-] Error: Memory allocation failed\n");
        fclose(file);
        return NULL;
    }
    
    strncpy(info->filename, filename, sizeof(info->filename) - 1);
    info->filename[sizeof(info->filename) - 1] = '\0';
    
    fseek(file, 0, SEEK_END);
    info->size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    printf("[+] File size: %zu bytes\n", info->size);
    
    info->data = (uint8_t*)malloc(info->size);
    if (!info->data) {
        printf("[-] Error: Memory allocation failed for file data\n");
        free(info);
        fclose(file);
        return NULL;
    }
    
    size_t bytes_read = fread(info->data, 1, info->size, file);
    if (bytes_read != info->size) {
        printf("[-] Error: Could not read entire file\n");
        free(info->data);
        free(info);
        fclose(file);
        return NULL;
    }
    
    fclose(file);
    
    info->checksum = calculate_checksum(info->data, info->size);
    printf("[+] Checksum: 0x%08X\n", info->checksum);
    
    return info;
}

// Fonction pour libérer la mémoire d'une structure file_info_t
void free_file_info(file_info_t *info) {
    if (info) {
        if (info->data) {
            free(info->data);
        }
        free(info);
    }
}

// Génération d'une clé XOR pseudo-aléatoire
xor_key_t* generate_xor_key(size_t key_size) {
    xor_key_t *key_info;
    key_info = (xor_key_t*)malloc(sizeof(xor_key_t));
    if (!key_info) {
        printf("[-] Failed to allocate memory for XOR key\n");
        return NULL;
    }
    key_info->key = (uint8_t*)malloc(key_size);
    if (!key_info->key) {
        printf("[-] Failed to allocate memory for XOR key data\n");
        free(key_info);
        return NULL;
    }
    key_info->size = key_size;

    srand(time(NULL));
    for (size_t i = 0; i < key_size; i++) {
        key_info->key[i] = rand() % 256;
    }

    return key_info;
}

// Fonction pour libérer la mémoire de la clé XOR
void free_xor_key(xor_key_t *key_info) {
    if (key_info) {
        if (key_info->key) {
            free(key_info->key);
        }
        free(key_info);
    }
}

// Fonction pour chiffrer/déchiffrer les données avec XOR
void xor_encrypt_decrypt(uint8_t *data, size_t data_size, const xor_key_t *key_info) {
    for (size_t i = 0; i < data_size; i++) {
        data[i] = data[i] ^ key_info->key[i % key_info->size];
    }
}

// Fonction pour convertir des données binaires en tableau C
void write_binary_as_c_array(FILE *output, const uint8_t *data, size_t size, const char *array_name) {
    fprintf(output, "static unsigned char %s[] = {\n", array_name);
    
    for (size_t i = 0; i < size; i++) {
        if (i % 12 == 0) {
            fprintf(output, "    ");
        }
        fprintf(output, "0x%02X", data[i]);
        if (i < size - 1) {
            fprintf(output, ",");
        }
        if ((i + 1) % 12 == 0 || i == size - 1) {
            fprintf(output, "\n");
        } else {
            fprintf(output, " ");
        }
    }
    
    fprintf(output, "};\n\n");
}

// Fonction pour générer le stub C
int generate_stub_file(const char *payload_file, const char *output_file) {
    printf("[+] Generating stub file: %s\n", output_file);
    
    // Lecture du payload
    file_info_t *payload_info = read_file(payload_file);
    if (!payload_info) {
        return -1;
    }
    
    // Génération de la clé XOR
    size_t key_size = 32; // Clé de 32 bytes
    xor_key_t *xor_key = generate_xor_key(key_size);
    if (!xor_key) {
        free_file_info(payload_info);
        return -1;
    }
    
    printf("[+] Generated XOR key of size: %zu bytes\n", key_size);
    
    // Chiffrement du payload
    uint8_t *encrypted_data = (uint8_t*)malloc(payload_info->size);
    if (!encrypted_data) {
        printf("[-] Failed to allocate memory for encrypted data\n");
        free_xor_key(xor_key);
        free_file_info(payload_info);
        return -1;
    }
    
    memcpy(encrypted_data, payload_info->data, payload_info->size);
    xor_encrypt_decrypt(encrypted_data, payload_info->size, xor_key);
    
    printf("[+] Payload encrypted successfully\n");
    
    // Création du header
    pack_header_t header;
    header.magic = MAGIC_SIGNATURE;
    header.original_size = payload_info->size;
    header.packed_size = payload_info->size; // Pas de compression pour le moment
    header.checksum = payload_info->checksum;
    header.key_size = key_size;
    header.flags = FLAG_ENCRYPTED;
    header.reserved = 0;
    
    // Ouverture du fichier de sortie
    FILE *output = fopen(output_file, "w");
    if (!output) {
        printf("[-] Error: Cannot create output file %s\n", output_file);
        free(encrypted_data);
        free_xor_key(xor_key);
        free_file_info(payload_info);
        return -1;
    }
    
    // Écriture du code C du stub
    fprintf(output, "/*\n");
    fprintf(output, " * Generated stub for packed executable\n");
    fprintf(output, " * Original file: %s\n", payload_file);
    fprintf(output, " * Original size: %u bytes\n", header.original_size);
    fprintf(output, " * Generation time: %s", ctime(&(time_t){time(NULL)}));
    fprintf(output, " */\n\n");
    
    fprintf(output, "#include <stdio.h>\n");
    fprintf(output, "#include <stdlib.h>\n");
    fprintf(output, "#include <string.h>\n");
    fprintf(output, "#include <stdint.h>\n");
    fprintf(output, "#include <unistd.h>\n");
    fprintf(output, "#include <sys/mman.h>\n");
    fprintf(output, "#include <sys/stat.h>\n");
    fprintf(output, "#include <fcntl.h>\n\n");
    
    // Définition des structures
    fprintf(output, "typedef struct {\n");
    fprintf(output, "    uint32_t magic;\n");
    fprintf(output, "    uint32_t original_size;\n");
    fprintf(output, "    uint32_t packed_size;\n");
    fprintf(output, "    uint32_t checksum;\n");
    fprintf(output, "    uint8_t key_size;\n");
    fprintf(output, "    uint8_t flags;\n");
    fprintf(output, "    uint16_t reserved;\n");
    fprintf(output, "} __attribute__((packed)) pack_header_t;\n\n");
    
    fprintf(output, "#define MAGIC_SIGNATURE 0x%08X\n", MAGIC_SIGNATURE);
    fprintf(output, "#define FLAG_ENCRYPTED 0x%02X\n\n", FLAG_ENCRYPTED);
    
    // Écriture du header en tant que données C
    fprintf(output, "// Packed file header\n");
    write_binary_as_c_array(output, (uint8_t*)&header, sizeof(header), "packed_header");
    
    // Écriture de la clé XOR
    fprintf(output, "// XOR decryption key\n");
    write_binary_as_c_array(output, xor_key->key, xor_key->size, "xor_key");
    
    // Écriture des données chiffrées
    fprintf(output, "// Encrypted payload data\n");
    write_binary_as_c_array(output, encrypted_data, payload_info->size, "encrypted_payload");
    
    // Fonction de déchiffrement XOR
    fprintf(output, "// XOR decryption function\n");
    fprintf(output, "void xor_decrypt(uint8_t *data, size_t data_size, const uint8_t *key, size_t key_size) {\n");
    fprintf(output, "    for (size_t i = 0; i < data_size; i++) {\n");
    fprintf(output, "        data[i] = data[i] ^ key[i %% key_size];\n");
    fprintf(output, "    }\n");
    fprintf(output, "}\n\n");
    
    // Fonction de calcul de checksum
    fprintf(output, "// Checksum calculation function\n");
    fprintf(output, "uint32_t calculate_checksum(const uint8_t *data, size_t size) {\n");
    fprintf(output, "    uint32_t checksum = 0;\n");
    fprintf(output, "    for (size_t i = 0; i < size; i++) {\n");
    fprintf(output, "        checksum += data[i];\n");
    fprintf(output, "        checksum = (checksum << 1) | (checksum >> 31);\n");
    fprintf(output, "    }\n");
    fprintf(output, "    return checksum;\n");
    fprintf(output, "}\n\n");
    
    // Fonction d'exécution en mémoire
    fprintf(output, "// Execute payload from memory\n");
    fprintf(output, "int execute_payload(uint8_t *payload_data, size_t payload_size) {\n");
    fprintf(output, "    // Create temporary file\n");
    fprintf(output, "    char temp_filename[] = \"/tmp/payload_XXXXXX\";\n");
    fprintf(output, "    int fd = mkstemp(temp_filename);\n");
    fprintf(output, "    if (fd == -1) {\n");
    fprintf(output, "        printf(\"[-] Failed to create temporary file\\n\");\n");
    fprintf(output, "        return -1;\n");
    fprintf(output, "    }\n\n");
    
    fprintf(output, "    // Write payload to temporary file\n");
    fprintf(output, "    ssize_t written = write(fd, payload_data, payload_size);\n");
    fprintf(output, "    if (written != (ssize_t)payload_size) {\n");
    fprintf(output, "        printf(\"[-] Failed to write payload to temporary file\\n\");\n");
    fprintf(output, "        close(fd);\n");
    fprintf(output, "        unlink(temp_filename);\n");
    fprintf(output, "        return -1;\n");
    fprintf(output, "    }\n\n");
    
    fprintf(output, "    // Make file executable\n");
    fprintf(output, "    if (fchmod(fd, 0755) != 0) {\n");
    fprintf(output, "        printf(\"[-] Failed to make file executable\\n\");\n");
    fprintf(output, "        close(fd);\n");
    fprintf(output, "        unlink(temp_filename);\n");
    fprintf(output, "        return -1;\n");
    fprintf(output, "    }\n\n");
    
    fprintf(output, "    close(fd);\n\n");
    
    fprintf(output, "    // Execute the payload\n");
    fprintf(output, "    int result = execl(temp_filename, temp_filename, (char*)NULL);\n");
    fprintf(output, "    \n");
    fprintf(output, "    // If execl returns, there was an error\n");
    fprintf(output, "    printf(\"[-] Failed to execute payload\\n\");\n");
    fprintf(output, "    unlink(temp_filename);\n");
    fprintf(output, "    return result;\n");
    fprintf(output, "}\n\n");
    
    // Fonction main
    fprintf(output, "int main(int argc, char *argv[]) {\n");
    fprintf(output, "    printf(\"[+] Starting packed executable...\\n\");\n\n");
    
    fprintf(output, "    // Verify header\n");
    fprintf(output, "    pack_header_t *header = (pack_header_t*)packed_header;\n");
    fprintf(output, "    if (header->magic != MAGIC_SIGNATURE) {\n");
    fprintf(output, "        printf(\"[-] Invalid magic signature\\n\");\n");
    fprintf(output, "        return -1;\n");
    fprintf(output, "    }\n\n");
    
    fprintf(output, "    if (!(header->flags & FLAG_ENCRYPTED)) {\n");
    fprintf(output, "        printf(\"[-] Payload is not encrypted\\n\");\n");
    fprintf(output, "        return -1;\n");
    fprintf(output, "    }\n\n");
    
    fprintf(output, "    printf(\"[+] Header verified successfully\\n\");\n");
    fprintf(output, "    printf(\"[+] Original size: %%u bytes\\n\", header->original_size);\n");
    fprintf(output, "    printf(\"[+] Key size: %%u bytes\\n\", header->key_size);\n\n");
    
    fprintf(output, "    // Allocate memory for decrypted payload\n");
    fprintf(output, "    uint8_t *decrypted_payload = malloc(header->original_size);\n");
    fprintf(output, "    if (!decrypted_payload) {\n");
    fprintf(output, "        printf(\"[-] Failed to allocate memory for payload\\n\");\n");
    fprintf(output, "        return -1;\n");
    fprintf(output, "    }\n\n");
    
    fprintf(output, "    // Copy and decrypt payload\n");
    fprintf(output, "    memcpy(decrypted_payload, encrypted_payload, header->original_size);\n");
    fprintf(output, "    xor_decrypt(decrypted_payload, header->original_size, xor_key, header->key_size);\n");
    fprintf(output, "    printf(\"[+] Payload decrypted successfully\\n\");\n\n");
    
    fprintf(output, "    // Verify checksum\n");
    fprintf(output, "    uint32_t calculated_checksum = calculate_checksum(decrypted_payload, header->original_size);\n");
    fprintf(output, "    if (calculated_checksum != header->checksum) {\n");
    fprintf(output, "        printf(\"[-] Checksum verification failed\\n\");\n");
    fprintf(output, "        printf(\"[-] Expected: 0x%%08X, Got: 0x%%08X\\n\", header->checksum, calculated_checksum);\n");
    fprintf(output, "        free(decrypted_payload);\n");
    fprintf(output, "        return -1;\n");
    fprintf(output, "    }\n");
    fprintf(output, "    printf(\"[+] Checksum verified successfully\\n\");\n\n");
    
    fprintf(output, "    // Execute the payload\n");
    fprintf(output, "    printf(\"[+] Executing payload...\\n\");\n");
    fprintf(output, "    int result = execute_payload(decrypted_payload, header->original_size);\n\n");
    
    fprintf(output, "    // Clean up\n");
    fprintf(output, "    free(decrypted_payload);\n");
    fprintf(output, "    return result;\n");
    fprintf(output, "}\n");
    
    fclose(output);
    
    printf("[+] Stub file generated successfully: %s\n", output_file);
    printf("[+] Original payload size: %zu bytes\n", payload_info->size);
    printf("[+] XOR key size: %zu bytes\n", key_size);
    
    // Nettoyage
    free(encrypted_data);
    free_xor_key(xor_key);
    free_file_info(payload_info);
    
    return 0;
}

int main(int argc, char *argv[]) {
    printf("=== XOR PACKER STUB GENERATOR ===\n");
    
    if (argc != 3) {
        printf("Usage: %s <payload_file> <output_stub.c>\n", argv[0]);
        printf("  payload_file  : Executable file to pack\n");
        printf("  output_stub.c : Generated C stub file\n");
        return 1;
    }
    
    const char *payload_file = argv[1];
    const char *output_file = argv[2];
    
    printf("[+] Payload file: %s\n", payload_file);
    printf("[+] Output stub: %s\n", output_file);
    
    int result = generate_stub_file(payload_file, output_file);
    if (result == 0) {
        printf("\n[+] Stub generation completed successfully!\n");
        printf("[+] To compile the stub:\n");
        printf("    gcc -o packed_executable %s\n", output_file);
        printf("[+] To run the packed executable:\n");
        printf("    ./packed_executable\n");
    } else {
        printf("\n[-] Stub generation failed!\n");
    }
    
    return result;
}