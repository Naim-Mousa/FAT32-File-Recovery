#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <stdbool.h>
#include <string.h>
#include <openssl/sha.h>

struct stat SB;

// Structure representing the Boot Entry in FAT32 file system
#pragma pack(push,1)
typedef struct BootEntry{
    unsigned char  BS_jmpBoot[3];     // Assembly instruction to jump to boot code
    unsigned char  BS_OEMName[8];     // OEM Name in ASCII
    
    // ===================================================================================================================================================
    unsigned short BPB_BytsPerSec;    // Bytes per sector. Allowed values include 512, 1024, 2048, and 4096
    unsigned char  BPB_SecPerClus;    // Sectors per cluster (data unit). Allowed values are powers of 2, but the cluster size must be 32KB or smaller
    unsigned short BPB_RsvdSecCnt;    // Size in sectors of the reserved area
    unsigned char  BPB_NumFATs;       // Number of FATs
    unsigned short BPB_TotSec16;      // 16-bit value of number of sectors in file system
    // ===================================================================================================================================================

    unsigned short BPB_RootEntCnt;    // Maximum number of files in the root directory for FAT12 and FAT16. This is 0 for FAT32
    unsigned char  BPB_Media;         // Media type
    unsigned short BPB_FATSz16;       // 16-bit size in sectors of each FAT for FAT12 and FAT16. For FAT32, this field is 0
    unsigned short BPB_SecPerTrk;     // Sectors per track of storage device
    unsigned short BPB_NumHeads;      // Number of heads in storage device
    unsigned int   BPB_HiddSec;       // Number of sectors before the start of partition
    
    // ===================================================================================================================================================
    unsigned int   BPB_TotSec32;      // 32-bit value of number of sectors in file system. Either this value or the 16-bit value above must be 0
    unsigned int   BPB_FATSz32;       // 32-bit size in sectors of one FAT
    // ===================================================================================================================================================

    unsigned short BPB_ExtFlags;      // A flag for FAT
    unsigned short BPB_FSVer;         // The major and minor version number
    
    // ===================================================================================================================================================
    unsigned int   BPB_RootClus;      // Cluster where the root directory can be found
    // ===================================================================================================================================================
    
    unsigned short BPB_FSInfo;        // Sector where FSINFO structure can be found
    unsigned short BPB_BkBootSec;     // Sector where backup copy of boot sector is located
    unsigned char  BPB_Reserved[12];  // Reserved
    unsigned char  BS_DrvNum;         // BIOS INT13h drive number
    unsigned char  BS_Reserved1;      // Not used
    unsigned char  BS_BootSig;        // Extended boot signature to identify if the next three values are valid
    unsigned int   BS_VolID;          // Volume serial number
    unsigned char  BS_VolLab[11];     // Volume label in ASCII. User defines when creating the file system
    unsigned char  BS_FilSysType[8];  // File system type label in ASCII
} BootEntry;
#pragma pack(pop)

// Structure representing a Directory Entry in FAT32
#pragma pack(push,1)
typedef struct DirEntry{
    // =============================================================================
    unsigned char  DIR_Name[11];      // File name
    unsigned char  DIR_Attr;          // File attributes
    // =============================================================================

    unsigned char  DIR_NTRes;         // Reserved
    unsigned char  DIR_CrtTimeTenth;  // Created time (tenths of second)
    unsigned short DIR_CrtTime;       // Created time (hours, minutes, seconds)
    unsigned short DIR_CrtDate;       // Created day
    unsigned short DIR_LstAccDate;    // Accessed day
    
    // =============================================================================
    unsigned short DIR_FstClusHI;     // High 2 bytes of the first cluster address
    // =============================================================================

    unsigned short DIR_WrtTime;       // Written time (hours, minutes, seconds
    unsigned short DIR_WrtDate;       // Written day

    // =============================================================================
    unsigned short DIR_FstClusLO;     // Low 2 bytes of the first cluster address
    unsigned int   DIR_FileSize;      // File size in bytes. (0 for directories)
    // =============================================================================
    
} DirEntry;
#pragma pack(pop)

BootEntry *BOOT_ENTRY;
__uint32_t *FAT;
unsigned int FIRST_DATA_SECTOR;

// Forward declarations of functions
int recover_file(char* filename);
void recover_large_file(DirEntry *entry, char* filename);

void print_usage(){
    printf("Usage: ./nyufile disk <options>\n");
    printf("  -i                     Print the file system information.\n");
    printf("  -l                     List the root directory.\n");
    printf("  -r filename [-s sha1]  Recover a contiguous file.\n");
    printf("  -R filename -s sha1    Recover a possibly non-contiguous file.\n");
}

// Function to map the disk image into memory
BootEntry *map_disk_image(const char *disk){

    // Check and open the disk image file
    if(stat(disk, &SB) != 0){
        print_usage();
        exit(EXIT_FAILURE);
    }

    int fd = open(disk, O_RDWR);
    
    if (fd == -1){
        print_usage();
        exit(EXIT_FAILURE);
    }
    
    if (fstat(fd, &SB) == -1){
        print_usage();
        close(fd);
        exit(EXIT_FAILURE);
    }

    // Map the disk image into memory
    BootEntry *diskImage = mmap(NULL, SB.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);

    if (diskImage == MAP_FAILED){
        print_usage();
        exit(EXIT_FAILURE);
    }
    
    // Return pointer to the mapped disk image
    return diskImage;
}

// Function to calculate the first sector of a cluster
unsigned int first_sector_of_cluster(unsigned int cluster){
    
    // cluster-2 because cluster numbers start at 2
    unsigned int firstSector = ((cluster - 2) * BOOT_ENTRY->BPB_SecPerClus) + FIRST_DATA_SECTOR;
    return firstSector;
}

// Function to get the byte offset of a given sector
unsigned int getOffset(unsigned int sectorNo){
    return sectorNo * BOOT_ENTRY->BPB_BytsPerSec;
}

// Function to calculate the cluster number from a directory entry
unsigned int entry_cluster_no(DirEntry* entry){
    
    // shift HIGH part left by 16 bits and combine two parts using OR
    return ((entry->DIR_FstClusHI << 16) | entry->DIR_FstClusLO);
}

// Function to extract the filename from a directory entry
char* get_filename(DirEntry *entry){
    
    char* entryName = malloc(13 * sizeof(char));

    // getting entry name into correct format
    int j;
    for (j = 0; j < 8; j++){
        if (entry->DIR_Name[j] == ' ') break;
        entryName[j] = entry->DIR_Name[j];
    }

    // Convert the 8.3 filename to a regular string
    if (entry->DIR_Name[8] != ' '){
        entryName[j] = '.';
        int n = j+1;
        for (j = 0; j < 3; j++){
            if (entry->DIR_Name[j + 8] == ' ') break;
            entryName[n+j] = entry->DIR_Name[j + 8];
        }

        entryName[n + j] = '\0';
    }

    else entryName[j] = '\0';

    return entryName;
}

// Function to list the contents of the root directory
void list_root_directory(){
    DirEntry *dirEntry;
    unsigned int clusterNo, firstSector, offset, rootClusterNo = BOOT_ENTRY->BPB_RootClus;
    int count = 0;
    int numEntries = BOOT_ENTRY->BPB_SecPerClus * BOOT_ENTRY->BPB_BytsPerSec / sizeof(DirEntry);
    clusterNo = rootClusterNo;

    // Iterate through the root directory entries and print their details
    while (clusterNo < 0x0FFFFFF8){

        firstSector = first_sector_of_cluster(clusterNo);
        offset = getOffset(firstSector);
        
        dirEntry = (DirEntry *)((unsigned char *)BOOT_ENTRY + offset);

        for(int i = 0; i<numEntries; i++){

            DirEntry *entry = &dirEntry[i];

            // if deleted entry
            if (entry->DIR_Name[0] == 0xE5) continue;

            char* entryName = get_filename(entry);

            // if directory
            if ((entry->DIR_Attr & 0x10) == 0x10){ 
                printf("%s/ (starting cluster = %u)\n", entryName, entry_cluster_no(entry));
                count++;
            }

            // if empty file
            else if (entry->DIR_Name[0] != 0x00 && entry->DIR_FileSize == 0){
                printf("%s (size = %u)\n", entryName, entry->DIR_FileSize);
                count++;
            }
            
            // if regular file
            else if (entry->DIR_FileSize != 0){
                printf("%s (size = %u, starting cluster = %u)\n", entryName, entry->DIR_FileSize, entry_cluster_no(entry));
                count++;
            }
        }
        
        // next cluster
        clusterNo = FAT[clusterNo];
    }

    printf("Total number of entries = %d\n", count);
}

// Function to recover a file with a given filename
int recover_file(char* filename){
    
    DirEntry *file, *dirEntry;
    unsigned int clusterNo, firstSector, offset, rootClusterNo = BOOT_ENTRY->BPB_RootClus;
    bool found, flag = false;
    bool multipleFiles = false;;
    int count = 0;
    int numEntries = BOOT_ENTRY->BPB_SecPerClus * BOOT_ENTRY->BPB_BytsPerSec / sizeof(DirEntry);
    clusterNo = rootClusterNo;

    // Search for the file in the directory structure
    while (clusterNo < 0x0FFFFFF8){

        firstSector = first_sector_of_cluster(clusterNo);
        offset = getOffset(firstSector);
        
        dirEntry = (DirEntry *)((unsigned char *)BOOT_ENTRY + offset);

        for(int i = 0; i<numEntries; i++){
            
            DirEntry *entry = &dirEntry[i];

            if (entry->DIR_Name[0] != 0xe5) continue;

            char* entryName = get_filename(entry);

            if (strlen(filename) != strlen(entryName)){
                free(entryName);
                continue;
            }

            found = true;
            for (size_t j = 1; j < strlen(filename); j++){
                if (filename[j] != entryName[j]){
                    found = false;
                    break;
                }
            }
            
            free(entryName);

            if(found && count == 0){
                flag = true;
                file = entry;
                count++;
            }

            else if(found && count == 1) multipleFiles = true;
            
            else continue;
        }

        // next cluster
        clusterNo = FAT[clusterNo];
    }

    // ambiguous file recovery request
    if (multipleFiles) return 2;

    // file recovered
    else if (flag){
            
        // if large file
        if (file->DIR_FileSize > (BOOT_ENTRY->BPB_BytsPerSec * BOOT_ENTRY->BPB_SecPerClus)){
            recover_large_file(file, filename);
            return 1;
        }

        file->DIR_Name[0] = filename[0];

        // if not an empty file
        if (file->DIR_FileSize > 0){
            unsigned short firstClusterNo = file->DIR_FstClusLO;
            FAT[firstClusterNo] = 0x0FFFFFFF;
            return 1;
        }
        
        return 1;
    }

    // file not found
    else return 0;
}

// Function to recover a large file spread across multiple clusters
void recover_large_file(DirEntry *entry, char *filename){
    entry->DIR_Name[0] = filename[0];
    unsigned int fileSize = entry->DIR_FileSize;
    unsigned int clusterSize= BOOT_ENTRY->BPB_SecPerClus * BOOT_ENTRY->BPB_BytsPerSec;
    unsigned short currentClusterNo = entry->DIR_FstClusLO;
    unsigned short nextClusterNo;

    // number of clusters the file is in
    unsigned int numberOfClusters = (fileSize + clusterSize - 1) / clusterSize;

    // Recover a file that spans multiple clusters
    for (int i = 1; i < numberOfClusters; i++){
        nextClusterNo = currentClusterNo + 1;
        FAT[currentClusterNo] = nextClusterNo;
        currentClusterNo = nextClusterNo;
    }
    
    FAT[currentClusterNo] = 0x0FFFFFFF;
}

// Function to recover a file with a given filename and SHA-1 hash
bool recover_file_sha1(char* filename, char* sha1){
    DirEntry *dirEntry;
    unsigned int clusterNo, firstSector, offset, rootClusterNo = BOOT_ENTRY->BPB_RootClus;
    bool found;
    int numEntries = BOOT_ENTRY->BPB_SecPerClus * BOOT_ENTRY->BPB_BytsPerSec / sizeof(DirEntry);
    clusterNo = rootClusterNo;

    unsigned char hash[SHA_DIGEST_LENGTH];

    // Search for the file and match its SHA-1 hash
    while (clusterNo < 0x0FFFFFF8){

        firstSector = first_sector_of_cluster(clusterNo);
        offset = getOffset(firstSector);
        
        dirEntry = (DirEntry *)((unsigned char *)BOOT_ENTRY + offset);

        for(int i = 0; i<numEntries; i++){
            
            DirEntry *entry = &dirEntry[i];

            if (entry->DIR_Name[0] != 0xe5) continue;

            char* entryName = get_filename(entry);

            if (strlen(filename) != strlen(entryName)){
                free(entryName);
                continue;
            }

            found = true;
            for (size_t j = 1; j < strlen(filename); j++){
                if (filename[j] != entryName[j]){
                    found = false;
                    break;
                }
            }
            
            free(entryName);
            
            // Recover the file if found and hash matches
            if (found){

                if (entry->DIR_FileSize > 0){
                    unsigned short fileStartingCluster = entry->DIR_FstClusLO;
                    unsigned int fileStartingSector = first_sector_of_cluster(fileStartingCluster);
                    unsigned int fileOffset = getOffset(fileStartingSector);
                    unsigned char* fileLocation = (unsigned char *)BOOT_ENTRY + fileOffset;

                    SHA1(fileLocation, entry->DIR_FileSize, hash);

                    unsigned char newBuffer[40];

                    for (size_t i = 0; i < 20; i++){
                        sprintf(&newBuffer[i*2], "%02x", hash[i]);
                    }
                    
                    if (memcmp(newBuffer, sha1, SHA_DIGEST_LENGTH*2) == 0){

                        entry->DIR_Name[0] = filename[0];
                        unsigned int fileSize = entry->DIR_FileSize;
                        unsigned int clusterSize= BOOT_ENTRY->BPB_SecPerClus * BOOT_ENTRY->BPB_BytsPerSec;
                        unsigned short currentClusterNo = entry->DIR_FstClusLO;
                        unsigned short nextClusterNo;

                        // number of clusters the file is in
                        unsigned int numberOfClusters = (fileSize + clusterSize - 1) / clusterSize;

                        if (entry->DIR_FileSize > (BOOT_ENTRY->BPB_BytsPerSec * BOOT_ENTRY->BPB_SecPerClus)){
                            for (int i = 1; i < numberOfClusters; i++){
                                nextClusterNo = currentClusterNo + 1;
                                FAT[currentClusterNo] = nextClusterNo;
                                currentClusterNo = nextClusterNo;
                            }
                            
                            FAT[currentClusterNo] = 0x0FFFFFFF;
                        }

                        else FAT[currentClusterNo] = 0x0FFFFFFF;
                        
                        return true;
                    }

                    else continue;
                }

                else{
                    if(memcmp(sha1, "da39a3ee5e6b4b0d3255bfef95601890afd80709", SHA_DIGEST_LENGTH) == 0){
                        entry->DIR_Name[0] = filename[0];
                        return true;
                    }

                    else continue;
                }
            }
        }

        // next cluster
        clusterNo = FAT[clusterNo];
    }
    
    return false;
}

int main(int argc, char *argv[]){
    char *filename, *sha1;
    int opt;
    int input = 0b00000;
    bool sha = false;

    if (argc < 3){
        print_usage();
        return EXIT_FAILURE;
    }

    char *disk = argv[1];
    
    BOOT_ENTRY = map_disk_image(disk);

    if (BOOT_ENTRY == NULL){
        print_usage();
        return EXIT_FAILURE;
    }

    // Initializing FAT
    FAT = (__uint32_t*)((unsigned char*)BOOT_ENTRY + (BOOT_ENTRY->BPB_RsvdSecCnt * BOOT_ENTRY->BPB_BytsPerSec));
    
    // where data blocks start
    FIRST_DATA_SECTOR = BOOT_ENTRY->BPB_RsvdSecCnt + (BOOT_ENTRY->BPB_NumFATs * BOOT_ENTRY->BPB_FATSz32);
    
    while ((opt = getopt(argc, argv, "ilr:R:s:")) != -1){
        
        switch (opt){
            case 'i':
                printf("Number of FATs = %u\n", BOOT_ENTRY->BPB_NumFATs);
                printf("Number of bytes per sector = %u\n", BOOT_ENTRY->BPB_BytsPerSec);
                printf("Number of sectors per cluster = %u\n", BOOT_ENTRY->BPB_SecPerClus);
                printf("Number of reserved sectors = %u\n", BOOT_ENTRY->BPB_RsvdSecCnt);
                exit(1);

            case 'l':
                list_root_directory();
                exit(1);

            case 'r':
                filename = optarg;
                break;

            case 's':
                sha1 = optarg;
                sha = true;
                break;

            case 'R':
                filename = optarg;
                break;

            // no options given
            default:
                print_usage();
                exit(1);
        }
    }

    // If given filename
    if(filename){
        // If given SHA-1 hash
        if (sha){
            if(recover_file_sha1(filename, sha1)) printf("%s: successfully recovered with SHA-1\n", filename);
            else printf("%s: file not found\n", filename);
            exit(1);
        }

        else{
            int val = recover_file(filename);

            if (val == 0) printf("%s: file not found\n", filename);

            else if (val == 1) printf("%s: successfully recovered\n", filename);

            else printf("%s: multiple candidates found\n", filename);
            
            exit(1);
        }
    }

    else print_usage();
}